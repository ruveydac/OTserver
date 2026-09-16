import { randomUUID } from 'node:crypto'
import {
  APIError,
  type CollectionAfterChangeHook,
  type CollectionBeforeChangeHook,
  type PayloadRequest,
  type Payload,
  type TypedUser,
  type Where,
} from 'payload'
import { idOf, requireTransaction } from './access'
import { scopedKey } from './keys'
import { record } from './keys'
import { mergeAssetData, type DataQuality } from '../importers/assetQuality'

export const inIdentityContext = async <T>(
  req: PayloadRequest,
  work: () => Promise<T>,
): Promise<T> => {
  const previous = req.context.identityAction
  req.context.identityAction = true
  try {
    return await work()
  } finally {
    req.context.identityAction = previous
  }
}

/** Serialize overlapping graph/identifier changes under MongoDB snapshot isolation. */
export const lockIdentityAssets = async (ids: string[], req: PayloadRequest) => {
  for (const id of [...new Set(ids)].sort()) {
    const asset = await req.payload.findByID({
      collection: 'assets',
      id,
      depth: 0,
      overrideAccess: !req.user,
      req,
    })
    await inIdentityContext(req, () =>
      req.payload.update({
        collection: 'assets',
        id,
        data: { identityRevision: (asset.identityRevision || 0) + 1 },
        overrideAccess: true,
        req,
      }),
    )
  }
}

export const defaultNetworkContext = async (site: string, req: PayloadRequest) => {
  const legacyKey = scopedKey('legacy-network-context', site)
  const result = await req.payload.find({
    collection: 'network-contexts',
    where: { legacyKey: { equals: legacyKey } },
    limit: 1,
    depth: 0,
    overrideAccess: !req.user,
    req,
  })
  if (result.docs[0]) return result.docs[0]
  return req.payload.create({
    collection: 'network-contexts',
    data: {
      name: 'Legacy / unspecified network',
      site,
      legacyKey,
      description:
        'Compatibility scope for imports without a selected network context. Select explicit contexts for overlapping networks.',
    },
    overrideAccess: true,
    req,
  })
}

export const syncEndpointProjection: CollectionAfterChangeHook = async ({
  doc,
  previousDoc,
  req,
}) => {
  const ids = new Set([idOf(doc.asset), idOf(previousDoc?.asset)].filter(Boolean))
  for (const id of ids) {
    const endpoints = await req.payload.find({
      collection: 'network-endpoints',
      depth: 0,
      pagination: false,
      where: { and: [{ asset: { equals: id } }, { endedAt: { exists: false } }] },
      overrideAccess: !req.user,
      req,
      sort: 'createdAt',
    })
    const asset = await req.payload.findByID({
      collection: 'assets',
      id,
      depth: 0,
      overrideAccess: !req.user,
      req,
    })
    const primary =
      endpoints.docs.find((endpoint) => endpoint.macAddress === asset.macAddress) ||
      endpoints.docs[0]
    const addresses = [
      ...new Set(
        endpoints.docs.flatMap((endpoint) =>
          (endpoint.addresses || []).map(({ address }) => address),
        ),
      ),
    ]
    const macs = [
      ...new Set(
        endpoints.docs.flatMap((endpoint) => (endpoint.macAddress ? [endpoint.macAddress] : [])),
      ),
    ]
    const firstAddress =
      primary?.addresses?.find(({ address }) => address === asset.ipAddress) ||
      primary?.addresses?.[0]
    const previous = req.context.networkProjection
    req.context.networkProjection = true
    try {
      await req.payload.update({
        collection: 'assets',
        id,
        overrideAccess: !req.user,
        req,
        data: {
          macAddress: primary?.macAddress || null,
          ipAddress: firstAddress?.address || null,
          networkMask: firstAddress?.networkMask || null,
          gatewayAddress: firstAddress?.gatewayAddress || null,
          networkAddresses: addresses.map((address) => ({ address })),
          networkMACs: macs.map((address) => ({ address })),
        },
      })
    } finally {
      req.context.networkProjection = previous
    }
  }
  return doc
}

export const protectAssetIdentity: CollectionBeforeChangeHook = async ({
  data,
  originalDoc,
  req,
}) => {
  data.uuid = originalDoc?.uuid || data.uuid || randomUUID()
  if (
    req.context.identityAction ||
    req.context.networkProjection ||
    req.context.assetImport ||
    req.context.assetClassMigration ||
    req.context.vulnerabilityCountSync
  )
    return data
  if (
    !originalDoc?.id &&
    (data.mergedInto ||
      data.replacedBy ||
      (data.lifecycle && data.lifecycle !== 'active') ||
      data.networkAddresses?.length ||
      data.networkMACs?.length)
  )
    throw new APIError('New hardware must start with an active, unreconciled identity.', 400)
  if (originalDoc?.id && Object.hasOwn(data, 'site') && idOf(data.site) !== idOf(originalDoc.site))
    throw new APIError('Use the Transfer identity action to move hardware between sites.', 400)
  for (const field of ['uuid', 'mergedInto', 'replacedBy', 'networkAddresses', 'networkMACs']) {
    if (
      originalDoc?.id &&
      Object.hasOwn(data, field) &&
      JSON.stringify(data[field]) !== JSON.stringify(originalDoc[field])
    )
      throw new APIError(`${field} is managed by device identity actions.`, 400)
  }
  if (
    originalDoc?.id &&
    Object.hasOwn(data, 'lifecycle') &&
    data.lifecycle !== originalDoc.lifecycle
  )
    throw new APIError('Change lifecycle through an identity action.', 400)
  if (originalDoc?.id && data.serialNumber && data.serialNumber !== originalDoc.serialNumber) {
    const keys = await req.payload.find({
      collection: 'asset-identifiers',
      depth: 0,
      limit: 1,
      req,
      overrideAccess: !req.user,
      where: {
        and: [
          { asset: { equals: originalDoc.id } },
          { state: { equals: 'accepted' } },
          { serial: { not_equals: data.serialNumber } },
        ],
      },
    })
    if (keys.docs.length)
      throw new APIError(
        'Review and revoke conflicting accepted identifiers before correcting the serial.',
        409,
      )
  }
  return { ...data, uuid: originalDoc?.uuid || randomUUID() }
}

/** Compatibility for manual/API edits of the primary address fields. */
export const syncManualEndpoint: CollectionAfterChangeHook = async ({ doc, previousDoc, req }) => {
  if (
    req.context.assetImport ||
    req.context.networkProjection ||
    (req.context.identityAction && !req.context.identityMigration)
  )
    return doc
  if (!doc.macAddress && !doc.ipAddress) return doc
  const changed = ['macAddress', 'ipAddress', 'networkMask', 'gatewayAddress'].some(
    (field) => doc[field] !== previousDoc?.[field],
  )
  if (!changed) return doc
  const context = await defaultNetworkContext(idOf(doc.site), req)
  const previousEndpoint = await req.payload.find({
    collection: 'network-endpoints',
    depth: 0,
    limit: 1,
    overrideAccess: !req.user,
    req,
    where: {
      and: [
        { asset: { equals: doc.id } },
        { endedAt: { exists: false } },
        ...(previousDoc?.macAddress ? [{ macAddress: { equals: previousDoc.macAddress } }] : []),
      ],
    },
  })
  const current = previousEndpoint.docs[0]
  if (current && current.macAddress !== doc.macAddress) {
    await inIdentityContext(req, () =>
      req.payload.update({
        collection: 'network-endpoints',
        id: current.id,
        data: { endedAt: new Date().toISOString() },
        overrideAccess: !req.user,
        req,
      }),
    )
  }
  const addresses = [
    ...(doc.ipAddress
      ? [
          {
            address: doc.ipAddress,
            networkMask: doc.networkMask,
            gatewayAddress: doc.gatewayAddress,
          },
        ]
      : []),
    ...(current?.addresses || []).filter(
      ({ address }) => address !== previousDoc?.ipAddress && address !== doc.ipAddress,
    ),
  ]
  const data = {
    asset: doc.id,
    site: idOf(doc.site),
    networkContext: current ? idOf(current.networkContext) : context.id,
    macAddress: doc.macAddress,
    interfaceKey: current?.interfaceKey || `manual:${doc.uuid}`,
    addresses,
    source: 'human',
  }
  const provenance = req.context.identityMigration
    ? mergeAssetData(
        {},
        ['ipAddress', 'networkMask', 'gatewayAddress']
          .filter((field) => doc[field])
          .map((field) => {
            const origin = record(record(doc.fieldProvenance)[field])
            const quality = ['human', 'high', 'medium', 'low'].includes(String(origin.quality))
              ? (origin.quality as DataQuality)
              : 'human'
            return {
              data: { addresses },
              quality,
              source: typeof origin.source === 'string' ? origin.source : 'human',
            }
          }),
      ).fieldProvenance
    : undefined
  if (provenance?.addresses) data.source = provenance.addresses.source
  const endpointData = {
    ...data,
    ...(provenance ? { fieldProvenance: provenance, lastSeen: doc.lastSeen } : {}),
  }
  if (current && current.macAddress === doc.macAddress) {
    await req.payload.update({
      collection: 'network-endpoints',
      id: current.id,
      data: endpointData,
      overrideAccess: !req.user,
      req,
    })
  } else {
    await req.payload.create({
      collection: 'network-endpoints',
      data: {
        ...endpointData,
        firstSeen:
          (req.context.identityMigration && (doc.lastSeen || doc.createdAt)) ||
          new Date().toISOString(),
      },
      overrideAccess: !req.user,
      req,
    })
  }
  return doc
}

export const validateInstallation: CollectionBeforeChangeHook = async ({
  data,
  originalDoc,
  req,
}) => {
  await requireTransaction(req)
  const value = { ...originalDoc, ...data }
  if (originalDoc?.removedAt)
    throw new APIError('Historical module installations are immutable.', 400)
  if (value.removedAt && Date.parse(value.removedAt) < Date.parse(value.installedAt))
    throw new APIError('Removal must not precede installation.', 400)
  const parentID = idOf(value.parent)
  const moduleID = idOf(value.module)
  const parentAsset = await req.payload.findByID({
    collection: 'assets',
    id: parentID,
    depth: 0,
    overrideAccess: false,
    req,
  })
  if (
    parentAsset.slotCapacity != null &&
    /^\d+$/.test(value.slotPath || '') &&
    Number(value.slotPath) >= parentAsset.slotCapacity
  )
    throw new APIError('Slot is outside the recorded chassis capacity.', 400)
  const visited = new Set([moduleID])
  let parent = parentID
  while (parent) {
    if (visited.has(parent))
      throw new APIError('A module cannot contain itself or an ancestor.', 400)
    visited.add(parent)
    const installed = await req.payload.find({
      collection: 'asset-installations',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: { and: [{ module: { equals: parent } }, { removedAt: { exists: false } }] },
    })
    parent = idOf(installed.docs[0]?.parent)
  }
  await lockIdentityAssets([...visited], req)
  return data
}

export const assetHistoryScope = async (assetID: string, payload: Payload, user?: TypedUser) => {
  const ids = new Set([assetID])
  let pending = [assetID]
  while (pending.length) {
    const aliases = await payload.find({
      collection: 'assets',
      depth: 0,
      pagination: false,
      overrideAccess: false,
      user,
      where: { mergedInto: { in: pending } },
    })
    pending = aliases.docs.map(({ id }) => id).filter((id) => !ids.has(id))
    for (const id of pending) ids.add(id)
  }
  const endpoints = await payload.find({
    collection: 'network-endpoints',
    depth: 0,
    pagination: false,
    overrideAccess: false,
    user,
    where: { asset: { in: [...ids] } },
  })
  const assets: Where = { asset: { in: [...ids] } }
  const observations: Where = {
    or: [assets, { endpoint: { in: endpoints.docs.map(({ id }) => id) } }],
  }
  return { assets, observations }
}
