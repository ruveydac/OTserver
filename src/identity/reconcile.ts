import { isIP } from 'node:net'
import type { PayloadRequest } from 'payload'
import type { Asset, NetworkEndpoint } from '../payload-types'
import type { ImportedAsset } from '../importers/types'
import { hardwareKey, scopedKey, text, endpointBindingKey } from './keys'
import { idOf, requireWritableAsset } from './access'
import { writeAudit } from '../collections/AuditLogs'
import { mergeAssetData, type DataQuality } from '../importers/assetQuality'
import { importSources } from '../importers/sources'

export const openIdentityCase = async (
  input: {
    site: string
    asset?: string
    candidate?: string
    kind: 'identity-conflict' | 'possible-duplicate' | 'replacement' | 'cross-site'
    reason: string
    evidence?: Record<string, unknown>
    confidence?: number
  },
  req: PayloadRequest,
) => {
  const caseKey = scopedKey(
    'case',
    input.site,
    input.asset,
    input.candidate,
    input.kind,
    input.reason,
    input.evidence,
  )
  const existing = await req.payload.find({
    collection: 'identity-cases',
    depth: 0,
    limit: 1,
    where: { caseKey: { equals: caseKey } },
    overrideAccess: false,
    req,
  })
  if (existing.docs[0]) return existing.docs[0]
  return req.payload.create({
    collection: 'identity-cases',
    data: { ...input, caseKey, status: 'open' },
    overrideAccess: true,
    req,
  })
}

export const resolveImportedIdentity = async (
  input: ImportedAsset,
  site: string,
  networkContext: string,
  req: PayloadRequest,
) => {
  let current: Asset | undefined
  let endpoint: NetworkEndpoint | undefined
  let blocked = false
  let unresolved = false
  if (input.macAddress) {
    const endpoints = await req.payload.find({
      collection: 'network-endpoints',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: {
        and: [
          { networkContext: { equals: networkContext } },
          { macAddress: { equals: input.macAddress } },
          { endedAt: { exists: false } },
        ],
      },
    })
    endpoint = endpoints.docs[0]
    if (endpoint?.asset) current = await requireWritableAsset(idOf(endpoint.asset), req)
    if (!endpoint) {
      // Only unmigrated legacy records participate in this compatibility lookup.
      const legacy = await req.payload.find({
        collection: 'assets',
        depth: 0,
        limit: 2,
        overrideAccess: false,
        req,
        where: {
          and: [
            { site: { equals: site } },
            { macAddress: { equals: input.macAddress } },
            { lifecycle: { not_in: ['merged', 'retired', 'replaced'] } },
          ],
        },
      })
      if (legacy.docs.length === 1) {
        const bindings = await req.payload.count({
          collection: 'network-endpoints',
          overrideAccess: false,
          req,
          where: { asset: { equals: legacy.docs[0].id } },
        })
        if (!bindings.totalDocs) current = await requireWritableAsset(legacy.docs[0].id, req)
      }
    }
  }
  const endpointAsset = current
  if (input.identity) {
    const key = hardwareKey(input.identity)
    // Narrow internal lookup reserves global hardware keys without exposing another site's inventory.
    const identifiers = await req.payload.find({
      collection: 'asset-identifiers',
      depth: 0,
      limit: 1,
      where: { key: { equals: key } },
      overrideAccess: true,
      req,
    })
    const identifier = identifiers.docs[0]
    if (identifier && idOf(identifier.site) !== site) {
      await openIdentityCase(
        {
          site,
          kind: 'cross-site',
          reason: 'Hardware identity requires an authorized cross-site reconciliation.',
          confidence: 3,
        },
        req,
      )
      return { current: undefined, endpoint, blocked: true, unresolved: true, suppressFields: true }
    }
    if (identifier?.state && identifier.state !== 'accepted') {
      await openIdentityCase(
        {
          site,
          asset: current?.id,
          kind: 'identity-conflict',
          confidence: 3,
          reason: 'This hardware identifier is contested or revoked.',
          evidence: { identity: input.identity },
        },
        req,
      )
      return { current, endpoint, blocked: true, unresolved: !current, suppressFields: true }
    }
    if (identifier) current = await requireWritableAsset(idOf(identifier.asset), req)
    else if (current) {
      const accepted = await req.payload.find({
        collection: 'asset-identifiers',
        depth: 0,
        limit: 1,
        overrideAccess: false,
        req,
        where: { and: [{ asset: { equals: current.id } }, { state: { equals: 'accepted' } }] },
      })
      if (
        accepted.docs.length ||
        (current.serialNumber && current.serialNumber !== input.identity.serial)
      )
        current = undefined
    }
    if (endpointAsset && current?.id !== endpointAsset.id) blocked = true
  } else if (current) {
    const serials = [
      ...new Set(
        (input.observations || []).map(({ fields }) => text(fields.serialNumber)).filter(Boolean),
      ),
    ]
    if (serials.some((serial) => current!.serialNumber && serial !== current!.serialNumber)) {
      blocked = true
      await openIdentityCase(
        {
          site,
          asset: current.id,
          kind: 'identity-conflict',
          reason: 'An unqualified serial changed at this endpoint; hardware fields were preserved.',
          evidence: { serials },
        },
        req,
      )
    }
  }
  if (current && current.lifecycle && current.lifecycle !== 'active') {
    blocked = true
    await openIdentityCase(
      {
        site,
        asset: current.id,
        kind: 'identity-conflict',
        reason: 'Archived hardware was observed; explicitly restore or reconcile it.',
      },
      req,
    )
  }
  if (!input.macAddress && !input.identity) unresolved = true
  return {
    current,
    endpoint,
    blocked,
    unresolved,
    endpointAsset,
    suppressFields: Boolean(
      current &&
      blocked &&
      (!input.identity || (current.lifecycle && current.lifecycle !== 'active')),
    ),
  }
}

export const bindImportedIdentity = async (
  input: ImportedAsset,
  asset: Asset,
  site: string,
  context: string,
  observedAt: string,
  blocked: boolean,
  endpointAsset: Asset | undefined,
  req: PayloadRequest,
) => {
  if (input.identity) {
    const key = hardwareKey(input.identity)
    const existing = await req.payload.find({
      collection: 'asset-identifiers',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: { key: { equals: key } },
    })
    if (!existing.docs.length)
      await req.payload.create({
        collection: 'asset-identifiers',
        data: {
          ...input.identity,
          site,
          asset: asset.id,
          key,
          state: 'accepted',
          source: 'qualified-otter-v2',
          evidence: { observedAt, sources: input.observations?.map(({ source }) => source) || [] },
        },
        overrideAccess: true,
        req,
      })
  }
  if (blocked) {
    if (endpointAsset && endpointAsset.id !== asset.id)
      await openIdentityCase(
        {
          site,
          asset: endpointAsset.id,
          candidate: asset.id,
          kind: 'replacement',
          confidence: 3,
          reason:
            'Different hardware identity was observed at an assigned endpoint. Confirm replacement or correct the association.',
        },
        req,
      )
    return []
  }
  const evidence = [...(input.endpoints || [])]
  if (!evidence.length && input.macAddress)
    evidence.push({
      macAddress: input.macAddress,
      addresses: [],
      source: text(req.context.identityImportSource) || 'unknown',
    })
  for (const endpoint of evidence) {
    if (endpoint.macAddress === input.macAddress && input.ipAddress && isIP(input.ipAddress)) {
      endpoint.addresses = [
        {
          address: input.ipAddress,
          networkMask: input.networkMask,
          gatewayAddress: input.gatewayAddress,
        },
        ...endpoint.addresses.filter(({ address }) => address !== input.ipAddress),
      ]
    }
  }
  const bound: NetworkEndpoint[] = []
  for (const endpoint of evidence) {
    const bindingKey = endpointBindingKey(
      context,
      endpoint.macAddress,
      asset.id,
      endpoint.interfaceKey || '',
    )
    const existing = await req.payload.find({
      collection: 'network-endpoints',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: { bindingKey: { equals: bindingKey } },
    })
    const current = existing.docs[0]
    if (current?.asset && idOf(current.asset) !== asset.id) {
      await openIdentityCase(
        {
          site,
          asset: asset.id,
          candidate: idOf(current.asset),
          kind: 'identity-conflict',
          confidence: 2,
          reason: 'An observed interface is already associated with another physical asset.',
          evidence: { macAddress: endpoint.macAddress },
        },
        req,
      )
      continue
    }
    if (current?.lastSeen && observedAt < current.lastSeen) {
      bound.push(current)
      continue
    }
    const fields = {
      ...endpoint,
      site,
      asset: asset.id,
      networkContext: context,
      lastSeen: observedAt,
      reachability: 'online' as const,
      bindingKey,
    }
    const quality = (source: string): DataQuality =>
      source === 'human'
        ? 'human'
        : input.observations?.find((observation) => observation.source === source)?.quality ||
          importSources.find((item) => item.value === source)?.quality ||
          'low'
    const merged = mergeAssetData(
      current
        ? {
            ...current,
            fieldProvenance: current.fieldProvenance || {
              addresses: {
                quality: quality(current.source || 'unknown'),
                source: current.source || 'unknown',
              },
            },
          }
        : {},
      [
        {
          data: { addresses: fields.addresses },
          quality: quality(endpoint.source),
          source: endpoint.source,
        },
        ...(endpoint.macAddress === input.macAddress
          ? (input.observations || []).flatMap((observation) => {
              const address = text(observation.fields.ipAddress)
              if (!isIP(address)) return []
              return [
                {
                  data: {
                    addresses: [
                      {
                        address,
                        networkMask: text(observation.fields.networkMask) || undefined,
                        gatewayAddress: text(observation.fields.gatewayAddress) || undefined,
                      },
                    ],
                  },
                  quality: observation.quality,
                  source: observation.source,
                },
              ]
            })
          : []),
      ],
    )
    fields.addresses = (merged.data.addresses ||
      current?.addresses ||
      fields.addresses) as typeof fields.addresses
    const endpointData = { ...fields, fieldProvenance: merged.fieldProvenance }
    if (current?.source === 'human') endpointData.source = 'human'
    const result = current
      ? await req.payload.update({
          collection: 'network-endpoints',
          id: current.id,
          data: endpointData,
          overrideAccess: false,
          req,
        })
      : await req.payload.create({
          collection: 'network-endpoints',
          data: { ...endpointData, firstSeen: observedAt },
          overrideAccess: false,
          req,
        })
    bound.push(result)
    if (
      current &&
      JSON.stringify(current.addresses?.map(({ address }) => address)) !==
        JSON.stringify(result.addresses?.map(({ address }) => address))
    )
      await writeAudit({
        action: 'custom',
        after: {
          asset: asset.id,
          site,
          eventType: 'network.reconfigured',
          endpoint: result.id,
          observedAt,
        },
        req,
        targetCollection: 'network-endpoints',
      })
  }
  for (const service of input.services || []) {
    const matching = bound.filter((endpoint) =>
      endpoint.addresses?.some(({ address }) => address === service.address),
    )
    if (matching.length !== 1) continue
    const endpoint = matching[0]
    const bindingKey = scopedKey(
      'service',
      endpoint.id,
      service.address,
      service.transport,
      service.port,
      service.protocol,
    )
    const existing = await req.payload.find({
      collection: 'service-bindings',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: { bindingKey: { equals: bindingKey } },
    })
    const current = existing.docs[0]
    if (current?.lastSeen && current.lastSeen >= observedAt) continue
    const fields = {
      ...service,
      site,
      asset: asset.id,
      endpoint: endpoint.id,
      bindingKey,
      lastSeen: observedAt,
    }
    if (current)
      await req.payload.update({
        collection: 'service-bindings',
        id: current.id,
        data: fields,
        overrideAccess: false,
        req,
      })
    else
      await req.payload.create({
        collection: 'service-bindings',
        data: { ...fields, firstSeen: observedAt },
        overrideAccess: true,
        req,
      })
  }
  return bound
}

export const recordContainment = async (
  input: ImportedAsset,
  assetID: string,
  parentID: string,
  site: string,
  observedAt: string,
  req: PayloadRequest,
) => {
  const existing = await req.payload.find({
    collection: 'asset-installations',
    depth: 0,
    limit: 1,
    overrideAccess: false,
    req,
    where: { and: [{ module: { equals: assetID } }, { removedAt: { exists: false } }] },
  })
  const current = existing.docs[0]
  if (current) {
    if (
      idOf(current.parent) !== parentID ||
      (input.slotPath && current.slotPath !== input.slotPath)
    )
      await openIdentityCase(
        {
          site,
          asset: assetID,
          candidate: parentID,
          kind: 'identity-conflict',
          confidence: 3,
          reason:
            'Component containment changed; confirm a module move before replacing its installation.',
        },
        req,
      )
    return
  }
  await req.payload.create({
    collection: 'asset-installations',
    data: {
      site,
      parent: parentID,
      module: assetID,
      slotPath: input.slotPath,
      installedAt: observedAt,
      source: 'snmp-entity-mib',
    },
    overrideAccess: false,
    req,
  })
}

export const importObservedAt = (input: ImportedAsset, fallback: string) => {
  const values = [
    input.lastSeen,
    ...(input.observations || []).map(({ observedAt }) => observedAt),
  ].filter((value): value is string => Boolean(value) && !Number.isNaN(Date.parse(value!)))
  return values.length ? new Date(Math.max(...values.map(Date.parse))).toISOString() : fallback
}

export const descriptiveFields = (value: Record<string, unknown>) =>
  Object.fromEntries(
    Object.entries(value).filter(
      ([key]) =>
        ![
          'macAddress',
          'ipAddress',
          'networkMask',
          'gatewayAddress',
          'lastSeen',
          'site',
          'identity',
          'endpoints',
          'services',
          'componentRef',
          'parentComponentRef',
          'slotPath',
          'observedViaMAC',
        ].includes(key),
    ),
  )

export const suggestAdjacentInterfaces = async (asset: Asset, mac: string, req: PayloadRequest) => {
  // Locally administered and multicast addresses have no trustworthy OUI allocation pattern.
  if (Number.parseInt(mac.slice(0, 2), 16) & 3) return
  const peers = await req.payload.find({
    collection: 'assets',
    depth: 0,
    limit: 50,
    overrideAccess: false,
    req,
    where: {
      and: [
        { site: { equals: idOf(asset.site) } },
        { id: { not_equals: asset.id } },
        { macAddress: { like: mac.slice(0, 14) } },
        { lifecycle: { not_in: ['merged', 'replaced', 'retired'] } },
      ],
    },
  })
  for (const peer of peers.docs) {
    if (
      !peer.macAddress?.startsWith(mac.slice(0, 14)) ||
      Math.abs(
        Number.parseInt(mac.slice(-2), 16) - Number.parseInt(peer.macAddress.slice(-2), 16),
      ) !== 1
    )
      continue
    if (asset.serialNumber && peer.serialNumber && asset.serialNumber !== peer.serialNumber)
      continue
    const [first, second] = [asset.id, peer.id].sort()
    await openIdentityCase(
      {
        site: idOf(asset.site),
        asset: first,
        candidate: second,
        kind: 'possible-duplicate',
        confidence: 1,
        reason:
          'Adjacent globally administered MACs may be interfaces of one device; hardware confirmation is required.',
      },
      req,
    )
  }
}

export const suggestAttachmentChange = async (
  site: string,
  localAsset: string,
  remoteAsset: string,
  port: string,
  observedAt: string,
  req: PayloadRequest,
) => {
  if (!port) return
  const prior = await req.payload.find({
    collection: 'topology-links',
    depth: 0,
    limit: 1,
    sort: '-observedAt',
    overrideAccess: false,
    req,
    where: {
      and: [
        { site: { equals: site } },
        { localAsset: { equals: localAsset } },
        { 'local.portId': { equals: port } },
        { observedAt: { less_than_equal: observedAt } },
      ],
    },
  })
  const other = idOf(prior.docs[0]?.remoteAsset)
  if (!other || other === remoteAsset) return
  await openIdentityCase(
    {
      site,
      asset: remoteAsset,
      candidate: other,
      kind: 'possible-duplicate',
      confidence: 1,
      reason:
        'Different endpoint identities were observed at the same switch attachment. This can also be replacement or shared downstream equipment.',
    },
    req,
  )
}
