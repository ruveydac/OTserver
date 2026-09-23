import { inTransaction } from '../integrations/payload/transactions'
import { randomUUID } from 'node:crypto'
import { APIError, type PayloadHandler, type PayloadRequest } from 'payload'
import { getAuthorization } from '../access/authorization'
import { writeAudit } from '../collections/AuditLogs'
import { idOf, requireWritableAsset } from './access'
import { record, text } from './keys'
import { inIdentityContext, syncManualEndpoint } from './relationships'
import type { Asset, NetworkEndpoint } from '../payload-types'

export const atomicIdentity = <T>(req: PayloadRequest, work: () => Promise<T>): Promise<T> =>
  inTransaction(req, () => inIdentityContext(req, work))

const activeEndpoints = (asset: string, req: PayloadRequest) =>
  req.payload.find({
    collection: 'network-endpoints',
    depth: 0,
    pagination: false,
    overrideAccess: false,
    req,
    where: { and: [{ asset: { equals: asset } }, { endedAt: { exists: false } }] },
  })

const closeEndpoint = async (endpoint: NetworkEndpoint, at: string, req: PayloadRequest) => {
  await req.payload.update({
    collection: 'network-endpoints',
    id: endpoint.id,
    data: { endedAt: at },
    overrideAccess: false,
    req,
  })
  const services = await req.payload.find({
    collection: 'service-bindings',
    pagination: false,
    depth: 0,
    where: { and: [{ endpoint: { equals: endpoint.id } }, { endedAt: { exists: false } }] },
    overrideAccess: false,
    req,
  })
  for (const service of services.docs)
    await req.payload.update({
      collection: 'service-bindings',
      id: service.id,
      data: { endedAt: at, bindingKey: null },
      overrideAccess: false,
      req,
    })
  return services.docs
}

const reassignEndpoint = async (endpoint: NetworkEndpoint, target: Asset, req: PayloadRequest) => {
  await req.payload.update({
    collection: 'network-endpoints',
    id: endpoint.id,
    data: { asset: target.id },
    overrideAccess: false,
    req,
  })
  const services = await req.payload.find({
    collection: 'service-bindings',
    pagination: false,
    depth: 0,
    where: { and: [{ endpoint: { equals: endpoint.id } }, { endedAt: { exists: false } }] },
    overrideAccess: false,
    req,
  })
  for (const service of services.docs)
    await req.payload.update({
      collection: 'service-bindings',
      id: service.id,
      data: { asset: target.id },
      overrideAccess: false,
      req,
    })
}

export const performIdentityAction = async (
  id: string,
  input: Record<string, unknown>,
  req: PayloadRequest,
) => {
  const reason = text(input.reason)
  if (!reason || reason.length > 2000)
    throw new APIError('Supply a reason (at most 2000 characters).', 400)
  const action = text(input.action)
  if (
    !['merge', 'split', 'replace', 'retire', 'restore', 'transfer', 'close-endpoint'].includes(
      action,
    )
  )
    throw new APIError('Unknown identity action.', 400)
  return atomicIdentity(req, async () => {
    const source = await requireWritableAsset(id, req)
    const at = new Date().toISOString()
    const endpoints = (await activeEndpoints(id, req)).docs
    let target = text(input.target)
      ? await requireWritableAsset(text(input.target), req)
      : undefined
    if (target?.id === id) throw new APIError('Select a different target asset.', 400)
    if (target && idOf(target.site) !== idOf(source.site))
      throw new APIError('Transfer to the same site before reconciling hardware.', 400)

    if (action === 'merge' || action === 'replace') {
      if (!target || target.lifecycle !== 'active' || source.lifecycle !== 'active')
        throw new APIError('Select two active assets.', 400)
      if (action === 'merge') {
        const keys = await req.payload.find({
          collection: 'asset-identifiers',
          pagination: false,
          depth: 0,
          overrideAccess: false,
          req,
          where: { and: [{ asset: { in: [id, target.id] } }, { state: { equals: 'accepted' } }] },
        })
        for (const left of keys.docs.filter((key) => idOf(key.asset) === id)) {
          if (
            keys.docs.some(
              (right) =>
                idOf(right.asset) === target!.id &&
                right.authority === left.authority &&
                right.manufacturer === left.manufacturer &&
                right.scope === left.scope &&
                right.serial !== left.serial,
            )
          )
            throw new APIError(
              'Conflicting hardware serials must be reviewed and revoked before merging.',
              409,
            )
        }
        if (
          source.physicalKind !== 'unknown' &&
          target.physicalKind !== 'unknown' &&
          source.physicalKind !== target.physicalKind
        )
          throw new APIError('Different physical component kinds cannot be merged.', 409)
        for (const endpoint of endpoints) await reassignEndpoint(endpoint, target, req)
        for (const key of keys.docs.filter((key) => idOf(key.asset) === id))
          await req.payload.update({
            collection: 'asset-identifiers',
            id: key.id,
            data: { asset: target.id },
            overrideAccess: false,
            req,
          })
        const installed = await req.payload.find({
          collection: 'asset-installations',
          pagination: false,
          depth: 0,
          overrideAccess: false,
          req,
          where: {
            and: [
              { or: [{ parent: { equals: id } }, { module: { equals: id } }] },
              { removedAt: { exists: false } },
            ],
          },
        })
        for (const installation of installed.docs) {
          await req.payload.update({
            collection: 'asset-installations',
            id: installation.id,
            data: { removedAt: at },
            overrideAccess: false,
            req,
          })
          await req.payload.create({
            collection: 'asset-installations',
            data: {
              site: idOf(source.site),
              parent: idOf(installation.parent) === id ? target.id : idOf(installation.parent),
              module: idOf(installation.module) === id ? target.id : idOf(installation.module),
              slotPath: installation.slotPath,
              installedAt: at,
              source: 'identity-merge',
            },
            overrideAccess: false,
            req,
          })
        }
        await req.payload.update({
          collection: 'assets',
          id,
          data: { lifecycle: 'merged', mergedInto: target.id },
          overrideAccess: false,
          req,
        })
      } else {
        for (const endpoint of endpoints) {
          await closeEndpoint(endpoint, at, req)
          await req.payload.create({
            collection: 'network-endpoints',
            data: {
              site: idOf(source.site),
              asset: target.id,
              macAddress: endpoint.macAddress,
              interfaceKey: endpoint.interfaceKey,
              addresses: endpoint.addresses,
              firstSeen: at,
              reachability: 'unknown',
              source: 'confirmed-replacement',
            },
            overrideAccess: false,
            req,
          })
        }
        const installed = await req.payload.find({
          collection: 'asset-installations',
          pagination: false,
          depth: 0,
          overrideAccess: false,
          req,
          where: { and: [{ module: { equals: id } }, { removedAt: { exists: false } }] },
        })
        for (const installation of installed.docs) {
          await req.payload.update({
            collection: 'asset-installations',
            id: installation.id,
            data: { removedAt: at },
            overrideAccess: false,
            req,
          })
          await req.payload.create({
            collection: 'asset-installations',
            data: {
              site: idOf(source.site),
              parent: idOf(installation.parent),
              module: target.id,
              slotPath: installation.slotPath,
              installedAt: at,
              source: 'confirmed-replacement',
            },
            overrideAccess: false,
            req,
          })
        }
        await req.payload.update({
          collection: 'assets',
          id,
          data: { lifecycle: 'replaced', replacedBy: target.id },
          overrideAccess: false,
          req,
        })
        await req.payload.update({
          collection: 'assets',
          id: target.id,
          data: { baselined: false },
          overrideAccess: false,
          req,
        })
      }
    } else if (action === 'split') {
      const selected = Array.isArray(input.endpoints) ? input.endpoints.map(String) : []
      if (
        !selected.length ||
        selected.some((endpoint) => !endpoints.some(({ id }) => id === endpoint))
      )
        throw new APIError('Select current endpoints belonging to this asset.', 400)
      if (!target) {
        target = await req.payload.create({
          collection: 'assets',
          data: {
            name: text(input.name) || `${source.name} (split)`,
            site: idOf(source.site),
            assetClass: idOf(source.assetClass),
            status: 'unknown',
            criticality: source.criticality,
            physicalKind: 'unknown',
            uuid: randomUUID(),
          },
          overrideAccess: false,
          req,
        })
      }
      if (target.lifecycle !== 'active')
        throw new APIError('Restore the split target before assigning endpoints.', 400)
      for (const endpoint of endpoints.filter(({ id }) => selected.includes(id)))
        await reassignEndpoint(endpoint, target, req)
      const identifiers = Array.isArray(input.identifiers) ? input.identifiers.map(String) : []
      for (const keyID of identifiers) {
        const key = await req.payload.findByID({
          collection: 'asset-identifiers',
          id: keyID,
          depth: 0,
          overrideAccess: false,
          req,
        })
        if (idOf(key.asset) !== id)
          throw new APIError('Identifiers must belong to the source asset.', 400)
        await req.payload.update({
          collection: 'asset-identifiers',
          id: keyID,
          data: { asset: target.id },
          overrideAccess: false,
          req,
        })
      }
    } else if (action === 'transfer') {
      const site = text(input.site)
      const authorization = await getAuthorization(req)
      if (!site || (!authorization.isAdmin && !authorization.writableSiteIDs.includes(site)))
        throw new APIError('Write access to the destination site is required.', 403)
      await req.payload.findByID({ collection: 'sites', id: site, overrideAccess: false, req })
      if (site === idOf(source.site))
        throw new APIError('Select a different destination site.', 400)
      const installations = await req.payload.find({
        collection: 'asset-installations',
        pagination: false,
        depth: 0,
        overrideAccess: false,
        req,
        where: {
          and: [
            { or: [{ module: { equals: id } }, { parent: { equals: id } }] },
            { removedAt: { exists: false } },
          ],
        },
      })
      if (installations.docs.length)
        throw new APIError(
          'Remove active module installations before transferring; reinstall them at the destination.',
          409,
        )
      for (const endpoint of endpoints) await closeEndpoint(endpoint, at, req)
      await req.payload.update({
        collection: 'assets',
        id,
        data: { site },
        overrideAccess: false,
        req,
      })
      const keys = await req.payload.find({
        collection: 'asset-identifiers',
        pagination: false,
        depth: 0,
        where: { asset: { equals: id } },
        overrideAccess: false,
        req,
      })
      for (const key of keys.docs)
        await req.payload.update({
          collection: 'asset-identifiers',
          id: key.id,
          data: { site },
          overrideAccess: false,
          req,
        })
      for (const endpoint of endpoints)
        await req.payload.create({
          collection: 'network-endpoints',
          data: {
            site,
            asset: id,
            macAddress: endpoint.macAddress,
            interfaceKey: endpoint.interfaceKey,
            firstSeen: at,
            reachability: 'unknown',
            source: 'site-transfer',
          },
          overrideAccess: false,
          req,
        })
    } else if (action === 'close-endpoint') {
      const endpoint = endpoints.find(({ id }) => id === text(input.endpoint))
      if (!endpoint) throw new APIError('Select a current endpoint belonging to this asset.', 400)
      await closeEndpoint(endpoint, at, req)
    } else {
      if (action === 'retire')
        for (const endpoint of endpoints) await closeEndpoint(endpoint, at, req)
      await req.payload.update({
        collection: 'assets',
        id,
        data: {
          lifecycle: action === 'retire' ? 'retired' : 'active',
          mergedInto: null,
          replacedBy: null,
        },
        overrideAccess: false,
        req,
      })
    }
    const event = {
      id,
      asset: id,
      site: idOf(source.site),
      eventType: `identity.${action}`,
      reason,
      ...(target ? { relatedAsset: target.id } : {}),
      selection: input,
    }
    await writeAudit({ action: 'custom', after: event, req, targetCollection: 'assets' })
    if (target)
      await writeAudit({
        action: 'custom',
        after: { ...event, id: target.id, asset: target.id, relatedAsset: id },
        req,
        targetCollection: 'assets',
      })
    return { asset: id, target: target?.id, action }
  })
}

export const identityAction: PayloadHandler = async (req) => {
  if (!req.user) throw new APIError('Authentication required.', 401)
  return Response.json(
    await performIdentityAction(String(req.routeParams?.id || ''), record(await req.json?.()), req),
  )
}

/** Explicit, resumable batches; legacy serials are never promoted into hardware keys. */
export const migrateIdentity: PayloadHandler = async (req) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
  const input = record(await req.json?.())
  const page = Math.max(1, Math.floor(Number(input.page) || 1))
  const assets = await req.payload.find({
    collection: 'assets',
    page,
    limit: 100,
    depth: 0,
    sort: 'id',
    overrideAccess: false,
    req,
  })
  if (input.apply !== true)
    return Response.json({
      dryRun: true,
      page,
      totalDocs: assets.totalDocs,
      hasNextPage: assets.hasNextPage,
      assets: assets.docs.map(({ id }) => id),
    })
  await atomicIdentity(req, async () => {
    for (const asset of assets.docs) {
      const updated = await req.payload.update({
        collection: 'assets',
        id: asset.id,
        data: {
          uuid: asset.uuid || randomUUID(),
          lifecycle: asset.lifecycle || 'active',
          physicalKind: asset.physicalKind || 'unknown',
        },
        overrideAccess: false,
        req,
      })
      if ((await activeEndpoints(asset.id, req)).docs.length) continue
      const previous = req.context.identityMigration
      req.context.identityMigration = true
      try {
        await syncManualEndpoint({ doc: updated, previousDoc: {}, req } as Parameters<
          typeof syncManualEndpoint
        >[0])
      } finally {
        req.context.identityMigration = previous
      }
    }
    await writeAudit({
      action: 'custom',
      after: { eventType: 'identity.migration', page, count: assets.docs.length },
      req,
      targetCollection: 'assets',
    })
  })
  return Response.json({ page, migrated: assets.docs.length, hasNextPage: assets.hasNextPage })
}
