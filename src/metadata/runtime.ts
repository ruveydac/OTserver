import { APIError, type Payload, type PayloadRequest } from 'payload'
import { createHash } from 'node:crypto'
import { emptyCatalog, createCatalogMatcher, type Catalog } from './catalog'

export const catalogRevision = (data: Catalog) =>
  createHash('sha256').update(JSON.stringify(data)).digest('hex')
export type ActiveCatalog = {
  catalog: Catalog
  revision: string
  match: ReturnType<typeof createCatalogMatcher>
}
export const unloadedCatalog: ActiveCatalog = {
  catalog: emptyCatalog,
  revision: 'unloaded',
  match: createCatalogMatcher(emptyCatalog, 'unloaded'),
}
const cache = new WeakMap<Payload, ActiveCatalog>()

export const activeCatalog = async (
  payload: Payload,
  req?: PayloadRequest,
): Promise<ActiveCatalog> => {
  const pinned = req?.context.deviceMetadataCatalog as ActiveCatalog | undefined
  if (pinned) return pinned
  const state = await payload.find({
    collection: 'device-catalog',
    where: { id: { equals: 'active' } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
    req,
    select: { revision: true },
  })
  const revision = state.docs.find(({ id }) => id === 'active')?.revision
  if (!revision) return unloadedCatalog
  const cached = cache.get(payload)
  if (cached?.revision === revision) return cached
  const stored = await payload.findByID({
    collection: 'device-catalog',
    id: 'active',
    depth: 0,
    overrideAccess: true,
    req,
  })
  const data = stored.catalog as unknown as Catalog
  if (catalogRevision(data) !== stored.revision)
    throw new APIError('Device catalog checksum mismatch.', 503)
  const result = {
    catalog: data,
    revision: stored.revision,
    match: createCatalogMatcher(data, stored.revision),
  }
  cache.set(payload, result)
  return result
}

export const matchAssetMetadata = async (
  payload: Payload,
  asset: Record<string, unknown>,
  req?: PayloadRequest,
) => (await activeCatalog(payload, req)).match(asset)
