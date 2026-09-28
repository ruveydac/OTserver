import type { CollectionAfterDeleteHook, PayloadRequest } from 'payload'
import { requireTransaction } from './access'

/** Release bindings only when their owner is permanently gone, including legacy orphans. */
export const removeOrphanedBindings = async (assetID: string, req: PayloadRequest) => {
  if (!assetID) return false
  await requireTransaction(req)
  // Global existence check must include Trash and inaccessible sites. Neither is an orphan.
  const owner = await req.payload.find({
    collection: 'assets',
    where: { id: { equals: assetID } },
    depth: 0,
    limit: 1,
    select: {},
    trash: true,
    overrideAccess: true,
    req,
  })
  if (owner.docs.length) return false

  for (const collection of [
    'service-bindings',
    'network-endpoints',
    'asset-identifiers',
  ] as const) {
    const bindings = await req.payload.find({
      collection,
      where: { asset: { equals: assetID } },
      depth: 0,
      pagination: false,
      overrideAccess: true,
      req,
    })
    // Keep audited deletes serial within the original transaction.
    for (const binding of bindings.docs)
      await req.payload.delete({ collection, id: binding.id, overrideAccess: true, req })
  }
  return true
}

export const releaseDeletedAssetBindings: CollectionAfterDeleteHook = async ({ id, doc, req }) => {
  await removeOrphanedBindings(String(id), req)
  return doc
}
