import { requireTransaction } from '../integrations/payload/transactions'
export { requireTransaction } from '../integrations/payload/transactions'
import { APIError, type CollectionBeforeChangeHook, type PayloadRequest } from 'payload'
import { getAuthorization, relationshipID } from '../access/authorization'

export const idOf = (value: unknown): string => String(relationshipID(value) ?? '')

export const requireWritableAsset = async (id: string, req: PayloadRequest) => {
  const asset = await req.payload.findByID({
    collection: 'assets',
    id,
    depth: 0,
    overrideAccess: false,
    req,
  })
  const authorization = await getAuthorization(req)
  if (!authorization.isAdmin && !authorization.writableSiteIDs.includes(idOf(asset.site)))
    throw new APIError('Write access to every affected asset is required.', 403)
  return asset
}

/** User-created relationships must never smuggle an asset from another permission scope. */
export const enforceIdentityRelationships: CollectionBeforeChangeHook = async ({
  data,
  originalDoc,
  req,
  collection,
}) => {
  await requireTransaction(req)
  const site = idOf(data.site ?? originalDoc?.site)
  const references = [
    ['asset', 'assets'],
    ['candidate', 'assets'],
    ['parent', 'assets'],
    ['module', 'assets'],
    ['endpoint', 'network-endpoints'],
  ] as const
  for (const [field, slug] of references) {
    const id = idOf(Object.hasOwn(data, field) ? data[field] : originalDoc?.[field])
    if (!id) continue
    const related = await req.payload.findByID({
      collection: slug,
      id,
      depth: 0,
      overrideAccess: !req.user,
      req,
    })
    if (idOf(related.site) !== site)
      throw new APIError('Related records must belong to the same site.', 400)
    if (
      field === 'asset' &&
      'lifecycle' in related &&
      related.lifecycle &&
      related.lifecycle !== 'active' &&
      collection.slug === 'asset-identifiers' &&
      (data.state ?? originalDoc?.state ?? 'accepted') === 'accepted' &&
      !req.context.identityAction
    )
      throw new APIError('Restore hardware before accepting additional identity keys.', 400)
    if (
      field === 'endpoint' &&
      'asset' in related &&
      idOf(data.asset ?? originalDoc?.asset) !== idOf(related.asset) &&
      !req.context.identityAction
    )
      throw new APIError('The service must belong to its endpoint’s asset.', 400)
  }
  if (originalDoc?.id && !req.context.identityAction) {
    for (const field of [
      'site',
      'asset',
      ...(collection.slug === 'asset-installations' ? ['parent', 'module', 'slotPath'] : []),
    ]) {
      if (Object.hasOwn(data, field) && idOf(data[field]) !== idOf(originalDoc[field]))
        throw new APIError(
          'Use an identity action to transfer or reassign an existing relationship.',
          400,
        )
    }
  }
  return data
}
