import { APIError, type FilterOptionsProps, type PayloadRequest, type Where } from 'payload'
import { filterWritableSites, relationshipID } from '../access/authorization'

export const IMPORTS_BLOCKED_MESSAGE = 'Imports and Otter scans are blocked by this site’s type.'

export const importableSitesWhere: Where = { 'type.blockImports': { not_equals: true } }

export const siteBlocksImports = async (site: unknown, req: PayloadRequest): Promise<boolean> => {
  const id = relationshipID(site)
  if (!id) throw new APIError('Select a site before importing assets.', 400)
  const current = await req.payload.findByID({
    collection: 'sites',
    id,
    depth: 0,
    overrideAccess: !req.user,
    req,
    select: { type: true },
  })
  const typeID = relationshipID(current.type)
  if (!typeID) throw new APIError('Assign a site type before importing assets.', 400)
  // The caller can read this exact site. Machine principals cannot read the catalogue;
  // only its import policy is needed, never any other site's inventory or configuration.
  const type = await req.payload.findByID({
    collection: 'site-types',
    id: typeID,
    depth: 0,
    overrideAccess: true,
    req,
    select: { blockImports: true },
  })
  return type.blockImports === true
}

export const assertSiteAllowsImports = async (site: unknown, req: PayloadRequest) => {
  if (await siteBlocksImports(site, req))
    throw new APIError(IMPORTS_BLOCKED_MESSAGE, 403, { code: 'SITE_IMPORTS_BLOCKED' })
}

export const filterImportSites =
  (collection: 'asset-imports' | 'otter-scanners' | 'otter-profiles' | 'otter-schedules') =>
  async ({ id, req }: FilterOptionsProps): Promise<Where> => {
    const writable = await filterWritableSites({ req })
    if (
      req.context.importWrite ||
      req.context.otterScannerSiteID ||
      req.context.otterScannerUpdate ||
      req.context.otterSchedulerUpdate ||
      req.context.otterCredentialWrite
    )
      // Machine principals cannot query catalogue fields. Their exact-site filter remains;
      // upload/processing guards enforce the policy before inventory writes.
      return writable === true ? {} : writable
    const original = id
      ? await req.payload.findByID({
          collection,
          id,
          depth: 0,
          disableErrors: true,
          overrideAccess: !req.user,
          req,
          select: { site: true },
        })
      : undefined
    const currentSite = relationshipID(original?.site)
    // Existing records must remain editable for diagnostics, cancellation, and disabling schedules.
    const available: Where = currentSite
      ? { or: [importableSitesWhere, { id: { equals: currentSite } }] }
      : importableSitesWhere
    return writable === true ? available : { and: [writable, available] }
  }
