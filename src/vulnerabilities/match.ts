import type { CollectionBeforeChangeHook, Payload, PayloadRequest, TypedUser, Where } from 'payload'

export * from './matching'
import { MATCH_FIELDS, distinctive } from './matching'
import {
  type VulnerabilityCandidate,
  type VulnerabilityMatch,
  type AssetMatchInput,
  MAX_CANDIDATES,
  record,
  text,
  normalizeKey,
  searchTokens,
  assetFingerprint,
  matchAssetVulnerabilities,
} from './matching'

export const vulnerabilityCandidateQuery = (asset: AssetMatchInput): Where | undefined => {
  const productText = [text(asset.model), text(asset.operatingSystem), text(asset.catalogNumber)]
    .filter(Boolean)
    .join(' ')
  const tokens = distinctive(searchTokens(productText))
  const keys = [
    normalizeKey(text(asset.model)),
    normalizeKey(text(asset.operatingSystem)),
    normalizeKey(text(asset.catalogNumber)),
  ].filter((key) => key.length > 1)
  if (!tokens.length && !keys.length) return undefined
  return {
    or: [
      ...(keys.length ? [{ products: { in: keys } }] : []),
      ...(tokens.length ? [{ productTokens: { in: tokens } }] : []),
    ],
  }
}

export const findAssetVulnerabilities = async (
  payload: Payload,
  asset: AssetMatchInput,
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
): Promise<VulnerabilityMatch[]> => {
  const where = vulnerabilityCandidateQuery(asset)
  if (!where) return []

  const user = access.req?.user ?? access.user
  const result = await payload.find({
    collection: 'vulnerabilities',
    depth: 0,
    limit: MAX_CANDIDATES,
    ...(user ? { overrideAccess: false, user } : { overrideAccess: true }),
    pagination: false,
    ...(access.req ? { req: access.req } : {}),
    select: {
      affected: true,
      cve: true,
      cvssScore: true,
      cvssSeverity: true,
      knownExploited: true,
    },
    where,
  })
  return matchAssetVulnerabilities(asset, result.docs as VulnerabilityCandidate[])
}

/** Distinct CVEs for the installed physical assembly; each match retains its module/version. */
export const findAssemblyVulnerabilities = async (
  payload: Payload,
  asset: AssetMatchInput & { id?: string; name?: string },
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
): Promise<VulnerabilityMatch[]> => {
  const matches = new Map<string, VulnerabilityMatch>()
  const pending = [asset]
  const visited = new Set<string>()
  while (pending.length) {
    const current = pending.shift()!
    if (current.id && visited.has(current.id)) continue
    if (current.id) visited.add(current.id)
    for (const match of await findAssetVulnerabilities(payload, current, access)) {
      const previous = matches.get(match.cve)
      const components = [
        ...(previous?.components || []),
        ...(current.id
          ? [{ id: current.id, name: current.name || current.id, version: match.version }]
          : []),
      ]
      matches.set(match.cve, { ...(previous || match), components })
    }
    if (!current.id) continue
    const installations = await payload.find({
      collection: 'asset-installations',
      depth: 0,
      pagination: false,
      where: { and: [{ parent: { equals: current.id } }, { removedAt: { exists: false } }] },
      overrideAccess: false,
      ...access,
    })
    for (const installation of installations.docs) {
      const moduleID =
        typeof installation.module === 'string' ? installation.module : installation.module.id
      const component = await payload.findByID({
        collection: 'assets',
        id: moduleID,
        depth: 0,
        disableErrors: true,
        overrideAccess: false,
        ...access,
      })
      if (component && component.lifecycle === 'active') pending.push(component)
    }
  }
  return [...matches.values()]
}

/**
 * Canonical match ordering: known-exploited first, then highest CVSS, then CVE. Every view that
 * lists matches sorts this way so a truncated list shows the same entries the full page leads with.
 */
export const countAssetVulnerabilities = async (
  payload: Payload,
  asset: AssetMatchInput,
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
): Promise<number> => {
  const req = access.req
  if (!req) return (await findAssetVulnerabilities(payload, asset, access)).length

  // Imports touch hundreds of near-identical devices; resolve each fingerprint once.
  const cache = (req.context.vulnerabilityCounts ??= new Map<string, Promise<number>>()) as Map<
    string,
    Promise<number>
  >
  const key = assetFingerprint(asset)
  const cached = cache.get(key)
  if (cached) return cached
  const pending = findAssetVulnerabilities(payload, asset, access).then((matches) => matches.length)
  if (cache.size >= 1000) cache.delete(cache.keys().next().value!)
  cache.set(key, pending)
  return pending
}

export const catalogIsLoaded = async (payload: Payload, req?: PayloadRequest): Promise<boolean> => {
  const cached = req?.context.vulnerabilityCatalogReady
  if (typeof cached === 'boolean') return cached

  const result = await payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    select: { state: true, status: true },
    where: { source: { equals: 'nvd' } },
  })
  const feed = result.docs[0]
  const loaded =
    (feed?.status === 'ready' || feed?.status === 'partial') &&
    Object.keys(record(feed.state)).length > 0
  if (req) req.context.vulnerabilityCatalogReady = loaded
  return loaded
}

/**
 * Keeps `vulnerabilityCount` in sync with the stored asset metadata. It is a derived
 * value: nothing but this hook and the post-sync recount may write it.
 */
export const assignVulnerabilityCount: CollectionBeforeChangeHook = async ({
  context,
  data,
  originalDoc,
  req,
}) => {
  if (context.vulnerabilityCountSync) return data
  if (!(await catalogIsLoaded(req.payload, req))) return data

  const asset: AssetMatchInput = {}
  for (const field of MATCH_FIELDS) {
    const value = Object.hasOwn(data, field) ? data[field] : originalDoc?.[field]
    if (typeof value === 'string') asset[field] = value
  }
  data.vulnerabilityCount = await countAssetVulnerabilities(req.payload, asset, { req })
  return data
}

/** Recomputes every asset count after the catalog changed; writes only real differences. */
export const recountAssetVulnerabilities = async (payload: Payload): Promise<number> => {
  const counts = new Map<string, number>()
  let after: string | undefined
  let updated = 0

  for (;;) {
    const result = await payload.find({
      collection: 'assets',
      depth: 0,
      limit: 100,
      overrideAccess: true,
      pagination: false,
      sort: 'id',
      ...(after ? { where: { id: { greater_than: after } } } : {}),
      select: {
        firmwareVersion: true,
        hardwareVersion: true,
        model: true,
        catalogNumber: true,
        operatingSystem: true,
        vendor: true,
        vulnerabilityCount: true,
      },
    })

    for (const asset of result.docs) {
      const fingerprint = assetFingerprint(asset)
      let count = counts.get(fingerprint)
      if (count === undefined) {
        count = (await findAssetVulnerabilities(payload, asset)).length
        if (counts.size >= 1000) counts.delete(counts.keys().next().value!)
        counts.set(fingerprint, count)
      }
      if ((asset.vulnerabilityCount ?? null) === count) continue

      await payload.update({
        collection: 'assets',
        context: { vulnerabilityCountSync: true },
        data: { vulnerabilityCount: count },
        id: asset.id,
        overrideAccess: true,
      })
      updated += 1
    }

    if (result.docs.length < 100) break
    after = result.docs.at(-1)!.id
  }

  return updated
}
