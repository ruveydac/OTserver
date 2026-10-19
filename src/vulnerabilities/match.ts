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
  const matches: VulnerabilityMatch[] = []
  let after: string | undefined
  for (let scanned = 0; scanned < MAX_CANDIDATES;) {
    const limit = Math.min(100, MAX_CANDIDATES - scanned)
    const result = await payload.find({
      collection: 'vulnerabilities',
      depth: 0,
      limit,
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
      sort: 'id',
      where: after ? { and: [where, { id: { greater_than: after } }] } : where,
    })
    matches.push(...matchAssetVulnerabilities(asset, result.docs as VulnerabilityCandidate[]))
    scanned += result.docs.length
    if (result.docs.length < limit) break
    after = result.docs.at(-1)!.id
  }
  return matches
}

type MatchCache = Map<string, Promise<VulnerabilityMatch[]>>

const cachedAssetVulnerabilityMatches = (
  payload: Payload,
  asset: AssetMatchInput,
  access: { req?: PayloadRequest; user?: TypedUser | null },
  suppliedCache?: MatchCache,
) => {
  const cache =
    suppliedCache ||
    (access.req
      ? ((access.req.context.vulnerabilityMatchResults ??= new Map<
          string,
          Promise<VulnerabilityMatch[]>
        >()) as MatchCache)
      : undefined)
  if (!cache) return findAssetVulnerabilities(payload, asset, access)
  const key = assetFingerprint(asset)
  const cached = cache.get(key)
  if (cached) return cached
  const pending = findAssetVulnerabilities(payload, asset, access)
  if (cache.size >= 1000) cache.delete(cache.keys().next().value!)
  cache.set(key, pending)
  return pending
}

/** Distinct CVEs for the installed physical assembly; each match retains its module/version. */
export const findAssemblyVulnerabilities = async (
  payload: Payload,
  asset: AssetMatchInput & { id?: string; name?: string },
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
): Promise<VulnerabilityMatch[]> => {
  const groups = await findAssemblyVulnerabilityGroups(payload, asset, access)
  const matches = new Map<string, VulnerabilityMatch>()
  for (const { asset: current, matches: currentMatches } of groups) {
    for (const match of currentMatches) {
      const previous = matches.get(match.cve)
      const components = [
        ...(previous?.components || []),
        ...(current.id
          ? [{ id: current.id, name: current.name || current.id, version: match.version }]
          : []),
      ]
      matches.set(match.cve, { ...(previous || match), components })
    }
  }
  return [...matches.values()]
}

export const findAssemblyVulnerabilityGroups = async (
  payload: Payload,
  asset: AssetMatchInput & { id?: string; name?: string },
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
) => {
  const groups: {
    asset: AssetMatchInput & { id?: string; name?: string }
    matches: VulnerabilityMatch[]
  }[] = []
  const pending = [asset]
  const visited = new Set<string>()
  while (pending.length) {
    const current = pending.shift()!
    if (current.id && visited.has(current.id)) continue
    if (current.id) visited.add(current.id)
    groups.push({
      asset: current,
      matches: await findAssetVulnerabilities(payload, current, access),
    })
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
  return groups
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
  return (await cachedAssetVulnerabilityMatches(payload, asset, access)).length
}

type AssetReviewStatus = { asset: string | { id: string }; cve: string; status: string }

const findReviewsForAssets = async (
  payload: Payload,
  assetIDs: string[],
  access: { req?: PayloadRequest; user?: TypedUser | null },
) => {
  if (!assetIDs.length) return [] as AssetReviewStatus[]
  const user = access.req?.user ?? access.user
  const reviews: AssetReviewStatus[] = []
  let after: string | undefined
  for (;;) {
    const result = await payload.find({
      collection: 'asset-vulnerability-reviews',
      depth: 0,
      limit: 100,
      pagination: false,
      ...(user ? { overrideAccess: false, user } : { overrideAccess: true }),
      ...(access.req ? { req: access.req } : {}),
      select: { asset: true, cve: true, status: true },
      sort: 'id',
      where: {
        and: [{ asset: { in: assetIDs } }, ...(after ? [{ id: { greater_than: after } }] : [])],
      },
    })
    reviews.push(...result.docs)
    if (result.docs.length < 100) break
    after = result.docs.at(-1)!.id
  }
  return reviews
}

export const countOpenAssetVulnerabilities = async (
  payload: Payload,
  asset: AssetMatchInput & { id?: string; lifecycle?: string | null },
  access: { req?: PayloadRequest; user?: TypedUser | null } = {},
  matchCache?: MatchCache,
  reviewStatuses?: AssetReviewStatus[],
): Promise<number> => {
  if (asset.lifecycle === 'merged') return 0
  const matches = await cachedAssetVulnerabilityMatches(payload, asset, access, matchCache)
  if (!asset.id) return matches.length
  const reviews = reviewStatuses ?? (await findReviewsForAssets(payload, [asset.id], access))
  const assetReviews = reviews.filter(
    (review) =>
      String(typeof review.asset === 'object' ? review.asset.id : review.asset) === asset.id,
  )
  const statuses = new Map(assetReviews.map(({ cve, status }) => [cve, status]))
  const matched = new Set(matches.map(({ cve }) => cve))
  let count = matches.filter(
    ({ cve }) => !['dismissed', 'resolved'].includes(statuses.get(cve) || ''),
  ).length
  for (const { cve, status } of assetReviews)
    if (status === 'confirmed' && !matched.has(cve)) count += 1
  return count
}

export const catalogIsLoaded = async (payload: Payload, req?: PayloadRequest): Promise<boolean> => {
  const cached = req?.context.vulnerabilityCatalogReady
  if (typeof cached === 'boolean') return cached

  const result = await payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    limit: 2,
    overrideAccess: true,
    req,
    select: { state: true, documentCount: true, source: true },
    where: { source: { in: ['nvd', 'csaf'] } },
  })
  const loaded = result.docs.some((feed) =>
    feed.source === 'nvd'
      ? Object.keys(record(feed.state)).length > 0
      : (feed.documentCount ?? 0) > 0,
  )
  if (req) req.context.vulnerabilityCatalogReady = loaded
  return loaded
}

export const refreshAssetVulnerabilityCount = async (
  payload: Payload,
  asset: AssetMatchInput & {
    id: string
    lifecycle?: string | null
    vulnerabilityCount?: number | null
  },
  req: PayloadRequest,
) => {
  if (asset.lifecycle !== 'merged' && !(await catalogIsLoaded(payload, req))) return
  const count = await countOpenAssetVulnerabilities(payload, asset, { req })
  if ((asset.vulnerabilityCount ?? null) === count) return
  await payload.update({
    collection: 'assets',
    id: asset.id,
    data: { vulnerabilityCount: count },
    context: { vulnerabilityCountSync: true },
    overrideAccess: true,
    req,
  })
}

/** Keeps the stored open-finding count in sync with asset metadata. */
export const assignVulnerabilityCount: CollectionBeforeChangeHook = async ({
  context,
  data,
  originalDoc,
  req,
}) => {
  if (context.vulnerabilityCountSync) return data
  if (!(await catalogIsLoaded(req.payload, req))) return data

  const asset: AssetMatchInput & { id?: string; lifecycle?: string | null } = {}
  for (const field of MATCH_FIELDS) {
    const value = Object.hasOwn(data, field) ? data[field] : originalDoc?.[field]
    if (typeof value === 'string') asset[field] = value
  }
  if (typeof data.lifecycle === 'string' || originalDoc?.lifecycle)
    asset.lifecycle = data.lifecycle || originalDoc?.lifecycle
  data.vulnerabilityCount = await countOpenAssetVulnerabilities(
    req.payload,
    {
      ...asset,
      id: originalDoc?.id,
    },
    { req },
  )
  return data
}

/** Recomputes every asset count after the catalog changed; writes only real differences. */
export const recountAssetVulnerabilities = async (
  payload: Payload,
  req?: PayloadRequest,
): Promise<number> => {
  if (!(await catalogIsLoaded(payload, req))) return 0
  const matches = new Map<string, Promise<VulnerabilityMatch[]>>()
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
        lifecycle: true,
        vulnerabilityCount: true,
      },
    })

    for (const asset of result.docs) {
      const fingerprint = assetFingerprint(asset)
      let pendingMatches = matches.get(fingerprint)
      if (!pendingMatches) {
        pendingMatches = findAssetVulnerabilities(payload, asset)
        if (matches.size >= 1000) matches.delete(matches.keys().next().value!)
        matches.set(fingerprint, pendingMatches)
      }
    }
    const pageReviews = await findReviewsForAssets(
      payload,
      result.docs.map(({ id }) => id),
      req ? { req } : {},
    )
    for (const asset of result.docs) {
      const count = await countOpenAssetVulnerabilities(
        payload,
        { ...asset, id: asset.id },
        req ? { req } : {},
        matches,
        pageReviews,
      )
      if ((asset.vulnerabilityCount ?? null) === count) continue

      await payload.update({
        collection: 'assets',
        context: { vulnerabilityCountSync: true },
        data: { vulnerabilityCount: count },
        id: asset.id,
        overrideAccess: true,
        req,
      })
      updated += 1
    }

    if (result.docs.length < 100) break
    after = result.docs.at(-1)!.id
  }

  return updated
}
