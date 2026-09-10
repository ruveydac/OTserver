import type { CollectionBeforeChangeHook, Payload, PayloadRequest, TypedUser, Where } from 'payload'

export type AffectedProduct = {
  part: string
  product: string
  vendor: string
  version: string
  versionEndExcluding?: string
  versionEndIncluding?: string
  versionStartExcluding?: string
  versionStartIncluding?: string
}

export type VulnerabilityCandidate = {
  affected?: AffectedProduct[] | null
  cve: string
  cvssScore?: null | number
  cvssSeverity?: null | string
  knownExploited?: boolean | null
}

export type VulnerabilityMatch = {
  constraint: string
  cve: string
  cvssScore?: null | number
  cvssSeverity?: null | string
  knownExploited: boolean
  matchedProduct: string
  matchedVendor: string
  version: string
  versionEvidence: string
}

export type AssetMatchInput = {
  firmwareVersion?: null | string
  hardwareVersion?: null | string
  model?: null | string
  operatingSystem?: null | string
  vendor?: null | string
}

const MATCH_FIELDS = [
  'vendor',
  'model',
  'operatingSystem',
  'firmwareVersion',
  'hardwareVersion',
] as const

// Legal suffixes and generic words carry no product identity; dropping them keeps
// "Siemens AG" comparable with the CPE vendor "siemens".
const NOISE_TOKENS = new Set([
  'ab',
  'ag',
  'and',
  'bv',
  'co',
  'corp',
  'corporation',
  'firmware',
  'for',
  'gmbh',
  'hardware',
  'inc',
  'kg',
  'llc',
  'ltd',
  'nv',
  'of',
  'oy',
  'plc',
  'sa',
  'series',
  'software',
  'the',
  'version',
  'versions',
])

const VENDOR_SIMILARITY = 0.8
const PRODUCT_SIMILARITY = 0.6
// ponytail: candidate window per asset; stream or narrow by vendor if a single
// product token ever pulls more than this many CVEs.
export const MAX_CANDIDATES = 5000

export const array = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

export const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

export const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : '')

export const normalizeKey = (value: string): string =>
  value.toLowerCase().replaceAll(/[^a-z0-9]+/g, '')

export const searchTokens = (value: string): string[] => [
  ...new Set(
    value
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((token) => token.length > 1 && !NOISE_TOKENS.has(token)),
  ),
]

const distinctive = (tokens: string[]): string[] =>
  tokens.filter((token) => token.length >= 4 || /[0-9]/.test(token))

const bigrams = (value: string): Set<string> => {
  const result = new Set<string>()
  for (let index = 0; index < value.length - 1; index += 1)
    result.add(value.slice(index, index + 2))
  return result
}

/** Dice coefficient over bigrams: 1 for identical strings, 0 when nothing is shared. */
export const similarity = (left: string, right: string): number => {
  if (!left || !right) return 0
  if (left === right) return 1
  const [a, b] = [bigrams(left), bigrams(right)]
  if (!a.size || !b.size) return 0
  let shared = 0
  for (const gram of a) if (b.has(gram)) shared += 1
  return (2 * shared) / (a.size + b.size)
}

/** Share of `needles` that also appear in `haystack`. */
const tokenScore = (needles: string[], haystack: string[]): number => {
  const unique = [...new Set(needles)]
  if (!unique.length) return 0
  const available = new Set(haystack)
  return unique.filter((token) => available.has(token)).length / unique.length
}

const versionSegments = (value: string): string[] =>
  value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
    // Devices report "V2.5" where catalogs say "2.5".
    .map((segment) => segment.replace(/^v(?=[0-9])/, ''))

/**
 * Segment-wise version comparison. Numeric segments compare numerically so
 * "1.2.10" sorts after "1.2.9"; anything else compares lexicographically.
 */
export const compareVersions = (left: string, right: string): number => {
  const [a, b] = [versionSegments(left), versionSegments(right)]
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const [segmentA, segmentB] = [a[index] ?? '0', b[index] ?? '0']
    const [numberA, numberB] = [Number(segmentA), Number(segmentB)]
    const numeric = Number.isFinite(numberA) && Number.isFinite(numberB)
    if (numeric) {
      if (numberA !== numberB) return numberA < numberB ? -1 : 1
      continue
    }
    if (segmentA !== segmentB) return segmentA < segmentB ? -1 : 1
  }
  return 0
}

export const describeConstraint = (entry: AffectedProduct): string => {
  const bounds: string[] = []
  if (entry.versionStartIncluding) bounds.push(`>= ${entry.versionStartIncluding}`)
  if (entry.versionStartExcluding) bounds.push(`> ${entry.versionStartExcluding}`)
  if (entry.versionEndIncluding) bounds.push(`<= ${entry.versionEndIncluding}`)
  if (entry.versionEndExcluding) bounds.push(`< ${entry.versionEndExcluding}`)
  if (bounds.length) return bounds.join(', ')
  if (entry.version === '*') return 'all versions'
  return entry.version
}

/** A dash carries no version; a wildcard explicitly applies to every reported version. */
export const satisfiesConstraint = (version: string, entry: AffectedProduct): boolean => {
  const exact = entry.version
  if (exact && exact !== '*' && exact !== '-') return compareVersions(version, exact) === 0
  if (
    !entry.versionStartIncluding &&
    !entry.versionStartExcluding &&
    !entry.versionEndIncluding &&
    !entry.versionEndExcluding
  )
    return exact === '*'
  if (entry.versionStartIncluding && compareVersions(version, entry.versionStartIncluding) < 0)
    return false
  if (entry.versionStartExcluding && compareVersions(version, entry.versionStartExcluding) <= 0)
    return false
  if (entry.versionEndIncluding && compareVersions(version, entry.versionEndIncluding) > 0)
    return false
  if (entry.versionEndExcluding && compareVersions(version, entry.versionEndExcluding) >= 0)
    return false
  return true
}

const numericTokens = (value?: null | string): string[] =>
  searchTokens(text(value)).filter((token) => /[0-9]/.test(token))

/** Multi-segment versions embedded in free text, e.g. "S7-1500 V2.9" -> ["V2.9"]. */
const embeddedVersions = (value?: null | string): string[] =>
  text(value).match(/\bv?[0-9]+(?:[._][0-9]+)+\b/gi) ?? []

/**
 * Versions the asset actually reports for a CPE part. Firmware CPEs also accept a
 * version embedded in the model string, which is how many OT devices report it.
 */
export const versionEvidence = (
  asset: AssetMatchInput,
  part: string,
): { source: string; version: string }[] => {
  if (part === 'o') {
    const operatingSystem = text(asset.operatingSystem)
    const versions = embeddedVersions(operatingSystem)
    const candidates = versions.length ? versions : numericTokens(operatingSystem).slice(-1)
    if (candidates.length)
      return candidates.map((version) => ({ source: 'operating system', version }))
    // NVD commonly classifies PLC firmware as an operating-system CPE.
    const firmwareVersion = text(asset.firmwareVersion)
    return firmwareVersion ? [{ source: 'firmware version', version: firmwareVersion }] : []
  }
  if (part === 'h') {
    const hardwareVersion = text(asset.hardwareVersion)
    return hardwareVersion ? [{ source: 'hardware version', version: hardwareVersion }] : []
  }
  return [
    ...(text(asset.firmwareVersion)
      ? [{ source: 'firmware version', version: text(asset.firmwareVersion) }]
      : []),
    ...embeddedVersions(asset.model).map((version) => ({ source: 'model', version })),
  ]
}

export const assetFingerprint = (asset: AssetMatchInput): string =>
  MATCH_FIELDS.map((field) => text(asset[field])).join('|')

/** CPE products carry the target as a suffix ("simatic_s7-1500_firmware"); it is not part of the name. */
export const productSearchKey = (product: string): string =>
  normalizeKey(product.replaceAll('_', ' ').replace(/ (?:firmware|hardware)$/, ''))

export const matchAssetVulnerabilities = (
  asset: AssetMatchInput,
  candidates: VulnerabilityCandidate[],
): VulnerabilityMatch[] => {
  const vendor = text(asset.vendor)
  const model = text(asset.model)
  const operatingSystem = text(asset.operatingSystem)
  if (!vendor || (!model && !operatingSystem)) return []

  const vendorTokens = searchTokens(vendor)
  const productText = [model, operatingSystem].filter(Boolean).join(' ')
  const assetProductKeys = [normalizeKey(model), normalizeKey(operatingSystem)].filter(
    (key) => key.length > 1,
  )
  const productTokens = searchTokens(productText)
  const distinctiveTokens = distinctive(productTokens)
  if (!distinctiveTokens.length) return []

  const matches: VulnerabilityMatch[] = []
  for (const candidate of candidates) {
    let match: VulnerabilityMatch | undefined
    let bestProductScore = -1
    for (const entry of array(candidate.affected) as AffectedProduct[]) {
      const entryVendorKey = normalizeKey(entry.vendor || '')
      const entryProductKey = productSearchKey(entry.product || '')
      const entryProductTokens = searchTokens((entry.product || '').replace(/_/g, ' '))
      const vendorScore = Math.max(
        similarity(normalizeKey(vendor), entryVendorKey),
        tokenScore(searchTokens(entry.vendor || ''), vendorTokens),
      )
      const productScore = Math.max(
        ...assetProductKeys.map((key) => similarity(key, entryProductKey)),
        tokenScore(entryProductTokens, productTokens),
      )
      if (vendorScore < VENDOR_SIMILARITY || productScore < PRODUCT_SIMILARITY) continue
      if (!entryProductTokens.some((token) => distinctiveTokens.includes(token))) continue

      for (const evidence of versionEvidence(asset, entry.part)) {
        if (!satisfiesConstraint(evidence.version, entry)) continue
        if (productScore > bestProductScore) {
          match = {
            constraint: describeConstraint(entry),
            cve: candidate.cve,
            cvssScore: candidate.cvssScore,
            cvssSeverity: candidate.cvssSeverity,
            knownExploited: Boolean(candidate.knownExploited),
            matchedProduct: entry.product,
            matchedVendor: entry.vendor,
            version: evidence.version,
            versionEvidence: evidence.source,
          }
          bestProductScore = productScore
        }
        break
      }
    }
    if (match) matches.push(match)
  }
  return matches
}

/** Indexed lookup terms for one asset: product keys plus distinctive product tokens. */
export const vulnerabilityCandidateQuery = (asset: AssetMatchInput): Where | undefined => {
  const productText = [text(asset.model), text(asset.operatingSystem)].filter(Boolean).join(' ')
  const tokens = distinctive(searchTokens(productText))
  const keys = [normalizeKey(text(asset.model)), normalizeKey(text(asset.operatingSystem))].filter(
    (key) => key.length > 1,
  )
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
  let page = 1
  let updated = 0

  for (;;) {
    const result = await payload.find({
      collection: 'assets',
      depth: 0,
      limit: 100,
      overrideAccess: true,
      page,
      select: {
        firmwareVersion: true,
        hardwareVersion: true,
        model: true,
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

    if (!result.hasNextPage) break
    page += 1
  }

  return updated
}
