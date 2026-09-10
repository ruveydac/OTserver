import { createHash } from 'node:crypto'
import { Readable } from 'node:stream'
import { createGunzip } from 'node:zlib'

import {
  createLocalReq,
  type Payload,
  type PayloadRequest,
  type RequiredDataFromCollectionSlug,
} from 'payload'

import { writeAudit } from '../collections/AuditLogs'
import {
  type AffectedProduct,
  array,
  normalizeKey,
  productSearchKey,
  record,
  recountAssetVulnerabilities,
  searchTokens,
  text,
} from './match'

export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
export const NVD_FEED_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0'
export const FIRST_NVD_YEAR = 2002
export const SYNC_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000
export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
export const MAX_FEED_BYTES = 2 * 1024 * 1024 * 1024

const BATCH_SIZE = 500
const MAX_AFFECTED = 200
const MAX_DESCRIPTION = 4000
const MAX_REFERENCES = 25
const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000
const CVE_PATTERN = /^CVE-\d{4}-\d{4,19}$/
const VERSION_BOUNDS = [
  'versionEndExcluding',
  'versionEndIncluding',
  'versionStartExcluding',
  'versionStartIncluding',
] as const

export type FeedDocument = {
  cve: string
  set: Record<string, unknown>
  setOnInsert?: Record<string, unknown>
}

export type DownloadFeed = (
  url: string,
  options?: { gzip?: boolean; sha256?: string },
) => Promise<Buffer>

export type SyncResult = {
  documentCount: number
  loaded: number
  skipped: boolean
  updatedAssets: number
}

const message = (error: unknown): string => (error instanceof Error ? error.message : String(error))

type RawCollection = {
  bulkWrite: (operations: unknown[]) => Promise<unknown>
  updateMany: (filter: unknown, update: unknown) => Promise<unknown>
}

const rawCollection = (payload: Payload, slug: string): RawCollection => {
  const collections = (
    payload.db as unknown as {
      collections?: Record<string, { collection?: RawCollection } | undefined>
    }
  ).collections
  const collection = collections?.[slug]?.collection
  if (!collection) throw new Error(`The MongoDB collection "${slug}" is unavailable.`)
  return collection
}

/**
 * Downloads a feed, verifies the checksum NVD publishes next to it, and caps the
 * payload size so a hostile or corrupt mirror cannot exhaust memory.
 */
export const downloadFeed: DownloadFeed = async (url, { gzip, sha256 } = {}) => {
  const response = await fetch(url, {
    headers: { 'user-agent': 'OTserver vulnerability catalog sync' },
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  })
  if (!response.ok || !response.body) throw new Error(`${url} responded with ${response.status}.`)

  const hash = createHash('sha256')
  const compressed: Buffer[] = []
  let compressedSize = 0
  for await (const chunk of Readable.fromWeb(
    response.body as Parameters<typeof Readable.fromWeb>[0],
  )) {
    const buffer = chunk as Buffer
    compressedSize += buffer.length
    if (compressedSize > MAX_DOWNLOAD_BYTES) {
      throw new Error(`${url} exceeded the ${MAX_DOWNLOAD_BYTES} byte download limit.`)
    }
    if (gzip && sha256) hash.update(buffer)
    compressed.push(buffer)
  }

  const body = Buffer.concat(compressed)
  if (!gzip) return body
  if (sha256 && hash.digest('hex') !== sha256.toLowerCase()) {
    throw new Error(`${url} did not match its published SHA-256 checksum.`)
  }

  // ponytail: whole feed held in memory (a full NVD year is ~300 MB uncompressed);
  // switch to the paginated NVD API if the annual files outgrow the heap.
  const decompressed: Buffer[] = []
  let size = 0
  for await (const chunk of createGunzip().end(body)) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > MAX_FEED_BYTES) throw new Error(`${url} exceeded the ${MAX_FEED_BYTES} byte limit.`)
    decompressed.push(buffer)
  }
  return Buffer.concat(decompressed)
}

export const parseNvdMeta = (
  meta: string,
): { lastModifiedDate?: string; sha256?: string; size?: number } => {
  const values: Record<string, string> = {}
  for (const line of meta.split(/\r?\n/)) {
    const separator = line.indexOf(':')
    if (separator < 0) continue
    values[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim()
  }
  const sha256 = values.sha256?.toLowerCase()
  return {
    ...(values.lastmodifieddate ? { lastModifiedDate: values.lastmodifieddate } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(Number(values.size) > 0 ? { size: Number(values.size) } : {}),
  }
}

export const parseCpe = (
  criteria: unknown,
): { part: string; product: string; vendor: string; version: string } | undefined => {
  const value = text(criteria)
  if (!value.startsWith('cpe:2.3:')) return undefined

  const parts = value.split(/(?<!\\):/).map((part) => part.replaceAll('\\:', ':'))
  const [part, vendor, product, version] = parts.slice(2, 6)
  if (!vendor || vendor === '*' || !product || product === '*') return undefined
  return { part: part || 'a', product, vendor, version: version || '*' }
}

export const affectedProducts = (configurations: unknown): AffectedProduct[] => {
  const entries: AffectedProduct[] = []
  const seen = new Set<string>()

  for (const configuration of array(configurations)) {
    for (const node of array(record(configuration).nodes)) {
      const nodeRecord = record(node)
      if (nodeRecord.negate === true) continue
      for (const candidate of array(nodeRecord.cpeMatch)) {
        const item = record(candidate)
        if (item.vulnerable !== true) continue
        const cpe = parseCpe(item.criteria)
        if (!cpe) continue

        const entry: AffectedProduct = { ...cpe }
        for (const bound of VERSION_BOUNDS) {
          const value = text(item[bound])
          if (value) entry[bound] = value
        }

        const key = JSON.stringify(entry)
        if (seen.has(key)) continue
        seen.add(key)
        entries.push(entry)
        if (entries.length >= MAX_AFFECTED) return entries
      }
    }
  }

  return entries
}

/** Indexed lookup terms: an asset is matched through product tokens, never through vendor alone. */
export const searchKeys = (affected: AffectedProduct[]) => {
  const products = new Set<string>()
  const productTokens = new Set<string>()
  const vendors = new Set<string>()

  for (const entry of affected) {
    const vendorKey = normalizeKey(entry.vendor)
    if (vendorKey) vendors.add(vendorKey)
    for (const token of searchTokens(entry.vendor)) vendors.add(token)

    const productKey = productSearchKey(entry.product)
    if (productKey) products.add(productKey)
    for (const token of searchTokens(entry.product.replaceAll('_', ' '))) productTokens.add(token)
  }

  return { products: [...products], productTokens: [...productTokens], vendors: [...vendors] }
}

const dateValue = (value: unknown): Date | undefined => {
  const candidate = text(value)
  if (!candidate) return undefined
  const date = new Date(candidate)
  return Number.isNaN(date.getTime()) ? undefined : date
}

const cvss = (metrics: unknown) => {
  const values = record(metrics)
  for (const key of ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']) {
    const metric = record(array(values[key])[0])
    const data = record(metric.cvssData)
    const score = Number(data.baseScore)
    if (!Number.isFinite(score)) continue
    const severity = text(data.baseSeverity || metric.baseSeverity).toUpperCase()
    return { cvssScore: score, ...(severity ? { cvssSeverity: severity } : {}) }
  }
  return {}
}

export const parseNvdFeed = (feed: unknown): FeedDocument[] => {
  const vulnerabilities = record(feed).vulnerabilities
  if (!Array.isArray(vulnerabilities)) {
    throw new Error('The NVD feed does not contain a vulnerabilities array.')
  }
  const documents: FeedDocument[] = []

  for (const item of vulnerabilities) {
    const cve = record(record(item).cve)
    const id = text(cve.id)
    if (!CVE_PATTERN.test(id)) continue

    const descriptions = array(cve.descriptions).map(record)
    const description =
      descriptions.find((entry) => text(entry.lang).startsWith('en'))?.value ??
      descriptions[0]?.value
    const affected = affectedProducts(cve.configurations)

    documents.push({
      cve: id,
      set: {
        affected,
        ...cvss(cve.metrics),
        description: text(description).slice(0, MAX_DESCRIPTION),
        modified: dateValue(cve.lastModified),
        ...searchKeys(affected),
        published: dateValue(cve.published),
        references: array(cve.references)
          .map((reference) => text(record(reference).url))
          .filter(Boolean)
          .slice(0, MAX_REFERENCES),
        status: text(cve.vulnStatus),
        updatedAt: new Date(),
      },
    })
  }

  return documents
}

export const parseCisaCatalog = (
  catalog: unknown,
): { catalogVersion?: string; dateReleased?: Date; documents: FeedDocument[] } => {
  const source = record(catalog)
  const catalogVersion = text(source.catalogVersion)
  const dateReleased = dateValue(source.dateReleased)
  const vulnerabilities = source.vulnerabilities
  if (
    !catalogVersion ||
    !dateReleased ||
    !Number.isInteger(source.count) ||
    !Array.isArray(vulnerabilities)
  ) {
    throw new Error('The CISA KEV feed does not match the expected catalog schema.')
  }
  const documents: FeedDocument[] = []

  for (const item of vulnerabilities) {
    const entry = record(item)
    const id = text(entry.cveID)
    const product = text(entry.product)
    const vendor = text(entry.vendorProject)
    const dateAdded = dateValue(entry.dateAdded)
    const dueDate = dateValue(entry.dueDate)
    if (
      !CVE_PATTERN.test(id) ||
      !vendor ||
      !product ||
      !text(entry.vulnerabilityName) ||
      !dateAdded ||
      !text(entry.shortDescription) ||
      !text(entry.requiredAction) ||
      !dueDate
    ) {
      throw new Error(`The CISA KEV feed contains an invalid entry${id ? ` (${id})` : ''}.`)
    }
    documents.push({
      cve: id,
      set: {
        knownExploited: true,
        kevDateAdded: dateAdded,
        kevDueDate: dueDate,
        kevName: text(entry.vulnerabilityName),
        kevProduct: product,
        kevRequiredAction: text(entry.requiredAction),
        kevRansomwareUse: text(entry.knownRansomwareCampaignUse),
        kevVendor: vendor,
        updatedAt: new Date(),
      },
      // Only KEV-only records need these; NVD supplies richer CPE data when it exists.
      ...(vendor && product
        ? {
            setOnInsert: {
              createdAt: new Date(),
              description: text(entry.shortDescription).slice(0, MAX_DESCRIPTION),
              ...searchKeys([{ part: 'a', product, vendor, version: '*' }]),
            },
          }
        : {}),
    })
  }

  if (documents.length !== source.count) {
    throw new Error('The CISA KEV feed count does not match its vulnerability entries.')
  }

  return {
    catalogVersion,
    dateReleased,
    documents,
  }
}

export const upsertVulnerabilities = async (
  payload: Payload,
  documents: FeedDocument[],
): Promise<void> => {
  if (!documents.length) return
  const collection = rawCollection(payload, 'vulnerabilities')
  const now = new Date()

  for (let index = 0; index < documents.length; index += BATCH_SIZE) {
    await collection.bulkWrite(
      documents.slice(index, index + BATCH_SIZE).map(({ cve, set, setOnInsert }) => ({
        updateOne: {
          filter: { cve },
          update: { $set: set, $setOnInsert: { createdAt: now, ...setOnInsert } },
          upsert: true,
        },
      })),
    )
  }
}

const clearRemovedKevEntries = async (payload: Payload, cves: string[]): Promise<void> => {
  await rawCollection(payload, 'vulnerabilities').updateMany(
    { cve: { $nin: cves }, knownExploited: true },
    {
      $set: { knownExploited: false, updatedAt: new Date() },
      $unset: {
        kevDateAdded: '',
        kevDueDate: '',
        kevName: '',
        kevProduct: '',
        kevRansomwareUse: '',
        kevRequiredAction: '',
        kevVendor: '',
      },
    },
  )
}

const feedState = async (payload: Payload, source: string) => {
  const result = await payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    where: { source: { equals: source } },
  })
  return result.docs[0]
}

const saveFeedState = async (
  payload: Payload,
  source: string,
  data: Record<string, unknown>,
): Promise<void> => {
  const existing = await feedState(payload, source)
  if (existing) {
    await payload.update({
      collection: 'vulnerability-feeds',
      data,
      id: existing.id,
      overrideAccess: true,
    })
    return
  }
  await payload.create({
    collection: 'vulnerability-feeds',
    // The feed state documents are system-owned; their shape is assembled per source.
    data: { ...data, source } as RequiredDataFromCollectionSlug<'vulnerability-feeds'>,
    overrideAccess: true,
  })
}

const lastSynchronizedAt = async (payload: Payload): Promise<Date | undefined> => {
  const result = await payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    overrideAccess: true,
    pagination: false,
    select: { lastSyncedAt: true },
  })
  const dates = result.docs
    .map((doc) => (doc.lastSyncedAt ? new Date(doc.lastSyncedAt).getTime() : 0))
    .filter(Boolean)
  return dates.length ? new Date(Math.min(...dates)) : undefined
}

const runSync = async (
  payload: Payload,
  {
    download = downloadFeed,
    force,
    req,
  }: { download?: DownloadFeed; force?: boolean; req?: PayloadRequest },
): Promise<SyncResult> => {
  const lastSyncedAt = await lastSynchronizedAt(payload)
  if (!force && lastSyncedAt && Date.now() - lastSyncedAt.getTime() < SYNC_INTERVAL_MS) {
    return {
      documentCount: (await payload.count({ collection: 'vulnerabilities', overrideAccess: true }))
        .totalDocs,
      loaded: 0,
      skipped: true,
      updatedAssets: 0,
    }
  }

  await saveFeedState(payload, 'cisa-kev', { status: 'running' })
  await saveFeedState(payload, 'nvd', { status: 'running' })

  let loaded = 0
  const failures: string[] = []

  try {
    const catalog = parseCisaCatalog(JSON.parse((await download(CISA_KEV_URL)).toString('utf8')))
    await upsertVulnerabilities(payload, catalog.documents)
    await clearRemovedKevEntries(
      payload,
      catalog.documents.map(({ cve }) => cve),
    )
    loaded += catalog.documents.length
    await saveFeedState(payload, 'cisa-kev', {
      catalogVersion: catalog.catalogVersion ?? null,
      dateReleased: catalog.dateReleased ?? null,
      documentCount: catalog.documents.length,
      error: null,
      lastSyncedAt: new Date(),
      status: 'ready',
    })
  } catch (error) {
    failures.push(`cisa-kev: ${message(error)}`)
    await saveFeedState(payload, 'cisa-kev', {
      error: message(error).slice(0, MAX_DESCRIPTION),
      status: 'failed',
    })
  }

  const nvdState = record((await feedState(payload, 'nvd'))?.state) as Record<
    string,
    { sha256?: string }
  >
  const state: Record<string, { lastModifiedDate?: string; sha256?: string }> = { ...nvdState }
  const nvdFailures: string[] = []
  for (let year = FIRST_NVD_YEAR; year <= new Date().getUTCFullYear(); year += 1) {
    try {
      const meta = parseNvdMeta(
        (await download(`${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}.meta`)).toString('utf8'),
      )
      if (!meta.sha256 || state[year]?.sha256 === meta.sha256) continue

      const feed = JSON.parse(
        (
          await download(`${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}.json.gz`, {
            gzip: true,
            sha256: meta.sha256,
          })
        ).toString('utf8'),
      )
      const documents = parseNvdFeed(feed)
      await upsertVulnerabilities(payload, documents)
      loaded += documents.length
      state[year] = { lastModifiedDate: meta.lastModifiedDate, sha256: meta.sha256 }
    } catch (error) {
      nvdFailures.push(`${year}: ${message(error)}`)
    }
  }
  failures.push(...nvdFailures)

  const documentCount = (
    await payload.count({ collection: 'vulnerabilities', overrideAccess: true })
  ).totalDocs
  const hasNvdData = Object.keys(state).length > 0
  await saveFeedState(payload, 'nvd', {
    documentCount,
    error: nvdFailures.length
      ? nvdFailures.join(' | ').slice(0, MAX_DESCRIPTION)
      : hasNvdData
        ? null
        : 'No NVD feed was available.',
    lastSyncedAt: new Date(),
    state,
    status: hasNvdData ? (nvdFailures.length ? 'partial' : 'ready') : 'failed',
  })

  // Asset counts are derived from the catalog, so they are refreshed whenever it moved.
  const updatedAssets = loaded ? await recountAssetVulnerabilities(payload) : 0

  await writeAudit({
    action: 'custom',
    after: {
      documentCount,
      id: 'vulnerability-catalog',
      loadedDocuments: loaded,
      name: 'Vulnerability catalog synchronization',
      updatedAssets,
      ...(failures.length ? { failures } : {}),
    },
    req: req ?? (await createLocalReq({}, payload)),
    targetCollection: 'vulnerabilities',
  })

  return { documentCount, loaded, skipped: false, updatedAssets }
}

let inFlight: Promise<SyncResult> | null = null

/** Downloads both catalogs at most once per interval, and never twice at the same time. */
export const syncVulnerabilityFeeds = async (
  payload: Payload,
  options: { download?: DownloadFeed; force?: boolean; req?: PayloadRequest } = {},
): Promise<SyncResult> => {
  if (inFlight) return inFlight
  const run = runSync(payload, options)
  inFlight = run.finally(() => {
    inFlight = null
  })
  return run
}

export const initializeVulnerabilityFeeds = async (payload: Payload): Promise<void> => {
  // Integration tests drive the sync with fixtures, and air-gapped plants have no egress.
  const mode = process.env['OTSERVER_VULNERABILITY_FEEDS']
  if (mode === 'off' || (process.env.NODE_ENV === 'test' && mode !== 'on')) return

  const sync = () =>
    void syncVulnerabilityFeeds(payload).catch((error) =>
      payload.logger.error(`Vulnerability catalog sync failed: ${message(error)}`),
    )
  sync()
  setInterval(sync, SYNC_INTERVAL_MS)
}
