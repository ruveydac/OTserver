import { createHash } from 'node:crypto'
import { Readable } from 'node:stream'
import { createGunzip } from 'node:zlib'

import { type Payload, type PayloadRequest, type RequiredDataFromCollectionSlug } from 'payload'

import { writeAudit } from '../collections/AuditLogs'
import { record } from './matching'
import { recountAssetVulnerabilities } from './match'
import { rawCollection } from '../integrations/payload/catalog'
import { systemRequest } from '../integrations/payload/requests'
import { MAX_DESCRIPTION } from './parsers'
export * from './parsers'
import {
  type FeedDocument,
  parseNvdMeta,
  parseNvdFeed,
  parseCisaCatalog,
  parseCsafAggregator,
  parseCsafProviderMetadata,
  parseRolieFeed,
  parseCsafDocument,
  mergeCsafDocuments,
  parseIcsAdvisories,
} from './parsers'

export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
export const CSAF_AGGREGATOR_URL =
  'https://aggregator.certvde.com/.well-known/csaf-aggregator/aggregator.json'
export const CISA_CSAF_FEED_URLS = [
  'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json',
  'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json',
] as const
export const ICS_ADVISORY_URL =
  'https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv'
export const NVD_FEED_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0'
export const FIRST_NVD_YEAR = 2002
export const SYNC_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000
export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
export const MAX_FEED_BYTES = 2 * 1024 * 1024 * 1024

const BATCH_SIZE = 500
const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000
const MAX_CSAF_FEEDS = 500
const MAX_CSAF_DOCUMENTS = 50_000

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

/**
 * Downloads a feed, verifies the checksum NVD publishes next to it, and caps the payload size so a
 * hostile or corrupt mirror cannot exhaust memory. NVD's `.meta` `sha256` covers the *uncompressed*
 * JSON (its `size` field is the uncompressed length too), so the digest is taken while gunzipping
 * rather than over the downloaded `.gz` bytes.
 */
export const downloadFeed: DownloadFeed = async (url, { gzip, sha256 } = {}) => {
  const response = await fetch(url, {
    headers: { 'user-agent': 'OTserver vulnerability catalog sync' },
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  })
  if (!response.ok || !response.body) throw new Error(`${url} responded with ${response.status}.`)

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
    compressed.push(buffer)
  }

  const body = Buffer.concat(compressed)
  if (!gzip) return body

  const expected = sha256?.toLowerCase()
  const hash = expected ? createHash('sha256') : undefined
  // ponytail: whole feed held in memory. The largest NVD year (2024, 278 MB gzipped) peaks near
  // 880 MB of heap across the decompressed buffer, its UTF-8 string, and the parsed object graph;
  // switch to the paginated NVD API 2.0 if the annual files outgrow the heap.
  const decompressed: Buffer[] = []
  let size = 0
  for await (const chunk of createGunzip().end(body)) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > MAX_FEED_BYTES) throw new Error(`${url} exceeded the ${MAX_FEED_BYTES} byte limit.`)
    hash?.update(buffer)
    decompressed.push(buffer)
  }
  if (expected && hash?.digest('hex') !== expected) {
    throw new Error(`${url} did not match its published SHA-256 checksum.`)
  }
  return Buffer.concat(decompressed)
}

const replaceCsafVulnerabilities = async (
  payload: Payload,
  documents: FeedDocument[],
): Promise<void> => {
  const collection = rawCollection(payload, 'vulnerabilities')
  const existing = new Map<string, string>()
  for (let index = 0; index < documents.length; index += BATCH_SIZE) {
    const cves = documents.slice(index, index + BATCH_SIZE).map(({ cve }) => cve)
    const result = await payload.find({
      collection: 'vulnerabilities',
      depth: 0,
      overrideAccess: true,
      pagination: false,
      select: { cve: true, status: true },
      where: { cve: { in: cves } },
    })
    for (const doc of result.docs) existing.set(doc.cve, doc.status || '')
  }
  // ponytail: only CSAF-owned or absent records are rewritten so NVD evidence survives. A stub
  // created by another source before NVD/CSAF saw the CVE keeps its weaker data; widen the check
  // to "no affected entries" if those stubs ever become visible.
  const writable = documents.filter(({ cve }) => !existing.has(cve) || existing.get(cve) === 'CSAF')
  await upsertVulnerabilities(payload, writable)
  await collection.deleteMany({ cve: { $nin: documents.map(({ cve }) => cve) }, status: 'CSAF' })
}

/** Minimal RFC 4180 reader; quoted fields may contain commas, quotes, and newlines. */
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

const clearRemovedIcsEntries = async (payload: Payload, cves: string[]): Promise<void> => {
  await rawCollection(payload, 'vulnerabilities').updateMany(
    { cve: { $nin: cves }, icsAdvisory: { $exists: true } },
    {
      $set: { updatedAt: new Date() },
      $unset: { icsAdvisory: '', icsDistribution: '', icsHeadquarters: '', icsSectors: '' },
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

const loadCsafSnapshot = async (
  download: DownloadFeed,
  previousState: Record<string, unknown>,
): Promise<{ documents?: FeedDocument[]; state: Record<string, string> }> => {
  const aggregator = parseCsafAggregator(
    JSON.parse((await download(CSAF_AGGREGATOR_URL)).toString('utf8')),
  )
  const feedURLs = new Set<string>(CISA_CSAF_FEED_URLS)
  for (const metadataURL of aggregator) {
    const feeds = parseCsafProviderMetadata(
      JSON.parse((await download(metadataURL)).toString('utf8')),
    )
    for (const url of feeds) feedURLs.add(url)
  }
  if (feedURLs.size > MAX_CSAF_FEEDS) throw new Error('The CSAF feed limit was exceeded.')

  const entries = new Map<string, string>()
  const state: Record<string, string> = {}
  for (const feedURL of feedURLs) {
    const feed = parseRolieFeed(JSON.parse((await download(feedURL)).toString('utf8')))
    state[feedURL] = feed.updated
    for (const entry of feed.entries) entries.set(entry.url, entry.updated)
    if (entries.size > MAX_CSAF_DOCUMENTS) throw new Error('The CSAF document limit was exceeded.')
  }
  if (
    Object.keys(state).length === Object.keys(previousState).length &&
    Object.entries(state).every(([url, updated]) => previousState[url] === updated)
  ) {
    return { state }
  }

  const documents: FeedDocument[] = []
  const urls = [...entries.keys()]
  for (let index = 0; index < urls.length; index += 10) {
    const parsed = await Promise.all(
      urls
        .slice(index, index + 10)
        .map(async (url) => parseCsafDocument(JSON.parse((await download(url)).toString('utf8')))),
    )
    documents.push(...parsed.flat())
  }
  return { documents: mergeCsafDocuments(documents), state }
}

const runSync = async (
  payload: Payload,
  {
    download = downloadFeed,
    force,
    req,
    failOnSourceError,
  }: {
    download?: DownloadFeed
    force?: boolean
    req?: PayloadRequest
    failOnSourceError?: boolean
  },
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

  payload.logger.info(
    'Vulnerability catalog sync started: downloading CISA KEV, CSAF, ICS Advisory Project, and NVD feeds.',
  )

  await saveFeedState(payload, 'cisa-kev', { status: 'running' })
  await saveFeedState(payload, 'csaf', { status: 'running' })
  await saveFeedState(payload, 'ics-advisories', { status: 'running' })
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

  try {
    const previousFeed = await feedState(payload, 'csaf')
    const previousState = record(previousFeed?.state)
    const snapshot = await loadCsafSnapshot(download, previousState)
    if (snapshot.documents) {
      await replaceCsafVulnerabilities(payload, snapshot.documents)
      loaded += snapshot.documents.length
    }
    await saveFeedState(payload, 'csaf', {
      documentCount: snapshot.documents?.length ?? previousFeed?.documentCount ?? 0,
      error: null,
      lastSyncedAt: new Date(),
      state: snapshot.state,
      status: 'ready',
    })
  } catch (error) {
    failures.push(`csaf: ${message(error)}`)
    await saveFeedState(payload, 'csaf', {
      error: message(error).slice(0, MAX_DESCRIPTION),
      status: 'failed',
    })
  }

  // Runs after CSAF so the advisory context lands on records CSAF already created.
  try {
    const advisories = parseIcsAdvisories((await download(ICS_ADVISORY_URL)).toString('utf8'))
    await upsertVulnerabilities(payload, advisories.documents)
    await clearRemovedIcsEntries(
      payload,
      advisories.documents.map(({ cve }) => cve),
    )
    loaded += advisories.documents.length
    await saveFeedState(payload, 'ics-advisories', {
      dateReleased: advisories.dateReleased ?? null,
      documentCount: advisories.documents.length,
      error: null,
      lastSyncedAt: new Date(),
      status: 'ready',
    })
  } catch (error) {
    failures.push(`ics-advisories: ${message(error)}`)
    await saveFeedState(payload, 'ics-advisories', {
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
      // Persist each year as it lands. The initial 2002-onward import takes many minutes, and
      // without this an interrupted run would restart from the first year on the next boot.
      await saveFeedState(payload, 'nvd', { state })
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

  payload.logger.info(
    `Vulnerability catalog sync finished downloading ${loaded} documents` +
      `${failures.length ? ` with ${failures.length} source failures` : ''}.`,
  )

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
    req: req ?? (await systemRequest(payload)),
    targetCollection: 'vulnerabilities',
  })

  if (failOnSourceError && failures.length) {
    const error = new Error(
      'One or more vulnerability sources failed; the previous usable data was retained.',
    )
    Object.assign(error, { code: 'ECONNRESET' })
    throw error
  }
  return { documentCount, loaded, skipped: false, updatedAssets }
}

let inFlight: Promise<SyncResult> | null = null

/** Downloads all catalogs at most once per interval, and never twice at the same time. */
export const syncVulnerabilityFeeds = async (
  payload: Payload,
  options: {
    download?: DownloadFeed
    force?: boolean
    req?: PayloadRequest
    failOnSourceError?: boolean
  } = {},
): Promise<SyncResult> => {
  if (inFlight) return inFlight
  const run = runSync(payload, options)
  inFlight = run.finally(() => {
    inFlight = null
  })
  // Callers handle `run`; this keeps the shared guard from surfacing as an unhandled rejection
  // when a sync fails, which would otherwise leak on every failed refresh.
  void inFlight.catch(() => {})
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
