import { setTimeout as delay } from 'node:timers/promises'
import { createHash } from 'node:crypto'
import {
  JobCancelledError,
  type Payload,
  type PayloadRequest,
  type RequiredDataFromCollectionSlug,
} from 'payload'

import { writeAudit } from '../collections/AuditLogs'
import { record } from './matching'
import { recountAssetVulnerabilities } from './match'
import { rawCollection } from '../integrations/payload/catalog'
import { systemRequest } from '../integrations/payload/requests'
import { inTransaction } from '../integrations/payload/transactions'
import { readVulnerabilityFeedSettings } from '../application/settings'
import { MAX_DESCRIPTION } from './parsers'
import {
  downloadFeed,
  feedText,
  feedUnavailable,
  MISSING_OFFLINE_FILE,
  readFeed,
  type DownloadFeed,
} from './feedIO'
import { importNvdFeed } from './nvd'
export * from './parsers'
export * from './sources'
export * from './feedIO'
import {
  CISA_KEV_URL,
  CSAF_AGGREGATOR_URLS,
  CISA_CSAF_FEED_URLS,
  ICS_ADVISORY_URL,
  NVD_FEED_BASE_URL,
  FIRST_NVD_YEAR,
  MAX_CSAF_DIRECTORY_INDEX_BYTES,
  type CustomCsafFeed,
  type FeedSource,
} from './sources'
import {
  type FeedDocument,
  parseNvdMeta,
  parseCisaCatalog,
  parseCsafAggregator,
  csafDirectoryFileURL,
  parseCsafDirectoryIndex,
  parseCsafDirectoryMetadata,
  parseCsafProviderMetadata,
  parseRolieFeed,
  parseCsafDocument,
  mergeCsafDocuments,
  parseIcsAdvisories,
} from './parsers'

const BATCH_SIZE = 500
const MAX_PROGRESS_LINES = 100
const MAX_PROGRESS_CHARS = 8_000
const PROGRESS_WRITE_MS = 15_000
const CANCEL_POLL_MS = 5_000
export const MAX_CSAF_FEEDS = 500
export const MAX_CSAF_DIRECTORY_FEEDS = 1_000
export const MAX_CSAF_DOCUMENTS = 50_000
// Publishers can list a document in a ROLIE index that they never serve (CISA shipped such an
// entry in its IT feed). A handful of those is skipped; more means a provider is broken and the
// previous snapshot must survive instead.
export const MAX_CSAF_UNAVAILABLE = 25

export type SyncResult = {
  documentCount: number
  loaded: number
  skipped: boolean
  updatedAssets: number
}

const message = (error: unknown): string => (error instanceof Error ? error.message : String(error))

const jobStopped = async (
  payload: Payload,
  jobID: string | number,
  req?: PayloadRequest,
): Promise<boolean> => {
  const result = await payload.find({
    collection: 'payload-jobs',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    ...(req ? { req } : {}),
    where: { id: { equals: jobID } },
  })
  return Boolean((result.docs[0]?.error as { cancelled?: boolean } | undefined)?.cancelled)
}

const feedStopped = () =>
  new JobCancelledError('The vulnerability feed update was stopped by the administrator.')

/** Writes CSAF batches as they arrive so a large snapshot does not wait for every download. */
const csafImporter = (payload: Payload) => {
  const collection = rawCollection(payload, 'vulnerabilities')
  const statuses = new Map<string, string>()
  const merged = new Map<string, FeedDocument>()
  const seen = new Set<string>()

  const write = async (documents: FeedDocument[]): Promise<void> => {
    const touched = new Map<string, FeedDocument>()
    for (const document of documents) {
      const previous = merged.get(document.cve)
      const next = previous ? (mergeCsafDocuments([previous, document])[0] ?? document) : document
      merged.set(document.cve, next)
      touched.set(document.cve, next)
      seen.add(document.cve)
    }
    const values = [...touched.values()]
    const unknown = values.map(({ cve }) => cve).filter((cve) => !statuses.has(cve))
    for (let index = 0; index < unknown.length; index += BATCH_SIZE) {
      const cves = unknown.slice(index, index + BATCH_SIZE)
      const result = await payload.find({
        collection: 'vulnerabilities',
        depth: 0,
        overrideAccess: true,
        pagination: false,
        select: { cve: true, status: true },
        where: { cve: { in: cves } },
      })
      for (const cve of cves) statuses.set(cve, '')
      for (const doc of result.docs) statuses.set(doc.cve, doc.status || '')
    }
    // ponytail: only CSAF-owned or absent records are rewritten so NVD evidence survives. A stub
    // created by another source before NVD/CSAF saw the CVE keeps its weaker data; widen the check
    // to "no affected entries" if those stubs ever become visible.
    await upsertVulnerabilities(
      payload,
      values.filter(({ cve }) => ['', 'CSAF'].includes(statuses.get(cve) ?? '')),
    )
  }

  return {
    count: () => merged.size,
    finish: async (replace: boolean) => {
      // An incomplete snapshot must not delete advisories that a skipped document still owns.
      if (replace) await collection.deleteMany({ cve: { $nin: [...seen] }, status: 'CSAF' })
    },
    write,
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

/** Serialize queue snapshots and staging cleanup on the same document inside their transactions. */
export const lockFeedOperations = async (req: PayloadRequest) => {
  const state = await req.payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    limit: 1,
    req,
    where: { source: { equals: 'nvd' } },
  })
  if (state.docs[0])
    await req.payload.update({
      collection: 'vulnerability-feeds',
      id: state.docs[0].id,
      data: { operationRevision: (state.docs[0].operationRevision || 0) + 1 },
      req,
    })
  else
    await req.payload.create({
      collection: 'vulnerability-feeds',
      data: { source: 'nvd', status: 'idle', operationRevision: 1 },
      req,
    })
}

const saveFeedState = async (
  payload: Payload,
  source: string,
  data: Record<string, unknown>,
  req?: PayloadRequest,
): Promise<void> => {
  const existing = await feedState(payload, source)
  if (existing) {
    await payload.update({
      collection: 'vulnerability-feeds',
      data,
      id: existing.id,
      overrideAccess: true,
      req,
    })
    return
  }
  await payload.create({
    collection: 'vulnerability-feeds',
    // The feed state documents are system-owned; their shape is assembled per source.
    data: { ...data, source } as RequiredDataFromCollectionSlug<'vulnerability-feeds'>,
    overrideAccess: true,
    req,
  })
}

export const lastSynchronizedAt = async (
  payload: Payload,
  req?: PayloadRequest,
): Promise<Date | undefined> => {
  const result = await payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    overrideAccess: true,
    pagination: false,
    select: { lastSyncedAt: true, status: true },
    ...(req ? { req } : {}),
  })
  const dates = result.docs
    .map((doc) =>
      doc.status === 'ready' && doc.lastSyncedAt ? new Date(doc.lastSyncedAt).getTime() : 0,
    )
    .filter(Boolean)
  return dates.length === 4 ? new Date(Math.min(...dates)) : undefined
}

export const loadCsafSnapshot = async (
  download: DownloadFeed,
  previousState: Record<string, unknown>,
  customFeeds: CustomCsafFeed[] = [],
  onBatch?: (batch: {
    documents: FeedDocument[]
    files: { file: string; documents: number }[]
  }) => Promise<void>,
  signal?: AbortSignal,
): Promise<{
  changed: boolean
  documents?: FeedDocument[]
  state: Record<string, string>
  unavailable: string[]
  missing: string[]
  invalid: string[]
}> => {
  // CERT@VDE's edge intermittently answers 404 under burst. A 404 only proves a document is
  // unserved after a second request, so it must not rest on one flaky response.
  const fetchFeed = async (url: string) => {
    try {
      return await download(url)
    } catch (error) {
      if ((error as { status?: number }).status !== 404) throw error
      await delay(2000)
      return download(url)
    }
  }
  const missing = new Set<string>()
  const invalid = new Set<string>()
  const load = async (url: string): Promise<unknown | undefined> => {
    try {
      return JSON.parse(await feedText(fetchFeed, url))
    } catch (error) {
      if ((error as { code?: string }).code === MISSING_OFFLINE_FILE) missing.add(url)
      else invalid.add(url)
      return undefined
    }
  }
  const providerURLs = new Set<string>()
  for (const url of CSAF_AGGREGATOR_URLS) {
    const aggregator = await load(url)
    if (aggregator === undefined) continue
    try {
      for (const providerURL of parseCsafAggregator(aggregator)) providerURLs.add(providerURL)
    } catch {
      invalid.add(url)
    }
  }
  const feedURLs = new Set<string>(CISA_CSAF_FEED_URLS)
  const directoryURLs = new Set<string>()
  for (const custom of customFeeds) {
    if (custom.type === 'rolie') {
      feedURLs.add(custom.url)
      continue
    }
    const content = await load(custom.url)
    if (content === undefined) continue
    try {
      if (custom.type === 'aggregator') {
        for (const url of parseCsafAggregator(content)) providerURLs.add(url)
      } else {
        for (const url of parseCsafProviderMetadata(content)) feedURLs.add(url)
        for (const url of parseCsafDirectoryMetadata(content)) directoryURLs.add(url)
      }
    } catch {
      invalid.add(custom.url)
    }
  }
  for (const metadataURL of providerURLs) {
    const metadata = await load(metadataURL)
    if (metadata === undefined) continue
    try {
      for (const url of parseCsafProviderMetadata(metadata)) feedURLs.add(url)
      for (const url of parseCsafDirectoryMetadata(metadata)) directoryURLs.add(url)
    } catch {
      invalid.add(metadataURL)
    }
  }
  if (feedURLs.size > MAX_CSAF_FEEDS) throw new Error('The CSAF feed limit was exceeded.')
  if (directoryURLs.size > MAX_CSAF_DIRECTORY_FEEDS)
    throw new Error('The CSAF directory feed limit was exceeded.')

  const entries = new Map<string, string>()
  const state: Record<string, string> = {}
  for (const feedURL of feedURLs) {
    const feed = await load(feedURL)
    if (feed === undefined) continue
    try {
      const parsed = parseRolieFeed(feed)
      state[feedURL] = parsed.updated
      for (const entry of parsed.entries) entries.set(entry.url, entry.updated)
    } catch {
      invalid.add(feedURL)
    }
    if (entries.size > MAX_CSAF_DOCUMENTS) throw new Error('The CSAF document limit was exceeded.')
  }
  const directories = [...directoryURLs]
  for (let index = 0; index < directories.length; index++) {
    if (entries.size >= MAX_CSAF_DOCUMENTS) {
      for (const skipped of directories.slice(index)) invalid.add(skipped)
      break
    }
    const directoryURL = directories[index]
    const indexURL = csafDirectoryFileURL(directoryURL, 'index.txt')
    const changesURL = csafDirectoryFileURL(directoryURL, 'changes.csv')
    try {
      const [index, changes] = await Promise.all([
        readFeed(await fetchFeed(indexURL), MAX_CSAF_DIRECTORY_INDEX_BYTES),
        readFeed(await fetchFeed(changesURL), MAX_CSAF_DIRECTORY_INDEX_BYTES),
      ])
      state[`directory:${directoryURL}`] = createHash('sha256')
        .update(index)
        .update('\0')
        .update(changes)
        .digest('hex')
      for (const url of parseCsafDirectoryIndex(index.toString('utf8'), directoryURL)) {
        if (entries.size >= MAX_CSAF_DOCUMENTS) {
          invalid.add(directoryURL)
          break
        }
        entries.set(url, '')
      }
    } catch (error) {
      if ((error as { code?: string }).code === MISSING_OFFLINE_FILE) missing.add(directoryURL)
      else invalid.add(directoryURL)
      continue
    }
  }
  if (
    Object.keys(state).length === Object.keys(previousState).length &&
    Object.entries(state).every(([url, updated]) => previousState[url] === updated)
  ) {
    return {
      changed: false,
      state,
      unavailable: [],
      missing: [...missing],
      invalid: [...invalid],
    }
  }

  const documents: FeedDocument[] = []
  const unavailable: string[] = []
  const urls = [...entries.keys()]
  for (let index = 0; index < urls.length; index += 10) {
    if (signal?.aborted) throw feedStopped()
    const parsed = await Promise.all(
      urls.slice(index, index + 10).map(async (url) => {
        try {
          return {
            documents: parseCsafDocument(JSON.parse(await feedText(fetchFeed, url))),
            file: url,
            imported: true,
          }
        } catch (error) {
          if ((error as { code?: string }).code === MISSING_OFFLINE_FILE) missing.add(url)
          else if (feedUnavailable(error)) unavailable.push(url)
          else invalid.add(url)
          return { documents: [], file: url, imported: false }
        }
      }),
    )
    const imported = parsed.filter(({ imported }) => imported)
    if (onBatch) {
      // Hand each finished batch to the importer before downloading the next one.
      if (imported.length)
        await onBatch({
          documents: imported.flatMap(({ documents }) => documents),
          files: imported.map(({ documents, file }) => ({
            documents: documents.length,
            file,
          })),
        })
    } else documents.push(...imported.flatMap(({ documents }) => documents))
  }
  if (unavailable.length > MAX_CSAF_UNAVAILABLE) {
    throw new Error(
      `The CSAF feeds list ${unavailable.length} documents the publishers do not serve; the previous snapshot was retained.`,
    )
  }
  return {
    changed: true,
    ...(onBatch ? {} : { documents: mergeCsafDocuments(documents) }),
    state,
    unavailable,
    missing: [...missing],
    invalid: [...invalid],
  }
}

const skippedSummary = (
  files: string[] | undefined,
  label = 'Missing files skipped',
): string | undefined =>
  files?.length
    ? `${label}: ${files.length}${files.length <= 5 ? ` (${files.join(', ')})` : ''}`
    : undefined

const runSync = async (
  payload: Payload,
  {
    download,
    force,
    req,
    failOnSourceError,
    source,
    nvdYears,
    method = 'online',
    customCsafFeeds,
    missingFiles,
    sourceDigest,
    signal,
    cancelled,
  }: {
    download?: DownloadFeed
    force?: boolean
    req?: PayloadRequest
    failOnSourceError?: boolean
    source?: FeedSource
    nvdYears?: number[]
    method?: 'online' | 'offline'
    customCsafFeeds?: CustomCsafFeed[]
    missingFiles?: string[]
    sourceDigest?: string
    signal?: AbortSignal
    cancelled?: () => Promise<boolean>
  },
): Promise<SyncResult> => {
  const fetchFeed: DownloadFeed =
    download ?? ((url, options) => downloadFeed(url, { ...options, signal }, payload.logger))
  const assertActive = async () => {
    if (signal?.aborted || (await cancelled?.())) throw feedStopped()
  }
  const rethrowIfStopped = async (error: unknown) => {
    if (error instanceof JobCancelledError || signal?.aborted || (await cancelled?.()))
      throw feedStopped()
  }
  await assertActive()
  const feedSettings = await readVulnerabilityFeedSettings(payload, req)
  const configuredCustomFeeds = customCsafFeeds ?? feedSettings.customCsafFeeds
  const saveState = (source: string, data: Record<string, unknown>) =>
    saveFeedState(payload, source, data, req)
  const progress = new Map<FeedSource, string[]>()
  const progressWrittenAt = new Map<FeedSource, number>()
  const progressText = (selected: FeedSource) => (progress.get(selected) ?? []).join('\n')
  const logImport = async (selected: FeedSource, file: string, count: number) => {
    const lines = [
      ...(progress.get(selected) ?? []),
      `${new Date().toISOString()} Imported ${file}: ${count} ${count === 1 ? 'vulnerability' : 'vulnerabilities'}.`,
    ]
    while (lines.length > MAX_PROGRESS_LINES) lines.shift()
    while (lines.join('\n').length > MAX_PROGRESS_CHARS) lines.shift()
    progress.set(selected, lines)
    if (Date.now() - (progressWrittenAt.get(selected) ?? 0) < PROGRESS_WRITE_MS) return
    progressWrittenAt.set(selected, Date.now())
    await saveState(selected, { progress: lines.join('\n') })
  }
  const lastSyncedAt = await lastSynchronizedAt(payload, req)
  const intervalMs = feedSettings.pullIntervalDays * 24 * 60 * 60 * 1000
  if (!force && lastSyncedAt && Date.now() - lastSyncedAt.getTime() < intervalMs) {
    return {
      documentCount: (await payload.count({ collection: 'vulnerabilities', overrideAccess: true }))
        .totalDocs,
      loaded: 0,
      skipped: true,
      updatedAssets: 0,
    }
  }

  payload.logger.info(
    method === 'offline'
      ? `Vulnerability catalog import started: reading uploaded ${source} files.`
      : 'Vulnerability catalog sync started: downloading CISA KEV, CSAF, ICS Advisory Project, and NVD feeds.',
  )

  await assertActive()
  for (const selected of source ? [source] : ['cisa-kev', 'csaf', 'ics-advisories', 'nvd'])
    await saveState(selected, {
      error: null,
      lastImportMethod: method,
      progress: '',
      status: 'running',
    })

  let loaded = 0
  let succeeded = 0
  const failures: string[] = []

  if (!source || source === 'cisa-kev') {
    const skipped = skippedSummary(missingFiles)
    try {
      await assertActive()
      const catalog = parseCisaCatalog(JSON.parse(await feedText(fetchFeed, CISA_KEV_URL)))
      await assertActive()
      await upsertVulnerabilities(payload, catalog.documents)
      await clearRemovedKevEntries(
        payload,
        catalog.documents.map(({ cve }) => cve),
      )
      loaded += catalog.documents.length
      await logImport('cisa-kev', 'known_exploited_vulnerabilities.json', catalog.documents.length)
      await assertActive()
      await saveState('cisa-kev', {
        catalogVersion: catalog.catalogVersion ?? null,
        dateReleased: catalog.dateReleased ?? null,
        documentCount: catalog.documents.length,
        error: skipped ?? null,
        lastSyncedAt: new Date(),
        progress: progressText('cisa-kev'),
        state: method === 'offline' && sourceDigest ? { digest: sourceDigest } : {},
        status: skipped ? 'partial' : 'ready',
      })
      succeeded += 1
    } catch (error) {
      await rethrowIfStopped(error)
      failures.push(`cisa-kev: ${message(error)}`)
      await saveState('cisa-kev', {
        error: [message(error), skipped].filter(Boolean).join(' | ').slice(0, MAX_DESCRIPTION),
        progress: progressText('cisa-kev'),
        status: 'failed',
      })
    }
  }

  if (!source || source === 'csaf') {
    try {
      await assertActive()
      const previousFeed = await feedState(payload, 'csaf')
      const previousState = record(previousFeed?.state)
      const importer = csafImporter(payload)
      const snapshot = await loadCsafSnapshot(
        fetchFeed,
        previousState,
        configuredCustomFeeds,
        async (batch) => {
          await assertActive()
          await importer.write(batch.documents)
          for (const file of batch.files) await logImport('csaf', file.file, file.documents)
        },
        signal,
      )
      await assertActive()
      if (snapshot.unavailable.length)
        payload.logger.warn({
          event: 'csaf.unavailable-documents',
          count: snapshot.unavailable.length,
          sample: snapshot.unavailable.slice(0, 10),
        })
      const incomplete = snapshot.invalid.length > 0 || snapshot.missing.length > 0
      if (snapshot.changed) {
        await importer.finish(!incomplete)
        loaded += importer.count()
      }
      await assertActive()
      const skipped = [
        skippedSummary(snapshot.invalid, 'Invalid files skipped'),
        skippedSummary(snapshot.missing, 'Missing files skipped'),
      ]
        .filter(Boolean)
        .join(' | ')
      await saveState('csaf', {
        documentCount: snapshot.changed ? importer.count() : (previousFeed?.documentCount ?? 0),
        error: skipped ? skipped.slice(0, MAX_DESCRIPTION) : null,
        lastSyncedAt: new Date(),
        progress: progressText('csaf'),
        state: snapshot.state,
        status: incomplete ? 'partial' : 'ready',
      })
      succeeded += 1
    } catch (error) {
      await rethrowIfStopped(error)
      failures.push(`csaf: ${message(error)}`)
      await saveState('csaf', {
        error: [message(error), skippedSummary(missingFiles)]
          .filter(Boolean)
          .join(' | ')
          .slice(0, MAX_DESCRIPTION),
        progress: progressText('csaf'),
        status: 'failed',
      })
    }
  }

  // Runs after CSAF so the advisory context lands on records CSAF already created.
  if (!source || source === 'ics-advisories') {
    const skipped = skippedSummary(missingFiles)
    try {
      await assertActive()
      const advisories = parseIcsAdvisories(await feedText(fetchFeed, ICS_ADVISORY_URL))
      await assertActive()
      await upsertVulnerabilities(payload, advisories.documents)
      await clearRemovedIcsEntries(
        payload,
        advisories.documents.map(({ cve }) => cve),
      )
      loaded += advisories.documents.length
      await logImport('ics-advisories', 'CISA_ICS_ADV_Master.csv', advisories.documents.length)
      await assertActive()
      await saveState('ics-advisories', {
        dateReleased: advisories.dateReleased ?? null,
        documentCount: advisories.documents.length,
        error: skipped ?? null,
        lastSyncedAt: new Date(),
        progress: progressText('ics-advisories'),
        state: method === 'offline' && sourceDigest ? { digest: sourceDigest } : {},
        status: skipped ? 'partial' : 'ready',
      })
      succeeded += 1
    } catch (error) {
      await rethrowIfStopped(error)
      failures.push(`ics-advisories: ${message(error)}`)
      await saveState('ics-advisories', {
        error: [message(error), skipped].filter(Boolean).join(' | ').slice(0, MAX_DESCRIPTION),
        progress: progressText('ics-advisories'),
        status: 'failed',
      })
    }
  }

  if (!source || source === 'nvd') {
    const nvdState = record((await feedState(payload, 'nvd'))?.state) as Record<
      string,
      { sha256?: string }
    >
    const state: Record<string, { sha256?: string }> = { ...nvdState }
    const nvdFailures: string[] = []
    const failedYears = new Set<number>()
    const allYears = Array.from(
      { length: new Date().getUTCFullYear() - FIRST_NVD_YEAR + 1 },
      (_, index) => FIRST_NVD_YEAR + index,
    )
    const selectedYears = nvdYears ?? allYears
    for (const year of selectedYears) {
      try {
        await assertActive()
        const meta = parseNvdMeta(
          await feedText(fetchFeed, `${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}.meta`),
        )
        await assertActive()
        if (!meta.sha256 || state[year]?.sha256 === meta.sha256) continue

        const count = await importNvdFeed(
          await fetchFeed(`${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}.json.gz`, {
            gzip: true,
            sha256: meta.sha256,
          }),
          (documents) => upsertVulnerabilities(payload, documents),
        )
        loaded += count
        state[year] = { sha256: meta.sha256 }
        await logImport('nvd', `nvdcve-2.0-${year}`, count)
        await assertActive()
        // Persist each year as it lands. The initial 2002-onward import takes many minutes, and
        // without this an interrupted run would restart from the first year on the next boot.
        await saveState('nvd', { progress: progressText('nvd'), state })
      } catch (error) {
        await rethrowIfStopped(error)
        failedYears.add(year)
        nvdFailures.push(`${year}: ${message(error)}`)
      }
    }
    failures.push(...nvdFailures)
    await assertActive()

    const documentCount = (
      await payload.count({ collection: 'vulnerabilities', overrideAccess: true })
    ).totalDocs
    const hasNvdData = Object.keys(state).length > 0
    const skipped = skippedSummary(missingFiles)
    const error = [nvdFailures.join(' | '), skipped].filter(Boolean).join(' | ')
    await saveState('nvd', {
      documentCount,
      error: error
        ? error.slice(0, MAX_DESCRIPTION)
        : hasNvdData
          ? null
          : 'No NVD feed was available.',
      lastSyncedAt: new Date(),
      progress: progressText('nvd'),
      state,
      status: hasNvdData
        ? error || (method === 'offline' && allYears.some((year) => !state[year]))
          ? 'partial'
          : 'ready'
        : 'failed',
    })
    if (hasNvdData && selectedYears.some((year) => !failedYears.has(year))) succeeded += 1
  }

  await assertActive()
  const documentCount = (
    await payload.count({ collection: 'vulnerabilities', overrideAccess: true })
  ).totalDocs

  payload.logger.info(
    `Vulnerability catalog ${method === 'offline' ? 'import finished reading' : 'sync finished downloading'} ${loaded} documents` +
      `${failures.length ? ` with ${failures.length} source failures` : ''}.`,
  )

  // Asset counts are derived from usable catalog data and preserved when no catalog is available.
  if (req) delete req.context.vulnerabilityCatalogReady
  const updatedAssets = await recountAssetVulnerabilities(payload, req)

  await writeAudit({
    action: 'custom',
    after: {
      documentCount,
      id: 'vulnerability-catalog',
      loadedDocuments: loaded,
      name: 'Vulnerability catalog synchronization',
      updatedAssets,
      method,
      ...(source ? { source } : {}),
      ...(failures.length ? { failures } : {}),
      ...(missingFiles?.length ? { missingFiles: missingFiles.length } : {}),
    },
    req: req ?? (await systemRequest(payload)),
    targetCollection: 'vulnerabilities',
  })

  // An offline selection may intentionally contain only some files. It fails only when no
  // source produced usable data; online sync keeps retrying any source failure.
  if (failOnSourceError && failures.length && (method === 'online' || succeeded === 0)) {
    const error = new Error(
      'One or more vulnerability sources failed; the previous usable data was retained.',
    )
    // An offline file failure is not fixed by retrying; only network failures are.
    if (method === 'online') Object.assign(error, { code: 'ECONNRESET' })
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
    source?: FeedSource
    nvdYears?: number[]
    method?: 'online' | 'offline'
    customCsafFeeds?: CustomCsafFeed[]
    missingFiles?: string[]
    sourceDigest?: string
    jobID?: string | number
  } = {},
): Promise<SyncResult> => {
  if (inFlight) return inFlight
  const jobID = options.jobID
  const abort = new AbortController()
  const cancelled = jobID === undefined ? undefined : () => jobStopped(payload, jobID, options.req)
  const watch = cancelled
    ? setInterval(() => {
        void cancelled()
          .then((stopped) => {
            if (stopped) abort.abort()
          })
          .catch(() => {})
      }, CANCEL_POLL_MS)
    : undefined
  const run = runSync(payload, { ...options, cancelled, signal: abort.signal })
  inFlight = run.finally(() => {
    if (watch) clearInterval(watch)
    inFlight = null
  })
  // Callers handle `run`; this keeps the shared guard from surfacing as an unhandled rejection
  // when a sync fails, which would otherwise leak on every failed refresh.
  void inFlight.catch(() => {})
  return run
}

export const scheduleVulnerabilityFeedSync = async (payload: Payload): Promise<void> => {
  if (process.env.OTSERVER_VULNERABILITY_FEEDS === 'off') return
  const req = await systemRequest(payload)
  await inTransaction(req, async () => {
    const settings = await readVulnerabilityFeedSettings(payload, req)
    if (!settings.automaticUpdates) return
    await lockFeedOperations(req)
    const intervalMs = settings.pullIntervalDays * 24 * 60 * 60 * 1000
    const lastSynced = await lastSynchronizedAt(payload, req)
    if (lastSynced && Date.now() - lastSynced.getTime() < intervalMs) return
    const pending = await payload.find({
      collection: 'payload-jobs',
      depth: 0,
      limit: 1,
      req,
      where: {
        and: [
          { taskSlug: { in: ['vulnerability-feed-auto-sync-v1', 'vulnerability-feed-sync-v1'] } },
          { completedAt: { exists: false } },
        ],
      },
    })
    if (pending.docs[0]) return
    const recent = await payload.find({
      collection: 'payload-jobs',
      depth: 0,
      limit: 1,
      sort: '-createdAt',
      req,
      where: { taskSlug: { equals: 'vulnerability-feed-auto-sync-v1' } },
    })
    if (recent.docs[0] && Date.now() - Date.parse(recent.docs[0].createdAt) < intervalMs) return
    await payload.jobs.queue({
      task: 'vulnerability-feed-auto-sync-v1',
      queue: 'maintenance',
      input: { version: 1 },
      req,
    })
  })
}

export const executeScheduledVulnerabilityFeedSync = async (
  payload: Payload,
  jobID?: string | number,
) => {
  if (process.env.OTSERVER_VULNERABILITY_FEEDS === 'off') return
  const req = await systemRequest(payload)
  if (!(await readVulnerabilityFeedSettings(payload, req)).automaticUpdates) return
  return syncVulnerabilityFeeds(payload, { failOnSourceError: true, req, jobID })
}

export const initializeVulnerabilityFeeds = async (payload: Payload): Promise<void> => {
  // Integration tests drive the sync with fixtures, and air-gapped plants have no egress.
  const mode = process.env['OTSERVER_VULNERABILITY_FEEDS']
  if (mode === 'off' || (process.env.NODE_ENV === 'test' && mode !== 'on')) return

  const sync = () =>
    void (async () => {
      if (process.env.OTSERVER_VULNERABILITY_FEEDS === 'off') return
      if (!(await readVulnerabilityFeedSettings(payload)).automaticUpdates) return
      await syncVulnerabilityFeeds(payload)
    })().catch((error) =>
      payload.logger.error(`Vulnerability catalog sync failed: ${message(error)}`),
    )
  sync()
  setInterval(sync, 60_000)
}
