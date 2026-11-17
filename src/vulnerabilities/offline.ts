import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import path from 'node:path'
import { APIError, type Payload, type PayloadRequest } from 'payload'

import {
  decodeFeed,
  lockFeedOperations,
  MAX_CSAF_DOCUMENTS,
  MAX_CSAF_DIRECTORY_FEEDS,
  MAX_CSAF_FEEDS,
  MAX_DOWNLOAD_BYTES,
  parseCisaCatalog,
  parseCsafAggregator,
  csafDirectoryFileURL,
  parseCsafDirectoryIndex,
  parseCsafDirectoryMetadata,
  parseCsafProviderMetadata,
  parseIcsAdvisories,
  parseNvdMeta,
  parseRolieFeed,
  type DownloadFeed,
} from './feeds'
import { feedText, readFeed, verifyFeed, MISSING_OFFLINE_FILE } from './feedIO'
import {
  CISA_KEV_URL,
  CSAF_AGGREGATOR_URLS,
  CISA_CSAF_FEED_URLS,
  ICS_ADVISORY_URL,
  NVD_FEED_BASE_URL,
  FIRST_NVD_YEAR,
  feedSources,
  MAX_CSAF_DIRECTORY_INDEX_BYTES,
  normalizeCustomCsafFeeds,
  type CustomCsafFeed,
  type FeedSource,
} from './sources'
import { inTransaction } from '../integrations/payload/transactions'
import { systemRequest } from '../integrations/payload/requests'
import { readVulnerabilityFeedSettings } from '../application/settings'

export const MAX_OFFLINE_FILES =
  MAX_CSAF_DOCUMENTS + MAX_CSAF_FEEDS + 2 * MAX_CSAF_DIRECTORY_FEEDS + 101
export const MAX_OFFLINE_BATCH_BYTES = 8 * 1024 * 1024 * 1024
export const digest = (data: Buffer) => createHash('sha256').update(data).digest('hex')

export type OfflineProblem = { file: string; reason: string }
export type OfflineSelection = {
  source: FeedSource
  batchID: string
  files: number
  bytes: number
  years: number[]
  missing: string[]
  invalid: OfflineProblem[]
  current: string[]
  releases: { label: string; date: string }[]
  usable: number
}

const reason = (error: unknown): string => (error instanceof Error ? error.message : String(error))

export const offlineFiles = async (req: PayloadRequest, batchID: string, ids?: string[]) => {
  const files = await req.payload.find({
    collection: 'vulnerability-feed-uploads',
    depth: 0,
    limit: MAX_OFFLINE_FILES + 1,
    sort: '-createdAt',
    overrideAccess: false,
    req,
    where: { and: [{ batchID: { equals: batchID } }, ...(ids ? [{ id: { in: ids } }] : [])] },
  })
  if (!files.docs.length) throw new APIError('Upload at least one feed file first.', 400)
  if (files.totalDocs > MAX_OFFLINE_FILES)
    throw new APIError('The offline file limit was exceeded.', 400)
  if (ids && files.docs.length !== ids.length)
    throw new APIError('A queued feed upload is missing.', 400)
  const sources = new Set(files.docs.map((file) => file.source))
  if (sources.size !== 1) throw new APIError('Upload one source per selection.', 400)
  const bytes = files.docs.reduce((sum, file) => sum + (file.filesize || 0), 0)
  if (bytes > MAX_OFFLINE_BATCH_BYTES)
    throw new APIError('The 8 GiB offline selection limit was exceeded.', 400)
  return files.docs
}

export const inspectOffline = async (
  req: PayloadRequest,
  batchID: string,
  ids?: string[],
  configuredFeeds?: CustomCsafFeed[],
): Promise<{
  selection: OfflineSelection
  download: DownloadFeed
  uploadIDs: string[]
  customCsafFeeds: CustomCsafFeed[]
  sourceDigest?: string
}> => {
  const files = await offlineFiles(req, batchID, ids)
  const source = files[0].source
  const customCsafFeeds =
    source === 'csaf'
      ? normalizeCustomCsafFeeds(
          configuredFeeds ??
            (await readVulnerabilityFeedSettings(req.payload, req)).customCsafFeeds,
        )
      : []
  const previous = (
    await req.payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: { source: { equals: source } },
    })
  ).docs[0]
  const previousState =
    previous?.state && typeof previous.state === 'object' && !Array.isArray(previous.state)
      ? (previous.state as Record<string, unknown>)
      : {}
  // A correction replaces the previous file at the same logical path, without mutating stored bytes.
  const latest = [
    ...new Map(
      [...files]
        .reverse()
        .map((file) => [file.sourceURL || file.relativePath || file.originalName, file]),
    ).values(),
  ]
  const claimed = new Map<string, string>()
  type Upload = (typeof latest)[number]
  const byURL = new Map<string, Upload>()
  const byMirror = new Map<string, Upload[]>()
  const byName = new Map<string, Upload[]>()
  const hosts = new Set(
    [
      CISA_KEV_URL,
      ...CSAF_AGGREGATOR_URLS,
      ...CISA_CSAF_FEED_URLS,
      NVD_FEED_BASE_URL,
      ...customCsafFeeds.map(({ url }) => url),
    ].map((url) => new URL(url).hostname),
  )
  for (const file of latest) {
    if (file.sourceURL) {
      byURL.set(file.sourceURL, file)
      continue
    }
    const parts = (file.relativePath || file.originalName).split('/')
    const host = parts.findIndex((part) => hosts.has(part))
    if (host >= 0 || (parts.length > 1 && parts[0].includes('.'))) {
      const key = host >= 0 ? parts.slice(host).join('/') : parts.join('/')
      const entries = byMirror.get(key) || []
      entries.push(file)
      byMirror.set(key, entries)
    } else if (parts.length <= 2) {
      const entries = byName.get(file.originalName) || []
      entries.push(file)
      byName.set(file.originalName, entries)
    }
  }
  const missing = new Set<string>()
  const invalid = new Map<string, string>()
  const problem = (file: string, error: unknown) => {
    if (!invalid.has(file)) invalid.set(file, reason(error))
  }
  const find = (url: string) => {
    const explicit = byURL.get(url)
    if (explicit) return explicit
    const parsed = new URL(url)
    const pathname = decodeURIComponent(parsed.pathname)
    const mirrored = byMirror.get(`${parsed.hostname}${pathname}`) || []
    if (mirrored.length === 1) return mirrored[0]
    const matches = mirrored.length ? mirrored : byName.get(path.posix.basename(pathname)) || []
    if (matches.length > 1) {
      problem(
        url,
        `Several uploaded files match ${url}. Preserve hostname/path folders or upload it with its missing-file control.`,
      )
      return undefined
    }
    const match = matches[0]
    if (match && claimed.has(match.id) && claimed.get(match.id) !== url) return undefined
    if (match) claimed.set(match.id, url)
    return match
  }
  const locate = (url: string) => {
    const file = find(url)
    if (!file && !invalid.has(url)) missing.add(url)
    return file
  }
  const directory = path.resolve(
    req.payload.collections['vulnerability-feed-uploads'].config.upload.staticDir!,
  )
  const open = async (url: string, limit = MAX_DOWNLOAD_BYTES) => {
    const file = locate(url)
    if (!file) return undefined
    if (!file.filename || path.basename(file.filename) !== file.filename)
      throw new APIError('Invalid stored feed file.', 400)
    const filename = path.join(directory, file.filename)
    if ((await stat(filename)).size > limit)
      throw new APIError(`${file.originalName} exceeds its file size limit.`, 400)
    return verifyFeed(createReadStream(filename), limit, file.digest, file.originalName)
  }
  const read = async (url: string, limit = MAX_DOWNLOAD_BYTES) => {
    const body = await open(url, limit)
    return body ? readFeed(body, limit) : undefined
  }
  const download: DownloadFeed = async (url, options = {}) => {
    // Original uncompressed NVD JSON is also accepted; the checksum still covers those exact bytes.
    const actual =
      url.endsWith('.json.gz') && !find(url) && find(url.slice(0, -3)) ? url.slice(0, -3) : url
    const body = await open(actual)
    if (!body)
      throw Object.assign(new APIError(`Missing offline file: ${url}`, 400), {
        code: MISSING_OFFLINE_FILE,
      })
    return decodeFeed(body, { ...options, gzip: options.gzip && actual.endsWith('.gz') }, actual)
  }
  const json = async (url: string) => {
    const body = await read(url, 16 * 1024 * 1024)
    return body ? (JSON.parse(body.toString('utf8')) as unknown) : undefined
  }
  const years: number[] = []
  const current: string[] = []
  const releases: OfflineSelection['releases'] = []
  let sourceDigest: string | undefined
  let usable = 0
  if (source === 'nvd') {
    const imported = previousState as Record<string, { sha256?: string }>
    const uploaded = new Map<number, { json: boolean }>()
    for (const file of latest) {
      const match = file.originalName.match(/^nvdcve-2\.0-(\d{4})\.(?:meta|json(?:\.gz)?)$/)
      if (!match) {
        problem(
          file.originalName,
          `Unexpected NVD filename: ${file.originalName}. Keep the publisher's original filename.`,
        )
        continue
      }
      const year = Number(match[1])
      if (year < FIRST_NVD_YEAR || year > new Date().getUTCFullYear()) {
        problem(file.originalName, `Unsupported NVD year: ${year}.`)
        continue
      }
      const entry = uploaded.get(year) || { json: false }
      if (!file.originalName.endsWith('.meta')) entry.json = true
      uploaded.set(year, entry)
    }
    for (const year of [...uploaded.keys()].sort((a, b) => a - b)) {
      const base = `${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}`
      let sha256: string | undefined
      let modified: string | undefined
      try {
        const meta = await read(`${base}.meta`, 64 * 1024)
        if (meta) {
          sha256 = parseNvdMeta(meta.toString('utf8')).sha256
          if (!/^[a-f\d]{64}$/i.test(sha256 || ''))
            problem(`${base}.meta`, `The ${year} .meta file must contain a valid SHA-256 checksum.`)
          modified = meta
            .toString('utf8')
            .match(/^lastModifiedDate:(.+)$/m)?.[1]
            ?.trim()
        }
      } catch (error) {
        problem(`${base}.meta`, error)
      }
      if (!uploaded.get(year)!.json) missing.add(`${base}.json.gz`)
      if (!sha256 || !uploaded.get(year)!.json) continue
      if (modified && Number.isFinite(Date.parse(modified)))
        releases.push({ label: String(year), date: new Date(modified).toISOString() })
      years.push(year)
      if (imported[year]?.sha256 === sha256) current.push(String(year))
    }
    usable = years.length
  } else if (source === 'csaf') {
    const feedURLs = new Set<string>(CISA_CSAF_FEED_URLS)
    const providerURLs = new Set<string>()
    const directoryURLs = new Set<string>()
    const snapshotState: Record<string, string> = {}
    const loadJSON = async (url: string) => {
      try {
        return await json(url)
      } catch (error) {
        problem(url, error)
        return undefined
      }
    }
    for (const url of CSAF_AGGREGATOR_URLS) {
      const aggregator = await loadJSON(url)
      if (aggregator === undefined) continue
      try {
        for (const providerURL of parseCsafAggregator(aggregator)) providerURLs.add(providerURL)
      } catch (error) {
        problem(url, error)
      }
    }
    for (const custom of customCsafFeeds) {
      if (custom.type === 'rolie') {
        feedURLs.add(custom.url)
        continue
      }
      const content = await loadJSON(custom.url)
      if (content === undefined) continue
      try {
        if (custom.type === 'aggregator') {
          for (const url of parseCsafAggregator(content)) providerURLs.add(url)
        } else {
          for (const url of parseCsafProviderMetadata(content)) feedURLs.add(url)
          for (const url of parseCsafDirectoryMetadata(content)) directoryURLs.add(url)
        }
      } catch (error) {
        problem(custom.url, error)
      }
    }
    for (const url of providerURLs) {
      const provider = await loadJSON(url)
      if (provider === undefined) continue
      try {
        for (const feed of parseCsafProviderMetadata(provider)) feedURLs.add(feed)
        for (const directoryURL of parseCsafDirectoryMetadata(provider))
          directoryURLs.add(directoryURL)
      } catch (error) {
        problem(url, error)
      }
    }
    if (feedURLs.size > MAX_CSAF_FEEDS) throw new APIError('The CSAF feed limit was exceeded.', 400)
    if (directoryURLs.size > MAX_CSAF_DIRECTORY_FEEDS)
      throw new APIError('The CSAF directory feed limit was exceeded.', 400)
    const documents = new Set<string>()
    for (const url of feedURLs) {
      const feed = await loadJSON(url)
      if (feed === undefined) continue
      try {
        const parsed = parseRolieFeed(feed)
        snapshotState[url] = parsed.updated
        releases.push({ label: url, date: parsed.updated })
        for (const entry of parsed.entries) documents.add(entry.url)
      } catch (error) {
        problem(url, error)
      }
    }
    for (const directoryURL of directoryURLs) {
      const indexURL = csafDirectoryFileURL(directoryURL, 'index.txt')
      const changesURL = csafDirectoryFileURL(directoryURL, 'changes.csv')
      try {
        const index = await read(indexURL, MAX_CSAF_DIRECTORY_INDEX_BYTES)
        const changes = await read(changesURL, MAX_CSAF_DIRECTORY_INDEX_BYTES)
        if (!index || !changes) continue
        snapshotState[`directory:${directoryURL}`] = createHash('sha256')
          .update(index)
          .update('\0')
          .update(changes)
          .digest('hex')
        for (const url of parseCsafDirectoryIndex(index.toString('utf8'), directoryURL))
          documents.add(url)
      } catch (error) {
        problem(directoryURL, error)
      }
    }
    if (documents.size > MAX_CSAF_DOCUMENTS)
      throw new APIError('The CSAF document limit was exceeded.', 400)
    for (const url of documents) locate(url)
    usable = Object.keys(snapshotState).length
    const unchanged =
      Object.keys(snapshotState).length > 0 &&
      Object.keys(snapshotState).length === Object.keys(previousState).length &&
      Object.entries(snapshotState).every(([key, value]) => previousState[key] === value)
    if (unchanged) current.push('CSAF')
  } else {
    const url = source === 'cisa-kev' ? CISA_KEV_URL : ICS_ADVISORY_URL
    const file = locate(url)
    if (file) {
      try {
        const body = await feedText(download, url)
        const parsed =
          source === 'cisa-kev' ? parseCisaCatalog(JSON.parse(body)) : parseIcsAdvisories(body)
        if (parsed.dateReleased)
          releases.push({ label: source, date: parsed.dateReleased.toISOString() })
        sourceDigest = file.digest
        if (previousState.digest === file.digest)
          current.push(feedSources.find(({ value }) => value === source)!.label)
        usable = 1
      } catch (error) {
        problem(file.originalName, error)
      }
    }
  }
  return {
    selection: {
      source,
      batchID,
      files: latest.length,
      bytes: files.reduce((sum, file) => sum + (file.filesize || 0), 0),
      years,
      missing: [...missing],
      invalid: [...invalid].map(([file, text]) => ({ file, reason: text })),
      current,
      releases,
      usable,
    },
    download,
    uploadIDs: files.map((file) => file.id),
    customCsafFeeds,
    sourceDigest,
  }
}

export const removeExpiredFeedUploads = async (payload: Payload) => {
  const cutoff = new Date(Date.now() - 7 * 86_400_000).toISOString()
  for (;;) {
    const req = await systemRequest(payload)
    const removed = await inTransaction(req, async () => {
      const candidate = await payload.count({
        collection: 'vulnerability-feed-uploads',
        where: { createdAt: { less_than: cutoff } },
        req,
      })
      if (!candidate.totalDocs) return 0
      await lockFeedOperations(req)
      const pending = await payload.find({
        collection: 'payload-jobs',
        pagination: false,
        depth: 0,
        req,
        select: { input: true },
        where: {
          and: [
            { taskSlug: { equals: 'vulnerability-feed-sync-v1' } },
            { completedAt: { exists: false } },
            { hasError: { not_equals: true } },
          ],
        },
      })
      const retained = pending.docs.flatMap(
        (job) => (job.input as { uploadIDs?: string[] })?.uploadIDs || [],
      )
      const expired = await payload.find({
        collection: 'vulnerability-feed-uploads',
        depth: 0,
        limit: 100,
        req,
        where: {
          and: [
            { createdAt: { less_than: cutoff } },
            ...(retained.length ? [{ id: { not_in: retained } }] : []),
          ],
        },
      })
      for (const file of expired.docs)
        await payload.delete({ collection: 'vulnerability-feed-uploads', id: file.id, req })
      return expired.docs.length
    })
    if (!removed) return
  }
}
