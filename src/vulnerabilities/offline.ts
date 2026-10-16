import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import path from 'node:path'
import { APIError, type Payload, type PayloadRequest } from 'payload'

import {
  decodeFeed,
  loadCsafSnapshot,
  lockFeedOperations,
  MAX_CSAF_DOCUMENTS,
  MAX_CSAF_FEEDS,
  MAX_DOWNLOAD_BYTES,
  parseCisaCatalog,
  parseCsafAggregator,
  parseCsafProviderMetadata,
  parseIcsAdvisories,
  parseNvdMeta,
  parseRolieFeed,
  type DownloadFeed,
} from './feeds'
import { feedText, readFeed, verifyFeed } from './feedIO'
import { nvdDocuments } from './nvd'
import {
  CISA_KEV_URL,
  CSAF_AGGREGATOR_URL,
  CISA_CSAF_FEED_URLS,
  ICS_ADVISORY_URL,
  NVD_FEED_BASE_URL,
  FIRST_NVD_YEAR,
  type FeedSource,
} from './sources'
import { inTransaction } from '../integrations/payload/transactions'
import { systemRequest } from '../integrations/payload/requests'

export const MAX_OFFLINE_FILES = MAX_CSAF_DOCUMENTS + MAX_CSAF_FEEDS + 101
export const MAX_OFFLINE_BATCH_BYTES = 8 * 1024 * 1024 * 1024
export const digest = (data: Buffer) => createHash('sha256').update(data).digest('hex')

export type OfflineSelection = {
  source: FeedSource
  batchID: string
  files: number
  bytes: number
  years: number[]
  missing: string[]
  releases: { label: string; date: string }[]
}

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
): Promise<{ selection: OfflineSelection; download: DownloadFeed; uploadIDs: string[] }> => {
  const files = await offlineFiles(req, batchID, ids)
  const source = files[0].source
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
    [CISA_KEV_URL, CSAF_AGGREGATOR_URL, ...CISA_CSAF_FEED_URLS, NVD_FEED_BASE_URL].map(
      (url) => new URL(url).hostname,
    ),
  )
  for (const file of latest) {
    if (file.sourceURL) {
      byURL.set(file.sourceURL, file)
      continue
    }
    const parts = (file.relativePath || file.originalName).split('/')
    const host = parts.findIndex((part) => hosts.has(part))
    const index = host >= 0 ? byMirror : byName
    if (host < 0 && parts.length > 2) continue
    const key = host >= 0 ? parts.slice(host).join('/') : file.originalName
    const entries = index.get(key) || []
    entries.push(file)
    index.set(key, entries)
  }
  const find = (url: string) => {
    const explicit = byURL.get(url)
    if (explicit) return explicit
    const parsed = new URL(url)
    const pathname = decodeURIComponent(parsed.pathname)
    const mirrored = byMirror.get(`${parsed.hostname}${pathname}`) || []
    if (mirrored.length === 1) return mirrored[0]
    const matches = mirrored.length ? mirrored : byName.get(path.posix.basename(pathname)) || []
    if (matches.length > 1)
      throw new APIError(
        `Several files match ${url}. Preserve hostname/path folders or upload using its missing-file control.`,
        400,
      )
    const match = matches[0]
    if (match && claimed.has(match.id) && claimed.get(match.id) !== url) return undefined
    if (match) claimed.set(match.id, url)
    return match
  }
  const missing = new Set<string>()
  const directory = path.resolve(
    req.payload.collections['vulnerability-feed-uploads'].config.upload.staticDir!,
  )
  const open = async (url: string, limit = MAX_DOWNLOAD_BYTES) => {
    const file = find(url)
    if (!file) {
      missing.add(url)
      return undefined
    }
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
    if (!body) throw new APIError(`Missing offline file: ${url}`, 400)
    return decodeFeed(body, { ...options, gzip: options.gzip && actual.endsWith('.gz') }, actual)
  }
  const json = async (url: string) => {
    const body = await read(url, 16 * 1024 * 1024)
    return body ? (JSON.parse(body.toString('utf8')) as unknown) : undefined
  }
  const years: number[] = []
  const releases: OfflineSelection['releases'] = []
  if (source === 'nvd') {
    for (const file of latest) {
      const match = file.originalName.match(/^nvdcve-2\.0-(\d{4})\.(?:meta|json(?:\.gz)?)$/)
      if (!match)
        throw new APIError(
          `Unexpected NVD filename: ${file.originalName}. Keep the publisher's original filename.`,
          400,
        )
      const year = Number(match[1])
      if (year < FIRST_NVD_YEAR || year > new Date().getUTCFullYear())
        throw new APIError('Unsupported NVD year.', 400)
      if (!years.includes(year)) years.push(year)
    }
    years.sort((a, b) => a - b)
    for (const year of years) {
      const base = `${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}`
      const meta = await read(`${base}.meta`, 64 * 1024)
      if (meta && !/^[a-f\d]{64}$/i.test(parseNvdMeta(meta.toString('utf8')).sha256 || ''))
        throw new APIError(`The ${year} .meta file must contain a valid SHA-256 checksum.`, 400)
      const modified = meta
        ?.toString('utf8')
        .match(/^lastModifiedDate:(.+)$/m)?.[1]
        ?.trim()
      if (modified && Number.isFinite(Date.parse(modified)))
        releases.push({ label: String(year), date: new Date(modified).toISOString() })
      if (!find(`${base}.json.gz`) && !find(`${base}.json`)) missing.add(`${base}.json.gz`)
    }
  } else if (source === 'csaf') {
    const aggregator = await json(CSAF_AGGREGATOR_URL)
    const feedURLs = new Set<string>(CISA_CSAF_FEED_URLS)
    if (aggregator !== undefined) {
      for (const url of parseCsafAggregator(aggregator)) {
        const provider = await json(url)
        if (provider !== undefined)
          for (const feed of parseCsafProviderMetadata(provider)) feedURLs.add(feed)
      }
    }
    if (feedURLs.size > MAX_CSAF_FEEDS) throw new APIError('The CSAF feed limit was exceeded.', 400)
    const documents = new Set<string>()
    for (const url of feedURLs) {
      const feed = await json(url)
      if (feed !== undefined) {
        const parsed = parseRolieFeed(feed)
        releases.push({ label: url, date: parsed.updated })
        for (const entry of parsed.entries) documents.add(entry.url)
      }
    }
    if (documents.size > MAX_CSAF_DOCUMENTS)
      throw new APIError('The CSAF document limit was exceeded.', 400)
    for (const url of documents) if (!find(url)) missing.add(url)
  } else {
    const url = source === 'cisa-kev' ? CISA_KEV_URL : ICS_ADVISORY_URL
    if (!find(url)) missing.add(url)
    else {
      const body = await feedText(download, url)
      const parsed =
        source === 'cisa-kev' ? parseCisaCatalog(JSON.parse(body)) : parseIcsAdvisories(body)
      if (parsed.dateReleased)
        releases.push({ label: source, date: parsed.dateReleased.toISOString() })
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
      releases,
    },
    download,
    uploadIDs: files.map((file) => file.id),
  }
}

/** Preflight every selected file before any catalog mutation, including all linked CSAF documents. */
export const validateOfflineContents = async ({
  selection,
  download,
}: Awaited<ReturnType<typeof inspectOffline>>) => {
  if (selection.missing.length)
    throw new APIError('The offline selection is incomplete. Check the missing-file list.', 400)
  if (selection.source === 'cisa-kev')
    parseCisaCatalog(JSON.parse(await feedText(download, CISA_KEV_URL)))
  if (selection.source === 'ics-advisories')
    parseIcsAdvisories(await feedText(download, ICS_ADVISORY_URL))
  if (selection.source === 'csaf') await loadCsafSnapshot(download, {})
  if (selection.source === 'nvd')
    for (const year of selection.years) {
      const base = `${NVD_FEED_BASE_URL}/nvdcve-2.0-${year}`
      const meta = parseNvdMeta(await feedText(download, `${base}.meta`))
      for await (const document of nvdDocuments(
        await download(`${base}.json.gz`, { gzip: true, sha256: meta.sha256 }),
      ))
        void document
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
