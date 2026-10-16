import { createHash } from 'node:crypto'
import { pipeline } from 'node:stream/promises'
import { createGunzip } from 'node:zlib'

export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
export const MAX_FEED_BYTES = 2 * 1024 * 1024 * 1024
const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000

export type FeedBody = Buffer | AsyncIterable<Uint8Array>
export type FeedOptions = { gzip?: boolean; sha256?: string }
export type DownloadFeed = (url: string, options?: FeedOptions) => Promise<FeedBody>

export async function* feedChunks(body: FeedBody): AsyncGenerator<Uint8Array> {
  if (Buffer.isBuffer(body)) {
    for (let offset = 0; offset < body.length; offset += 64 * 1024)
      yield body.subarray(offset, offset + 64 * 1024)
  } else yield* body
}

export async function* verifyFeed(
  body: FeedBody,
  limit: number,
  sha256?: string,
  label = 'The feed',
): AsyncGenerator<Uint8Array> {
  const hash = sha256 ? createHash('sha256') : undefined
  let size = 0
  for await (const chunk of feedChunks(body)) {
    size += chunk.length
    if (size > limit) throw new Error(`${label} exceeded the ${limit} byte limit.`)
    hash?.update(chunk)
    yield chunk
  }
  if (hash && hash.digest('hex') !== sha256!.toLowerCase())
    throw new Error(
      `${label} did not match its SHA-256 checksum; it changed after upload or is corrupt.`,
    )
}

export async function* decodeFeed(
  body: FeedBody,
  { gzip, sha256 }: FeedOptions = {},
  label = 'The feed',
): AsyncGenerator<Uint8Array> {
  // NVD hashes the uncompressed JSON. Consumers must reach EOF before trusting any records.
  if (!gzip) {
    yield* verifyFeed(body, MAX_FEED_BYTES, sha256, label)
    return
  }
  const unzip = createGunzip()
  const completed = pipeline(feedChunks(body), unzip)
  void completed.catch(() => {})
  try {
    yield* verifyFeed(unzip, MAX_FEED_BYTES, sha256, label)
  } finally {
    unzip.destroy()
    await completed
  }
}

export const downloadFeed: DownloadFeed = async (url, options) => {
  const response = await fetch(url, {
    headers: { 'user-agent': 'OTserver vulnerability catalog sync' },
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  })
  if (!response.ok || !response.body) throw new Error(`${url} responded with ${response.status}.`)
  return decodeFeed(
    verifyFeed(
      response.body as unknown as AsyncIterable<Uint8Array>,
      MAX_DOWNLOAD_BYTES,
      undefined,
      url,
    ),
    options,
    url,
  )
}

/** Only small catalogs and metadata use whole-buffer reads; annual NVD feeds stay streamed. */
export const readFeed = async (body: FeedBody, limit = MAX_DOWNLOAD_BYTES): Promise<Buffer> => {
  const chunks: Buffer[] = []
  for await (const chunk of verifyFeed(body, limit)) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

export const feedText = async (download: DownloadFeed, url: string): Promise<string> =>
  (await readFeed(await download(url))).toString('utf8')
