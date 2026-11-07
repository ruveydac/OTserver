import { createHash } from 'node:crypto'
import { lookup as dnsLookup } from 'node:dns/promises'
import { request as httpRequest, type IncomingMessage } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { pipeline } from 'node:stream/promises'
import { createGunzip } from 'node:zlib'
import type { Payload } from 'payload'

export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
export const MAX_FEED_BYTES = 2 * 1024 * 1024 * 1024
const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000

export type FeedBody = Buffer | AsyncIterable<Uint8Array>
export type FeedOptions = { gzip?: boolean; sha256?: string }
export type DownloadFeed = (url: string, options?: FeedOptions) => Promise<FeedBody>
export const MISSING_OFFLINE_FILE = 'MISSING_OFFLINE_FILE'
type FeedLogger = Pick<Payload['logger'], 'warn'>

const safeURL = (value: string): string => {
  try {
    const url = new URL(value)
    url.username = ''
    url.password = ''
    url.search = ''
    url.hash = ''
    return url.toString()
  } catch {
    return '[invalid URL]'
  }
}

const safeError = (error: unknown): string =>
  (error instanceof Error ? error.message : String(error)).replace(
    /https?:\/\/[^\s"'<>]+/g,
    (url) => safeURL(url),
  )

export const isPublicFeedAddress = (address: string): boolean => {
  if (isIP(address) === 4) {
    const [first, second, third] = address.split('.').map(Number)
    return !(
      first === 0 ||
      first === 10 ||
      first === 127 ||
      first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || (second === 168 && third >= 0))) ||
      (first === 192 && second === 88 && third === 99) ||
      (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))) ||
      (first === 203 && second === 0 && third === 113)
    )
  }
  if (isIP(address) !== 6) return false
  let value = address.toLowerCase().split('%')[0]
  const dotted = value.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1]
  if (dotted) {
    const octets = dotted.split('.').map(Number)
    if (octets.length !== 4 || octets.some((octet) => octet > 255)) return false
    value = value.replace(
      dotted,
      `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`,
    )
  }
  const [left = '', right] = value.split('::')
  const leftParts = left ? left.split(':') : []
  const rightParts = right ? right.split(':') : []
  const zeros = 8 - leftParts.length - rightParts.length
  const parts = [...leftParts, ...Array(Math.max(0, zeros)).fill('0'), ...rightParts]
  if (parts.length !== 8 || parts.some((part) => !/^[a-f\d]{1,4}$/i.test(part))) return false
  const integer = parts.reduce((result, part) => (result << 16n) | BigInt(`0x${part}`), 0n)
  return integer >> 125n === 1n && integer >> 96n !== 0x20010db8n
}

const loopbackTestURL = (url: URL) =>
  process.env.NODE_ENV === 'test' &&
  url.protocol === 'http:' &&
  ['127.0.0.1', '[::1]'].includes(url.hostname)

const responseFor = async (url: URL): Promise<IncomingMessage> => {
  const localTest = loopbackTestURL(url)
  if ((url.protocol !== 'https:' && !localTest) || url.username || url.password || url.hash)
    throw new Error('Vulnerability feeds must use public HTTPS URLs.')
  const addresses = localTest
    ? [
        {
          address: url.hostname.replace(/^\[|\]$/g, ''),
          family: isIP(url.hostname.replace(/^\[|\]$/g, '')),
        },
      ]
    : await dnsLookup(url.hostname, { all: true, verbatim: true })
  if (
    !addresses.length ||
    (!localTest && addresses.some(({ address }) => !isPublicFeedAddress(address)))
  )
    throw new Error('The vulnerability feed URL must resolve only to public IP addresses.')

  let lastError: unknown
  for (const address of addresses) {
    const pinnedLookup: LookupFunction = (_hostname, options, callback) => {
      if (typeof options === 'object' && options.all) callback(null, [address])
      else callback(null, address.address, address.family)
    }
    try {
      return await new Promise<IncomingMessage>((resolve, reject) => {
        const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
          {
            hostname: url.hostname,
            port: url.port || undefined,
            path: `${url.pathname}${url.search}`,
            method: 'GET',
            headers: {
              accept: '*/*',
              'accept-encoding': 'identity',
              'user-agent': 'OTserver vulnerability catalog sync',
            },
            lookup: pinnedLookup,
            signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
            ...(url.protocol === 'https:' ? { servername: url.hostname } : {}),
          },
          resolve,
        )
        request.once('error', reject)
        request.end()
      })
    } catch (error) {
      lastError = error
    }
  }
  throw lastError
}

const publicResponse = async (input: string): Promise<IncomingMessage> => {
  let url = new URL(input)
  for (let redirects = 0; redirects <= 5; redirects++) {
    const response = await responseFor(url)
    const status = response.statusCode || 0
    if (![301, 302, 303, 307, 308].includes(status)) return response
    const location = response.headers.location
    response.resume()
    if (!location)
      throw Object.assign(new Error('The feed redirect has no destination.'), { status })
    const next = new URL(location, url)
    if (next.username || next.password || next.hash)
      throw new Error('The feed redirect contains credentials or a fragment.')
    url = next
  }
  throw new Error('The feed exceeded the redirect limit.')
}

const logRequestFailure = (
  logger: FeedLogger | undefined,
  url: string,
  error: unknown,
  status?: number,
) => {
  const value = error as { code?: string | number; cause?: { code?: string | number } }
  const code = value?.code ?? value?.cause?.code
  logger?.warn({
    event: 'vulnerability-feed.request-failed',
    url: safeURL(url),
    ...(status === undefined ? {} : { status }),
    ...(code === undefined ? {} : { code }),
    error: safeError(error),
  })
}

/** The publisher lists this feed but does not serve it: an HTTP 404, or a file left out offline. */
export const feedUnavailable = (error: unknown): boolean =>
  (error as { code?: string }).code === MISSING_OFFLINE_FILE ||
  (error as { status?: number }).status === 404

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

export const downloadFeed = async (
  url: string,
  options?: FeedOptions,
  logger?: FeedLogger,
): Promise<FeedBody> => {
  let response: IncomingMessage
  try {
    response = await publicResponse(url)
  } catch (error) {
    logRequestFailure(logger, url, error)
    throw error
  }
  if (
    !response.statusCode ||
    response.statusCode < 200 ||
    response.statusCode >= 300 ||
    response.statusCode === 204
  ) {
    const error = Object.assign(
      new Error(`${safeURL(url)} responded with ${response.statusCode || 'no status'}.`),
      {
        status: response.statusCode,
      },
    )
    response.resume()
    logRequestFailure(logger, url, error, response.statusCode)
    throw error
  }
  const body = decodeFeed(
    verifyFeed(
      response as unknown as AsyncIterable<Uint8Array>,
      MAX_DOWNLOAD_BYTES,
      undefined,
      url,
    ),
    options,
    url,
  )
  return (async function* () {
    try {
      yield* body
    } catch (error) {
      logRequestFailure(logger, url, error, response.statusCode)
      throw error
    }
  })()
}

/** Only small catalogs and metadata use whole-buffer reads; annual NVD feeds stay streamed. */
export const readFeed = async (body: FeedBody, limit = MAX_DOWNLOAD_BYTES): Promise<Buffer> => {
  const chunks: Buffer[] = []
  for await (const chunk of verifyFeed(body, limit)) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

export const feedText = async (download: DownloadFeed, url: string): Promise<string> =>
  (await readFeed(await download(url))).toString('utf8')
