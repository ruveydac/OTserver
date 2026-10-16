import { createReadStream, createWriteStream } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import { parser } from 'stream-json'
import { pick } from 'stream-json/filters/pick.js'
import { streamArray } from 'stream-json/streamers/stream-array.js'

import { feedChunks, type FeedBody } from './feedIO'
import { parseNvdFeed, type FeedDocument } from './parsers'

export const NVD_BATCH_SIZE = 100
const MAX_VALUE_SIZE = 4 * 1024 * 1024
const MAX_RECORD_SIZE = 16 * 1024 * 1024
type Token = { name: string; value?: unknown }

// Bound individual values, nesting, and record assembly before the streaming assembler sees them.
async function* checkNvdTokens(tokens: AsyncIterable<Token>) {
  let depth = 0
  let found = false
  let arrayPending = false
  let inArray = false
  let scalarSize = 0
  let recordSize = 0
  for await (const token of tokens) {
    const { name, value } = token
    if (depth === 0 && name !== 'startObject')
      throw new Error('The NVD feed must be an object containing a vulnerabilities array.')
    if (arrayPending) {
      if (name !== 'startArray')
        throw new Error('The NVD feed does not contain a vulnerabilities array.')
      arrayPending = false
      inArray = true
    }
    if (depth === 1 && name === 'keyValue' && value === 'vulnerabilities') {
      if (found) throw new Error('The NVD feed repeats its vulnerabilities array.')
      found = arrayPending = true
    }
    if (['startKey', 'startString', 'startNumber'].includes(name)) scalarSize = 0
    if (name === 'stringChunk' || name === 'numberChunk') {
      scalarSize += String(value).length
      if (scalarSize > MAX_VALUE_SIZE) throw new Error('An NVD value exceeds the size limit.')
    }
    if (inArray && depth >= 2) {
      if (
        depth === 2 &&
        (name.startsWith('start') || ['nullValue', 'trueValue', 'falseValue'].includes(name))
      )
        recordSize = 0
      recordSize += 16 + (typeof value === 'string' ? value.length : 0)
      if (recordSize > MAX_RECORD_SIZE) throw new Error('An NVD record exceeds the size limit.')
    }
    if (name === 'startObject' || name === 'startArray') depth += 1
    if (name === 'endObject' || name === 'endArray') depth -= 1
    if (depth > 64) throw new Error('The NVD feed exceeds the nesting limit.')
    if (inArray && depth === 1 && name === 'endArray') inArray = false
    yield token
  }
  if (!found) throw new Error('The NVD feed does not contain a vulnerabilities array.')
}

export async function* nvdDocuments(body: FeedBody): AsyncGenerator<FeedDocument> {
  const records = streamArray.asStream()
  const completed = pipeline(
    feedChunks(body),
    parser.asStream(),
    checkNvdTokens,
    pick.asStream({ filter: 'vulnerabilities' }),
    records,
  )
  void completed.catch(() => {})
  try {
    for await (const { value } of records) yield* parseNvdFeed({ vulnerabilities: [value] })
  } finally {
    records.destroy()
    await completed
  }
}

/** Validate through EOF, including checksums and trailing JSON, before the first catalog write. */
export const importNvdFeed = async (
  body: FeedBody,
  writeBatch: (documents: FeedDocument[]) => Promise<void>,
): Promise<number> => {
  const directory = await mkdtemp(path.join(tmpdir(), 'otserver-nvd-'))
  try {
    const filename = path.join(directory, 'feed.json')
    await pipeline(feedChunks(body), createWriteStream(filename, { mode: 0o600 }))
    for await (const document of nvdDocuments(createReadStream(filename))) void document

    let count = 0
    let batchSize = 0
    let batch: FeedDocument[] = []
    for await (const document of nvdDocuments(createReadStream(filename))) {
      batch.push(document)
      batchSize += JSON.stringify(document).length
      count += 1
      if (batch.length === NVD_BATCH_SIZE || batchSize >= MAX_VALUE_SIZE) {
        await writeBatch(batch)
        batch = []
        batchSize = 0
      }
    }
    if (batch.length) await writeBatch(batch)
    return count
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}
