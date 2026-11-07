import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'
import { gunzip } from 'node:zlib'
import { APIError } from 'payload'

export const MAX_OTTER_RELEASE_SIZE = 512 * 1024 * 1024
export const OTTER_UPDATE_TARGETS = [
  'x86_64-unknown-linux-gnu',
  'aarch64-unknown-linux-gnu',
  'x86_64-pc-windows-msvc',
] as const

const trailerSize = 312
const messageSize = 248
const magic = Buffer.from('OTTER-SIGNED-v1\0', 'ascii')
const unzip = promisify(gunzip)

export const unpackOtterRelease = async (input: Buffer): Promise<Buffer> => {
  if (input.length > MAX_OTTER_RELEASE_SIZE)
    throw new APIError('Upload an Otter release no larger than 512 MiB.', 400)
  if (input[0] !== 0x1f || input[1] !== 0x8b) return input

  const invalid = () =>
    new APIError('Upload an official Linux archive containing one otserver-otter executable.', 400)
  let tar: Buffer
  try {
    tar = await unzip(input, { maxOutputLength: MAX_OTTER_RELEASE_SIZE + 10_240 })
  } catch {
    throw new APIError('The Linux archive is corrupt or its unpacked size exceeds 512 MiB.', 400)
  }
  if (tar.length < 1536 || tar.length % 512 !== 0) throw invalid()
  const octal = (start: number, end: number) => {
    const value = tar
      .subarray(start, end)
      .toString('utf8')
      .replace(/[\0 ]+$/, '')
      .trimStart()
    if (!/^[0-7]+$/.test(value)) throw invalid()
    return Number.parseInt(value, 8)
  }
  const name = tar.subarray(0, 100).toString('utf8').replace(/\0+$/, '')
  const size = octal(124, 136)
  const checksum = tar
    .subarray(0, 512)
    .reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0)
  const end = 512 + Math.ceil(size / 512) * 512
  // Read the single official member in memory; archive paths and links never reach the filesystem.
  if (
    !['otserver-otter', './otserver-otter'].includes(name) ||
    ![0, 48].includes(tar[156]) ||
    tar.subarray(257, 262).toString('ascii') !== 'ustar' ||
    tar.subarray(345, 500).some((byte) => byte !== 0) ||
    checksum !== octal(148, 156) ||
    size <= trailerSize ||
    size > MAX_OTTER_RELEASE_SIZE ||
    end + 1024 > tar.length ||
    tar.subarray(512 + size).some((byte) => byte !== 0)
  )
    throw invalid()
  return tar.subarray(512, 512 + size)
}

const text = (bytes: Buffer) => {
  const padded = bytes.toString('utf8')
  const value = padded.replace(/\u0000+$/, '')
  if (
    Buffer.from(padded, 'utf8').compare(bytes) !== 0 ||
    value.includes('\u0000') ||
    !/^[\x20-\x7e]*$/.test(value)
  )
    throw new APIError('The signed Otter executable metadata is invalid.', 400)
  return value
}

export const parseOtterVersion = (version: string) => {
  const match =
    /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(
      version,
    )
  if (!match) throw new APIError('The signed Otter version is invalid.', 400)
  const prerelease = match[4]?.split('.') || []
  if (
    prerelease.some((part) => !part || (/^\d+$/.test(part) && part.length > 1 && part[0] === '0'))
  )
    throw new APIError('The signed Otter version is invalid.', 400)
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3] || 0),
    prerelease,
  }
}

export const compareOtterVersions = (left: string, right: string) => {
  const a = parseOtterVersion(left)
  const b = parseOtterVersion(right)
  for (const key of ['major', 'minor', 'patch'] as const)
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1
  if (!a.prerelease.length || !b.prerelease.length)
    return a.prerelease.length === b.prerelease.length ? 0 : a.prerelease.length ? -1 : 1
  for (let index = 0; index < Math.max(a.prerelease.length, b.prerelease.length); index++) {
    const x = a.prerelease[index]
    const y = b.prerelease[index]
    if (x === undefined || y === undefined) return x === y ? 0 : x === undefined ? -1 : 1
    if (x === y) continue
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) return Number(x) < Number(y) ? -1 : 1
    if (xn !== yn) return xn ? -1 : 1
    return x < y ? -1 : 1
  }
  return 0
}

export const verifyOtterRelease = async (input: Uint8Array) => {
  const binary = Buffer.isBuffer(input)
    ? input
    : Buffer.from(input.buffer, input.byteOffset, input.byteLength)
  if (binary.length <= trailerSize || binary.length > MAX_OTTER_RELEASE_SIZE)
    throw new APIError('Upload a signed Otter executable no larger than 512 MiB.', 400)
  const offset = binary.length - trailerSize
  const record = binary.subarray(offset)
  if (!record.subarray(0, 16).equals(magic))
    throw new APIError('The executable has no supported embedded Otter signature.', 400)
  const payloadSize = Number(record.readBigUInt64LE(16))
  if (!Number.isSafeInteger(payloadSize) || payloadSize !== offset)
    throw new APIError('The signed Otter executable length is invalid.', 400)
  const version = text(record.subarray(24, 152))
  parseOtterVersion(version)
  const target = text(record.subarray(152, 216))
  if (!OTTER_UPDATE_TARGETS.includes(target as (typeof OTTER_UPDATE_TARGETS)[number]))
    throw new APIError('The signed Otter executable target is unsupported.', 400)
  const publicKey = await readFile(path.resolve(process.cwd(), 'src/otter/otter-update-public.pem'))
  const payloadDigest = createHash('sha256').update(binary.subarray(0, offset)).digest()
  if (!payloadDigest.equals(record.subarray(216, messageSize)))
    throw new APIError('The signed Otter executable digest is invalid.', 400)
  if (
    !verify(
      null,
      record.subarray(0, messageSize),
      createPublicKey(publicKey),
      record.subarray(messageSize),
    )
  )
    throw new APIError('The Otter executable signature is invalid.', 400)
  return {
    version,
    target,
    binaryDigest: createHash('sha256').update(binary).digest('hex'),
    filesize: binary.length,
  }
}
