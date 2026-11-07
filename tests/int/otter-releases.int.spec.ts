import { generateKeyPairSync, createHash, randomUUID, sign } from 'node:crypto'
import { readFile, rm } from 'node:fs/promises'
import path from 'node:path'
import { gzipSync } from 'node:zlib'
import { createLocalReq, getPayload, handleEndpoints, type Payload } from 'payload'
import type { User } from '../../src/payload-types'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ publicKey: '' }))
vi.mock('node:fs/promises', async (original) => {
  const fs = await original<typeof import('node:fs/promises')>()
  return {
    ...fs,
    readFile: (
      file: Parameters<typeof fs.readFile>[0],
      options?: Parameters<typeof fs.readFile>[1],
    ) =>
      String(file).endsWith('/src/otter/otter-update-public.pem')
        ? Promise.resolve(Buffer.from(mocks.publicKey))
        : fs.readFile(file, options),
  }
})

import config from '@/payload.config'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { acquireWorker, renewWorker } from '../../src/jobs/ownership'
import { withWorkerFence } from '../../src/integrations/payload/workerContext'
import { readApplicationSettings } from '../../src/application/settings'
import {
  compareOtterVersions,
  parseOtterVersion,
  unpackOtterRelease,
  verifyOtterRelease,
  MAX_OTTER_RELEASE_SIZE,
  OTTER_UPDATE_TARGETS,
} from '../../src/otter/releases'
import {
  executeOtterReleaseSync,
  otterReleaseControl,
  queueOtterReleaseSync,
  refreshOtterReleases,
  scheduleOtterReleaseSync,
} from '../../src/otter/releaseSync'

const keys = generateKeyPairSync('ed25519')
mocks.publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const signedBinary = (version = '98.1.0', target: string = OTTER_UPDATE_TARGETS[0]) => {
  const body = Buffer.alloc(1024)
  body.set(target.includes('windows') ? [0x4d, 0x5a] : [0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])
  const message = Buffer.alloc(248)
  message.write('OTTER-SIGNED-v1\0')
  message.writeBigUInt64LE(BigInt(body.length), 16)
  message.write(version, 24)
  message.write(target, 152)
  createHash('sha256').update(body).digest().copy(message, 216)
  return Buffer.concat([body, message, sign(null, message, keys.privateKey)])
}
const archive = (binary: Buffer, name = 'otserver-otter', type = '0') => {
  const tar = Buffer.alloc(512 + Math.ceil(binary.length / 512) * 512 + 1024)
  tar.write(name)
  tar.write(binary.length.toString(8).padStart(11, '0'), 124)
  tar.fill(32, 148, 156)
  tar.write(type, 156)
  tar.write('ustar\0', 257)
  tar.write(
    tar
      .subarray(0, 512)
      .reduce((sum, byte) => sum + byte, 0)
      .toString(8)
      .padStart(6, '0'),
    148,
  )
  tar[154] = 0
  binary.copy(tar, 512)
  return tar
}

let payload: Payload
let admin: User
let reader: User
let readerRole: string
let originalSettings: Awaited<ReturnType<typeof readApplicationSettings>>
const adminPassword = randomUUID()
const emptyState = {
  requestedAt: null,
  lastCheckedAt: null,
  lastSyncedAt: null,
  version: null,
  error: null,
  jobID: null,
}
const untrustedMetadata = {
  version: 'forged',
  target: 'forged',
  binaryDigest: 'forged',
  filesize: 0,
}
const request = () => createLocalReq({ user: admin }, payload)
beforeAll(async () => {
  payload = await getPayload({ config })
  originalSettings = await readApplicationSettings(payload)
  const adminRole = await ensureAdminRole(payload)
  const role = await payload.create({
    collection: 'user-roles',
    data: { name: `Release reader ${randomUUID()}`, permissions: [] },
  })
  readerRole = role.id
  admin = await payload.create({
    collection: 'users',
    data: {
      email: `release-admin-${randomUUID()}@example.test`,
      password: adminPassword,
      role: adminRole.id,
    },
  })
  reader = await payload.create({
    collection: 'users',
    data: {
      email: `release-reader-${randomUUID()}@example.test`,
      password: randomUUID(),
      role: role.id,
    },
  })
})
beforeEach(async () => {
  await payload.updateGlobal({
    slug: 'application-settings',
    data: { otterReleaseImports: false, otterReleaseSync: emptyState },
  })
})
afterEach(async () => {
  vi.unstubAllGlobals()
  const releases = await payload.find({
    collection: 'otter-releases',
    pagination: false,
    where: { version: { like: '98.' } },
  })
  await payload.db.collections['otter-releases'].deleteMany({ version: /^v?98\./ })
  for (const release of releases.docs)
    await rm(
      path.join(process.env.OTSERVER_TEST_UPLOAD_DIR!, 'otter-releases', release.filename!),
      { force: true },
    )
  await payload.db.collections['payload-jobs'].deleteMany({ taskSlug: 'otter-release-sync-v1' })
})
afterAll(async () => {
  await payload.updateGlobal({
    slug: 'application-settings',
    data: {
      otterReleaseImports: originalSettings.otterReleaseImports || false,
      otterReleaseSync: { ...emptyState, ...originalSettings.otterReleaseSync },
    },
  })
  for (const user of [admin, reader]) await payload.delete({ collection: 'users', id: user.id })
  await payload.delete({ collection: 'user-roles', id: readerRole })
})

const github = (version = '98.2.0') => {
  const names = [
    'otserver-otter-linux-x86_64.tar.gz',
    'otserver-otter-linux-aarch64.tar.gz',
    'otserver-otter.exe',
  ]
  const files = OTTER_UPDATE_TARGETS.map((target, index) => {
    const binary = signedBinary(version, target)
    return index < 2 ? gzipSync(archive(binary)) : binary
  })
  const metadata = {
    tag_name: `v${version}`,
    draft: false,
    prerelease: false,
    assets: names.map((name, index) => ({
      name,
      size: files[index].length,
      browser_download_url: `https://github.com/ruveydac/otserver-otter/releases/download/v${version}/${name}`,
    })),
  }
  const fetch = vi.fn(async (url: string) => {
    if (url.endsWith('/releases/latest')) return new Response(JSON.stringify(metadata))
    const index = names.findIndex((name) => url.endsWith(`/${name}`))
    if (index === -1) throw new Error('Unexpected download')
    return new Response(Uint8Array.from(files[index]))
  })
  vi.stubGlobal('fetch', fetch)
  return { metadata, files, fetch }
}

describe('signed Otter release uploads', () => {
  it('parses and orders stable and prerelease versions', () => {
    expect(parseOtterVersion('v1.2+build.7')).toEqual({
      major: 1,
      minor: 2,
      patch: 0,
      prerelease: [],
    })
    expect(() => parseOtterVersion('1.0.0-01')).toThrow('version')

    for (const [left, right, result] of [
      ['1.0.0', '2.0.0', -1],
      ['2.0.0', '1.0.0', 1],
      ['1.1.0', '1.2.0', -1],
      ['1.2.0', '1.1.0', 1],
      ['1.0.1', '1.0.2', -1],
      ['1.0.2', '1.0.1', 1],
      ['1.0.0-alpha', '1.0.0', -1],
      ['1.0.0', '1.0.0-alpha', 1],
      ['1.0.0', '1.0.0', 0],
      ['1.0.0-alpha', '1.0.0-alpha.1', -1],
      ['1.0.0-alpha.1', '1.0.0-alpha', 1],
      ['1.0.0-alpha.2', '1.0.0-alpha.10', -1],
      ['1.0.0-alpha.10', '1.0.0-alpha.2', 1],
      ['1.0.0-alpha.1', '1.0.0-alpha.beta', -1],
      ['1.0.0-alpha.beta', '1.0.0-alpha.1', 1],
      ['1.0.0-alpha.beta', '1.0.0-alpha.gamma', -1],
      ['1.0.0-alpha.gamma', '1.0.0-alpha.beta', 1],
      ['1.0.0-alpha.beta', '1.0.0-alpha.beta', 0],
    ] as const)
      expect(compareOtterVersions(left, right)).toBe(result)
  })

  it('accepts unpacked Linux binaries, official archives and Windows binaries through Payload validation', async () => {
    const cases = [
      ['otserver-otter', 'application/octet-stream', 0, false],
      ['otserver-otter', 'application/x-pie-executable', 1, false],
      ['otserver-otter-linux-x86_64.tar.gz', 'application/gzip', 0, true],
      ['otserver-otter-linux-aarch64.tar.gz', 'application/octet-stream', 1, true],
      ['otserver-otter.exe', 'application/x-msdos-program', 2, false],
    ] as const
    for (const [index, [name, mimetype, targetIndex, compressed]] of cases.entries()) {
      const binary = signedBinary(`98.1.${index}`, OTTER_UPDATE_TARGETS[targetIndex])
      const data = compressed ? gzipSync(archive(binary)) : binary
      const release = await payload.create({
        collection: 'otter-releases',
        data: untrustedMetadata,
        file: { data, name, mimetype, size: data.length },
        req: await request(),
        overrideAccess: false,
      })
      expect(release).toMatchObject({
        version: `98.1.${index}`,
        target: OTTER_UPDATE_TARGETS[targetIndex],
        filesize: binary.length,
        binaryDigest: createHash('sha256').update(binary).digest('hex'),
      })
      expect(
        await readFile(
          path.join(process.env.OTSERVER_TEST_UPLOAD_DIR!, 'otter-releases', release.filename!),
        ),
      ).toEqual(binary)
      const audit = await payload.find({
        collection: 'audit-logs',
        where: { documentID: { equals: release.id } },
        limit: 1,
      })
      expect(audit.docs[0]).toMatchObject({
        actorID: admin.id,
        action: 'create',
        targetCollection: 'otter-releases',
      })
      await expect(
        payload.update({
          collection: 'otter-releases',
          id: release.id,
          data: { version: '98.9.9' },
        }),
      ).rejects.toMatchObject({ status: 409 })
    }
  })

  it('rejects unsigned, tampered, mismatched and appended signatures', async () => {
    const binary = signedBinary()
    const tampered = Buffer.from(binary)
    tampered[30] ^= 1
    const signature = Buffer.from(binary)
    signature[signature.length - 1] ^= 1
    for (const data of [
      binary.subarray(0, 1024),
      tampered,
      signature,
      Buffer.concat([binary, Buffer.from('extra')]),
    ]) {
      await expect(
        payload.create({
          collection: 'otter-releases',
          data: untrustedMetadata,
          file: {
            data,
            name: 'otserver-otter',
            size: data.length,
            mimetype: 'application/octet-stream',
          },
          req: await request(),
          overrideAccess: false,
        }),
      ).rejects.toMatchObject({ status: 400 })
    }
    await expect(verifyOtterRelease(Buffer.alloc(0))).rejects.toThrow('signed Otter executable')
    const wrongLength = Buffer.from(binary)
    wrongLength.writeBigUInt64LE(0n, wrongLength.length - 312 + 16)
    await expect(verifyOtterRelease(wrongLength)).rejects.toThrow('length is invalid')
    await expect(verifyOtterRelease(new Uint8Array(binary))).resolves.toMatchObject({
      version: '98.1.0',
      target: OTTER_UPDATE_TARGETS[0],
    })
    await expect(verifyOtterRelease(signedBinary('98.1.0', 'unsupported'))).rejects.toThrow(
      'unsupported',
    )
    await expect(verifyOtterRelease(signedBinary('not-a-version'))).rejects.toThrow('version')
  })

  it('rejects oversized uploads and non-text signed metadata', async () => {
    await expect(
      unpackOtterRelease({ length: MAX_OTTER_RELEASE_SIZE + 1 } as unknown as Buffer),
    ).rejects.toThrow('no larger than 512 MiB')

    const binary = signedBinary()
    const recordOffset = binary.length - 312
    const message = Buffer.from(binary.subarray(recordOffset, recordOffset + 248))
    message[24] = 1
    message.copy(binary, recordOffset)
    sign(null, message, keys.privateKey).copy(binary, recordOffset + 248)
    await expect(verifyOtterRelease(binary)).rejects.toThrow('metadata is invalid')
  })

  it('rejects unsafe, ambiguous, corrupt and truncated archives', async () => {
    const binary = signedBinary()
    for (const [name, type] of [
      ['../otserver-otter', '0'],
      ['/otserver-otter', '0'],
      ['otserver-otter', '2'],
      ['otserver-otter', '1'],
    ])
      await expect(unpackOtterRelease(gzipSync(archive(binary, name, type)))).rejects.toThrow(
        'official Linux archive',
      )
    const brokenChecksum = archive(binary)
    brokenChecksum[100] = 255
    const multiple = Buffer.concat([archive(binary).subarray(0, -1024), archive(binary)])
    for (const tar of [brokenChecksum, multiple, archive(binary).subarray(0, -512)])
      await expect(unpackOtterRelease(gzipSync(tar))).rejects.toThrow('official Linux archive')
    await expect(unpackOtterRelease(Buffer.from([0x1f, 0x8b, 0x08]))).rejects.toThrow('corrupt')
    await expect(unpackOtterRelease(gzipSync(archive(Buffer.alloc(300))))).rejects.toThrow(
      'official Linux archive',
    )
    const badOctal = archive(binary)
    badOctal.write('x', 124)
    await expect(unpackOtterRelease(gzipSync(badOctal))).rejects.toThrow('official Linux archive')
    const badPrefix = archive(binary)
    badPrefix[345] = 1
    await expect(unpackOtterRelease(gzipSync(badPrefix))).rejects.toThrow('official Linux archive')
    const badPadding = archive(binary)
    badPadding[512 + binary.length] = 1
    await expect(unpackOtterRelease(gzipSync(badPadding))).rejects.toThrow('official Linux archive')
    expect(await unpackOtterRelease(gzipSync(archive(binary, 'otserver-otter', '\0')))).toEqual(
      binary,
    )
    expect(await unpackOtterRelease(gzipSync(archive(binary, './otserver-otter')))).toEqual(binary)
  })

  it('denies non-administrator uploads', async () => {
    const data = signedBinary()
    await expect(
      payload.create({
        collection: 'otter-releases',
        data: untrustedMetadata,
        file: {
          data,
          name: 'otserver-otter',
          size: data.length,
          mimetype: 'application/octet-stream',
        },
        req: await createLocalReq({ user: reader }, payload),
        overrideAccess: false,
      }),
    ).rejects.toMatchObject({ status: 403 })
  })

  it('rejects update records not written by the controller', async () => {
    await expect(
      payload.create({
        collection: 'otter-updates',
        data: {},
        draft: true,
        overrideAccess: true,
      }),
    ).rejects.toMatchObject({ status: 403 })
  })
})

describe('GitHub Otter release imports', () => {
  it('accepts browser multipart raw and archive uploads and exposes authenticated release controls', async () => {
    const { token } = await payload.login({
      collection: 'users',
      data: { email: admin.email, password: adminPassword },
    })
    for (const compressed of [false, true]) {
      const binary = signedBinary(compressed ? '98.4.1' : '98.4.0')
      const bytes = compressed ? gzipSync(archive(binary)) : binary
      const form = new FormData()
      form.append(
        'file',
        new Blob([Uint8Array.from(bytes)], {
          type: compressed ? 'application/gzip' : 'application/x-executable',
        }),
        compressed ? 'otserver-otter-linux-x86_64.tar.gz' : 'otserver-otter',
      )
      form.append('_payload', '{}')
      const uploaded = await handleEndpoints({
        config,
        path: '/api/otter-releases',
        request: new Request('http://localhost/api/otter-releases', {
          method: 'POST',
          headers: { Authorization: `JWT ${token}` },
          body: form,
        }),
      })
      const body = await uploaded.json()
      expect(uploaded.status, JSON.stringify(body)).toBe(201)
      expect(body.doc).toMatchObject({ filesize: binary.length, target: OTTER_UPDATE_TARGETS[0] })
    }
    const control = await handleEndpoints({
      config,
      path: '/api/otter-releases/control',
      request: new Request('http://localhost/api/otter-releases/control', {
        headers: { Authorization: `JWT ${token}` },
      }),
    })
    expect(control.status).toBe(200)
    expect(await control.json()).toMatchObject({ enabled: false, active: false })
  })
  it('imports all platforms, records administrator audit evidence, and skips existing releases on retry', async () => {
    const remote = github()
    const job = await queueOtterReleaseSync(await request())
    const fence = await acquireWorker(payload, 'maintenance')
    expect(fence).not.toBeNull()
    try {
      await withWorkerFence(fence!, () =>
        payload.jobs.run({
          queue: 'maintenance',
          limit: 1,
          sequential: true,
          where: { taskSlug: { equals: 'otter-release-sync-v1' } },
        }),
      )
      const completed = await payload.findByID({ collection: 'payload-jobs', id: job!.id })
      expect(completed, JSON.stringify(completed.error)).toMatchObject({
        completedAt: expect.any(String),
        hasError: false,
      })
      expect(
        (
          await payload.count({
            collection: 'otter-releases',
            where: { version: { equals: '98.2.0' } },
          })
        ).totalDocs,
      ).toBe(3)
    } finally {
      if (fence) await renewWorker(payload, fence, true)
    }
    expect(remote.fetch).toHaveBeenCalledTimes(4)
    expect(await executeOtterReleaseSync(payload, { submittedBy: admin.id })).toEqual({
      imported: 0,
      skipped: 3,
    })
    expect(remote.fetch).toHaveBeenCalledTimes(5)
    expect((await readApplicationSettings(payload)).otterReleaseSync).toMatchObject({
      version: 'v98.2.0',
      error: null,
      lastSyncedAt: expect.any(String),
    })
    const audit = await payload.find({
      collection: 'audit-logs',
      sort: '-createdAt',
      limit: 1,
      where: { documentLabel: { equals: 'Otter release import completed' } },
    })
    expect(audit.docs[0]).toMatchObject({ actorID: admin.id, changes: { skipped: { after: 3 } } })
  })

  it('skips only a matching release created concurrently', async () => {
    const importWithConcurrentInsert = async (version: string, matchingDigest: boolean) => {
      github(version)
      const originalCreate = payload.create.bind(payload)
      const duplicate = Object.assign(new Error('duplicate key'), { code: 11000 })
      let injectDuplicate = true
      const create = vi.spyOn(payload, 'create')
      create.mockImplementation(async (args) => {
        const input = args as { collection?: string; file?: { data?: Buffer } }
        if (input.collection === 'otter-releases' && injectDuplicate) {
          injectDuplicate = false
          const verified = await verifyOtterRelease(input.file!.data!)
          await payload.db.collections['otter-releases'].collection.insertOne({
            binaryDigest: matchingDigest ? verified.binaryDigest : 'different-digest',
            createdAt: new Date(),
            filename: `concurrent-${randomUUID()}`,
            target: verified.target,
            updatedAt: new Date(),
            version: verified.version,
          })
          throw duplicate
        }
        return originalCreate(args as never) as never
      })
      try {
        return await executeOtterReleaseSync(payload, { submittedBy: admin.id })
      } finally {
        create.mockRestore()
      }
    }

    await expect(importWithConcurrentInsert('98.5.0', true)).resolves.toEqual({
      imported: 2,
      skipped: 1,
    })
    await expect(importWithConcurrentInsert('98.6.0', false)).rejects.toThrow('duplicate key')
  })

  it('keeps successful platform imports after a later failure and resumes without duplicates', async () => {
    const remote = github()
    const good = remote.files[1]
    const tampered = signedBinary('98.2.0', OTTER_UPDATE_TARGETS[1])
    tampered[tampered.length - 1] ^= 1
    remote.files[1] = gzipSync(archive(tampered))
    remote.metadata.assets[1].size = remote.files[1].length
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'signature',
    )
    expect((await readApplicationSettings(payload)).otterReleaseSync?.error).toContain('signature')
    expect(
      (
        await payload.count({
          collection: 'otter-releases',
          where: { version: { equals: '98.2.0' } },
        })
      ).totalDocs,
    ).toBe(1)
    remote.files[1] = good
    remote.metadata.assets[1].size = good.length
    expect(await executeOtterReleaseSync(payload, { submittedBy: admin.id })).toEqual({
      imported: 2,
      skipped: 1,
    })
  })

  it('rejects untrusted metadata and a signed executable for the wrong version or platform', async () => {
    const remote = github()
    remote.metadata.draft = true
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'stable',
    )
    remote.metadata.draft = false
    const url = remote.metadata.assets[0].browser_download_url
    remote.metadata.assets[0].browser_download_url = 'https://attacker.example/file'
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'usable',
    )
    expect(remote.fetch).toHaveBeenCalledTimes(2)
    remote.metadata.assets[0].browser_download_url = url
    remote.metadata.assets[0].size += 1
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'size does not match',
    )
    remote.metadata.assets[0].size = remote.files[0]!.length
    for (const binary of [
      signedBinary('98.3.0'),
      signedBinary('98.2.0+different-build'),
      signedBinary('98.2.0', OTTER_UPDATE_TARGETS[1]),
    ]) {
      remote.files[0] = gzipSync(archive(binary))
      remote.metadata.assets[0].size = remote.files[0].length
      await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
        'version and platform',
      )
    }
    expect(
      (
        await payload.count({
          collection: 'otter-releases',
          where: { version: { equals: '98.2.0' } },
        })
      ).totalDocs,
    ).toBe(0)
  })

  it('handles GitHub redirects and retryable failures without following foreign locations', async () => {
    const remote = github()
    const warning = vi.spyOn(payload.logger, 'warn').mockImplementation(() => undefined as never)
    remote.fetch.mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: {
          location:
            'https://github.com/ruveydac/otserver-otter/releases/download/v98.2.0/binary?token=do-not-log',
        },
      }),
    )
    remote.fetch.mockResolvedValueOnce(new Response(null, { status: 503 }))
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toMatchObject(
      { status: 503 },
    )
    expect(warning).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'otter-release.request-failed',
        url: 'https://github.com/ruveydac/otserver-otter/releases/download/v98.2.0/binary',
        status: 503,
      }),
    )
    expect(JSON.stringify(warning.mock.calls)).not.toContain('do-not-log')
    remote.fetch.mockRejectedValueOnce(new Error('Could not reach https://[invalid'))
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toMatchObject(
      { status: 503 },
    )
    expect(JSON.stringify(warning.mock.calls)).toContain('[invalid URL]')
    remote.fetch.mockResolvedValueOnce(
      new Response(null, { status: 403, headers: { 'x-ratelimit-remaining': '0' } }),
    )
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toMatchObject(
      { status: 503 },
    )
    remote.fetch.mockResolvedValueOnce(
      new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/private' } }),
    )
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'unsupported release download location',
    )
    remote.fetch.mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: {
          location: 'https://api.github.com/repos/ruveydac/otserver-otter/releases/latest',
        },
      }),
    )
    expect(await executeOtterReleaseSync(payload, { submittedBy: admin.id })).toEqual({
      imported: 3,
      skipped: 0,
    })
    warning.mockRestore()
  })

  it('bounds release downloads, rejects malformed metadata, and stops redirect loops', async () => {
    const remote = github()
    const warning = vi.spyOn(payload.logger, 'warn').mockImplementation(() => undefined as never)

    remote.fetch.mockResolvedValueOnce(new Response('{'))
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'invalid release metadata',
    )

    remote.fetch.mockResolvedValueOnce(new Response(JSON.stringify(remote.metadata)))
    remote.fetch.mockResolvedValueOnce(
      new Response(new ReadableStream({ start: (stream) => stream.close() }), {
        headers: { 'content-length': String(MAX_OTTER_RELEASE_SIZE + 1) },
      }),
    )
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'exceeds its size limit',
    )

    remote.fetch.mockResolvedValueOnce(new Response(JSON.stringify(remote.metadata)))
    remote.fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      body: (async function* () {
        yield { length: MAX_OTTER_RELEASE_SIZE + 1 } as Uint8Array
      })(),
    } as unknown as Response)
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'exceeds its size limit',
    )

    remote.fetch.mockResolvedValueOnce(new Response(JSON.stringify(remote.metadata)))
    remote.fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      body: (async function* () {
        throw new Error('stream interrupted')
      })(),
    } as unknown as Response)
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toMatchObject(
      { status: 503 },
    )
    expect(warning).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('stream interrupted') }),
    )

    remote.fetch.mockReset()
    remote.fetch.mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: {
          location: 'https://api.github.com/repos/ruveydac/otserver-otter/releases/latest',
        },
      }),
    )
    await expect(executeOtterReleaseSync(payload, { submittedBy: admin.id })).rejects.toThrow(
      'too many release download redirects',
    )
    expect(remote.fetch).toHaveBeenCalledTimes(4)
    warning.mockRestore()
  })

  it('rechecks administrator permissions and the daily option before execution', async () => {
    const remote = github()
    await expect(
      executeOtterReleaseSync(payload, { submittedBy: reader.id }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      executeOtterReleaseSync(payload, { submittedBy: '000000000000000000000000' }),
    ).rejects.toThrow('no longer exists')
    expect(await executeOtterReleaseSync(payload, {})).toEqual({ imported: 0, skipped: 0 })
    expect(remote.fetch).not.toHaveBeenCalled()
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { otterReleaseImports: true },
    })
    expect(await executeOtterReleaseSync(payload, {})).toEqual({ imported: 3, skipped: 0 })
    const audit = await payload.find({
      collection: 'audit-logs',
      sort: '-createdAt',
      limit: 1,
      where: { documentLabel: { equals: 'Otter release import completed' } },
    })
    expect(audit.docs[0].actorType).toBe('system')
  })

  it('allows an administrator to request a manual refresh while daily imports are disabled', async () => {
    const response = await refreshOtterReleases(await createLocalReq({ user: admin }, payload))
    expect(response.status).toBe(202)
    expect(await response.json()).toMatchObject({ jobID: expect.any(String) })
  })

  it('maps queue conflicts to a retryable response and passes other queue errors through', async () => {
    const queue = vi.spyOn(payload.jobs, 'queue')
    const duplicate = Object.assign(new Error('duplicate request'), { code: 11000 })
    queue.mockRejectedValueOnce(duplicate)
    await expect(queueOtterReleaseSync(await request())).rejects.toMatchObject({ status: 409 })

    const failure = new Error('queue unavailable')
    queue.mockRejectedValueOnce(failure)
    await expect(queueOtterReleaseSync(await request())).rejects.toBe(failure)
    queue.mockRestore()
  })

  it('protects controls and status fields, deduplicates queue requests, and schedules once per day', async () => {
    for (const action of [otterReleaseControl, refreshOtterReleases])
      await expect(action(await createLocalReq({ user: reader }, payload))).rejects.toMatchObject({
        status: 403,
      })
    await scheduleOtterReleaseSync(payload)
    expect((await readApplicationSettings(payload)).otterReleaseSync?.jobID).toBeFalsy()
    const req = await request()
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { otterReleaseImports: true },
      overrideAccess: false,
      req,
    })
    await scheduleOtterReleaseSync(payload)
    const state = (await readApplicationSettings(payload)).otterReleaseSync!
    expect(state.jobID).toBeTruthy()
    const queued = await queueOtterReleaseSync(await request())
    expect(String(queued!.id)).toBe(state.jobID)
    expect(await (await otterReleaseControl(await request())).json()).toMatchObject({
      enabled: true,
      active: true,
      processing: false,
    })
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { otterReleaseSync: { error: 'forged', jobID: null } },
      overrideAccess: false,
      req: await request(),
    })
    expect((await readApplicationSettings(payload)).otterReleaseSync?.jobID).toBe(state.jobID)
    await payload.update({
      collection: 'payload-jobs',
      id: state.jobID!,
      data: { completedAt: new Date().toISOString() },
    })
    await scheduleOtterReleaseSync(payload)
    expect((await readApplicationSettings(payload)).otterReleaseSync?.jobID).toBe(state.jobID)
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { otterReleaseSync: { ...state, requestedAt: '2000-01-01T00:00:00Z' } },
    })
    await scheduleOtterReleaseSync(payload)
    expect((await readApplicationSettings(payload)).otterReleaseSync?.jobID).not.toBe(state.jobID)
  })

  it('commits only one job for concurrent manual requests', async () => {
    const requests = await Promise.all([request(), request()])
    const outcomes = await Promise.allSettled(requests.map((req) => queueOtterReleaseSync(req)))
    expect(outcomes.some((outcome) => outcome.status === 'fulfilled')).toBe(true)
    expect(
      (
        await payload.count({
          collection: 'payload-jobs',
          where: { taskSlug: { equals: 'otter-release-sync-v1' } },
        })
      ).totalDocs,
    ).toBe(1)
  })
})
