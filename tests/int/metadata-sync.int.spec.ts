import { createHash, randomUUID } from 'node:crypto'
import config from '@/payload.config'
import { createLocalReq, getPayload, type Payload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { catalog } from '../fixtures/device-metadata'
import { readApplicationSettings } from '../../src/application/settings'
import { activeCatalog } from '../../src/metadata/runtime'
import {
  executeMetadataSync,
  queueMetadataSync,
  scheduleMetadataSync,
} from '../../src/metadata/sync'
import { MAX_METADATA_BYTES } from '../../src/metadata/import'

let payload: Payload
let originalSettings: Awaited<ReturnType<typeof readApplicationSettings>>

const setSettings = (data: Record<string, unknown>) =>
  payload.updateGlobal({ slug: 'application-settings', data, overrideAccess: true })

const blob = (content: Buffer) =>
  createHash('sha1').update(`blob ${content.length}\0`).update(content).digest('hex')

const mockGitHub = (commitSHA: string, corrupt = false) => {
  const treeSHA = 'b'.repeat(40)
  const manufacturers = structuredClone(catalog.manufacturers)
  manufacturers[0]!.data.description = `Automatic updater test ${randomUUID()}`
  const files = [
    {
      path: 'data/ot-manufacturers.json',
      content: Buffer.from(JSON.stringify(manufacturers)),
    },
    { path: 'data/ot-devices-test.json', content: Buffer.from(JSON.stringify(catalog.devices)) },
  ]
  const fetchMock = vi.fn(async (input: string) => {
    if (input.endsWith('/commits/main'))
      return new Response(JSON.stringify({ sha: commitSHA, commit: { tree: { sha: treeSHA } } }))
    if (input.endsWith(`/git/trees/${treeSHA}?recursive=1`))
      return new Response(
        JSON.stringify({
          truncated: false,
          tree: files.map(({ path, content }, index) => ({
            path,
            type: 'blob',
            sha: corrupt && index === 0 ? '0'.repeat(40) : blob(content),
            size: content.length,
          })),
        }),
      )
    const file = files.find(({ path }) => input.endsWith(`/${commitSHA}/${path}`))
    if (file) return new Response(file.content)
    throw new Error('Unexpected GitHub request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

beforeAll(async () => {
  payload = await getPayload({ config })
  originalSettings = await readApplicationSettings(payload)
})

afterEach(() => vi.unstubAllGlobals())

afterAll(async () => {
  await setSettings({
    metadataImports: originalSettings.metadataImports ?? false,
    metadataSync: originalSettings.metadataSync ?? null,
  })
  const catalog = await payload.find({
    collection: 'device-catalog',
    where: { id: { equals: 'active' } },
    limit: 1,
  })
  if (catalog.docs.length) await payload.delete({ collection: 'device-catalog', id: 'active' })
  await payload.destroy()
})

describe('automatic device metadata updates', () => {
  it('does not contact GitHub while disabled', async () => {
    await setSettings({ metadataImports: false })
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(executeMetadataSync(payload)).resolves.toEqual({ updated: false })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('records GitHub failures and enforces metadata response limits', async () => {
    await setSettings({ metadataImports: true, metadataSync: {} })
    const tooLarge = new Uint8Array(1024 * 1024 + 1)
    const responses = [
      new Response('rate limited', { status: 429 }),
      new Response('unavailable', { status: 503 }),
      new Response('rate limited', { status: 403, headers: { 'x-ratelimit-remaining': '0' } }),
      new Response('forbidden', { status: 403, headers: { 'x-ratelimit-remaining': '1' } }),
      new Response('not found', { status: 404 }),
      new Response(null),
      new Response('small body', { headers: { 'content-length': String(tooLarge.length) } }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(tooLarge)
            controller.close()
          },
        }),
      ),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error('connection interrupted'))
          },
        }),
      ),
    ]
    const fetchMock = vi.fn().mockRejectedValueOnce(new Error('network unavailable'))
    for (const response of responses) fetchMock.mockResolvedValueOnce(response)
    vi.stubGlobal('fetch', fetchMock)

    for (const message of [
      'GitHub could not be reached',
      'HTTP 429',
      'HTTP 503',
      'HTTP 403',
      'HTTP 403',
      'HTTP 404',
      'HTTP 200',
      'exceeds its size limit',
      'exceeds its size limit',
      'download was interrupted',
    ])
      await expect(executeMetadataSync(payload)).rejects.toThrow(message)

    expect((await readApplicationSettings(payload)).metadataSync?.error).toContain(
      'download was interrupted',
    )
  })

  it('rejects malformed GitHub commit and tree responses', async () => {
    await setSettings({ metadataImports: true, metadataSync: {} })
    const commitSHA = '1'.repeat(40)
    const treeSHA = 'b'.repeat(40)
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ sha: 'invalid', commit: { tree: { sha: treeSHA } } })),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ sha: commitSHA, commit: { tree: { sha: treeSHA } } })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ truncated: true, tree: [] })))
    vi.stubGlobal('fetch', fetchMock)

    await expect(executeMetadataSync(payload)).rejects.toThrow('invalid metadata commit')
    await expect(executeMetadataSync(payload)).rejects.toThrow('incomplete metadata file list')
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('rejects invalid metadata JSON, incomplete manifests, malformed entries, and oversized snapshots', async () => {
    await setSettings({ metadataImports: true, metadataSync: {} })
    const commitSHA = '3'.repeat(40)
    const treeSHA = '4'.repeat(40)
    const commit = JSON.stringify({ sha: commitSHA, commit: { tree: { sha: treeSHA } } })
    const requiredFiles = [
      {
        path: 'data/ot-manufacturers.json',
        type: 'blob',
        sha: '5'.repeat(40),
        size: 1,
      },
      { path: 'data/ot-devices-test.json', type: 'blob', sha: '6'.repeat(40), size: 1 },
    ]
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('not JSON'))
      .mockResolvedValueOnce(new Response(commit))
      .mockResolvedValueOnce(new Response(JSON.stringify({ truncated: false, tree: [] })))
      .mockResolvedValueOnce(new Response(commit))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            truncated: false,
            tree: [{ ...requiredFiles[0]!, type: 'tree' }, requiredFiles[1]],
          }),
        ),
      )
      .mockResolvedValueOnce(new Response(commit))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            truncated: false,
            tree: [{ ...requiredFiles[0]!, size: MAX_METADATA_BYTES + 1 }, requiredFiles[1]],
          }),
        ),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(executeMetadataSync(payload)).rejects.toThrow('invalid metadata commit')
    await expect(executeMetadataSync(payload)).rejects.toThrow('missing required')
    await expect(executeMetadataSync(payload)).rejects.toThrow('invalid metadata file information')
    await expect(executeMetadataSync(payload)).rejects.toThrow('exceeds 8 MiB')
  })

  it('logs when the failed-sync status cannot be saved', async () => {
    await setSettings({ metadataImports: true, metadataSync: {} })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('GitHub unavailable')))
    const updateGlobal = vi
      .spyOn(payload, 'updateGlobal')
      .mockRejectedValueOnce(new Error('status write failed'))
    const warn = vi.spyOn(payload.logger, 'warn')

    try {
      await expect(executeMetadataSync(payload)).rejects.toThrow('GitHub could not be reached')
      expect(warn).toHaveBeenCalledWith(
        expect.objectContaining({ event: 'metadata-sync.status-write-failed' }),
      )
    } finally {
      updateGlobal.mockRestore()
      warn.mockRestore()
    }
  })

  it('imports a commit-pinned catalog, skips the same commit, and leaves the catalog unchanged on integrity failure', async () => {
    const firstCommit = '1'.repeat(40)
    await setSettings({ metadataImports: true, metadataSync: {} })
    const fetchMock = mockGitHub(firstCommit)
    await expect(executeMetadataSync(payload)).resolves.toEqual({ updated: true })
    expect(fetchMock).toHaveBeenCalledTimes(4)
    const imported = await activeCatalog(payload)
    expect(imported.catalog.manufacturers.map(({ id }) => id)).toEqual(
      expect.arrayContaining(catalog.manufacturers.map(({ id }) => id)),
    )
    expect((await readApplicationSettings(payload)).metadataSync).toMatchObject({
      commitSHA: firstCommit,
      lastSyncedAt: expect.any(String),
      error: null,
    })

    const unchangedCommit = mockGitHub(firstCommit)
    await expect(executeMetadataSync(payload)).resolves.toEqual({ updated: false })
    expect(unchangedCommit).toHaveBeenCalledTimes(1)

    const revision = imported.revision
    const nextCommit = '2'.repeat(40)
    mockGitHub(nextCommit, true)
    await expect(executeMetadataSync(payload)).rejects.toThrow('integrity check')
    expect((await activeCatalog(payload)).revision).toBe(revision)
    expect((await readApplicationSettings(payload)).metadataSync).toMatchObject({
      commitSHA: firstCommit,
      error: expect.stringContaining('integrity check'),
    })
  })

  it('queues an update only when enabled and at most once per day', async () => {
    await setSettings({ metadataImports: false, metadataSync: {} })
    const req = await createLocalReq({}, payload)
    await expect(queueMetadataSync(req)).resolves.toBeUndefined()

    await setSettings({
      metadataImports: true,
      metadataSync: { requestedAt: '2000-01-01T00:00:00.000Z' },
    })
    const job = await queueMetadataSync(req)
    try {
      expect(job).toMatchObject({ taskSlug: 'device-metadata-sync-v1' })
      expect((await readApplicationSettings(payload)).metadataSync?.jobID).toBe(String(job!.id))
      await expect(scheduleMetadataSync(payload)).resolves.toBeUndefined()
      await setSettings({
        metadataImports: true,
        metadataSync: { requestedAt: '2000-01-01T00:00:00.000Z' },
      })
      await expect(queueMetadataSync(req)).resolves.toMatchObject({ id: job!.id })
    } finally {
      if (job)
        await payload.delete({ collection: 'payload-jobs', id: job.id, overrideAccess: true })
    }
  })
})
