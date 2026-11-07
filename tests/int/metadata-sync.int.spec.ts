import { createHash, randomUUID } from 'node:crypto'
import config from '@/payload.config'
import { createLocalReq, getPayload, type Payload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { catalog } from '../fixtures/device-metadata'
import { readApplicationSettings } from '../../src/application/settings'
import { activeCatalog } from '../../src/metadata/runtime'
import { executeMetadataSync, queueMetadataSync } from '../../src/metadata/sync'

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
      await expect(queueMetadataSync(req)).resolves.toBeUndefined()
    } finally {
      if (job)
        await payload.delete({ collection: 'payload-jobs', id: job.id, overrideAccess: true })
    }
  })
})
