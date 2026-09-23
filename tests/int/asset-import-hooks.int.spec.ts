import { afterEach, describe, expect, it, vi } from 'vitest'

import { AssetImports } from '../../src/collections/AssetImports'

const beforeValidate = AssetImports.hooks!.beforeValidate![0]!
const afterChange = AssetImports.hooks!.afterChange![0]!
const protectProcessing = AssetImports.hooks!.beforeChange![2]!
const applyReplayKey = AssetImports.hooks!.beforeChange![3]!
const beforeOperation = AssetImports.hooks!.beforeOperation![0]!

const adminRequest = (file?: { data: Buffer }) => ({
  context: {
    siteAuthorization: Promise.resolve({
      isAdmin: true,
      readableSiteIDs: [],
      writableSiteIDs: [],
    }),
  },
  file,
  payload: {
    find: vi.fn(async () => ({ docs: [] as Record<string, unknown>[] })),
    jobs: { queue: vi.fn(async () => ({ id: 'job-1' })) },
    update: vi.fn(async ({ data }: { data: object }) => ({ id: 'import-1', ...data })),
  },
  user: { id: 'admin-1' },
})

afterEach(() => {
  process.env.OTSERVER_QUEUED_IMPORTS = 'off'
})

describe('asset import collection boundaries', () => {
  it('normalizes the legacy source without changing current sources', async () => {
    const legacy = { source: 'otserver-scanner' }
    expect(await beforeValidate({ data: legacy } as never)).toMatchObject({
      source: 'otserver-otter',
    })
    const current = { source: 'nmap' }
    expect(await beforeValidate({ data: current } as never)).toBe(current)
  })

  it('leaves internal writes alone and rejects caller-managed processing changes', async () => {
    const internal = { status: 'running' }
    expect(
      await protectProcessing({ context: { importWrite: true }, data: internal } as never),
    ).toBe(internal)

    await expect(
      protectProcessing({
        context: {},
        data: { status: 'running' },
        operation: 'update',
        originalDoc: { executionMode: 'sync', status: 'pending' },
        req: adminRequest(),
      } as never),
    ).rejects.toMatchObject({ status: 400 })

    const unchanged = { status: 'pending' }
    expect(
      await protectProcessing({
        context: {},
        data: unchanged,
        operation: 'update',
        originalDoc: { executionMode: 'sync', status: 'pending' },
        req: adminRequest(),
      } as never),
    ).toBe(unchanged)
  })

  it('makes queued inputs immutable and prevents conversion after upload', async () => {
    await expect(
      protectProcessing({
        context: {},
        data: { source: 'proneta' },
        operation: 'update',
        originalDoc: { executionMode: 'queued', source: 'nmap' },
        req: adminRequest(),
      } as never),
    ).rejects.toMatchObject({ status: 409 })

    const unchanged = { source: 'nmap' }
    expect(
      await protectProcessing({
        context: {},
        data: unchanged,
        operation: 'update',
        originalDoc: { executionMode: 'queued', source: 'nmap' },
        req: adminRequest(),
      } as never),
    ).toBe(unchanged)

    await expect(
      protectProcessing({
        context: {},
        data: { executionMode: 'queued' },
        operation: 'update',
        originalDoc: { executionMode: 'sync' },
        req: adminRequest(),
      } as never),
    ).rejects.toMatchObject({ status: 400 })
  })

  it('discards supplied state and creates an immutable queued input snapshot', async () => {
    const sync = { executionMode: 'sync', status: 'failed', warnings: 'caller value' }
    expect(
      await protectProcessing({
        context: {},
        data: sync,
        operation: 'create',
        req: adminRequest(),
      } as never),
    ).toEqual({ executionMode: 'sync', status: 'pending', attemptCount: 0 })

    const disabled = { executionMode: 'queued', site: 'site-1', source: 'nmap' }
    await expect(
      protectProcessing({
        context: {},
        data: disabled,
        operation: 'create',
        req: adminRequest({ data: Buffer.from('xml') }),
      } as never),
    ).rejects.toMatchObject({ status: 503 })

    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    await expect(
      protectProcessing({
        context: {},
        data: { executionMode: 'queued', site: 'site-1', source: 'nmap' },
        operation: 'create',
        req: adminRequest(),
      } as never),
    ).rejects.toMatchObject({ status: 400 })

    const queued = {
      assetOverrides: { vendor: 'Human Vendor' },
      customFieldOverrides: { owner: 'Operations' },
      executionMode: 'queued',
      site: { id: 'site-1' },
      source: 'nmap',
      sourceVersion: '7.95',
    }
    const result = await protectProcessing({
      context: {},
      data: queued,
      operation: 'create',
      req: adminRequest({ data: Buffer.from('xml') }),
    } as never)
    expect(result).toMatchObject({
      attemptCount: 0,
      executorID: 'admin-1',
      fileDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      processingInput: {
        assetOverrides: { vendor: 'Human Vendor' },
        customFieldOverrides: { owner: 'Operations' },
        site: 'site-1',
        source: 'nmap',
        sourceVersion: '7.95',
        version: 1,
      },
      status: 'pending',
      submittedBy: 'admin-1',
    })
  })

  it('protects queued upload bytes before update or active deletion', async () => {
    const passthrough = { id: 'import-1' }
    expect(
      await beforeOperation({
        args: passthrough,
        operation: 'read',
        req: adminRequest(),
      } as never),
    ).toBe(passthrough)
    expect(
      await beforeOperation({
        args: passthrough,
        operation: 'update',
        req: { ...adminRequest(), context: { importWrite: true } },
      } as never),
    ).toBe(passthrough)

    const noMatch = adminRequest({ data: Buffer.from('replacement') })
    expect(
      await beforeOperation({ args: passthrough, operation: 'update', req: noMatch } as never),
    ).toBe(passthrough)

    const queued = adminRequest({ data: Buffer.from('replacement') })
    queued.payload.find.mockResolvedValueOnce({ docs: [{ id: 'import-1' }] })
    await expect(
      beforeOperation({ args: passthrough, operation: 'update', req: queued } as never),
    ).rejects.toMatchObject({ status: 409 })

    const active = adminRequest()
    active.payload.find.mockResolvedValueOnce({ docs: [{ id: 'import-1' }] })
    await expect(
      beforeOperation({
        args: { where: { site: { equals: 'site-1' } } },
        operation: 'delete',
        req: active,
      } as never),
    ).rejects.toMatchObject({ status: 409 })
    expect(active.payload.find).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          and: [
            { site: { equals: 'site-1' } },
            { executionMode: { equals: 'queued' } },
            { status: { in: ['pending', 'running'] } },
          ],
        },
      }),
    )
  })

  it('queues only new queued uploads and applies an internal replay key', async () => {
    const req = adminRequest({ data: Buffer.from('xml') })
    const skipped = { id: 'import-1', executionMode: 'queued' }
    expect(
      await afterChange({ context: { skipAssetImport: true }, doc: skipped, req } as never),
    ).toBe(skipped)
    expect(await afterChange({ context: {}, doc: skipped, req: adminRequest() } as never)).toBe(
      skipped,
    )
    expect(
      await afterChange({ context: {}, doc: skipped, operation: 'update', req } as never),
    ).toBe(skipped)
    const accepted = await afterChange({
      context: {},
      doc: skipped,
      operation: 'create',
      req,
    } as never)
    expect(accepted).toEqual({ id: 'import-1' })
    expect(accepted.jobID).toBeUndefined()
    expect(req.payload.jobs.queue).toHaveBeenCalledTimes(1)

    const data: Record<string, unknown> = {}
    expect(await applyReplayKey({ context: {}, data } as never)).toBe(data)
    expect(
      await applyReplayKey({ context: { appliedImportKey: 'replay-1' }, data } as never),
    ).toMatchObject({ appliedKey: 'replay-1' })
  })
})
