import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  authorization: { isAdmin: true, writableSiteIDs: [] as string[] },
  bytes: Buffer.from('stored upload'),
  processImport: vi.fn(),
}))

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(async () => mocks.bytes),
}))

vi.mock('../../src/access/authorization', () => ({
  getAuthorization: vi.fn(async () => mocks.authorization),
  relationshipID: (value: unknown) =>
    value && typeof value === 'object' && 'id' in value
      ? (value as { id: string }).id
      : (value as string | undefined),
}))

vi.mock('../../src/integrations/payload/transactions', () => ({
  inTransaction: async (_req: unknown, work: () => Promise<unknown>) => work(),
}))

vi.mock('../../src/integrations/payload/context', () => ({
  withRequestContext: (_req: unknown, _context: unknown, work: () => Promise<unknown>) => work(),
}))

vi.mock('../../src/integrations/payload/requests', () => ({
  principalRequest: vi.fn(async (_payload, user, context) => ({
    context,
    payload: _payload,
    user,
  })),
  systemRequest: vi.fn(async (_payload, context) => ({ context, payload: _payload })),
}))

vi.mock('../../src/application/processImport', () => ({
  processImport: mocks.processImport,
}))

import {
  executeQueuedImport,
  fileDigest,
  requireSiteWriter,
} from '../../src/application/queuedImports'

const baseDoc = () => ({
  attemptCount: 0,
  executionMode: 'queued',
  executorID: 'user-1',
  fileDigest: fileDigest(mocks.bytes),
  filename: 'upload.xml',
  id: 'import-1',
  jobID: 'job-1',
  processingInput: { site: 'site-1', source: 'nmap', version: 1 },
  site: 'site-1',
  source: 'nmap',
  status: 'pending',
})

const makePayload = (doc = baseDoc()) => {
  let importReads = 0
  return {
    collections: { 'asset-imports': { config: { upload: { staticDir: 'import-files' } } } },
    findByID: vi.fn(
      async ({ collection }: { collection: string }): Promise<Record<string, unknown> | null> => {
        if (collection === 'users') return { id: 'user-1' }
        importReads += 1
        return importReads === 1 ? doc : { ...doc, status: 'running' }
      },
    ),
    logger: { info: vi.fn(), warn: vi.fn() },
    update: vi.fn(async ({ data }: { data: object }) => ({ ...doc, ...data })),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.authorization = { isAdmin: true, writableSiteIDs: [] }
  mocks.bytes = Buffer.from('stored upload')
  mocks.processImport.mockResolvedValue(undefined)
})

describe('queued import execution boundary', () => {
  it('enforces current site write access for every principal state', async () => {
    await expect(requireSiteWriter('site-1', { user: undefined } as never)).rejects.toMatchObject({
      status: 403,
    })
    mocks.authorization = { isAdmin: false, writableSiteIDs: ['site-1'] }
    await expect(
      requireSiteWriter({ id: 'site-1' }, { user: { id: 'user-1' } } as never),
    ).resolves.toBeUndefined()
    mocks.authorization = { isAdmin: false, writableSiteIDs: ['another-site'] }
    await expect(
      requireSiteWriter('site-1', { user: { id: 'user-1' } } as never),
    ).rejects.toMatchObject({ status: 403 })
    mocks.authorization = { isAdmin: true, writableSiteIDs: [] }
    await expect(
      requireSiteWriter('site-1', { user: { id: 'admin-1' } } as never),
    ).resolves.toBeUndefined()
  })

  it('treats completion and superseded jobs as idempotent no-ops', async () => {
    for (const doc of [
      { ...baseDoc(), status: 'completed' },
      { ...baseDoc(), jobID: 'newer-job' },
    ]) {
      const payload = makePayload(doc)
      await executeQueuedImport(payload as never, doc.id, 'job-1', 0)
      expect(payload.update).not.toHaveBeenCalled()
    }
  })

  it('refuses to redeliver an already failed import', async () => {
    const doc = { ...baseDoc(), status: 'failed' }
    await expect(
      executeQueuedImport(makePayload(doc) as never, doc.id, 'job-1', 0),
    ).rejects.toMatchObject({ status: 400 })
  })

  it.each([
    ['non-queued mode', { executionMode: 'sync' }],
    ['unsafe stored filename', { filename: '../upload.xml' }],
    ['digest mismatch', { fileDigest: '0'.repeat(64) }],
    [
      'unsupported immutable input',
      { processingInput: { site: 'wrong', source: 'nmap', version: 1 } },
    ],
  ])('records terminal failure for %s', async (_label, patch) => {
    const doc = { ...baseDoc(), ...patch }
    const payload = makePayload(doc)
    await expect(executeQueuedImport(payload as never, doc.id, 'job-1', 0)).rejects.toMatchObject({
      status: 400,
    })
    expect(payload.update).toHaveBeenLastCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'failed' }) }),
    )
    expect(payload.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('integrity check') }),
    )
  })

  it('fails closed when the executing user disappears', async () => {
    const payload = makePayload()
    payload.findByID.mockResolvedValueOnce(baseDoc()).mockResolvedValueOnce(null)
    await expect(
      executeQueuedImport(payload as never, 'import-1', 'job-1', 0),
    ).rejects.toMatchObject({
      status: 400,
    })
    expect(payload.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('permission') }),
    )
  })

  it('accepts a concurrent completion and rejects a conflicting running state', async () => {
    const completed = makePayload()
    completed.findByID
      .mockResolvedValueOnce(baseDoc())
      .mockResolvedValueOnce({ id: 'user-1' })
      .mockResolvedValueOnce({ ...baseDoc(), status: 'completed' })
    await executeQueuedImport(completed as never, 'import-1', 'job-1', 0)
    expect(mocks.processImport).not.toHaveBeenCalled()
    expect(completed.logger.info).toHaveBeenCalled()

    const changed = makePayload()
    changed.findByID
      .mockResolvedValueOnce(baseDoc())
      .mockResolvedValueOnce({ id: 'user-1' })
      .mockResolvedValueOnce({ ...baseDoc(), jobID: 'other-job', status: 'running' })
    await expect(
      executeQueuedImport(changed as never, 'import-1', 'job-1', 0),
    ).rejects.toMatchObject({
      status: 400,
    })
  })

  it('returns transient work to pending for two attempts, then records failure', async () => {
    for (const retry of [0, 2]) {
      const payload = makePayload()
      payload.findByID
        .mockResolvedValueOnce(baseDoc())
        .mockRejectedValueOnce(Object.assign(new Error('database address'), { code: 91 }))
      await expect(
        executeQueuedImport(payload as never, 'import-1', 'job-1', retry),
      ).rejects.toThrow('temporary database or network failure')
      expect(payload.update).toHaveBeenLastCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: retry < 2 ? 'pending' : 'failed' }),
        }),
      )
    }
  })
})
