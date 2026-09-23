import { beforeEach, describe, expect, it, vi } from 'vitest'
import { JobCancelledError } from 'payload'

const mocks = vi.hoisted(() => ({
  executeImport: vi.fn(),
  maintenance: vi.fn(),
  worker: undefined as undefined | { queue: string },
}))

vi.mock('../../src/application/queuedImports', () => ({
  executeQueuedImport: mocks.executeImport,
}))

vi.mock('../../src/jobs/maintenance', () => ({
  runMaintenance: mocks.maintenance,
}))

vi.mock('../../src/integrations/payload/workerContext', () => ({
  currentWorker: () => mocks.worker,
}))

import { jobs } from '../../src/jobs/config'

type Handler = (args: {
  input: Record<string, unknown>
  job: { id: string; totalTried?: number }
  req: { payload: { logger: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> } } }
}) => Promise<unknown>

const request = () => ({
  payload: { logger: { info: vi.fn(), warn: vi.fn() } },
})

const handler = (index: number) => jobs.tasks![index]!.handler as unknown as Handler

beforeEach(() => {
  vi.clearAllMocks()
  mocks.worker = undefined
  mocks.executeImport.mockResolvedValue(undefined)
  mocks.maintenance.mockResolvedValue(undefined)
})

describe('Payload job configuration', () => {
  it('keeps the raw queue operations private and audits its collection', async () => {
    expect(await jobs.access!.run!({} as never)).toBe(false)
    expect(await jobs.access!.queue!({} as never)).toBe(false)
    expect(await jobs.access!.cancel!({} as never)).toBe(false)
    expect(jobs.autoRun).toEqual([])
    expect(jobs.deleteJobOnComplete).toBe(false)
    // Payload's queue engine relies on atomic update operators for its task log.
    expect(jobs.runHooks).toBe(false)

    const collection = jobs.jobsCollectionOverrides!({
      defaultJobsCollection: {
        slug: 'payload-jobs',
        fields: [],
        hooks: {},
        indexes: [{ fields: ['taskSlug'] }],
      },
    } as never)
    expect(collection.admin).toMatchObject({ group: 'Operations' })
    expect(collection.indexes).toEqual(
      expect.arrayContaining([
        { fields: ['taskSlug'] },
        { fields: ['queue', 'processing', 'hasError', 'completedAt', 'createdAt'] },
      ]),
    )
    expect(await collection.access!.create!({} as never)).toBe(false)
    expect(await collection.access!.update!({} as never)).toBe(false)
    expect(await collection.access!.delete!({} as never)).toBe(false)
  })

  it('runs only versioned import jobs on the import worker', async () => {
    const req = request()
    await expect(
      handler(0)({ input: { importID: 'i1', version: 1 }, job: { id: 'j1' }, req }),
    ).rejects.toBeInstanceOf(JobCancelledError)
    mocks.worker = { queue: 'imports' }
    await expect(
      handler(0)({ input: { importID: 'i1', version: 2 }, job: { id: 'j1' }, req }),
    ).rejects.toBeInstanceOf(JobCancelledError)

    expect(
      await handler(0)({
        input: { importID: 'i1', version: 1 },
        job: { id: 'j1', totalTried: 2 },
        req,
      }),
    ).toEqual({ output: {} })
    expect(mocks.executeImport).toHaveBeenCalledWith(req.payload, 'i1', 'j1', 2)
  })

  it('stops validation failures and leaves unexpected import failures retryable', async () => {
    mocks.worker = { queue: 'imports' }
    const req = request()
    mocks.executeImport.mockRejectedValueOnce(
      Object.assign(new Error('invalid upload'), { status: 400 }),
    )
    await expect(
      handler(0)({ input: { importID: 'i1', version: 1 }, job: { id: 'j1' }, req }),
    ).rejects.toMatchObject({ message: 'invalid upload' })

    const unexpected = Object.assign(new Error('database'), { status: 500 })
    mocks.executeImport.mockRejectedValueOnce(unexpected)
    await expect(
      handler(0)({ input: { importID: 'i1', version: 1 }, job: { id: 'j1' }, req }),
    ).rejects.toBe(unexpected)
  })

  it('runs maintenance, logs its bounded result, and rejects invalid context', async () => {
    const req = request()
    await expect(
      handler(1)({ input: { version: 1 }, job: { id: 'j2' }, req }),
    ).rejects.toBeInstanceOf(JobCancelledError)
    mocks.worker = { queue: 'maintenance' }
    await expect(
      handler(1)({ input: { version: 2 }, job: { id: 'j2' }, req }),
    ).rejects.toBeInstanceOf(JobCancelledError)

    expect(
      await handler(1)({ input: { version: 1 }, job: { id: 'j2', totalTried: 1 }, req }),
    ).toEqual({ output: {} })
    expect(mocks.maintenance).toHaveBeenCalledWith(req.payload)
    expect(req.payload.logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'maintenance.completed', jobID: 'j2', attempt: 2 }),
    )
  })

  it('cancels permanent maintenance failures and retries transient failures', async () => {
    mocks.worker = { queue: 'maintenance' }
    const req = request()
    mocks.maintenance.mockRejectedValueOnce(
      Object.assign(new Error('forbidden secret'), { status: 403 }),
    )
    await expect(
      handler(1)({ input: { version: 1 }, job: { id: 'j2' }, req }),
    ).rejects.toBeInstanceOf(JobCancelledError)
    expect(req.payload.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'maintenance.failed',
        error: expect.stringContaining('permission'),
      }),
    )

    mocks.maintenance.mockRejectedValueOnce(Object.assign(new Error('host secret'), { code: 91 }))
    await expect(
      handler(1)({ input: { version: 1 }, job: { id: 'j3', totalTried: 2 }, req }),
    ).rejects.toThrow('temporary database or network failure')
    expect(req.payload.logger.warn).toHaveBeenLastCalledWith(
      expect.objectContaining({ jobID: 'j3', attempt: 3 }),
    )
  })
})
