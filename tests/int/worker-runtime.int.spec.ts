import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  acquireWorker: vi.fn(),
  renewWorker: vi.fn(),
  systemRequest: vi.fn(),
}))

vi.mock('../../src/jobs/ownership', () => ({
  acquireWorker: mocks.acquireWorker,
  renewWorker: mocks.renewWorker,
}))
vi.mock('../../src/jobs/maintenance', () => ({ SYNC_INTERVAL_MS: 60_000 }))
vi.mock('../../src/integrations/payload/requests', () => ({
  systemRequest: mocks.systemRequest,
}))

import { recoverQueue, runWorker, scheduleMaintenance } from '../../src/jobs/worker'
import {
  catalogWrite,
  currentWorker,
  guardWorkerWrite,
  withWorkerFence,
} from '../../src/integrations/payload/workerContext'

const fence = {
  assert: vi.fn().mockResolvedValue(undefined),
  owner: 'owner-1',
  queue: 'imports' as const,
}

beforeEach(() => {
  vi.useRealTimers()
  vi.clearAllMocks()
  mocks.acquireWorker.mockResolvedValue(fence)
  mocks.renewWorker.mockResolvedValue(undefined)
  mocks.systemRequest.mockResolvedValue({ id: 'system-request' })
  fence.assert.mockResolvedValue(undefined)
})

describe('worker runtime boundaries', () => {
  it('recovers interrupted jobs and schedules only stale maintenance work', async () => {
    const payload = {
      find: vi.fn(),
      jobs: { queue: vi.fn().mockResolvedValue({ id: 'job-1' }) },
      update: vi.fn().mockResolvedValue({}),
    }
    await recoverQueue(payload as never, fence)
    expect(payload.update).toHaveBeenCalledWith({
      collection: 'payload-jobs',
      data: { processing: false },
      where: {
        and: [
          { queue: { equals: 'imports' } },
          { processing: { equals: true } },
          { completedAt: { exists: false } },
        ],
      },
    })

    payload.find.mockResolvedValueOnce({
      docs: [{ lastSuccessAt: new Date().toISOString() }],
    })
    await scheduleMaintenance(payload as never, fence)
    expect(payload.find).toHaveBeenCalledTimes(1)
    expect(payload.jobs.queue).not.toHaveBeenCalled()

    payload.find
      .mockResolvedValueOnce({ docs: [] })
      .mockResolvedValueOnce({ docs: [{ createdAt: '2000-01-01T00:00:00.000Z', hasError: true }] })
    await scheduleMaintenance(payload as never, { ...fence, queue: 'maintenance' })
    expect(payload.jobs.queue).toHaveBeenCalledWith({
      input: { version: 1 },
      queue: 'maintenance',
      req: { id: 'system-request' },
      task: 'maintenance-v1',
    })
  })

  it('stops cleanly when aborted and reports ownership and job failures', async () => {
    const payload = {
      jobs: { run: vi.fn() },
      logger: { error: vi.fn() },
      update: vi.fn().mockResolvedValue({}),
    }
    const aborted = new AbortController()
    aborted.abort()
    await runWorker(payload as never, 'imports', aborted.signal)
    expect(payload.jobs.run).not.toHaveBeenCalled()
    expect(mocks.renewWorker).toHaveBeenCalledWith(payload, fence, true)

    mocks.acquireWorker.mockResolvedValueOnce(null)
    await expect(runWorker(payload as never, 'imports', aborted.signal)).rejects.toThrow(
      'Another imports worker owns the queue.',
    )

    const failure = new Error('job failed')
    payload.jobs.run.mockRejectedValueOnce(failure)
    const running = new AbortController()
    await expect(runWorker(payload as never, 'imports', running.signal)).rejects.toBe(failure)
    expect(payload.logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'worker.stopped', queue: 'imports' }),
    )
    expect(mocks.renewWorker).toHaveBeenCalledWith(payload, fence, true)
  })

  it('exits when the heartbeat is lost and fences writes once per transaction', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const payload = {
      jobs: {
        run: vi.fn(async () => {
          await vi.advanceTimersByTimeAsync(20_000)
          await Promise.resolve()
          controller.abort()
        }),
      },
      logger: { error: vi.fn() },
      update: vi.fn().mockResolvedValue({}),
    }
    mocks.renewWorker.mockRejectedValueOnce(new Error('heartbeat failed'))
    await expect(runWorker(payload as never, 'imports', controller.signal)).rejects.toThrow(
      'heartbeat failed; ownership must be recovered',
    )
    expect(mocks.renewWorker).toHaveBeenCalledTimes(1)

    const req = { context: {}, transactionID: Promise.resolve('transaction-1') }
    await guardWorkerWrite(req as never)
    await withWorkerFence(fence, async () => {
      await guardWorkerWrite(req as never)
      await guardWorkerWrite(req as never)
      req.transactionID = Promise.resolve('transaction-2')
      await guardWorkerWrite(req as never)
    })
    expect(fence.assert).toHaveBeenCalledTimes(2)
    expect(currentWorker()).toBeUndefined()

    const work = vi.fn().mockResolvedValue('catalog-result')
    await expect(catalogWrite({} as never, work)).resolves.toBe('catalog-result')
    expect(work).toHaveBeenCalledWith()
  })
})
