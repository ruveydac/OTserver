import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  acquireWorker: vi.fn(),
  authorization: { isAdmin: true },
  renewWorker: vi.fn(),
  systemRequest: vi.fn(async () => ({ context: {} })),
}))

vi.mock('../../src/access/authorization', () => ({
  getAuthorization: vi.fn(async () => mocks.authorization),
}))

vi.mock('../../src/jobs/ownership', () => ({
  acquireWorker: mocks.acquireWorker,
  renewWorker: mocks.renewWorker,
}))

vi.mock('../../src/jobs/maintenance', () => ({ SYNC_INTERVAL_MS: 10_000 }))

vi.mock('../../src/integrations/payload/requests', () => ({
  systemRequest: mocks.systemRequest,
}))

vi.mock('../../src/integrations/payload/workerContext', () => ({
  withWorkerFence: (_fence: unknown, work: () => Promise<unknown>) => work(),
}))

import { readiness, workerDiagnostics } from '../../src/jobs/diagnostics'
import { safeFailure, transientFailure } from '../../src/jobs/errors'
import { recoverQueue, runWorker, scheduleMaintenance } from '../../src/jobs/worker'

const fence = {
  assert: vi.fn(async () => undefined),
  owner: 'worker-a',
  queue: 'maintenance',
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.authorization = { isAdmin: true }
  mocks.acquireWorker.mockResolvedValue(fence)
  mocks.renewWorker.mockResolvedValue(undefined)
})

afterEach(() => vi.useRealTimers())

describe('job failure sanitization', () => {
  it('recognizes driver labels, retryable codes, names, and ordinary validation failures', () => {
    expect(
      transientFailure({ hasErrorLabel: (label: string) => label === 'TransientTransactionError' }),
    ).toBe(true)
    expect(
      transientFailure({
        hasErrorLabel: (label: string) => label === 'UnknownTransactionCommitResult',
      }),
    ).toBe(true)
    expect(transientFailure({ code: 91 })).toBe(true)
    expect(transientFailure({ code: 'ECONNRESET' })).toBe(true)
    expect(transientFailure({ name: 'MongoNetworkError' })).toBe(true)
    expect(transientFailure(new Error('invalid'))).toBe(false)
  })

  it('returns only the bounded public error categories', () => {
    expect(safeFailure({ code: 'ETIMEDOUT' })).toContain('temporary')
    expect(safeFailure({ status: 401 })).toContain('permission')
    expect(safeFailure({ status: 403 })).toContain('permission')
    expect(safeFailure({ status: 404 })).toContain('missing')
    expect(safeFailure({ status: 409 })).toContain('ownership')
    expect(safeFailure(new Error('contains /secret/path'))).toContain('integrity check')
    expect(safeFailure(new Error('contains /secret/path'))).not.toContain('/secret/path')
  })
})

describe('worker diagnostics', () => {
  const makePayload = (healthy = true) => ({
    count: vi.fn(async () => ({ totalDocs: 2 })),
    find: vi.fn(async ({ collection }: { collection: string }) => {
      if (collection === 'worker-heartbeats')
        return {
          docs: healthy
            ? [
                {
                  expiresAt: new Date(Date.now() + 60_000).toISOString(),
                  heartbeatAt: new Date().toISOString(),
                },
              ]
            : [],
          totalDocs: healthy ? 1 : 0,
        }
      if (collection === 'payload-jobs')
        return healthy
          ? { docs: [{ createdAt: new Date(Date.now() - 5000).toISOString() }], totalDocs: 1 }
          : { docs: [], totalDocs: 0 }
      if (collection === 'vulnerability-feeds')
        return { docs: [{ source: 'nvd', status: 'ready' }], totalDocs: 1 }
      return {
        docs: healthy ? [{ lastSuccessAt: '2026-01-01T00:00:00.000Z' }] : [],
        totalDocs: healthy ? 1 : 0,
      }
    }),
  })

  it('reports bounded healthy and empty queue state to administrators', async () => {
    for (const healthy of [true, false]) {
      const payload = makePayload(healthy)
      const result = await workerDiagnostics({ payload } as never)
      const body = await result.json()
      expect(result.headers.get('Cache-Control')).toBe('no-store')
      expect(body.queues).toHaveLength(2)
      expect(body.queues[0]).toMatchObject({
        failed: 2,
        healthy,
        pending: healthy ? 1 : 0,
        queueAgeSeconds: healthy ? expect.any(Number) : 0,
      })
      expect(body.lastSuccessfulMaintenanceAt).toBe(healthy ? '2026-01-01T00:00:00.000Z' : null)
    }
  })

  it('rejects non-administrators', async () => {
    mocks.authorization = { isAdmin: false }
    await expect(workerDiagnostics({ payload: makePayload() } as never)).rejects.toMatchObject({
      status: 403,
    })
  })

  it('returns ready and unavailable responses without inventory data', async () => {
    const ready = await readiness({ payload: makePayload() } as never)
    expect(ready.status).toBe(200)
    expect(await ready.json()).toEqual({ ready: true })

    const payload = makePayload()
    payload.find.mockRejectedValueOnce(new Error('database host and credentials'))
    const unavailable = await readiness({ payload } as never)
    expect(unavailable.status).toBe(503)
    expect(await unavailable.json()).toEqual({ ready: false })
  })
})

describe('worker scheduling and execution', () => {
  const makePayload = (state: Record<string, unknown> = {}) => ({
    find: vi.fn(async ({ collection }: { collection: string }) => {
      if (collection === 'worker-leases') return { docs: state.lease ? [state.lease] : [] }
      return { docs: (state.jobs as unknown[]) || [] }
    }),
    jobs: {
      queue: vi.fn(async () => ({ id: 'maintenance-job' })),
      run: vi.fn(async () => undefined),
    },
    logger: { error: vi.fn() },
    update: vi.fn(async () => ({ docs: [] })),
  })

  it('recovers interrupted claims only in the owned queue', async () => {
    const payload = makePayload()
    await recoverQueue(payload as never, fence)
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'payload-jobs',
        data: { processing: false },
        where: {
          and: [
            { queue: { equals: 'maintenance' } },
            { processing: { equals: true } },
            { completedAt: { exists: false } },
          ],
        },
      }),
    )
  })

  it('queues overdue work and suppresses fresh or already-pending work', async () => {
    const overdue = makePayload()
    await scheduleMaintenance(overdue as never, fence)
    expect(overdue.jobs.queue).toHaveBeenCalledWith(
      expect.objectContaining({ task: 'maintenance-v1', queue: 'maintenance' }),
    )

    const fresh = makePayload({
      lease: { lastSuccessAt: new Date(Date.now() + 10_000).toISOString() },
    })
    await scheduleMaintenance(fresh as never, fence)
    expect(fresh.jobs.queue).not.toHaveBeenCalled()

    const pending = makePayload({ jobs: [{ createdAt: '2000-01-01T00:00:00.000Z' }] })
    await scheduleMaintenance(pending as never, fence)
    expect(pending.jobs.queue).not.toHaveBeenCalled()

    const recentFailure = makePayload({
      jobs: [{ createdAt: new Date().toISOString(), hasError: true }],
    })
    await scheduleMaintenance(recentFailure as never, fence)
    expect(recentFailure.jobs.queue).not.toHaveBeenCalled()

    const oldFailure = makePayload({
      jobs: [{ createdAt: '2000-01-01T00:00:00.000Z', hasError: true }],
    })
    await scheduleMaintenance(oldFailure as never, fence)
    expect(oldFailure.jobs.queue).toHaveBeenCalledTimes(1)
  })

  it('rejects a duplicate worker owner', async () => {
    mocks.acquireWorker.mockResolvedValueOnce(null)
    const payload = makePayload()
    await expect(
      runWorker(payload as never, 'imports', new AbortController().signal),
    ).rejects.toThrow('Another imports worker owns the queue.')
  })

  it('runs one owned queue cycle and releases its heartbeat', async () => {
    const controller = new AbortController()
    const payload = makePayload()
    payload.jobs.run.mockImplementationOnce(async () => {
      controller.abort()
    })
    await runWorker(payload as never, 'maintenance', controller.signal)
    expect(payload.jobs.run).toHaveBeenCalledWith(
      expect.objectContaining({ queue: 'maintenance', limit: 1, sequential: true }),
    )
    expect(mocks.renewWorker).toHaveBeenLastCalledWith(payload, fence, true)
  })

  it('logs a sanitized execution failure and still releases ownership', async () => {
    const payload = makePayload()
    payload.jobs.run.mockRejectedValueOnce(Object.assign(new Error('secret'), { status: 400 }))
    await expect(
      runWorker(payload as never, 'imports', new AbortController().signal),
    ).rejects.toThrow('secret')
    expect(payload.logger.error).toHaveBeenCalledWith({
      event: 'worker.stopped',
      queue: 'imports',
      error: expect.stringContaining('integrity check'),
    })
    expect(mocks.renewWorker).toHaveBeenLastCalledWith(payload, fence, true)
  })
})
