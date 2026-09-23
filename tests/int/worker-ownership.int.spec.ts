import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  session: undefined as undefined | { id: string },
  transactionError: undefined as undefined | (Error & { code?: number }),
  request: { context: {} as Record<string, unknown> },
}))

vi.mock('../../src/integrations/payload/transactions', () => ({
  inTransaction: async (_req: unknown, work: () => Promise<unknown>) => {
    if (mocks.transactionError) throw mocks.transactionError
    return work()
  },
}))

vi.mock('../../src/integrations/payload/mongo', () => ({
  mongoSession: vi.fn(async () => mocks.session),
}))

vi.mock('../../src/integrations/payload/requests', () => ({
  systemRequest: vi.fn(async () => mocks.request),
}))

import { acquireWorker, LEASE_MS, renewWorker } from '../../src/jobs/ownership'

const makePayload = ({
  beat,
  lease,
  heartbeatUpdates = [{ id: 'heartbeat' }],
}: {
  beat?: Record<string, unknown>
  lease?: Record<string, unknown>
  heartbeatUpdates?: unknown[]
} = {}) => {
  const native = {
    findOne: vi.fn(async (): Promise<{ queue: string } | null> => ({ queue: 'imports' })),
    updateOne: vi.fn(async () => ({ matchedCount: 1 })),
  }
  return {
    create: vi.fn(async ({ data }: { data: object }) => ({ id: 'created', ...data })),
    db: { collections: { 'worker-leases': { collection: native } } },
    find: vi.fn(async ({ collection }: { collection: string }) => ({
      docs: collection === 'worker-leases' ? (lease ? [lease] : []) : beat ? [beat] : [],
    })),
    native,
    update: vi.fn(async ({ collection, data }: { collection: string; data: object }) =>
      collection === 'worker-heartbeats'
        ? { docs: heartbeatUpdates, ...data }
        : { docs: [{ id: 'lease' }], ...data },
    ),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.session = undefined
  mocks.transactionError = undefined
  mocks.request = { context: {} }
})

describe('worker ownership fencing', () => {
  it('creates a new lease and heartbeat and validates it outside a transaction', async () => {
    const payload = makePayload()
    const fence = await acquireWorker(payload as never, 'imports')
    expect(fence).toMatchObject({ queue: 'imports', owner: expect.any(String) })
    expect(payload.create).toHaveBeenCalledTimes(2)
    expect(payload.create).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'worker-heartbeats',
        data: expect.objectContaining({
          expiresAt: expect.any(String),
          heartbeatAt: expect.any(String),
          queue: 'imports',
        }),
      }),
    )
    expect(
      Date.parse(
        (payload.create.mock.calls[1][0] as { data: { expiresAt: string } }).data.expiresAt,
      ),
    ).toBeGreaterThan(Date.now() + LEASE_MS - 10_000)
    await fence!.assert(mocks.request as never)
    expect(payload.native.findOne).toHaveBeenCalledWith({ queue: 'imports', owner: fence!.owner })

    payload.native.findOne.mockResolvedValueOnce(null)
    await expect(fence!.assert(mocks.request as never)).rejects.toMatchObject({ status: 409 })
  })

  it('takes over expired records and fences through the MongoDB session', async () => {
    const payload = makePayload({
      beat: { id: 'heartbeat', expiresAt: '2000-01-01T00:00:00.000Z' },
      lease: { id: 'lease', revision: 4 },
    })
    const fence = await acquireWorker(payload as never, 'maintenance')
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'worker-leases',
        data: expect.objectContaining({ revision: 5 }),
        id: 'lease',
      }),
    )
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'worker-heartbeats', id: 'heartbeat' }),
    )

    mocks.session = { id: 'session' }
    await fence!.assert(mocks.request as never)
    expect(payload.native.updateOne).toHaveBeenCalledWith(
      { queue: 'maintenance', owner: fence!.owner },
      { $inc: { revision: 1 } },
      { session: mocks.session },
    )
    payload.native.updateOne.mockResolvedValueOnce({ matchedCount: 0 })
    await expect(fence!.assert(mocks.request as never)).rejects.toMatchObject({ status: 409 })
  })

  it('does not take over a live heartbeat', async () => {
    const payload = makePayload({
      beat: { expiresAt: new Date(Date.now() + 60_000).toISOString() },
      lease: { id: 'lease' },
    })
    expect(await acquireWorker(payload as never, 'imports')).toBeNull()
    expect(payload.update).not.toHaveBeenCalled()
  })

  it('treats duplicate and write-conflict takeovers as lost races', async () => {
    for (const code of [11000, 112]) {
      mocks.transactionError = Object.assign(new Error('race'), { code })
      expect(await acquireWorker(makePayload() as never, 'imports')).toBeNull()
    }
    const fatal = Object.assign(new Error('fatal'), { code: 50 })
    mocks.transactionError = fatal
    await expect(acquireWorker(makePayload() as never, 'imports')).rejects.toBe(fatal)
  })

  it('renews and releases only the matching owned heartbeat', async () => {
    const payload = makePayload()
    const fence = { assert: vi.fn(async () => undefined), owner: 'owner-a', queue: 'imports' }
    await renewWorker(payload as never, fence as never)
    expect(payload.update).toHaveBeenLastCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ expiresAt: expect.any(String) }),
        where: {
          and: [{ queue: { equals: 'imports' } }, { owner: { equals: 'owner-a' } }],
        },
      }),
    )
    const renewedExpiry = Date.parse(
      (payload.update.mock.calls.at(-1)![0] as { data: { expiresAt: string } }).data.expiresAt,
    )
    expect(renewedExpiry).toBeGreaterThan(Date.now())

    await renewWorker(payload as never, fence as never, true)
    expect(
      (payload.update.mock.calls.at(-1)![0] as { data: { expiresAt: string } }).data.expiresAt,
    ).toBe('1970-01-01T00:00:00.000Z')

    const missing = makePayload({ heartbeatUpdates: [] })
    await expect(renewWorker(missing as never, fence as never)).rejects.toMatchObject({
      status: 409,
    })
  })
})
