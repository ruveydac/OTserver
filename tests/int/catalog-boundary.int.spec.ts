import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  request: undefined as undefined | { transactionID: Promise<string> },
  session: { id: 'mongo-session' },
}))

vi.mock('../../src/integrations/payload/workerContext', () => ({
  catalogWrite: (_payload: unknown, work: (req?: unknown) => Promise<unknown>) =>
    work(mocks.request),
}))

vi.mock('../../src/integrations/payload/mongo', () => ({
  mongoSession: vi.fn(async () => mocks.session),
}))

import { rawCollection } from '../../src/integrations/payload/catalog'

describe('MongoDB catalog boundary', () => {
  const native = {
    bulkWrite: vi.fn(async () => ({ ok: 1 })),
    deleteMany: vi.fn(async () => ({ deletedCount: 1 })),
    updateMany: vi.fn(async () => ({ modifiedCount: 1 })),
  }
  const payload = { db: { collections: { vulnerabilities: { collection: native } } } }

  beforeEach(() => {
    vi.clearAllMocks()
    mocks.request = undefined
  })

  it('fails explicitly when the adapter collection is unavailable', () => {
    expect(() => rawCollection({ db: {} } as never, 'missing')).toThrow(
      'The MongoDB collection "missing" is unavailable.',
    )
  })

  it('performs unfenced catalog operations without a session', async () => {
    const collection = rawCollection(payload as never, 'vulnerabilities')
    await collection.bulkWrite([{ insertOne: {} }])
    await collection.deleteMany({ source: 'old' })
    await collection.updateMany({ source: 'nvd' }, { $set: { ready: true } })
    expect(native.bulkWrite).toHaveBeenCalledWith([{ insertOne: {} }], undefined)
    expect(native.deleteMany).toHaveBeenCalledWith({ source: 'old' }, undefined)
    expect(native.updateMany).toHaveBeenCalledWith(
      { source: 'nvd' },
      { $set: { ready: true } },
      undefined,
    )
  })

  it('passes the worker transaction session to every native operation', async () => {
    mocks.request = { transactionID: Promise.resolve('transaction') }
    const collection = rawCollection(payload as never, 'vulnerabilities')
    await collection.bulkWrite([])
    await collection.deleteMany({})
    await collection.updateMany({}, { $set: { ready: true } })
    const options = { session: mocks.session }
    expect(native.bulkWrite).toHaveBeenCalledWith([], options)
    expect(native.deleteMany).toHaveBeenCalledWith({}, options)
    expect(native.updateMany).toHaveBeenCalledWith({}, { $set: { ready: true } }, options)
  })
})
