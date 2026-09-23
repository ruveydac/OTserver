import { describe, expect, it, vi } from 'vitest'

import { down, up } from '../../src/migrations/20260922_205151_queued_import_baseline'

describe('queued import baseline migration', () => {
  it('adds synchronous defaults and reverses only untouched records', async () => {
    const updateMany = vi.fn(async () => ({ modifiedCount: 1 }))
    const args = {
      payload: {
        db: { collections: { 'asset-imports': { collection: { updateMany } } } },
      },
      session: { id: 'session' },
    }

    await up(args as never)
    expect(updateMany).toHaveBeenNthCalledWith(
      1,
      { executionMode: { $exists: false } },
      { $set: { executionMode: 'sync', attemptCount: 0 } },
      { session: args.session },
    )

    await down(args as never)
    expect(updateMany).toHaveBeenNthCalledWith(
      2,
      { executionMode: 'sync', jobID: { $exists: false } },
      { $unset: { executionMode: '', attemptCount: '' } },
      { session: args.session },
    )
  })
})
