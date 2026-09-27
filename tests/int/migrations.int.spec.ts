import { describe, expect, it, vi } from 'vitest'

import { down, up } from '../../src/migrations/20260922_205151_queued_import_baseline'
import {
  down as removeSitePaths,
  up as addSitePaths,
} from '../../src/migrations/20260926_111902_site_paths'

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

describe('site path migration', () => {
  it('backfills hierarchical paths and removes them on rollback', async () => {
    const docs = [
      { _id: 'line', name: 'Line 1', parent: 'plant' },
      { _id: 'plant', name: 'Plant' },
    ]
    const bulkWrite = vi.fn(async () => ({ modifiedCount: 2 }))
    const updateMany = vi.fn(async () => ({ modifiedCount: 2 }))
    const args = {
      payload: {
        db: {
          collections: {
            sites: {
              collection: {
                bulkWrite,
                find: vi.fn(() => ({ toArray: vi.fn(async () => docs) })),
                updateMany,
              },
            },
          },
        },
      },
      session: { id: 'session' },
    }

    await addSitePaths(args as never)
    expect(bulkWrite).toHaveBeenCalledWith(
      [
        {
          updateOne: {
            filter: { _id: 'line' },
            update: { $set: { path: 'Plant / Line 1' } },
          },
        },
        {
          updateOne: { filter: { _id: 'plant' }, update: { $set: { path: 'Plant' } } },
        },
      ],
      { session: args.session },
    )

    await removeSitePaths(args as never)
    expect(updateMany).toHaveBeenCalledWith({}, { $unset: { path: '' } }, { session: args.session })
  })
})
