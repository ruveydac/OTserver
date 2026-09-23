import type { Payload } from 'payload'
import { catalogWrite } from './workerContext'
import { mongoSession } from './mongo'

type RawCollection = {
  bulkWrite: (operations: unknown[], options?: object) => Promise<unknown>
  deleteMany: (filter: unknown, options?: object) => Promise<unknown>
  updateMany: (filter: unknown, update: unknown, options?: object) => Promise<unknown>
}

export const rawCollection = (payload: Payload, slug: string): RawCollection => {
  const collections = (
    payload.db as unknown as {
      collections?: Record<string, { collection?: RawCollection } | undefined>
    }
  ).collections
  const collection = collections?.[slug]?.collection
  if (!collection) throw new Error(`The MongoDB collection "${slug}" is unavailable.`)
  return {
    bulkWrite: (operations) =>
      catalogWrite(payload, async (req) =>
        collection.bulkWrite(operations, req ? { session: await mongoSession(req) } : undefined),
      ),
    deleteMany: (filter) =>
      catalogWrite(payload, async (req) =>
        collection.deleteMany(filter, req ? { session: await mongoSession(req) } : undefined),
      ),
    updateMany: (filter, update) =>
      catalogWrite(payload, async (req) =>
        collection.updateMany(
          filter,
          update,
          req ? { session: await mongoSession(req) } : undefined,
        ),
      ),
  }
}
