import { randomUUID } from 'node:crypto'
import { APIError, type Payload } from 'payload'
import type { MongooseAdapter } from '@payloadcms/db-mongodb'
import { inTransaction } from '../integrations/payload/transactions'
import { mongoSession } from '../integrations/payload/mongo'
import type { WorkerFence } from '../integrations/payload/workerContext'
import { systemRequest } from '../integrations/payload/requests'

export const LEASE_MS = 120_000
export type Queue = 'imports' | 'maintenance'

/** A takeover writes the fence document. Old in-flight transactions conflict and cannot commit. */
export const acquireWorker = async (
  payload: Payload,
  queue: Queue,
): Promise<WorkerFence | null> => {
  const req = await systemRequest(payload)
  const owner = randomUUID()
  try {
    return await inTransaction(req, async () => {
      const leases = await payload.find({
        collection: 'worker-leases',
        where: { queue: { equals: queue } },
        limit: 1,
        depth: 0,
        req,
      })
      const beats = await payload.find({
        collection: 'worker-heartbeats',
        where: { queue: { equals: queue } },
        limit: 1,
        depth: 0,
        req,
      })
      const lease = leases.docs[0]
      const beat = beats.docs[0]
      if (beat && Date.parse(beat.expiresAt) > Date.now()) return null
      const data = { queue, owner, revision: (lease?.revision || 0) + 1 }
      if (lease) await payload.update({ collection: 'worker-leases', id: lease.id, data, req })
      else await payload.create({ collection: 'worker-leases', data, req })
      const heartbeat = {
        queue,
        owner,
        heartbeatAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + LEASE_MS).toISOString(),
      }
      if (beat)
        await payload.update({ collection: 'worker-heartbeats', id: beat.id, data: heartbeat, req })
      else await payload.create({ collection: 'worker-heartbeats', data: heartbeat, req })
      return {
        queue,
        owner,
        assert: async (request) => {
          const session = await mongoSession(request)
          const collection = (payload.db as MongooseAdapter).collections['worker-leases'].collection
          if (!session) {
            if (!(await collection.findOne({ queue, owner })))
              throw new APIError('Worker ownership was lost.', 409)
            return
          }
          // Operational counter only; ownership transitions themselves use audited Payload writes.
          const result = await collection.updateOne(
            { queue, owner },
            { $inc: { revision: 1 } },
            { session },
          )
          if (result.matchedCount !== 1) throw new APIError('Worker ownership was lost.', 409)
        },
      }
    })
  } catch (error) {
    const code = (error as { code?: number }).code
    if (code === 11000 || code === 112) return null
    throw error
  }
}

export const renewWorker = async (payload: Payload, fence: WorkerFence, release = false) => {
  const req = await systemRequest(payload)
  await fence.assert(req)
  const result = await payload.update({
    collection: 'worker-heartbeats',
    req,
    where: { and: [{ queue: { equals: fence.queue } }, { owner: { equals: fence.owner } }] },
    data: {
      heartbeatAt: new Date().toISOString(),
      expiresAt: new Date(release ? 0 : Date.now() + LEASE_MS).toISOString(),
    },
  })
  if (result.docs.length !== 1) throw new APIError('Worker ownership was lost.', 409)
}
