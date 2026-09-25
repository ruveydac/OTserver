import { setTimeout as delay } from 'node:timers/promises'
import type { Payload } from 'payload'
import { acquireWorker, renewWorker, type Queue } from './ownership'
import { withWorkerFence, type WorkerFence } from '../integrations/payload/workerContext'
import { SYNC_INTERVAL_MS } from './maintenance'
import { safeFailure } from './errors'
import { systemRequest } from '../integrations/payload/requests'

export const recoverQueue = async (payload: Payload, fence: WorkerFence) =>
  withWorkerFence(fence, async () => {
    // Ownership is acquired before resetting interrupted Payload claims. Completed imports remain the authority.
    await payload.update({
      collection: 'payload-jobs',
      where: {
        and: [
          { queue: { equals: fence.queue } },
          { processing: { equals: true } },
          { completedAt: { exists: false } },
        ],
      },
      data: { processing: false },
    })
  })

export const scheduleMaintenance = async (payload: Payload, fence: WorkerFence) =>
  withWorkerFence(fence, async () => {
    const state = await payload.find({
      collection: 'worker-leases',
      limit: 1,
      where: { queue: { equals: 'maintenance' } },
    })
    if (
      state.docs[0]?.lastSuccessAt &&
      Date.parse(state.docs[0].lastSuccessAt) > Date.now() - SYNC_INTERVAL_MS
    )
      return
    const pending = await payload.find({
      collection: 'payload-jobs',
      limit: 1,
      sort: '-createdAt',
      where: { and: [{ queue: { equals: 'maintenance' } }, { completedAt: { exists: false } }] },
    })
    // Keep a terminal failure visible; the next seven-day slot (or admin retry) may queue again.
    if (
      pending.docs.some(
        (job) => !job.hasError || Date.parse(job.createdAt) > Date.now() - SYNC_INTERVAL_MS,
      )
    )
      return
    await payload.jobs.queue({
      task: 'maintenance-v1',
      queue: 'maintenance',
      input: { version: 1 },
      req: await systemRequest(payload),
    })
  })

export const runWorker = async (payload: Payload, queue: Queue, signal: AbortSignal) => {
  const fence = await acquireWorker(payload, queue)
  if (!fence) throw new Error(`Another ${queue} worker owns the queue.`)
  let lost = false
  let heartbeat: Promise<void> = Promise.resolve()
  const timer = setInterval(() => {
    heartbeat = heartbeat
      .then(() => renewWorker(payload, fence))
      .catch(() => {
        lost = true
      })
  }, 20_000)
  try {
    await recoverQueue(payload, fence)
    while (!signal.aborted && !lost) {
      if (queue === 'maintenance') await scheduleMaintenance(payload, fence)
      await withWorkerFence(fence, () =>
        payload.jobs.run({
          queue,
          limit: 1,
          sequential: true,
          processingOrder: 'createdAt',
          silent: true,
        }),
      )
      await delay(1000, undefined, { signal }).catch(() => {})
    }
    if (lost) throw new Error('Worker heartbeat failed; ownership must be recovered.')
  } catch (error) {
    payload.logger.error({ event: 'worker.stopped', queue, error: safeFailure(error) })
    throw error
  } finally {
    clearInterval(timer)
    await heartbeat
    if (!lost) await renewWorker(payload, fence, true).catch(() => {})
  }
}

export const superviseWorker = async (payload: Payload, queue: Queue, signal: AbortSignal) => {
  while (!signal.aborted) {
    try {
      await runWorker(payload, queue, signal)
    } catch {
      if (!signal.aborted) await delay(5000, undefined, { signal }).catch(() => {})
    }
  }
}
