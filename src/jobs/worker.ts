import { setTimeout as delay } from 'node:timers/promises'
import type { Payload } from 'payload'
import { acquireWorker, renewWorker, type Queue } from './ownership'
import { withWorkerFence, type WorkerFence } from '../integrations/payload/workerContext'
import { SYNC_INTERVAL_MS } from './maintenance'
import { safeFailure } from './errors'
import { systemRequest } from '../integrations/payload/requests'
import { expireOtterLeases } from '../otter/controller'
import { scheduleOtterReleaseSync } from '../otter/releaseSync'

const OTTER_LEASE_SWEEP_MS = 15_000

// Reclassifications are quick administrator-triggered refreshes. A separate drain keeps an
// import's reclassification from waiting behind the long weekly maintenance job.
const REAPPLY_TASK = 'reapply-asset-classes-v1'

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
      where: {
        and: [
          { taskSlug: { equals: 'maintenance-v1' } },
          { queue: { equals: 'maintenance' } },
          { completedAt: { exists: false } },
        ],
      },
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

/** Runs reclassification jobs on their own loop, concurrently with the main maintenance loop. */
const drainReapplyJobs = async (
  payload: Payload,
  fence: WorkerFence,
  signal: AbortSignal,
  stopped: () => boolean,
) => {
  while (!signal.aborted && !stopped()) {
    await withWorkerFence(fence, () =>
      payload.jobs.run({
        queue: 'maintenance',
        limit: 10,
        sequential: true,
        processingOrder: 'createdAt',
        silent: true,
        where: { taskSlug: { equals: REAPPLY_TASK } },
      }),
    )
    await delay(1000, undefined, { signal }).catch(() => {})
  }
}

export const runWorker = async (payload: Payload, queue: Queue, signal: AbortSignal) => {
  const fence = await acquireWorker(payload, queue)
  if (!fence) throw new Error(`Another ${queue} worker owns the queue.`)
  let lost = false
  let stopped = false
  let heartbeat: Promise<void> = Promise.resolve()
  let timer: ReturnType<typeof setInterval> | undefined
  let nextReleaseCheck = 0
  try {
    await recoverQueue(payload, fence)
    if (queue === 'maintenance') await withWorkerFence(fence, () => expireOtterLeases(payload))
    timer = setInterval(
      () => {
        heartbeat = heartbeat
          .then(async () => {
            await renewWorker(payload, fence)
            if (queue === 'maintenance')
              await withWorkerFence(fence, () => expireOtterLeases(payload))
          })
          .catch(() => {
            lost = true
          })
      },
      queue === 'maintenance' ? OTTER_LEASE_SWEEP_MS : 20_000,
    )
    // The drain and the main loop share the fence; Payload claims each job atomically, so the two
    // runners cannot take the same job. Reclassifications stay quick even while the weekly
    // maintenance job downloads vulnerability feeds for many minutes. Ownership loss aborts the
    // drain with a guarded fence error; the supervisor restarts the whole worker.
    if (queue === 'maintenance')
      drainReapplyJobs(payload, fence, signal, () => lost || stopped).catch((error) =>
        payload.logger.warn({
          event: 'worker.reapply-drain-stopped',
          error: safeFailure(error),
        }),
      )
    while (!signal.aborted && !lost) {
      if (queue === 'maintenance') {
        await scheduleMaintenance(payload, fence)
        if (Date.now() >= nextReleaseCheck) {
          await withWorkerFence(fence, () => scheduleOtterReleaseSync(payload))
          nextReleaseCheck = Date.now() + 60_000
        }
      }
      await withWorkerFence(fence, () =>
        payload.jobs.run({
          queue,
          limit: 1,
          sequential: true,
          processingOrder: 'createdAt',
          silent: true,
          where: queue === 'maintenance' ? { taskSlug: { not_equals: REAPPLY_TASK } } : undefined,
        }),
      )
      await delay(1000, undefined, { signal }).catch(() => {})
    }
    if (lost) throw new Error('Worker heartbeat failed; ownership must be recovered.')
  } catch (error) {
    payload.logger.error({ event: 'worker.stopped', queue, error: safeFailure(error) })
    throw error
  } finally {
    // Ends the drain loop when this worker run exits for any reason; the supervisor restarts it.
    stopped = true
    if (timer) clearInterval(timer)
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
