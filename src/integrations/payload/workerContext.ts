import { AsyncLocalStorage } from 'node:async_hooks'
import { createLocalReq, type Payload, type PayloadRequest } from 'payload'
import { inTransaction } from './transactions'

export type WorkerFence = {
  queue: string
  owner: string
  assert: (req: PayloadRequest) => Promise<void>
}
const execution = new AsyncLocalStorage<WorkerFence>()
export const withWorkerFence = <T>(fence: WorkerFence, work: () => Promise<T>) =>
  execution.run(fence, work)
export const currentWorker = () => execution.getStore()

export const guardWorkerWrite = async (req: PayloadRequest) => {
  const fence = currentWorker()
  if (!fence) return
  const transaction = await req.transactionID
  if (transaction && req.context.workerFenceTransaction === transaction) return
  await fence.assert(req)
  if (transaction) req.context.workerFenceTransaction = transaction
}

// Native catalog writes participate in the same fencing transaction as the ownership check.
export const catalogWrite = async <T>(
  payload: Payload,
  work: (req?: PayloadRequest) => Promise<T>,
) => {
  if (!currentWorker()) return work()
  const req = await createLocalReq({}, payload)
  return inTransaction(req, async () => {
    await guardWorkerWrite(req)
    return work(req)
  })
}
