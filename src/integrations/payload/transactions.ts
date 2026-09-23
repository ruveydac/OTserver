import { APIError, type PayloadRequest } from 'payload'

export const requireTransaction = async (req: PayloadRequest) => {
  if (!(await req.transactionID))
    throw new APIError(
      'Identity writes require MongoDB replica-set transactions. See docs/device-identity.md.',
      503,
    )
}

// Establish the session before Payload's parallel relationship validation issues reads.
export const primeTransaction = async (req: PayloadRequest) => {
  const transaction = await req.transactionID
  if (!transaction || req.context.startedTransaction === transaction) return
  req.context.startedTransaction = transaction
  await req.payload.find({
    collection: 'audit-logs',
    limit: 1,
    depth: 0,
    select: { action: true },
    overrideAccess: true,
    req,
  })
}

/** Join an existing transaction or own its complete commit/rollback lifecycle. */
export const inTransaction = async <T>(req: PayloadRequest, work: () => Promise<T>): Promise<T> => {
  const existing = await req.transactionID
  try {
    if (!existing) req.transactionID = (await req.payload.db.beginTransaction()) ?? undefined
    await requireTransaction(req)
    await primeTransaction(req)
    const result = await work()
    if (!existing) await req.payload.db.commitTransaction((await req.transactionID)!)
    return result
  } catch (error) {
    if (!existing && req.transactionID)
      await req.payload.db.rollbackTransaction((await req.transactionID)!)
    throw error
  } finally {
    if (!existing) {
      delete req.transactionID
      delete req.context.startedTransaction
    }
  }
}
