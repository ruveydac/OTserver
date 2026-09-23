import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { APIError, type Payload, type PayloadHandler, type PayloadRequest } from 'payload'
import { getAuthorization, relationshipID } from '../access/authorization'
import { inTransaction } from '../integrations/payload/transactions'
import { withRequestContext } from '../integrations/payload/context'
import { processImport } from './processImport'
import { safeFailure, transientFailure } from '../jobs/errors'
import type { AssetImport } from '../payload-types'
import { principalRequest, systemRequest } from '../integrations/payload/requests'

export const queuedImportsEnabled = () => process.env.OTSERVER_QUEUED_IMPORTS === 'on'
export const fileDigest = (data: Buffer) => createHash('sha256').update(data).digest('hex')
const internalImportFields = [
  'jobID',
  'submittedBy',
  'executorID',
  'retriedBy',
  'fileDigest',
  'processingInput',
] as const

const publicImport = (doc: AssetImport): AssetImport => {
  const result = { ...doc }
  for (const field of internalImportFields) delete result[field]
  return result
}

export const requireSiteWriter = async (site: unknown, req: PayloadRequest) => {
  const access = await getAuthorization(req)
  if (
    !req.user ||
    (!access.isAdmin && !access.writableSiteIDs.includes(String(relationshipID(site))))
  )
    throw new APIError('Site write permission is required.', 403)
}

export const queueImport = async (doc: AssetImport, req: PayloadRequest) => {
  const job = await req.payload.jobs.queue({
    task: 'import-v1',
    queue: 'imports',
    input: { version: 1, importID: doc.id },
    req,
  })
  const updated = await withRequestContext(req, { importWrite: true, skipAssetImport: true }, () =>
    req.payload.update({
      collection: 'asset-imports',
      id: doc.id,
      data: { jobID: String(job.id) },
      // The caller already passed collection create/retry authorization. Only this server field is
      // written with elevated access, using the original request for hooks, audit, and transaction.
      overrideAccess: true,
      req,
    }),
  )
  return publicImport(updated)
}

export const retryImport: PayloadHandler = async (req) => {
  if (!queuedImportsEnabled()) throw new APIError('Queued imports are not enabled.', 503)
  const id = String(req.routeParams?.id || '')
  const doc = await inTransaction(req, async () => {
    const previous = await req.payload.findByID({
      collection: 'asset-imports',
      id,
      depth: 0,
      overrideAccess: false,
      req,
    })
    await requireSiteWriter(previous.site, req)
    if (previous.executionMode !== 'queued' || previous.status !== 'failed')
      throw new APIError('Only failed queued imports can be retried.', 409)
    return withRequestContext(req, { importWrite: true, skipAssetImport: true }, async () => {
      const pending = await req.payload.update({
        collection: 'asset-imports',
        id,
        overrideAccess: true,
        req,
        data: {
          status: 'pending',
          executorID: String(req.user!.id),
          retriedBy: String(req.user!.id),
          error: null,
          completedAt: null,
          queuedAt: new Date().toISOString(),
        },
      })
      return queueImport(pending, req)
    })
  })
  return Response.json({ doc })
}

export const executeQueuedImport = async (
  payload: Payload,
  importID: string,
  jobID: string,
  retry: number,
) => {
  const systemReq = await systemRequest(payload, { importWrite: true, skipAssetImport: true })
  const doc = await payload.findByID({
    collection: 'asset-imports',
    id: importID,
    depth: 0,
    req: systemReq,
  })
  if (doc.status === 'completed' || String(doc.jobID) !== jobID) return
  if (doc.status === 'failed') throw new APIError('Import already failed.', 400)
  const start = Date.now()
  try {
    if (doc.executionMode !== 'queued') throw new APIError('Invalid processing mode.', 400)
    const user = await payload.findByID({
      collection: 'users',
      id: doc.executorID || '',
      depth: 0,
      disableErrors: true,
    })
    if (!user) throw new APIError('Executing user is missing.', 403)
    const req = await principalRequest(
      payload,
      { ...user, collection: 'users' },
      {
        importWrite: true,
        skipAssetImport: true,
      },
    )
    await requireSiteWriter(doc.site, req)
    await payload.update({
      collection: 'asset-imports',
      id: doc.id,
      req,
      overrideAccess: false,
      data: {
        status: 'running',
        startedAt: new Date().toISOString(),
        attemptCount: (doc.attemptCount || 0) + 1,
        error: null,
      },
    })
    const directory = path.resolve(payload.collections['asset-imports'].config.upload.staticDir!)
    if (!doc.filename || path.basename(doc.filename) !== doc.filename)
      throw new APIError('Invalid stored upload.', 400)
    const bytes = await readFile(path.join(directory, doc.filename))
    if (fileDigest(bytes) !== doc.fileDigest) throw new APIError('Upload digest mismatch.', 400)
    const input = doc.processingInput as
      { version?: number; site?: string; source?: string } | undefined
    if (
      input?.version !== 1 ||
      input.site !== relationshipID(doc.site) ||
      input.source !== doc.source
    )
      throw new APIError('Unsupported import inputs.', 400)
    // Recheck current user and authorization in each attempt, then commit all inventory and completion together.
    await inTransaction(req, async () => {
      const current = await payload.findByID({
        collection: 'asset-imports',
        id: doc.id,
        depth: 0,
        req,
        // Current site permission was rechecked immediately above. This narrow internal read is
        // required to compare the concealed job ID before any inventory mutation.
        overrideAccess: true,
      })
      if (current.status === 'completed') return
      if (current.status !== 'running' || current.jobID !== jobID)
        throw new APIError('Import state changed.', 409)
      await processImport({ doc: current, data: bytes, req, throwValidationErrors: true })
      await payload.update({
        collection: 'asset-imports',
        id: doc.id,
        req,
        overrideAccess: false,
        data: { completedAt: new Date().toISOString() },
      })
    })
    payload.logger.info({
      event: 'import.completed',
      importID,
      jobID,
      attempt: (doc.attemptCount || 0) + 1,
      durationMs: Date.now() - start,
    })
  } catch (error) {
    const transient = transientFailure(error) && retry < 2
    const details = safeFailure(error)
    // This is deliberately outside the failed inventory transaction. No credentials or request are persisted.
    await payload.update({
      collection: 'asset-imports',
      id: doc.id,
      req: systemReq,
      data: {
        status: transient ? 'pending' : 'failed',
        error: details,
        ...(transient ? {} : { completedAt: new Date().toISOString() }),
      },
    })
    payload.logger.warn({
      event: 'import.failed',
      importID,
      jobID,
      attempt: (doc.attemptCount || 0) + 1,
      durationMs: Date.now() - start,
      error: details,
    })
    if (transient) throw new Error(details)
    throw new APIError(details, 400)
  }
}
