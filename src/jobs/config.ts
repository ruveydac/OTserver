import { JobCancelledError, type JobsConfig } from 'payload'
import { adminOnly, hideFromNonAdmins } from '../access/authorization'
import { withAudit } from '../collections/AuditLogs'
import { executeQueuedImport } from '../application/queuedImports'
import { runMaintenance } from './maintenance'
import { safeFailure, transientFailure } from './errors'
import { currentWorker } from '../integrations/payload/workerContext'

export const jobs: JobsConfig = {
  access: { run: () => false, queue: () => false, cancel: () => false },
  autoRun: [],
  deleteJobOnComplete: false,
  // Payload's queue engine writes atomic operators such as `{ log: { $push: entry } }`.
  // Routing those internal writes through collection hooks makes the local API validate the
  // operator object as a Log value and rejects failed-job bookkeeping. Application-level job
  // effects remain audited; the generated jobs collection is operational metadata.
  runHooks: false,
  jobsCollectionOverrides: ({ defaultJobsCollection }) =>
    withAudit({
      ...defaultJobsCollection,
      access: { create: () => false, update: () => false, delete: () => false, read: adminOnly },
      admin: { ...defaultJobsCollection.admin, group: 'Operations', hidden: hideFromNonAdmins },
      indexes: [
        ...(defaultJobsCollection.indexes || []),
        { fields: ['queue', 'processing', 'hasError', 'completedAt', 'createdAt'] },
      ],
    }),
  tasks: [
    {
      slug: 'import-v1',
      retries: { attempts: 2, backoff: { type: 'exponential', delay: 5000 } },
      inputSchema: [
        { name: 'version', type: 'number', required: true },
        { name: 'importID', type: 'text', required: true },
      ],
      handler: async ({ input, req, job }) => {
        if (input.version !== 1 || currentWorker()?.queue !== 'imports')
          throw new JobCancelledError('Unsupported worker input or execution context.')
        try {
          await executeQueuedImport(
            req.payload,
            input.importID,
            String(job.id),
            job.totalTried || 0,
          )
        } catch (error) {
          if ((error as { status?: number }).status === 400)
            throw new JobCancelledError((error as Error).message)
          throw error
        }
        return { output: {} }
      },
    },
    {
      slug: 'maintenance-v1',
      retries: { attempts: 2, backoff: { type: 'exponential', delay: 30_000 } },
      inputSchema: [{ name: 'version', type: 'number', required: true }],
      handler: async ({ input, req, job }) => {
        if (input.version !== 1 || currentWorker()?.queue !== 'maintenance')
          throw new JobCancelledError('Unsupported worker input or execution context.')
        const started = Date.now()
        try {
          await runMaintenance(req.payload)
        } catch (error) {
          const sanitized = safeFailure(error)
          req.payload.logger.warn({
            event: 'maintenance.failed',
            jobID: job.id,
            attempt: (job.totalTried || 0) + 1,
            durationMs: Date.now() - started,
            error: sanitized,
          })
          if (!transientFailure(error)) throw new JobCancelledError(sanitized)
          throw new Error(sanitized)
        }
        req.payload.logger.info({
          event: 'maintenance.completed',
          jobID: job.id,
          attempt: (job.totalTried || 0) + 1,
          durationMs: Date.now() - started,
        })
        return { output: {} }
      },
    },
  ],
}
