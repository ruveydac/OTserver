import {
  APIError,
  createLocalReq,
  JobCancelledError,
  type Payload,
  type PayloadHandler,
  type PayloadRequest,
} from 'payload'
import { getAuthorization } from '../access/authorization'
import { writeAudit } from '../collections/AuditLogs'
import { inTransaction } from '../integrations/payload/transactions'
import { principalRequest } from '../integrations/payload/requests'
import { inspectOffline, offlineFiles, type OfflineSelection } from './offline'
import { lockFeedOperations, syncVulnerabilityFeeds } from './feeds'
import { feedSources, normalizeCustomCsafFeeds, type FeedSource } from './sources'
import { readVulnerabilityFeedSettings } from '../application/settings'

const requireAdmin = async (req: PayloadRequest) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
}
const noUsableFiles = (selection: OfflineSelection) =>
  selection.invalid[0]
    ? `No usable feed file: ${selection.invalid[0].file}: ${selection.invalid[0].reason}`
    : 'No usable feed file was found in this selection.'
const requireOnline = () => {
  if (process.env.OTSERVER_VULNERABILITY_FEEDS === 'off')
    throw new APIError('Online feed downloads are disabled. Upload downloaded feeds instead.', 409)
}
const batchFromRequest = async (req: PayloadRequest) => {
  let data: { batchID?: unknown }
  try {
    data = (await req.json!()) as { batchID?: unknown }
  } catch {
    throw new APIError('Send a JSON upload selection.', 400)
  }
  if (
    typeof data?.batchID !== 'string' ||
    !/^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(data.batchID)
  )
    throw new APIError('Invalid upload selection ID.', 400)
  return { batchID: data.batchID }
}

export const feedControl: PayloadHandler = async (req) => {
  await requireAdmin(req)
  const settings = await readVulnerabilityFeedSettings(req.payload, req)
  const feeds = await req.payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    pagination: false,
    overrideAccess: false,
    req,
  })
  const jobs = await req.payload.find({
    collection: 'payload-jobs',
    depth: 0,
    limit: 5,
    sort: '-createdAt',
    overrideAccess: false,
    req,
    where: { taskSlug: { in: ['vulnerability-feed-sync-v1', 'maintenance-v1'] } },
  })
  return Response.json(
    {
      onlineEnabled: process.env.OTSERVER_VULNERABILITY_FEEDS !== 'off',
      automaticUpdates: settings.automaticUpdates,
      pullIntervalDays: settings.pullIntervalDays,
      customCsafFeeds: settings.customCsafFeeds,
      feeds: feeds.docs,
      jobs: jobs.docs.map((job) => ({
        id: job.id,
        processing: job.processing,
        completedAt: job.completedAt,
        hasError: job.hasError,
      })),
    },
    { headers: { 'Cache-Control': 'no-store' } },
  )
}

export const checkOffline: PayloadHandler = async (req) => {
  await requireAdmin(req)
  try {
    const { batchID } = await batchFromRequest(req)
    return Response.json((await inspectOffline(req, batchID)).selection)
  } catch (error) {
    throw new APIError(
      error instanceof Error ? error.message : 'Could not check the uploaded files.',
      400,
    )
  }
}

const queueFeedUpdate = async (
  req: PayloadRequest,
  offline?: Awaited<ReturnType<typeof inspectOffline>>,
) => {
  const source = offline?.selection.source
  // Both enqueue paths contend on the same catalog document. Worker fencing serializes execution.
  try {
    return await inTransaction(req, async () => {
      await lockFeedOperations(req)
      if (offline) await offlineFiles(req, offline.selection.batchID, offline.uploadIDs)
      const pending = await req.payload.find({
        collection: 'payload-jobs',
        depth: 0,
        limit: 1,
        overrideAccess: false,
        req,
        where: {
          and: [
            { completedAt: { exists: false } },
            { hasError: { not_equals: true } },
            ...(offline
              ? [
                  { taskSlug: { equals: 'vulnerability-feed-sync-v1' } },
                  { 'input.batchID': { equals: offline.selection.batchID } },
                ]
              : [
                  {
                    or: [
                      { taskSlug: { equals: 'maintenance-v1' } },
                      {
                        and: [
                          { taskSlug: { equals: 'vulnerability-feed-sync-v1' } },
                          { 'input.method': { equals: 'online' } },
                        ],
                      },
                    ],
                  },
                ]),
          ],
        },
      })
      if (pending.docs[0]) return pending.docs[0]
      const job = await req.payload.jobs.queue({
        task: 'vulnerability-feed-sync-v1',
        queue: 'maintenance',
        req,
        input: {
          version: 1,
          method: offline ? 'offline' : 'online',
          submittedBy: String(req.user!.id),
          ...(offline
            ? {
                batchID: offline.selection.batchID,
                source,
                uploadIDs: offline.uploadIDs,
                customCsafFeeds: offline.customCsafFeeds,
              }
            : {}),
        },
      })
      for (const selected of source ? [source] : feedSources.map(({ value }) => value)) {
        const existing = await req.payload.find({
          collection: 'vulnerability-feeds',
          depth: 0,
          limit: 1,
          overrideAccess: false,
          req,
          where: { source: { equals: selected } },
        })
        const data = {
          status: 'queued' as const,
          error: null,
          jobID: String(job.id),
          lastImportMethod: offline ? ('offline' as const) : ('online' as const),
          progress: null,
        }
        if (existing.docs[0])
          await req.payload.update({
            collection: 'vulnerability-feeds',
            id: existing.docs[0].id,
            data,
            overrideAccess: true,
            req,
          })
        else
          await req.payload.create({
            collection: 'vulnerability-feeds',
            data: { ...data, source: selected },
            overrideAccess: true,
            req,
          })
      }
      await writeAudit({
        action: 'custom',
        req,
        targetCollection: 'vulnerabilities',
        after: {
          id: 'vulnerability-catalog',
          name: 'Vulnerability feed update requested',
          jobID: String(job.id),
          method: offline ? 'offline' : 'online',
          source: source || 'all',
        },
      })
      return job
    })
  } catch (error) {
    if ([11000, 112].includes((error as { code?: number }).code || 0))
      throw new APIError(
        'Another feed request was submitted at the same time. Refresh the status and try again.',
        409,
      )
    throw error
  }
}

export const refreshFeeds: PayloadHandler = async (req) => {
  await requireAdmin(req)
  requireOnline()
  const job = await queueFeedUpdate(req)
  return Response.json({ jobID: String(job.id) }, { status: 202 })
}

const FEED_TASKS = ['vulnerability-feed-sync-v1', 'vulnerability-feed-auto-sync-v1']

export const stopFeeds: PayloadHandler = async (req) => {
  await requireAdmin(req)
  const jobs = await req.payload.find({
    collection: 'payload-jobs',
    depth: 0,
    limit: 20,
    overrideAccess: true,
    req,
    where: {
      and: [
        { taskSlug: { in: FEED_TASKS } },
        { completedAt: { exists: false } },
        { hasError: { not_equals: true } },
      ],
    },
  })
  for (const job of jobs.docs)
    await req.payload.jobs.cancelByID({ id: job.id, overrideAccess: true, req })
  const feeds = await req.payload.find({
    collection: 'vulnerability-feeds',
    depth: 0,
    limit: 10,
    overrideAccess: false,
    req,
    where: { status: { in: ['queued', 'running'] } },
  })
  for (const feed of feeds.docs)
    await req.payload.update({
      collection: 'vulnerability-feeds',
      id: feed.id,
      data: { status: 'cancelled', error: 'Stopped by the administrator.' },
      overrideAccess: true,
      req,
    })
  if (jobs.docs.length || feeds.docs.length)
    await writeAudit({
      action: 'custom',
      req,
      targetCollection: 'vulnerabilities',
      after: {
        id: 'vulnerability-catalog',
        name: 'Vulnerability feed update stopped',
        jobs: jobs.docs.map((job) => String(job.id)),
        sources: feeds.docs.map((feed) => feed.source),
      },
    })
  return Response.json({ jobs: jobs.docs.length, sources: feeds.docs.length })
}

export const importOffline: PayloadHandler = async (req) => {
  await requireAdmin(req)
  const { batchID } = await batchFromRequest(req)
  let offline: Awaited<ReturnType<typeof inspectOffline>>
  try {
    offline = await inspectOffline(req, batchID)
  } catch (error) {
    throw new APIError(
      error instanceof Error ? error.message : 'Could not check the uploaded files.',
      400,
    )
  }
  if (!offline.selection.usable) throw new APIError(noUsableFiles(offline.selection), 400)
  const job = await queueFeedUpdate(req, offline)
  return Response.json({ jobID: String(job.id) }, { status: 202 })
}

export type FeedJobInput = {
  version: number
  method: 'online' | 'offline'
  submittedBy: string
  source?: FeedSource | null
  customCsafFeeds?: unknown
  batchID?: string | null
  uploadIDs?: unknown
  skipMissing?: boolean | null
}

export const executeFeedUpdate = async (
  payload: Payload,
  input: FeedJobInput,
  jobID?: string | number,
) => {
  let req = await createLocalReq({}, payload)
  try {
    const user = await payload.findByID({
      collection: 'users',
      id: input.submittedBy,
      depth: 0,
      disableErrors: true,
    })
    if (!user)
      throw new APIError('The administrator who requested this update no longer exists.', 403)
    req = await principalRequest(payload, { ...user, collection: 'users' })
    await requireAdmin(req)
    if (input.method === 'online') {
      requireOnline()
      return await syncVulnerabilityFeeds(payload, {
        force: true,
        failOnSourceError: true,
        req,
        jobID,
      })
    }
    if (
      !input.batchID ||
      !Array.isArray(input.uploadIDs) ||
      !input.uploadIDs.length ||
      !input.uploadIDs.every((id) => typeof id === 'string')
    )
      throw new APIError('Invalid offline feed job inputs.', 400)
    const customCsafFeeds = normalizeCustomCsafFeeds(input.customCsafFeeds)
    const offlineWithSnapshot = await inspectOffline(
      req,
      input.batchID,
      input.uploadIDs as string[],
      customCsafFeeds,
    )
    if (offlineWithSnapshot.selection.source !== input.source)
      throw new APIError('The offline source changed.', 400)
    if (!offlineWithSnapshot.selection.usable)
      throw new APIError(noUsableFiles(offlineWithSnapshot.selection), 400)
    return await syncVulnerabilityFeeds(payload, {
      force: true,
      failOnSourceError: true,
      req,
      method: 'offline',
      source: offlineWithSnapshot.selection.source,
      nvdYears: offlineWithSnapshot.selection.years,
      download: offlineWithSnapshot.download,
      customCsafFeeds,
      missingFiles: offlineWithSnapshot.selection.missing,
      sourceDigest: offlineWithSnapshot.sourceDigest,
      jobID,
    })
  } catch (error) {
    const cancelled = error instanceof JobCancelledError
    const details = error instanceof Error ? error.message : 'Feed update failed.'
    for (const source of input.method === 'offline' && input.source
      ? [input.source]
      : feedSources.map(({ value }) => value)) {
      const state = await payload.find({
        collection: 'vulnerability-feeds',
        depth: 0,
        limit: 1,
        where: { source: { equals: source } },
      })
      // A cancelled sync can overwrite the stop request while it is between checkpoints.
      if (state.docs[0] && ['queued', 'running'].includes(state.docs[0].status))
        await payload.update({
          collection: 'vulnerability-feeds',
          id: state.docs[0].id,
          data: cancelled
            ? { status: 'cancelled', error: 'Stopped by the administrator.' }
            : { status: 'failed', error: details.slice(0, 4000) },
          req,
        })
    }
    if (cancelled) throw error
    await writeAudit({
      action: 'custom',
      req,
      targetCollection: 'vulnerabilities',
      after: {
        id: 'vulnerability-catalog',
        name: 'Vulnerability feed update failed',
        method: input.method,
        source: input.source || 'all',
        error: details.slice(0, 4000),
      },
    })
    throw error
  }
}
