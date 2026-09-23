import { APIError, type PayloadHandler } from 'payload'
import { getAuthorization } from '../access/authorization'

export const workerDiagnostics: PayloadHandler = async (req) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
  const queues = []
  for (const queue of ['imports', 'maintenance']) {
    const where = { queue: { equals: queue } }
    const [heartbeats, pending, failed] = await Promise.all([
      req.payload.find({ collection: 'worker-heartbeats', where, depth: 0, limit: 1 }),
      req.payload.find({
        collection: 'payload-jobs',
        depth: 0,
        limit: 1,
        sort: 'createdAt',
        where: {
          and: [where, { completedAt: { exists: false } }, { hasError: { not_equals: true } }],
        },
      }),
      req.payload.count({
        collection: 'payload-jobs',
        where: { and: [where, { hasError: { equals: true } }] },
      }),
    ])
    const heartbeat = heartbeats.docs[0]
    queues.push({
      queue,
      heartbeatAt: heartbeat?.heartbeatAt || null,
      healthy: Boolean(heartbeat && Date.parse(heartbeat.expiresAt) > Date.now()),
      oldestPendingAt: pending.docs[0]?.createdAt || null,
      queueAgeSeconds: pending.docs[0]
        ? Math.max(0, (Date.now() - Date.parse(pending.docs[0].createdAt)) / 1000)
        : 0,
      pending: pending.totalDocs,
      failed: failed.totalDocs,
    })
  }
  const feeds = await req.payload.find({
    collection: 'vulnerability-feeds',
    limit: 10,
    depth: 0,
    select: { source: true, lastSyncedAt: true, status: true },
  })
  const maintenance = await req.payload.find({
    collection: 'worker-leases',
    limit: 1,
    where: { queue: { equals: 'maintenance' } },
  })
  return Response.json(
    {
      queues,
      feeds: feeds.docs,
      lastSuccessfulMaintenanceAt: maintenance.docs[0]?.lastSuccessAt || null,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  )
}

export const readiness: PayloadHandler = async (req) => {
  try {
    await req.payload.find({
      collection: 'worker-leases',
      limit: 1,
      depth: 0,
      select: { queue: true },
    })
    return Response.json({ ready: true }, { headers: { 'Cache-Control': 'no-store' } })
  } catch {
    return Response.json(
      { ready: false },
      { status: 503, headers: { 'Cache-Control': 'no-store' } },
    )
  }
}
