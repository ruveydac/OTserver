import type { Payload } from 'payload'
import { syncVulnerabilityFeeds, SYNC_INTERVAL_MS } from '../vulnerabilities/feeds'
import { recountAssetVulnerabilities } from '../vulnerabilities/match'
import { systemRequest } from '../integrations/payload/requests'

export { SYNC_INTERVAL_MS }
export const TRASH_RETENTION_DAYS = 90

export const runMaintenance = async (payload: Payload) => {
  if (process.env.OTSERVER_VULNERABILITY_FEEDS !== 'off') {
    await syncVulnerabilityFeeds(payload, { force: true, failOnSourceError: true })
    // Always recount, including recovery after catalog commit but before the previous recount finished.
    await recountAssetVulnerabilities(payload)
  }
  const cutoff = new Date(Date.now() - TRASH_RETENTION_DAYS * 86_400_000).toISOString()
  for (;;) {
    const expired = await payload.find({
      collection: 'assets',
      trash: true,
      limit: 100,
      depth: 0,
      sort: 'id',
      where: { deletedAt: { less_than_equal: cutoff } },
      select: { name: true },
    })
    if (!expired.docs.length) break
    for (const asset of expired.docs)
      await payload.delete({ collection: 'assets', id: asset.id, trash: true })
  }
  const req = await systemRequest(payload)
  await payload.update({
    collection: 'worker-leases',
    where: { queue: { equals: 'maintenance' } },
    req,
    data: { lastSuccessAt: new Date().toISOString() },
  })
}
