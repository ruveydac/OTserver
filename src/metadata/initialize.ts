import type { Payload } from 'payload'
import { metadataGroups } from './catalog'
import { systemRequest } from '../integrations/payload/requests'
import { inTransaction } from '../integrations/payload/transactions'
import { transientFailure } from '../jobs/errors'
import { setTimeout as delay } from 'node:timers/promises'
import { activeCatalog } from './runtime'
import { queueAssetTagReapply } from '../tags/assign'

const initializeCatalog = async (payload: Payload) => {
  const revisionHash = (await activeCatalog(payload)).revision
  const query = {
    collection: 'asset-classes',
    depth: 0,
    pagination: false,
    overrideAccess: true,
  } as const
  const initial = await payload.find(query)
  const keys = new Set(['plc', 'hmi', 'rtu', 'network-device', 'sensor-actuator'])
  const needsMapping = initial.docs.some(
    (item) => item.legacyKey && keys.has(item.legacyKey) && !item.catalogMappingSeeded,
  )
  const revision = initial.docs.find(({ legacyKey }) => legacyKey === 'other')
  if (!needsMapping && (!revision || revision.catalogRevision === revisionHash)) return
  const req = await systemRequest(payload, { assetClassRuleSeed: true })
  await inTransaction(req, async () => {
    const classes = await payload.find({ ...query, req })
    for (const item of classes.docs) {
      if (!item.legacyKey || !keys.has(item.legacyKey) || item.catalogMappingSeeded) continue
      const group = metadataGroups.find(({ key }) => key === item.legacyKey)!
      await payload.update({
        collection: 'asset-classes',
        id: item.id,
        overrideAccess: true,
        req,
        context: { assetClassRuleSeed: true },
        data: {
          catalogMappingSeeded: true,
          catalogGroups: item.catalogGroups?.length
            ? item.catalogGroups
            : [group.id as NonNullable<typeof item.catalogGroups>[number]],
        },
      })
    }
    const marker = classes.docs.find(({ legacyKey }) => legacyKey === 'other')
    if (!marker || marker.catalogRevision === revisionHash) return
    await payload.update({
      collection: 'asset-classes',
      id: marker.id,
      overrideAccess: true,
      req,
      context: { assetClassRuleSeed: true },
      data: { catalogRevision: revisionHash },
    })
    await payload.jobs.queue({
      task: 'reapply-asset-classes-v1',
      queue: 'maintenance',
      req,
      input: { version: 1, assetClassID: marker.id, catalogRevision: revisionHash },
    })
    await queueAssetTagReapply(req)
  })
}

export const initializeMetadataCatalog = async (payload: Payload) => {
  for (let attempt = 0; ; attempt++) {
    try {
      return await initializeCatalog(payload)
    } catch (error) {
      if (attempt >= 2 || !transientFailure(error)) throw error
      await delay(100 * 2 ** attempt)
    }
  }
}
