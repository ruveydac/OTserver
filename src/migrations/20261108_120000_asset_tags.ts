import type { MigrateUpArgs } from '@payloadcms/db-mongodb'

import { initializeAssetTags } from '../collections/Tags'
import { writeMigrationAudit } from './20261013_130000_legacy_identity'

type ExistingAsset = {
  _id: unknown
  criticality?: unknown
  name?: unknown
  site?: unknown
}
type ExistingTag = { _id: unknown; name: string; systemKey?: string }

export async function up(args: MigrateUpArgs): Promise<void> {
  const { payload, req, session } = args
  await initializeAssetTags(payload, req)
  const seeded = (await payload.db.collections.tags.collection
    .find(
      {
        systemKey: {
          $in: [
            'criticality-low',
            'criticality-medium',
            'criticality-high',
            'criticality-critical',
          ],
        },
      },
      { projection: { _id: 1, name: 1, systemKey: 1 }, session },
    )
    .toArray()) as ExistingTag[]
  const byCriticality = new Map(
    seeded.map((tag) => [tag.systemKey, { id: tag._id, name: tag.name }]),
  )
  const assets = (await payload.db.collections.assets.collection
    .find({}, { projection: { _id: 1, criticality: 1, name: 1, site: 1 }, session })
    .toArray()) as ExistingAsset[]

  for (const asset of assets) {
    const criticality =
      typeof asset.criticality === 'string'
        ? byCriticality.get(`criticality-${asset.criticality}`)
        : undefined
    const selected = criticality ? [criticality] : []
    const tagIDs = selected.map(({ id }) => id)
    const tagNames = selected.map(({ name }) => name)
    const id = String(asset._id)
    const siteID = String(asset.site || '')
    await payload.db.collections.assets.collection.updateOne(
      { _id: asset._id as never },
      {
        $set: {
          manualTags: tagIDs,
          tags: tagIDs,
          tagNames,
        },
        $unset: { criticality: '' },
      },
      { session },
    )
    await writeMigrationAudit(args, {
      before: { id, name: asset.name, criticality: asset.criticality },
      after: {
        id,
        name: asset.name,
        criticality: null,
        manualTags: tagNames,
        tags: tagNames,
      },
      assetID: id,
      siteID,
      targetCollection: 'assets',
    })
  }
}

export async function down(): Promise<void> {
  throw new Error(
    'Asset-tag migration removes the criticality field; restore a database backup to recover it.',
  )
}
