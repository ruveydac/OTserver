import type { MigrateUpArgs } from '@payloadcms/db-mongodb'
import { initializeSiteTypes } from '../collections/SiteTypes'
import { writeMigrationAudit } from './20261013_130000_legacy_identity'

export async function up(args: MigrateUpArgs): Promise<void> {
  const { payload, req, session } = args
  await initializeSiteTypes(payload, req)
  const types = await payload.find({
    collection: 'site-types',
    depth: 0,
    limit: 1,
    pagination: false,
    overrideAccess: true,
    req,
    where: { key: { equals: 'to-be-changed' } },
  })
  const type = types.docs[0]!
  const ObjectId = payload.db.connection.base.Types.ObjectId
  const sites = payload.db.collections.sites.collection
  const cursor = sites.find({ $or: [{ type: { $type: 'string' } }, { type: null }] }, { session })
  for await (const site of cursor) {
    const id = String(site._id)
    await sites.updateOne({ _id: site._id }, { $set: { type: new ObjectId(type.id) } }, { session })
    await writeMigrationAudit(args, {
      before: { id, name: site.name, type: site.type },
      after: { id, name: site.name, type: type.id },
      siteID: id,
      targetCollection: 'sites',
    })
  }
}

export async function down(): Promise<void> {
  throw new Error(
    'Site-type migration is not reversible; restore a database backup to recover free-text types.',
  )
}
