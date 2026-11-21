import type { MigrateUpArgs } from '@payloadcms/db-mongodb'

import { writeMigrationAudit } from './20261013_130000_legacy_identity'

export async function up(args: MigrateUpArgs): Promise<void> {
  const { payload, session } = args
  const profiles = payload.db.collections['otter-profiles'].collection
  const missing = { $or: [{ 'configuration.noIoLink': null }, { 'configuration.noCdp': null }] }

  for await (const profile of profiles.find(
    { configuration: { $type: 'object' }, ...missing },
    {
      projection: { name: 1, site: 1, 'configuration.noIoLink': 1, 'configuration.noCdp': 1 },
      session,
    },
  )) {
    const before: Record<string, unknown> = {}
    const after: Record<string, true> = {}
    for (const key of ['noIoLink', 'noCdp']) {
      const value = profile.configuration?.[key]
      if (value === undefined || value === null) {
        before[key] = value
        after[key] = true
      }
    }
    await profiles.updateOne(
      { _id: profile._id },
      { $set: Object.fromEntries(Object.keys(after).map((key) => [`configuration.${key}`, true])) },
      { session },
    )
    const subject = { id: String(profile._id), name: profile.name }
    await writeMigrationAudit(args, {
      before: { ...subject, configuration: before },
      after: { ...subject, configuration: after },
      siteID: profile.site ? String(profile.site) : undefined,
      targetCollection: 'otter-profiles',
    })
  }
}

export async function down(): Promise<void> {
  throw new Error('Otter protocol defaults are not reversible; restore a database backup.')
}
