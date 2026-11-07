import type { MigrateDownArgs, MigrateUpArgs } from '@payloadcms/db-mongodb'

const activeIndex = 'otter_update_one_active_per_scanner'

export async function up({ payload }: MigrateUpArgs): Promise<void> {
  await payload.db.collections['otter-updates'].collection.createIndex(
    { scanner: 1 },
    {
      name: activeIndex,
      partialFilterExpression: {
        status: { $in: ['queued', 'downloading', 'verified', 'installing'] },
      },
      unique: true,
    },
  )
}

export async function down({ payload }: MigrateDownArgs): Promise<void> {
  await payload.db.collections['otter-updates'].collection.dropIndex(activeIndex)
}
