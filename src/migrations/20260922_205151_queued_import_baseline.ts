import type { MigrateDownArgs, MigrateUpArgs } from '@payloadcms/db-mongodb'

export async function up({ payload, session }: MigrateUpArgs): Promise<void> {
  const imports = payload.db.collections['asset-imports'].collection
  await imports.updateMany(
    { executionMode: { $exists: false } },
    { $set: { executionMode: 'sync', attemptCount: 0 } },
    { session },
  )
}

export async function down({ payload, session }: MigrateDownArgs): Promise<void> {
  const imports = payload.db.collections['asset-imports'].collection
  await imports.updateMany(
    { executionMode: 'sync', jobID: { $exists: false } },
    { $unset: { executionMode: '', attemptCount: '' } },
    { session },
  )
}
