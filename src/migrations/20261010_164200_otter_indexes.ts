import type { MigrateDownArgs, MigrateUpArgs } from '@payloadcms/db-mongodb'

const indexNames = [
  'otter_run_schedule_occurrence_unique',
  'otter_scanner_credential_unique',
  'otter_scanner_enrollment_unique',
]

export async function up({ payload }: MigrateUpArgs): Promise<void> {
  await payload.db.collections['otter-runs'].collection.createIndex(
    { scheduleOccurrenceKey: 1 },
    {
      name: indexNames[0],
      partialFilterExpression: { scheduleOccurrenceKey: { $type: 'string' } },
      unique: true,
    },
  )
  await payload.db.collections['otter-scanners'].collection.createIndex(
    { credentialHash: 1 },
    {
      name: indexNames[1],
      partialFilterExpression: { credentialHash: { $type: 'string' } },
      unique: true,
    },
  )
  await payload.db.collections['otter-scanners'].collection.createIndex(
    { enrollmentTokenHash: 1 },
    {
      name: indexNames[2],
      partialFilterExpression: { enrollmentTokenHash: { $type: 'string' } },
      unique: true,
    },
  )
}

export async function down({ payload }: MigrateDownArgs): Promise<void> {
  for (const name of indexNames)
    await (
      name === indexNames[0]
        ? payload.db.collections['otter-runs'].collection
        : payload.db.collections['otter-scanners'].collection
    ).dropIndex(name)
}
