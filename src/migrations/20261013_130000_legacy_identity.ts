import type { MigrateUpArgs } from '@payloadcms/db-mongodb'
import { ensureAssetClass } from '../collections/AssetClasses'
import { getAuditChanges } from '../collections/AuditLogs'
import { ensureAdminRole } from '../collections/UserRoles'

type LegacyAsset = {
  _id: unknown
  assetType?: unknown
  fieldProvenance?: unknown
  name?: unknown
  site?: unknown
}
type LegacyUser = { _id: unknown; email?: unknown; name?: unknown }

export const writeMigrationAudit = async (
  { payload, req, session }: MigrateUpArgs,
  {
    after,
    assetID,
    before,
    siteID,
    targetCollection,
  }: {
    after: Record<string, unknown>
    assetID?: string
    before: Record<string, unknown>
    siteID?: string
    targetCollection: string
  },
) => {
  const ObjectId = payload.db.connection.base.Types.ObjectId
  const id = String(after.id)
  const label = [after.name, after.title, after.label, after.email, after.filename].find(
    (value) => typeof value === 'string' && value,
  ) as string | undefined
  const now = new Date()
  const ipAddress = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  await payload.db.collections['audit-logs'].collection.insertOne(
    {
      _id: new ObjectId(),
      action: 'update',
      ...(siteID ? { site: new ObjectId(siteID) } : {}),
      summary: `update ${targetCollection}${label ? `: ${label}` : ` ${id}`}`,
      targetCollection,
      documentID: id,
      ...(label ? { documentLabel: label } : {}),
      ...(assetID ? { asset: new ObjectId(assetID), assetID } : {}),
      actorType: 'system',
      actorName: 'Versioned migration',
      ...(ipAddress ? { ipAddress } : {}),
      requestMethod: req.method,
      ...(req.url ? { requestPath: new URL(req.url, 'http://local').pathname } : {}),
      changes: getAuditChanges(before, after),
      createdAt: now,
      updatedAt: now,
    },
    { session },
  )
}

export async function up({ payload, req, session }: MigrateUpArgs): Promise<void> {
  const adminRole = await ensureAdminRole(payload, req)
  const users = (await payload.db.collections.users.collection
    .find({ role: { $exists: false } }, { projection: { _id: 1, email: 1, name: 1 }, session })
    .toArray()) as LegacyUser[]
  // Migration writes use the active session directly and record audit entries in the same transaction.
  for (const user of users) {
    const id = String(user._id)
    const updated = await payload.db.collections.users.collection.updateOne(
      { _id: user._id as never, role: { $exists: false } },
      {
        $set: {
          role: new payload.db.connection.base.Types.ObjectId(adminRole.id),
        },
      },
      { session },
    )
    if (updated.modifiedCount)
      await writeMigrationAudit(
        { payload, req, session },
        {
          after: { email: user.email, id, name: user.name, role: adminRole.id },
          before: { email: user.email, id, name: user.name },
          targetCollection: 'users',
        },
      )
  }

  const assets = (await payload.db.collections.assets.collection
    .find(
      { assetClass: { $exists: false } },
      { projection: { _id: 1, assetType: 1, fieldProvenance: 1, name: 1, site: 1 }, session },
    )
    .toArray()) as LegacyAsset[]
  for (const asset of assets) {
    const key = typeof asset.assetType === 'string' ? asset.assetType : 'other'
    const assetClass = await ensureAssetClass(payload, key, req)
    const existing = asset.fieldProvenance
    const fieldProvenance: Record<string, unknown> =
      existing && typeof existing === 'object' && !Array.isArray(existing)
        ? { ...(existing as Record<string, unknown>) }
        : {}
    if (fieldProvenance.assetType && !fieldProvenance.assetClass)
      fieldProvenance.assetClass = fieldProvenance.assetType
    delete fieldProvenance.assetType

    const id = String(asset._id)
    const siteID = String(asset.site || '')
    const before = {
      id,
      name: asset.name,
      assetType: asset.assetType,
      fieldProvenance: existing,
    }
    const updated = await payload.db.collections.assets.collection.updateOne(
      { _id: asset._id as never, assetClass: { $exists: false } },
      {
        $set: {
          assetClass: new payload.db.connection.base.Types.ObjectId(assetClass.id),
          assetType: null,
          fieldProvenance,
        },
      },
      { session },
    )
    if (updated.modifiedCount)
      await writeMigrationAudit(
        { payload, req, session },
        {
          after: { ...before, assetClass: assetClass.id, assetType: null, fieldProvenance },
          before,
          assetID: id,
          siteID,
          targetCollection: 'assets',
        },
      )
  }
}

export async function down(): Promise<void> {
  throw new Error(
    'Legacy asset classification and Admin-role migration is not reversible; restore a database backup to roll back.',
  )
}
