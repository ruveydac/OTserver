import config from '@/payload.config'
import { siteTypeID } from '../siteType'
import { randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { createLocalReq, getPayload, type Payload } from 'payload'
import { ensureAssetClass, initializeAssetClasses } from '../../src/collections/AssetClasses'
import { ensureAdminRole, initializeAuthorization } from '../../src/collections/UserRoles'
import { migrations } from '../../src/migrations'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})

describe('versioned legacy identity migration', () => {
  it('leaves legacy rows unchanged at startup and migrates populated rows explicitly', async () => {
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Legacy migration ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    const childSite = await payload.create({
      collection: 'sites',
      data: {
        name: `Legacy child ${randomUUID()}`,
        parent: site.id,
        type: await siteTypeID(payload),
      },
    })
    const adminRole = await ensureAdminRole(payload)
    const user = await payload.create({
      collection: 'users',
      data: {
        email: `legacy-migration-${randomUUID()}@example.test`,
        name: 'Legacy user',
        password: randomUUID(),
        role: adminRole.id,
      },
    })
    const initialClass = await ensureAssetClass(payload, 'other')
    const asset = await payload.create({
      collection: 'assets',
      data: {
        assetClass: initialClass.id,
        criticality: 'low',
        name: 'Legacy PLC',
        site: site.id,
        status: 'unknown',
      },
    })

    try {
      const ObjectId = payload.db.connection.base.Types.ObjectId
      for (const [id, type] of [
        [site.id, 'Plant'],
        [childSite.id, 'Bespoke work cell'],
      ]) {
        await payload.db.collections.sites.collection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { type } },
        )
      }
      await payload.db.collections.users.updateOne({ _id: user.id }, { $unset: { role: '' } })
      await payload.db.collections.assets.updateOne(
        { _id: asset.id },
        {
          $set: {
            assetType: 'plc',
            fieldProvenance: { assetType: { quality: 'medium', source: 'nmap' } },
          },
          $unset: { assetClass: '' },
        },
      )
      await initializeAssetClasses(payload)
      await initializeAuthorization(payload)
      const legacyAsset = (await payload.db.collections.assets
        .findById(asset.id)
        .select({ assetClass: 1 })
        .lean()) as unknown as Record<string, unknown> | null
      const legacyUser = (await payload.db.collections.users
        .findById(user.id)
        .select({ role: 1 })
        .lean()) as unknown as Record<string, unknown> | null
      expect(legacyAsset).not.toHaveProperty('assetClass')
      expect(legacyUser).not.toHaveProperty('role')

      await payload.db.migrate({ migrations: migrations as never })
      const fallbackType = await siteTypeID(payload, 'to-be-changed')
      for (const id of [site.id, childSite.id]) {
        const migratedSite = await payload.findByID({ collection: 'sites', id, depth: 0 })
        expect(migratedSite.type).toBe(fallbackType)
        expect(migratedSite).not.toHaveProperty('legacyType')
      }
      const siteAudit = await payload.find({
        collection: 'audit-logs',
        where: {
          and: [
            { targetCollection: { equals: 'sites' } },
            { documentID: { equals: childSite.id } },
            { actorName: { equals: 'Versioned migration' } },
          ],
        },
      })
      expect(siteAudit.docs[0]).toMatchObject({
        site: childSite.id,
        changes: { type: { before: 'Bespoke work cell', after: fallbackType } },
      })
      await payload.db.migrate({ migrations: migrations as never })

      const migratedAsset = (await payload.db.collections.assets
        .findById(asset.id)
        .lean()) as unknown as Record<string, unknown> | null
      const migratedUser = (await payload.db.collections.users
        .findById(user.id)
        .lean()) as unknown as Record<string, unknown> | null
      expect(migratedAsset).not.toBeNull()
      expect(migratedUser).not.toBeNull()
      expect(String(migratedAsset!.assetClass)).toBe((await ensureAssetClass(payload, 'plc')).id)
      expect(migratedAsset!.fieldProvenance).toMatchObject({
        assetClass: { quality: 'medium', source: 'nmap' },
      })
      expect(migratedAsset!.assetType).toBeFalsy()
      expect(String(migratedUser?.role)).toBe(adminRole.id)
      const auditCount = await payload.count({
        collection: 'audit-logs',
        where: {
          and: [{ targetCollection: { equals: 'assets' } }, { documentID: { equals: asset.id } }],
        },
      })
      expect(auditCount.totalDocs).toBeGreaterThan(0)
      const migrationArgs = {
        payload,
        req: await createLocalReq({}, payload),
        session: undefined,
      }
      const baseline = migrations[0]!
      await baseline.up(migrationArgs as never)
      await baseline.down(migrationArgs as never)
      await baseline.up(migrationArgs as never)

      const sitePaths = migrations[1]!
      await payload.db.collections.sites.updateOne(
        { _id: childSite.id },
        { $set: { parent: childSite.id } },
      )
      await expect(sitePaths.up(migrationArgs as never)).rejects.toThrow(
        'Cannot migrate cyclic site hierarchy.',
      )
      await payload.db.collections.sites.updateOne(
        { _id: childSite.id },
        { $set: { parent: site.id } },
      )
      await sitePaths.up(migrationArgs as never)
      await sitePaths.down(migrationArgs as never)
      await sitePaths.up(migrationArgs as never)

      const otterIndexes = migrations[2]!
      await otterIndexes.down(migrationArgs as never)
      await otterIndexes.up(migrationArgs as never)
      const reviewIndexes = migrations.at(-1)!
      await reviewIndexes.down(migrationArgs as never)
      await reviewIndexes.up(migrationArgs as never)
      await expect(migrations.at(-2)!.down({} as never)).rejects.toThrow('not reversible')
    } finally {
      await payload.delete({ collection: 'assets', id: asset.id })
      await payload.delete({ collection: 'users', id: user.id })
      await payload.delete({ collection: 'sites', id: childSite.id })
      await payload.delete({ collection: 'sites', id: site.id })
    }
  })
})
