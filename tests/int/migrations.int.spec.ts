import config from '@/payload.config'
import { siteTypeID } from '../siteType'
import { randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { createLocalReq, getPayload, type Payload } from 'payload'
import { ensureAssetClass, initializeAssetClasses } from '../../src/collections/AssetClasses'
import { ensureAdminRole, initializeAuthorization } from '../../src/collections/UserRoles'
import { migrations } from '../../src/migrations'

let payload: Payload
const otterProtocolDefaults = migrations.find(
  ({ name }) => name === '20261121_150000_otter_protocol_defaults',
)!
const legacyMigrations = migrations.filter((migration) => migration !== otterProtocolDefaults)

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
      await payload.db.collections.assets.collection.updateOne(
        { _id: new ObjectId(asset.id) },
        {
          $set: {
            assetType: 'plc',
            criticality: 'low',
            fieldProvenance: { assetType: { quality: 'medium', source: 'nmap' } },
          },
          $unset: { assetClass: '' },
        },
      )
      expect(
        await payload.db.collections.assets.collection.findOne(
          { _id: new ObjectId(asset.id) },
          { projection: { criticality: 1 } },
        ),
      ).toMatchObject({ criticality: 'low' })
      expect(
        await payload.db.collections.tags.collection.findOne({ systemKey: 'criticality-low' }),
      ).not.toBeNull()
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

      await payload.db.migrate({ migrations: legacyMigrations as never })
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
      await payload.db.migrate({ migrations: legacyMigrations as never })

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
      const lowTag = await payload.find({
        collection: 'tags',
        depth: 0,
        limit: 1,
        where: { systemKey: { equals: 'criticality-low' } },
      })
      expect(migratedAsset).not.toHaveProperty('criticality')
      expect((migratedAsset!.manualTags as unknown[]).map(String)).toContain(lowTag.docs[0]!.id)
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
      const reviewIndexes = migrations.find(
        ({ name }) => name === '20261019_120000_asset_vulnerability_reviews',
      )!
      await reviewIndexes.down(migrationArgs as never)
      await reviewIndexes.up(migrationArgs as never)
      const siteTypes = migrations.find(({ name }) => name === '20261018_120000_site_types')!
      await expect(siteTypes.down({} as never)).rejects.toThrow('not reversible')
    } finally {
      await payload.delete({ collection: 'assets', id: asset.id })
      await payload.delete({ collection: 'users', id: user.id })
      await payload.delete({ collection: 'sites', id: childSite.id })
      await payload.delete({ collection: 'sites', id: site.id })
    }
  })
})

describe('Otter protocol defaults migration', () => {
  it('disables only unset protocols and lets operators opt in after the upgrade', async () => {
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Otter defaults ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    const scanner = await payload.create({
      collection: 'otter-scanners',
      data: { name: 'Otter defaults', site: site.id },
    })
    const admin = await payload.create({
      collection: 'users',
      data: {
        email: `otter-migration-${randomUUID()}@example.test`,
        name: 'Otter migration admin',
        password: randomUUID(),
        role: (await ensureAdminRole(payload)).id,
      },
    })
    const profiles = payload.db.collections['otter-profiles'].collection
    const ObjectId = payload.db.connection.base.Types.ObjectId
    const targets = ['192.0.2.1']
    const legacy = await profiles.insertOne({
      configuration: { targets, noSnmp: true },
      name: 'Legacy configuration',
      scanner: new ObjectId(scanner.id),
      site: new ObjectId(site.id),
    })
    const mixed = await profiles.insertOne({
      configuration: { targets, noIoLink: null, noCdp: false },
      name: 'Existing CDP choice',
      scanner: new ObjectId(scanner.id),
      site: new ObjectId(site.id),
    })
    const explicit = await profiles.insertOne({
      configuration: { targets, noIoLink: false, noCdp: true },
      name: 'Existing protocol choices',
      scanner: new ObjectId(scanner.id),
      site: new ObjectId(site.id),
    })
    const ids = [legacy.insertedId, mixed.insertedId, explicit.insertedId]
    try {
      await payload.db.migrate({ migrations: [otterProtocolDefaults] as never })
      for (const [index, expected] of [
        { targets, noSnmp: true, noIoLink: true, noCdp: true },
        { targets, noIoLink: true, noCdp: false },
        { targets, noIoLink: false, noCdp: true },
      ].entries()) {
        expect(
          await payload.findByID({
            collection: 'otter-profiles',
            id: String(ids[index]),
            depth: 0,
          }),
        ).toMatchObject({ configuration: expected })
      }
      const audit = await payload.find({
        collection: 'audit-logs',
        depth: 0,
        where: { targetCollection: { equals: 'otter-profiles' }, site: { equals: site.id } },
      })
      expect(audit.totalDocs).toBe(2)
      expect(audit.docs).toContainEqual(
        expect.objectContaining({
          actorName: 'Versioned migration',
          documentID: String(legacy.insertedId),
          changes: { configuration: { before: {}, after: { noIoLink: true, noCdp: true } } },
        }),
      )

      await payload.update({
        collection: 'otter-profiles',
        id: String(legacy.insertedId),
        data: { configuration: { targets, noIoLink: false } },
        user: admin,
      })
      await payload.db.migrate({ migrations: [otterProtocolDefaults] as never })
      expect(await profiles.findOne({ _id: legacy.insertedId })).toMatchObject({
        configuration: { noIoLink: false, noCdp: true, noSnmp: true },
      })
      const fresh = await payload.create({
        collection: 'otter-profiles',
        data: {
          configuration: { targets },
          name: 'New configuration',
          scanner: scanner.id,
          site: site.id,
        },
        user: admin,
      })
      ids.push(new ObjectId(fresh.id))
      expect(fresh.configuration).toMatchObject({ noIoLink: false, noCdp: false })
    } finally {
      await profiles.deleteMany({ _id: { $in: ids } })
      await payload.delete({ collection: 'users', id: admin.id })
      await payload.delete({ collection: 'otter-scanners', id: scanner.id })
      await payload.delete({ collection: 'sites', id: site.id })
    }
  })
})
