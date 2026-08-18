import config from '@/payload.config'
import { randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import {
  createLocalReq,
  createPayloadRequest,
  getPayload,
  type Payload,
  type RequiredDataFromCollectionSlug,
} from 'payload'

import { hideFromNonAdmins } from '../../src/access/authorization'
import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { exportAssetsCSV } from '../../src/collections/AssetExport'
import { filterSiteParents } from '../../src/collections/Sites'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { buildSiteTree } from '../../src/components/SiteTreeView'

vi.mock('@payloadcms/ui', () => ({ DefaultListView: () => null }))

let payload: Payload
let otherClassID: string
let plcClassID: string

describe('asset CRUD', () => {
  beforeAll(async () => {
    payload = await getPayload({ config })
    otherClassID = (await ensureAssetClass(payload, 'other')).id
    plcClassID = (await ensureAssetClass(payload, 'plc')).id
  })

  it('creates, updates, and deletes an asset', async () => {
    const mac = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
    let assetID: string | undefined
    let secondAssetID: string | undefined
    let siteID: string | undefined
    let userID: string | undefined

    try {
      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `bulk-${randomUUID()}@example.test`,
          name: 'Bulk operation test user',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const site = await payload.create({
        collection: 'sites',
        data: { name: `CRUD site ${randomUUID()}`, type: 'Test site' },
      })
      siteID = site.id

      const asset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: plcClassID,
          criticality: 'medium',
          ipAddress: '192.0.2.10',
          macAddress: mac.replaceAll(':', '-').toLowerCase(),
          name: 'CRUD test PLC',
          site: siteID,
          status: 'unknown',
        },
      })
      assetID = asset.id

      await expect(payload.delete({ collection: 'sites', id: siteID })).rejects.toThrow(
        'Move or delete this site',
      )

      const updated = await payload.update({
        collection: 'assets',
        id: assetID,
        data: { status: 'online' },
      })
      expect(updated.status).toBe('online')
      expect(updated.macAddress).toBe(mac)

      const sameIP = await payload.create({
        collection: 'assets',
        data: {
          assetClass: otherClassID,
          criticality: 'low',
          ipAddress: '192.0.2.10',
          macAddress: `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`,
          name: 'Same IP, different MAC',
          site: siteID,
          status: 'unknown',
        },
      })
      secondAssetID = sameIP.id

      const bulkUpdate = await payload.update({
        collection: 'assets',
        data: { description: 'Bulk updated' },
        overrideAccess: false,
        user,
        where: { id: { in: [assetID, secondAssetID] } },
      })
      expect(bulkUpdate.errors).toEqual([])
      expect(bulkUpdate.docs).toHaveLength(2)
      for (const doc of bulkUpdate.docs) {
        expect(doc.description).toBe('Bulk updated')
        expect(doc.fieldProvenance).toMatchObject({
          description: { quality: 'human', source: 'human' },
        })
      }

      const bulkDelete = await payload.delete({
        collection: 'assets',
        overrideAccess: false,
        user,
        where: { id: { in: [assetID, secondAssetID] } },
      })
      expect(bulkDelete.errors).toEqual([])
      expect(bulkDelete.docs).toHaveLength(2)
      assetID = undefined
      secondAssetID = undefined

      const deleted = await payload.count({
        collection: 'assets',
        where: { macAddress: { equals: mac } },
      })
      expect(deleted.totalDocs).toBe(0)
    } finally {
      if (assetID) await payload.delete({ collection: 'assets', id: assetID })
      if (secondAssetID) await payload.delete({ collection: 'assets', id: secondAssetID })
      if (siteID) await payload.delete({ collection: 'sites', id: siteID })
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })

  it('soft-deletes assets via trash and hides them from normal queries', async () => {
    let assetID: string | undefined
    let siteID: string | undefined

    try {
      const site = await payload.create({
        collection: 'sites',
        data: { name: `Trash site ${randomUUID()}`, type: 'Test site' },
      })
      siteID = site.id

      const mac = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
      const asset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: otherClassID,
          criticality: 'low',
          macAddress: mac,
          name: 'Trash test asset',
          site: siteID,
          status: 'unknown',
        },
      })
      assetID = asset.id

      await payload.delete({ collection: 'assets', id: assetID })

      const normal = await payload.find({
        collection: 'assets',
        where: { id: { equals: assetID } },
      })
      expect(normal.docs).toHaveLength(0)

      const count = await payload.count({
        collection: 'assets',
        where: { macAddress: { equals: mac } },
      })
      expect(count.totalDocs).toBe(0)
    } finally {
      if (assetID)
        await payload
          .delete({ collection: 'assets', id: assetID, overrideAccess: true, trash: true })
          .catch(() => {})
      if (siteID) await payload.delete({ collection: 'sites', id: siteID })
    }
  })

  it('manages asset classes as documents and protects classes that are in use', async () => {
    let assetClassID: string | undefined
    let assetID: string | undefined
    let siteID: string | undefined
    let userID: string | undefined

    try {
      const seededPLC = await payload.findByID({
        collection: 'asset-classes',
        depth: 0,
        id: plcClassID,
      })
      expect(seededPLC.assignmentRules).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            manufacturerRegex: expect.stringContaining('Siemens'),
            modelRegex: expect.stringContaining('S7-'),
          }),
        ]),
      )

      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `asset-class-${randomUUID()}@example.test`,
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const assetClass = await payload.create({
        collection: 'asset-classes',
        data: {
          assignmentPriority: 1,
          assignmentRules: [{ manufacturerRegex: '^Acme Controls$', modelRegex: '^Drive-.*$' }],
          description: 'Variable-frequency drives',
          name: `Drive ${randomUUID()}`,
        },
        overrideAccess: false,
        user,
      })
      assetClassID = assetClass.id

      const site = await payload.create({
        collection: 'sites',
        data: { name: `Asset class site ${randomUUID()}`, type: 'Test site' },
      })
      siteID = site.id

      const asset = await payload.create({
        collection: 'assets',
        data: {
          criticality: 'medium',
          macAddress: `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`,
          model: 'Drive-9000',
          name: 'Drive under test',
          site: siteID,
          status: 'unknown',
          vendor: 'Acme Controls',
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      assetID = asset.id

      const classified = await payload.findByID({
        collection: 'assets',
        depth: 0,
        id: assetID,
      })
      expect(classified).toMatchObject({
        assetClass: assetClassID,
        fieldProvenance: {
          assetClass: { quality: 'medium', source: 'asset-class-rule' },
        },
      })

      const classes = await payload.find({
        collection: 'asset-classes',
        depth: 0,
        overrideAccess: false,
        user,
        where: { id: { equals: assetClassID } },
      })
      expect(classes.docs).toHaveLength(1)
      expect(classes.docs[0]).toMatchObject({
        description: 'Variable-frequency drives',
        id: assetClassID,
      })

      await expect(
        payload.delete({
          collection: 'asset-classes',
          id: assetClassID,
          overrideAccess: false,
          user,
        }),
      ).rejects.toThrow('Reassign affected assets')

      await payload.update({
        collection: 'assets',
        data: { assetClass: otherClassID },
        id: assetID,
        overrideAccess: false,
        user,
      })
      const afterHumanOverride = await payload.update({
        collection: 'assets',
        data: { model: 'Drive-9001' },
        id: assetID,
        overrideAccess: false,
        user,
      })
      expect(
        typeof afterHumanOverride.assetClass === 'object'
          ? afterHumanOverride.assetClass.id
          : afterHumanOverride.assetClass,
      ).toBe(otherClassID)
      expect(afterHumanOverride.fieldProvenance).toMatchObject({
        assetClass: { quality: 'human', source: 'human' },
      })

      await payload.delete({ collection: 'assets', id: assetID })
      assetID = undefined
      await payload.delete({
        collection: 'asset-classes',
        id: assetClassID,
        overrideAccess: false,
        user,
      })
      assetClassID = undefined
    } finally {
      if (assetID) await payload.delete({ collection: 'assets', id: assetID })
      if (assetClassID) await payload.delete({ collection: 'asset-classes', id: assetClassID })
      if (siteID) await payload.delete({ collection: 'sites', id: siteID })
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })

  it('supports custom site types and prevents hierarchy cycles', async () => {
    const siteIDs: string[] = []

    try {
      const continent = await payload.create({
        collection: 'sites',
        data: { name: 'EU', type: 'Continent' },
      })
      siteIDs.push(continent.id)
      const region = await payload.create({
        collection: 'sites',
        data: {
          name: 'Germany',
          parent: continent.id,
          type: 'Custom region',
        },
      })
      siteIDs.push(region.id)
      const berlin = await payload.create({
        collection: 'sites',
        data: {
          name: 'Berlin',
          parent: region.id,
          type: 'Production campus',
        },
      })
      siteIDs.push(berlin.id)
      const aachen = await payload.create({
        collection: 'sites',
        data: { name: 'Aachen', parent: region.id, type: 'Production campus' },
      })
      siteIDs.push(aachen.id)

      const tree = buildSiteTree([berlin, continent, aachen, region])
      expect(tree.map(({ site }) => site.id)).toEqual([
        continent.id,
        region.id,
        aachen.id,
        berlin.id,
      ])
      expect(tree.find(({ site }) => site.id === aachen.id)).toMatchObject({
        depth: 2,
        path: 'EU / Germany / Aachen',
      })

      const parentFilter = await filterSiteParents({
        id: continent.id,
        req: await createLocalReq({}, payload),
      })
      expect(parentFilter).toEqual({
        and: [{ id: { not_in: expect.arrayContaining(siteIDs) } }],
      })

      await expect(
        payload.update({
          collection: 'sites',
          data: { parent: berlin.id },
          id: siteIDs[0],
        }),
      ).rejects.toThrow('cannot be its own parent or descendant')
    } finally {
      if (siteIDs[0]) {
        await payload.update({ collection: 'sites', data: { parent: null }, id: siteIDs[0] })
      }
      for (const id of siteIDs.reverse()) await payload.delete({ collection: 'sites', id })
    }
  })

  it('enforces role access for a site and every descendant', async () => {
    const assetMACs: string[] = []
    const roleIDs: string[] = []
    const siteIDs: string[] = []
    const userIDs: string[] = []
    const passwords: string[] = []

    const mac = () => {
      const value = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
      assetMACs.push(value)
      return value
    }

    try {
      const adminRole = await ensureAdminRole(payload)
      await expect(payload.delete({ collection: 'user-roles', id: adminRole.id })).rejects.toThrow(
        'Admin role cannot be deleted',
      )

      const eu = await payload.create({
        collection: 'sites',
        data: { name: `EU ${randomUUID()}`, type: 'Continent' },
      })
      siteIDs.push(eu.id)
      const germany = await payload.create({
        collection: 'sites',
        data: { name: `Germany ${randomUUID()}`, parent: eu.id, type: 'Country' },
      })
      siteIDs.push(germany.id)
      const aachen = await payload.create({
        collection: 'sites',
        data: { name: `Aachen ${randomUUID()}`, parent: germany.id, type: 'Plant' },
      })
      siteIDs.push(aachen.id)
      const usa = await payload.create({
        collection: 'sites',
        data: { name: `USA ${randomUUID()}`, parent: eu.id, type: 'Country' },
      })
      siteIDs.push(usa.id)

      const writerRole = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Germany writer ${randomUUID()}`,
          permissions: [{ access: 'read-write', site: germany.id }],
        },
      })
      roleIDs.push(writerRole.id)
      const readerRole = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Germany reader ${randomUUID()}`,
          permissions: [{ access: 'read', site: germany.id }],
        },
      })
      roleIDs.push(readerRole.id)

      for (const [label, role] of [
        ['writer', writerRole],
        ['reader', readerRole],
        ['admin', adminRole],
      ] as const) {
        const password = randomUUID()
        const user = await payload.create({
          collection: 'users',
          data: {
            email: `${label}-${randomUUID()}@example.test`,
            name: `${label} test user`,
            password,
            role: role.id,
          },
        })
        passwords.push(password)
        userIDs.push(user.id)
      }
      const [writer, reader, admin] = await Promise.all(
        userIDs.map((id) => payload.findByID({ collection: 'users', id })),
      )
      expect(hideFromNonAdmins({ user: reader })).toBe(true)
      expect(hideFromNonAdmins({ user: admin })).toBe(false)

      const aachenMAC = mac()
      const usaMAC = mac()
      const aachenAsset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: plcClassID,
          criticality: 'medium',
          macAddress: aachenMAC,
          name: 'Aachen PLC',
          site: aachen.id,
          status: 'unknown',
        },
      })
      const usaAsset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: plcClassID,
          criticality: 'medium',
          macAddress: usaMAC,
          name: 'USA PLC',
          site: usa.id,
          status: 'unknown',
        },
      })

      const visibleToWriter = await payload.find({
        collection: 'assets',
        depth: 0,
        overrideAccess: false,
        user: writer,
        where: { id: { in: [aachenAsset.id, usaAsset.id] } },
      })
      expect(visibleToWriter.docs.map(({ id }) => id)).toEqual([aachenAsset.id])

      const visibleToReader = await payload.find({
        collection: 'assets',
        depth: 0,
        overrideAccess: false,
        user: reader,
        where: { id: { in: [aachenAsset.id, usaAsset.id] } },
      })
      expect(visibleToReader.docs.map(({ id }) => id)).toEqual([aachenAsset.id])

      const login = await payload.login({
        collection: 'users',
        data: { email: reader.email, password: passwords[1] },
      })
      const browserReq = await createPayloadRequest({
        config: payload.config,
        request: new Request('http://localhost/api/assets', {
          headers: { Authorization: `JWT ${login.token}` },
        }),
      })
      const visibleInBrowser = await payload.find({
        collection: 'assets',
        depth: 0,
        overrideAccess: false,
        req: browserReq,
        where: { id: { in: [aachenAsset.id, usaAsset.id] } },
      })
      expect(visibleInBrowser.docs.map(({ id }) => id)).toEqual([aachenAsset.id])

      browserReq.query.search = 'name:USA'
      const luceneFiltered = await payload.find({
        collection: 'assets',
        depth: 0,
        overrideAccess: false,
        req: browserReq,
        where: { id: { in: [aachenAsset.id, usaAsset.id] } },
      })
      expect(luceneFiltered.totalDocs).toBe(0)

      const visibleSites = await payload.find({
        collection: 'sites',
        depth: 0,
        overrideAccess: false,
        user: writer,
        where: { id: { in: siteIDs } },
      })
      expect(new Set(visibleSites.docs.map(({ id }) => id))).toEqual(
        new Set([germany.id, aachen.id]),
      )

      await payload.update({
        collection: 'assets',
        data: { status: 'online' },
        id: aachenAsset.id,
        overrideAccess: false,
        user: writer,
      })
      await expect(
        payload.update({
          collection: 'assets',
          data: { status: 'online' },
          id: usaAsset.id,
          overrideAccess: false,
          user: writer,
        }),
      ).rejects.toThrow()
      await expect(
        payload.update({
          collection: 'assets',
          data: { status: 'offline' },
          id: aachenAsset.id,
          overrideAccess: false,
          user: reader,
        }),
      ).rejects.toThrow()

      const writerMAC = mac()
      await payload.create({
        collection: 'assets',
        data: {
          assetClass: otherClassID,
          criticality: 'low',
          macAddress: writerMAC,
          name: 'Writer-created asset',
          site: aachen.id,
          status: 'unknown',
        },
        overrideAccess: false,
        user: writer,
      })
      await expect(
        payload.create({
          collection: 'assets',
          data: {
            assetClass: otherClassID,
            criticality: 'low',
            macAddress: mac(),
            name: 'Out-of-scope asset',
            site: usa.id,
            status: 'unknown',
          },
          overrideAccess: false,
          user: writer,
        }),
      ).rejects.toThrow()

      const visibleToAdmin = await payload.find({
        collection: 'assets',
        overrideAccess: false,
        user: admin,
        where: { id: { in: [aachenAsset.id, usaAsset.id] } },
      })
      expect(visibleToAdmin.totalDocs).toBe(2)
    } finally {
      const assets = await payload.find({
        collection: 'assets',
        depth: 0,
        pagination: false,
        where: { macAddress: { in: assetMACs } },
      })
      for (const asset of assets.docs) await payload.delete({ collection: 'assets', id: asset.id })
      for (const id of userIDs) await payload.delete({ collection: 'users', id })
      for (const id of roleIDs) await payload.delete({ collection: 'user-roles', id })
      for (const id of siteIDs.reverse()) await payload.delete({ collection: 'sites', id })
    }
  })

  it('exports selected assets as CSV within the reader site scope', async () => {
    const assetMACs: string[] = []
    const roleIDs: string[] = []
    const siteIDs: string[] = []
    const userIDs: string[] = []

    const mac = () => {
      const value = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
      assetMACs.push(value)
      return value
    }

    const exportCSV = async (token: string | undefined, ids: string[], search?: string) => {
      const parts = ids.map((id) => `where[id][in]=${encodeURIComponent(id)}`)
      if (search) parts.push(`search=${encodeURIComponent(search)}`)
      const request = new Request(`http://localhost/api/assets/export-csv?${parts.join('&')}`, {
        headers: token ? { Authorization: `JWT ${token}` } : {},
      })
      const browserReq = await createPayloadRequest({ config: payload.config, request })
      const response = await exportAssetsCSV(browserReq)
      return response.text()
    }

    try {
      const allowedSite = await payload.create({
        collection: 'sites',
        data: { name: `Export allowed ${randomUUID()}`, type: 'Plant' },
      })
      siteIDs.push(allowedSite.id)
      const otherSite = await payload.create({
        collection: 'sites',
        data: { name: `Export other ${randomUUID()}`, type: 'Plant' },
      })
      siteIDs.push(otherSite.id)

      const adminRole = await ensureAdminRole(payload)
      const readerRole = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Export reader ${randomUUID()}`,
          permissions: [{ access: 'read', site: allowedSite.id }],
        },
      })
      roleIDs.push(readerRole.id)

      const password = randomUUID()
      const reader = await payload.create({
        collection: 'users',
        data: {
          email: `export-${randomUUID()}@example.test`,
          name: 'Export test user',
          password,
          role: readerRole.id,
        },
      })
      userIDs.push(reader.id)
      const adminPassword = randomUUID()
      const admin = await payload.create({
        collection: 'users',
        data: {
          email: `export-admin-${randomUUID()}@example.test`,
          name: 'Export admin user',
          password: adminPassword,
          role: adminRole.id,
        },
      })
      userIDs.push(admin.id)

      const allowedAsset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: plcClassID,
          criticality: 'medium',
          macAddress: mac(),
          name: 'Exported PLC, with "quotes"',
          notes: 'line one\nline two',
          site: allowedSite.id,
          status: 'online',
          vendor: 'Siemens',
        },
      })
      const otherAsset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: otherClassID,
          criticality: 'low',
          macAddress: mac(),
          name: 'Hidden asset',
          site: otherSite.id,
          status: 'unknown',
        },
      })

      const login = await payload.login({
        collection: 'users',
        data: { email: reader.email, password },
      })
      const csv = await exportCSV(login.token, [allowedAsset.id, otherAsset.id])
      const [header, ...rows] = csv.trim().split('\r\n')
      const columns = header.replace(/^\uFEFF/, '').split(',')
      expect(columns).toEqual(expect.arrayContaining(['macAddress', 'vendor', 'notes']))
      expect(rows).toHaveLength(1)
      expect(csv).toContain(allowedAsset.macAddress)
      expect(csv).toContain('"Exported PLC, with ""quotes"""')
      expect(csv).toContain('"line one\nline two"')
      expect(csv).not.toContain(otherAsset.macAddress)

      const adminLogin = await payload.login({
        collection: 'users',
        data: { email: admin.email, password: adminPassword },
      })
      const adminCSV = await exportCSV(adminLogin.token, [allowedAsset.id, otherAsset.id])
      expect(adminCSV).toContain(allowedAsset.macAddress)
      expect(adminCSV).toContain(otherAsset.macAddress)

      const searchedCSV = await exportCSV(adminLogin.token, [], 'vendor:Siemens')
      expect(searchedCSV).toContain(allowedAsset.macAddress)
      expect(searchedCSV).not.toContain(otherAsset.macAddress)

      const anonymousCSV = await exportCSV(undefined, [allowedAsset.id, otherAsset.id])
      expect(anonymousCSV.trim()).toBe('id')
    } finally {
      const assets = await payload.find({
        collection: 'assets',
        depth: 0,
        pagination: false,
        where: { macAddress: { in: assetMACs } },
      })
      for (const asset of assets.docs) await payload.delete({ collection: 'assets', id: asset.id })
      for (const id of userIDs) await payload.delete({ collection: 'users', id })
      for (const id of roleIDs) await payload.delete({ collection: 'user-roles', id })
      for (const id of siteIDs.reverse()) await payload.delete({ collection: 'sites', id })
    }
  })

  it('merges PRONETA and Nmap assets using only their MAC as identity', async () => {
    const mac = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
    const importIDs: string[] = []
    let assetFieldID: string | undefined
    let assetID: string | undefined
    let siteID: string | undefined
    let userID: string | undefined

    const topology = (name: string, ipAddress: string) =>
      Buffer.from(`
      <Topology PronetaVersion="3.8"><DeviceCollection><Device>
        <NameOfStation>${name}</NameOfStation>
        <IpAddress>${ipAddress}</IpAddress>
        <MAC>${mac}</MAC>
      </Device></DeviceCollection></Topology>
    `)

    try {
      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `import-${randomUUID()}@example.test`,
          name: 'Import test user',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const customField = await payload.create({
        collection: 'asset-fields',
        data: { label: `ISA-95 level ${randomUUID()}`, type: 'text' },
        overrideAccess: false,
        user,
      })
      assetFieldID = customField.id

      const site = await payload.create({
        collection: 'sites',
        data: { name: `Import site ${randomUUID()}`, type: 'Plant' },
        overrideAccess: false,
        user,
      })
      siteID = site.id

      for (const [name, ipAddress] of [
        ['First name', '192.0.2.20'],
        ['Updated name', '192.0.2.21'],
      ]) {
        const file = topology(name, ipAddress)
        const imported = await payload.create({
          collection: 'asset-imports',
          data: { site: siteID, source: 'proneta', sourceVersion: 'unknown', status: 'pending' },
          file: {
            data: file,
            mimetype: 'application/xml',
            name: `proneta-${randomUUID()}.xml`,
            size: file.length,
          },
          overrideAccess: false,
          user,
        })
        importIDs.push(imported.id)
        expect(imported.status).toBe('completed')
      }

      const nmap = Buffer.from(`
        <!DOCTYPE nmaprun>
        <nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
          <host endtime="1700000000">
            <status state="up" reason="arp-response" reason_ttl="0" />
            <address addr="192.0.2.22" addrtype="ipv4" />
            <address addr="${mac}" addrtype="mac" vendor="Siemens AG" />
            <hostnames><hostname name="Nmap updated name" type="PTR" /></hostnames>
          </host>
        </nmaprun>
      `)
      const nmapImport = await payload.create({
        collection: 'asset-imports',
        data: {
          assetOverrides: {
            assetOwner: 'OT operations',
            location: 'Building 1 / Cabinet A',
          },
          customFieldOverrides: { [assetFieldID]: 'Level 2' },
          site: siteID,
          source: 'nmap',
          sourceVersion: 'unknown',
          status: 'pending',
        },
        file: {
          data: nmap,
          mimetype: 'application/xml',
          name: `nmap-${randomUUID()}.xml`,
          size: nmap.length,
        },
        overrideAccess: false,
        user,
      })
      importIDs.push(nmapImport.id)
      expect(nmapImport.status).toBe('completed')

      const importedAssets = await payload.find({
        collection: 'assets',
        depth: 0,
        where: { macAddress: { equals: mac } },
      })
      expect(importedAssets.totalDocs).toBe(1)
      expect(importedAssets.docs[0]).toMatchObject({
        assetOwner: 'OT operations',
        assetClass: otherClassID,
        criticality: 'medium',
        importSource: 'nmap',
        ipAddress: '192.0.2.21',
        macAddress: mac,
        name: 'Updated name',
        location: 'Building 1 / Cabinet A',
        site: siteID,
        sourceVersion: '7.95',
        status: 'online',
      })
      expect(importedAssets.docs[0]?.customFields).toMatchObject({ [assetFieldID]: 'Level 2' })
      assetID = importedAssets.docs[0]?.id

      await payload.update({
        collection: 'assets',
        data: { name: 'Human corrected name' },
        id: assetID,
        overrideAccess: false,
        user,
      })

      const confirmedFile = topology('Scanner name after correction', '192.0.2.23')
      for (let attempt = 0; attempt < 2; attempt++) {
        const confirmedImport = await payload.create({
          collection: 'asset-imports',
          data: { site: siteID, source: 'proneta', sourceVersion: 'unknown', status: 'pending' },
          file: {
            data: confirmedFile,
            mimetype: 'application/xml',
            name: `proneta-confirm-${randomUUID()}.xml`,
            size: confirmedFile.length,
          },
          overrideAccess: false,
          user,
        })
        importIDs.push(confirmedImport.id)
        expect(confirmedImport.updatedAssets).toBe(attempt === 0 ? 1 : 0)
      }

      const protectedAsset = await payload.findByID({ collection: 'assets', id: assetID })
      expect(protectedAsset).toMatchObject({
        ipAddress: '192.0.2.23',
        name: 'Human corrected name',
      })

      const secondImport = await payload.findByID({
        collection: 'asset-imports',
        id: importIDs[1],
      })
      expect(secondImport.createdAssets).toBe(0)
      expect(secondImport.updatedAssets).toBe(1)
      expect(nmapImport.createdAssets).toBe(0)
      expect(nmapImport.updatedAssets).toBe(1)
    } finally {
      for (const id of importIDs) await payload.delete({ collection: 'asset-imports', id })
      if (assetID) await payload.delete({ collection: 'assets', id: assetID })
      if (siteID) await payload.delete({ collection: 'sites', id: siteID })
      if (userID) await payload.delete({ collection: 'users', id: userID })
      if (assetFieldID) await payload.delete({ collection: 'asset-fields', id: assetFieldID })
    }
  })

  it('imports the anonymized full Nmap scan', async () => {
    const fixture = await readFile(new URL('../nmap_files/nmap.xml', import.meta.url), 'utf8')
    const randomMACPrefix = `02:${randomBytes(4).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`
    const file = Buffer.from(fixture.replaceAll('02:00:00:00:00:', `${randomMACPrefix}:`))
    let importID: string | undefined
    let siteID: string | undefined
    let userID: string | undefined

    try {
      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `nmap-fixture-${randomUUID()}@example.test`,
          name: 'Nmap fixture test user',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const site = await payload.create({
        collection: 'sites',
        data: { name: `Nmap fixture site ${randomUUID()}`, type: 'Test site' },
        overrideAccess: false,
        user,
      })
      siteID = site.id

      const imported = await payload.create({
        collection: 'asset-imports',
        data: { site: siteID, source: 'nmap', sourceVersion: 'unknown', status: 'pending' },
        file: {
          data: file,
          mimetype: 'application/xml',
          name: `nmap-fixture-${randomUUID()}.xml`,
          size: file.length,
        },
        overrideAccess: false,
        user,
      })
      importID = imported.id

      expect(imported).toMatchObject({
        createdAssets: 7,
        skippedAssets: 3,
        sourceVersion: '7.92',
        status: 'completed',
        updatedAssets: 0,
      })

      const assets = await payload.find({
        collection: 'assets',
        depth: 0,
        pagination: false,
        where: { site: { equals: siteID } },
      })
      expect(assets.docs).toHaveLength(7)
      expect(
        assets.docs.find(({ macAddress }) => macAddress === `${randomMACPrefix}:03`),
      ).toMatchObject({
        importSource: 'nmap',
        ipAddress: '192.0.2.8',
        name: 'server-01.example.test',
        operatingSystem: 'Linux 5.3 - 5.4',
        osAccuracy: 96,
        site: siteID,
        status: 'online',
      })
    } finally {
      if (importID) await payload.delete({ collection: 'asset-imports', id: importID })
      if (siteID) {
        const assets = await payload.find({
          collection: 'assets',
          depth: 0,
          pagination: false,
          where: { site: { equals: siteID } },
        })
        for (const asset of assets.docs)
          await payload.delete({ collection: 'assets', id: asset.id })
        await payload.delete({ collection: 'sites', id: siteID })
      }
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })
})
