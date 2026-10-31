import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createLocalReq, getPayload, type RequiredDataFromCollectionSlug } from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { createCatalogMatcher, type Catalog } from '../../src/metadata/catalog'
import { catalog, catalogManifest, matchDeviceMetadata } from '../fixtures/device-metadata'
import { importMetadata } from '../../src/metadata/import'
import {
  ensureAssetClass,
  reapplyAssetClassRules,
  resolveAssetClassification,
} from '../../src/collections/AssetClasses'
import { initializeMetadataCatalog } from '../../src/metadata/initialize'
import CatalogReference from '../../src/components/AssetView/CatalogReference'
import { siteTypeID } from '../siteType'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { parseOTserverOtter } from '../../src/importers/otserverOtter'

const robot = catalog.devices.find(({ data }) => data.model === 'ACTIVE Shuttle')!
const maker = catalog.manufacturers.find(({ id }) => id === robot.manufacturer_id)!
const facts = { vendor: maker.data.name, model: 'ACTIVE Shuttle' }
const source = (): Catalog => ({
  groups: catalog.groups,
  manufacturers: [maker],
  devices: [structuredClone(robot)],
})

let fixtureAdminID: string
beforeAll(async () => {
  const payload = await getPayload({ config })
  const role = await ensureAdminRole(payload)
  const user = await payload.create({
    collection: 'users',
    data: {
      name: 'Metadata fixture importer',
      email: `metadata-fixture-${randomUUID()}@example.test`,
      password: randomUUID(),
      role: role.id,
    },
  })
  fixtureAdminID = user.id
  await importMetadata(await createLocalReq({ user: { ...user, collection: 'users' } }, payload), [
    { name: 'manufacturers.json', content: catalog.manufacturers },
    { name: 'devices.json', content: catalog.devices },
  ])
})
afterAll(async () => {
  const payload = await getPayload({ config })
  await payload.delete({ collection: 'device-catalog', id: 'active' })
  if (fixtureAdminID) await payload.delete({ collection: 'users', id: fixtureAdminID })
})

describe('device metadata', () => {
  it('retries transient startup races without hiding permanent failures', async () => {
    const find = vi
      .fn()
      .mockRejectedValueOnce(Object.assign(new Error('write conflict'), { code: 112 }))
      .mockResolvedValue({ docs: [] })
    await initializeMetadataCatalog({ find } as never)
    expect(find).toHaveBeenCalledTimes(3)
    await expect(
      initializeMetadataCatalog({
        find: vi.fn().mockRejectedValue(new Error('permanent failure')),
      } as never),
    ).rejects.toThrow('permanent failure')
    const unavailable = vi
      .fn()
      .mockRejectedValue(Object.assign(new Error('still unavailable'), { code: 112 }))
    await expect(initializeMetadataCatalog({ find: unavailable } as never)).rejects.toThrow(
      'still unavailable',
    )
    expect(unavailable).toHaveBeenCalledTimes(3)
  })

  it('retains explicitly reported Otter qualifiers and validates their types', () => {
    const scan = JSON.parse(
      readFileSync(
        new URL('../otserver_otter_files/OTserver-Otter-known-vulnerability.json', import.meta.url),
        'utf8',
      ),
    )
    const qualifiers = {
      productFamily: 'SIMATIC S7-1500',
      partNumber: 'P-001',
      orderNumber: 'O-002',
      softwareVersion: '1.0',
      versionComponent: 'CPU runtime',
    }
    Object.assign(scan.devices[0].observations[0].fields, qualifiers)
    expect(parseOTserverOtter(JSON.stringify(scan)).assets[0]).toMatchObject(qualifiers)
    scan.devices[0].observations[0].fields.productFamily = []
    expect(parseOTserverOtter(JSON.stringify(scan)).assets[0].productFamily).toBeUndefined()
  })

  it('uses scoped aliases, records evidence, and never matches hostnames or missing qualifiers', () => {
    const matched = matchDeviceMetadata(facts)
    expect(matched).toMatchObject({
      status: 'matched',
      catalogRevision: catalogManifest.sha256,
      manufacturerIDs: [maker.id],
      groupIDs: [robot.device_type_id],
      products: [
        expect.objectContaining({
          id: robot.id,
          manufacturerID: maker.id,
          groupID: robot.device_type_id,
        }),
      ],
    })
    expect(matched.manufacturerEvidence.length).toBeGreaterThan(0)
    expect(matched.products[0].evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'model', actual: 'ACTIVE Shuttle' }),
      ]),
    )
    expect(matchDeviceMetadata({ ...facts, vendor: 'ABB' }).products).toEqual([])
    expect(matchDeviceMetadata({ vendor: facts.vendor, name: facts.model }).products).toEqual([])
    expect(matchDeviceMetadata({ ...facts, model: 'ACTIVE Shuttle replacement' }).products).toEqual(
      [],
    )
    const versioned = matchDeviceMetadata({
      vendor: 'Siemens',
      model: 'S7-1500',
      firmwareVersion: 'V3.1',
    })
    expect(versioned.products.some(({ id }) => id === '01a17c83-695b-7f83-8cf0-ebf1b58d4c68')).toBe(
      true,
    )
    expect(
      matchDeviceMetadata({ vendor: 'Siemens', model: 'S7-1500' }).products.some(
        ({ id }) => id === '01a17c83-695b-7f83-8cf0-ebf1b58d4c68',
      ),
    ).toBe(false)
    expect(
      matchDeviceMetadata({
        vendor: 'Siemens',
        model: 'S7-1500',
        firmwareVersion: 'wrong',
        softwareVersion: 'V3.1',
      }).products.some(({ id }) => id === '01a17c83-695b-7f83-8cf0-ebf1b58d4c68'),
    ).toBe(false)
    const family = catalog.devices.find(
      ({ data }) =>
        data.product_family &&
        !data.model &&
        !data.part_number &&
        !data.order_number &&
        !data.version,
    )!
    const vendor = catalog.manufacturers.find(({ id }) => id === family.manufacturer_id)!.data.name
    expect(matchDeviceMetadata({ vendor }).products.some(({ id }) => id === family.id)).toBe(false)
    expect(
      matchDeviceMetadata({ vendor, productFamily: family.data.product_family }).products.some(
        ({ id }) => id === family.id,
      ),
    ).toBe(true)
  })

  it('detects conflicting groups and rejects malformed or unsafe catalogs', () => {
    const data = source()
    data.devices.push({
      ...structuredClone(robot),
      id: 'different-product',
      device_type_id: catalog.groups[0].id,
      data: { ...robot.data, device_type: catalog.groups[0].name, part_number: 'P1' },
      rules: { all: [robot.rules, { field: 'part_number', operator: 'equals', value: 'P1' }] },
    })
    expect(createCatalogMatcher(data, 'test')({ ...facts, catalogNumber: 'P1' }).status).toBe(
      'ambiguous',
    )
    for (const mutate of [
      (value: Catalog) => {
        value.devices[0].manufacturer_id = 'missing'
      },
      (value: Catalog) => {
        value.devices[0].device_type_id = 'missing'
      },
      (value: Catalog) => {
        value.devices.push(value.devices[0])
      },
      (value: Catalog) => {
        value.devices.push({ ...structuredClone(value.devices[0]), id: 'duplicate-identity' })
      },
      (value: Catalog) => {
        value.devices[0].data.manufacturer = 'ABB'
      },
      (value: Catalog) => {
        value.groups = [...value.groups, value.groups[0]]
      },
      (value: Catalog) => {
        value.manufacturers.push(value.manufacturers[0])
      },
      (value: Catalog) => {
        value.devices[0].rules = { all: [] }
      },
      (value: Catalog) => {
        value.devices[0].rules = { field: 'model', operator: 'invalid', value: 'ACTIVE Shuttle' }
      },
      (value: Catalog) => {
        value.devices[0].rules = {
          field: 'unsupported',
          operator: 'equals',
          value: 'ACTIVE Shuttle',
        }
      },
      (value: Catalog) => {
        value.devices[0].rules = { all: [{ field: 'model', operator: 'regex', value: '(a+)+' }] }
      },
      (value: Catalog) => {
        value.devices[0].rules = {
          all: [{ field: 'manufacturer', operator: 'equals', value: maker.data.name }],
        }
      },
    ])
      expect(() => {
        const changed = source()
        mutate(changed)
        createCatalogMatcher(changed, 'test')
      }).toThrow()
  })

  it('implements literal operators, case sensitivity, arrays and nesting without truncation', () => {
    for (const operator of ['equals', 'contains', 'starts_with', 'ends_with', 'regex']) {
      const value = source()
      value.devices[0].rules = {
        all: [
          {
            field: 'model',
            operator,
            value: operator === 'regex' ? '^ACTIVE Shuttle$' : 'ACTIVE Shuttle',
            caseSensitive: true,
          },
        ],
      }
      const match = createCatalogMatcher(value, 'test')
      expect(match(facts).status).toBe('matched')
      expect(match({ ...facts, model: 'active shuttle' }).status).toBe('unmatched')
      expect(match({ ...facts, model: 'x'.repeat(513) }).status).toBe('unmatched')
    }
    const value = source()
    value.devices[0].data.protocols_json = ['profinet']
    value.devices[0].rules = {
      all: [
        robot.rules,
        {
          any: [
            { field: 'protocol', operator: 'equals', value: 'profinet' },
            { field: 'model', operator: 'equals', value: 'ACTIVE Shuttle' },
          ],
        },
      ],
    }
    expect(
      createCatalogMatcher(value, 'test')({ ...facts, protocols: ['http', 'profinet'] }).status,
    ).toBe('matched')
  })

  it('preserves manual-rule priority and refuses ambiguous catalog mappings', async () => {
    const mapped = {
      id: 'catalog',
      assignmentPriority: 100,
      catalogAssignmentPriority: undefined as number | undefined,
      assignmentRules: [],
      catalogGroups: [robot.device_type_id],
    }
    const explicit = {
      id: 'explicit',
      assignmentPriority: 20,
      assignmentRules: [
        { enabled: true, conditions: [{ field: 'model', regex: '^ACTIVE Shuttle$' }] },
      ],
    }
    const payload = (classes: unknown[]) => ({
      find: async ({ collection }: { collection: string }) => ({
        docs:
          collection === 'asset-classes'
            ? classes
            : collection === 'device-catalog'
              ? [{ id: 'active', revision: catalogManifest.sha256 }]
              : [],
      }),
      findByID: async () => ({ catalog, revision: catalogManifest.sha256 }),
    })
    expect(
      (
        await resolveAssetClassification(payload([explicit, mapped]) as never, facts, {
          context: {},
        } as never)
      )?.source,
    ).toBe('asset-class-rule')
    explicit.assignmentRules[0].enabled = false
    expect(
      (
        await resolveAssetClassification(payload([explicit, mapped]) as never, facts, {
          context: {},
        } as never)
      )?.source,
    ).toBe('device-metadata')
    explicit.assignmentRules[0].enabled = true
    mapped.catalogAssignmentPriority = 10
    expect(
      (
        await resolveAssetClassification(payload([explicit, mapped]) as never, facts, {
          context: {},
        } as never)
      )?.source,
    ).toBe('device-metadata')
    mapped.catalogAssignmentPriority = 20
    expect(
      (
        await resolveAssetClassification(payload([explicit, mapped]) as never, facts, {
          context: {},
        } as never)
      )?.source,
    ).toBe('asset-class-rule')
    mapped.catalogAssignmentPriority = 30
    expect(
      (
        await resolveAssetClassification(payload([explicit, mapped]) as never, facts, {
          context: {},
        } as never)
      )?.source,
    ).toBe('asset-class-rule')
    delete mapped.catalogAssignmentPriority
    expect(
      await resolveAssetClassification(
        payload([mapped, { ...mapped, id: 'duplicate' }]) as never,
        facts,
        { context: {} } as never,
      ),
    ).toBeUndefined()
    expect(
      await resolveAssetClassification(
        payload([{ ...mapped, assignmentEnabled: false }]) as never,
        facts,
        { context: {} } as never,
      ),
    ).toBeUndefined()
    expect(
      await resolveAssetClassification(
        payload([{ ...mapped, catalogRulesEnabled: false }]) as never,
        facts,
        { context: {} } as never,
      ),
    ).toBeUndefined()
    const familyRule = {
      id: 'family-rule',
      assignmentRules: [{ conditions: [{ field: 'productFamily', regex: '^Reported family$' }] }],
    }
    expect(
      (
        await resolveAssetClassification(
          payload([familyRule, mapped]) as never,
          { ...facts, productFamily: 'Reported family' },
          { context: {} } as never,
        )
      )?.source,
    ).toBe('asset-class-rule')
  })

  it('shows empty, current, ambiguous and stale reference states without promoting capabilities', () => {
    const html = (metadataMatch?: unknown) =>
      renderToStaticMarkup(
        createElement(CatalogReference, {
          asset: { metadataMatch } as never,
          snapshot: { catalog, revision: catalogManifest.sha256 },
        }),
      )
    expect(renderToStaticMarkup(createElement(CatalogReference, { asset: {} as never }))).toContain(
      'No device catalog has been imported',
    )
    expect(html()).toContain('has not run')
    expect(html({ ...matchDeviceMetadata(facts), catalogRevision: 'old' })).toContain(
      'older revision',
    )
    expect(html(matchDeviceMetadata({}))).toContain('No product matches')
    const current = html(matchDeviceMetadata(facts))
    expect(current).toContain(maker.id)
    expect(current).toContain(robot.id)
    expect(current).toContain('Manufacturer website')
    expect(current).toContain('ACTIVE Shuttle')
    expect(current).toContain('Publisher source')
    expect(current).toContain('<summary>Match and source evidence</summary>')
    expect(html({ ...matchDeviceMetadata(facts), status: 'ambiguous' })).toContain(
      'Conflicting catalog candidates',
    )
  })

  it('renders imported metadata values safely and caps the candidate list', () => {
    const referenceCatalog: Catalog = {
      ...catalog,
      manufacturers: [
        {
          ...maker,
          data: {
            ...maker.data,
            website: 'javascript:alert(1)',
            support_url: 'not a URL',
            account_url: 'https://user:pass@example.test',
            reference_urls: ['https://example.test/reference', 'javascript:alert(1)', 42],
            extra_refs: ['one', 2, false],
            rating: 4,
            enabled: false,
            nested: { safe: true },
            ignored: null,
          },
        },
      ],
      devices: Array.from({ length: 21 }, (_, index) => ({
        ...robot,
        id: `candidate-${index}`,
        manufacturer_id: index === 1 ? '' : maker.id,
        data: {
          model: index > 1 ? `Candidate ${index}` : undefined,
          product_family: index === 0 ? 'Family fallback' : undefined,
          source_url: index === 0 ? '/relative/source' : undefined,
          protocols: index === 0 ? ['OPC UA', 502, false] : undefined,
          evidence_json: index === 0 ? { safe: true } : undefined,
        },
      })),
    }
    const metadataMatch = {
      catalogRevision: catalogManifest.sha256,
      status: 'matched' as const,
      manufacturerIDs: [maker.id],
      manufacturerEvidence: [],
      groupIDs: [robot.device_type_id],
      products: referenceCatalog.devices.map(({ id }) => ({
        id,
        manufacturerID: id === 'candidate-1' ? '' : maker.id,
        groupID: robot.device_type_id,
        evidence: [],
      })),
    }
    const rendered = renderToStaticMarkup(
      createElement(CatalogReference, {
        asset: { metadataMatch } as never,
        snapshot: { catalog: referenceCatalog, revision: catalogManifest.sha256 },
      }),
    )

    expect(rendered).toContain('Family fallback')
    expect(rendered).toContain('candidate-1')
    expect(rendered).toContain('Unavailable')
    expect(rendered).toContain('OPC UA, 502, false')
    expect(rendered).toContain('safe&quot;: true')
    expect(rendered).toContain('<a href="https://example.test/reference"')
    expect(rendered).not.toContain('href="javascript:')
    expect(rendered).not.toContain('href="https://user:pass@')
    expect(rendered).toContain('Only the first 20 catalog candidates are shown.')
    expect(rendered).not.toContain('candidate-20')
  })

  it('persists matches, audits toggles, preserves human choices, and makes background retries idempotent', async () => {
    const payload = await getPayload({ config })
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Metadata ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    const other = await ensureAssetClass(payload, 'other')
    const type = await payload.create({
      collection: 'asset-classes',
      data: {
        name: `Robotics ${randomUUID()}`,
        assignmentPriority: 100,
        catalogGroups: [robot.device_type_id as '019a34b0-0000-7000-8000-000000000003'],
      },
    })
    const ids: string[] = []
    try {
      const asset = await payload.create({
        collection: 'assets',
        depth: 0,
        data: {
          ...facts,
          name: 'Catalog robot',
          site: site.id,
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      ids.push(asset.id)
      expect(asset.assetClass).toBe(type.id)
      expect(asset.fieldProvenance).toMatchObject({
        assetClass: { quality: 'medium', source: 'device-metadata' },
      })
      expect(asset.metadataMatch).toMatchObject({
        status: 'matched',
        catalogRevision: catalogManifest.sha256,
      })
      const human = await payload.create({
        collection: 'assets',
        data: {
          ...facts,
          assetClass: other.id,
          name: 'Human robot class',
          site: site.id,
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      ids.push(human.id)
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: {
          assignmentRules: [
            { enabled: true, conditions: [{ field: 'model', regex: '^ACTIVE Shuttle$' }] },
          ],
        },
      })
      const req = await createLocalReq({}, payload)
      await reapplyAssetClassRules(req)
      expect(
        (await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).fieldProvenance,
      ).toMatchObject({ assetClass: { source: 'asset-class-rule' } })
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: { catalogAssignmentPriority: 5 },
      })
      await reapplyAssetClassRules(req)
      expect(
        (await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).fieldProvenance,
      ).toMatchObject({ assetClass: { source: 'device-metadata' } })
      const changed = await payload.findByID({ collection: 'asset-classes', id: type.id })
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: {
          assignmentRules: changed.assignmentRules!.map((rule) => ({ ...rule, enabled: false })),
          catalogRulesEnabled: false,
          catalogAssignmentPriority: null,
        },
      })
      await reapplyAssetClassRules(req)
      const disabled = await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })
      expect(disabled.assetClass).toBe(other.id)
      expect(
        (await payload.findByID({ collection: 'assets', id: human.id, depth: 0 })).fieldProvenance,
      ).toMatchObject({ assetClass: { quality: 'human' } })
      expect((await reapplyAssetClassRules(req)).updated).toBe(0)
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: { catalogRulesEnabled: true, assignmentEnabled: false },
      })
      await reapplyAssetClassRules(req)
      expect(
        (await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).assetClass,
      ).toBe(other.id)
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: { assignmentEnabled: true },
      })
      await reapplyAssetClassRules(req)
      expect(
        (await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).assetClass,
      ).toBe(type.id)
      const audit = await payload.find({
        collection: 'audit-logs',
        where: { documentID: { equals: type.id } },
        limit: 100,
      })
      expect(audit.docs.length).toBeGreaterThan(0)
      await initializeMetadataCatalog(payload)
      const second = await payload.findByID({ collection: 'asset-classes', id: type.id })
      expect(second.assignmentRules?.[0].enabled).toBe(false)
      await payload.update({
        collection: 'asset-classes',
        id: type.id,
        data: { catalogRulesEnabled: false },
      })
      const originalUpdate = payload.update.bind(payload)
      let concurrentDecision = false
      const spy = vi.spyOn(payload, 'update').mockImplementation(async (options) => {
        if (
          options.collection === 'assets' &&
          'id' in options &&
          options.id === asset.id &&
          options.context?.assetClassReclassification &&
          !concurrentDecision
        ) {
          concurrentDecision = true
          await originalUpdate({
            collection: 'assets',
            id: asset.id,
            data: { assetClass: other.id },
          })
        }
        return originalUpdate(options)
      })
      try {
        await reapplyAssetClassRules(req)
      } finally {
        spy.mockRestore()
      }
      expect(concurrentDecision).toBe(true)
      expect(
        (await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).fieldProvenance,
      ).toMatchObject({ assetClass: { quality: 'human', source: 'human' } })
    } finally {
      for (const id of ids) await payload.delete({ collection: 'assets', id, trash: true })
      await payload.delete({ collection: 'asset-classes', id: type.id })
      await payload.delete({ collection: 'sites', id: site.id })
    }
  })

  it('keeps catalog evidence site-scoped and server-owned, and class switches administrator-only', async () => {
    const payload = await getPayload({ config })
    const adminRole = await ensureAdminRole(payload)
    const admin = await payload.create({
      collection: 'users',
      data: {
        name: 'Metadata admin',
        email: `metadata-admin-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: adminRole.id,
      },
    })
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Metadata visible ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    const hidden = await payload.create({
      collection: 'sites',
      data: { name: `Metadata hidden ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    const role = await payload.create({
      collection: 'user-roles',
      data: {
        name: `Metadata writer ${randomUUID()}`,
        permissions: [{ site: site.id, access: 'read-write' }],
      },
    })
    const writer = await payload.create({
      collection: 'users',
      data: {
        name: 'Metadata writer',
        email: `metadata-writer-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: role.id,
      },
    })
    const other = await ensureAssetClass(payload, 'other')
    const ids: string[] = []
    try {
      const visible = await payload.create({
        collection: 'assets',
        depth: 0,
        data: {
          ...facts,
          assetClass: other.id,
          name: 'Visible catalog robot',
          site: site.id,
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      ids.push(visible.id)
      const invisible = await payload.create({
        collection: 'assets',
        depth: 0,
        data: {
          ...facts,
          assetClass: other.id,
          name: 'Hidden catalog robot',
          site: hidden.id,
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      ids.push(invisible.id)
      const user = { ...writer, collection: 'users' as const }
      const loaded = await payload.findByID({
        collection: 'assets',
        id: visible.id,
        user,
        overrideAccess: false,
      })
      expect(loaded.metadataMatch).toMatchObject({ status: 'matched' })
      await expect(
        payload.findByID({ collection: 'assets', id: invisible.id, user, overrideAccess: false }),
      ).rejects.toThrow()
      const changed = await payload.update({
        collection: 'assets',
        id: visible.id,
        user,
        overrideAccess: false,
        depth: 0,
        data: { metadataMatch: { status: 'spoofed', catalogRevision: 'evil' } },
      })
      expect(changed.metadataMatch).toEqual(visible.metadataMatch)
      await expect(
        payload.update({
          collection: 'asset-classes',
          id: other.id,
          user,
          overrideAccess: false,
          data: { assignmentEnabled: false },
        }),
      ).rejects.toThrow()
    } finally {
      for (const id of ids) await payload.delete({ collection: 'assets', id, trash: true })
      await payload.delete({ collection: 'users', id: writer.id })
      await payload.delete({ collection: 'user-roles', id: role.id })
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'sites', id: hidden.id })
      await payload.delete({ collection: 'users', id: admin.id })
    }
  })
})
