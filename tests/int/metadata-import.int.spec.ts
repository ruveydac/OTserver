import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { createLocalReq, getPayload, type RequiredDataFromCollectionSlug } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { catalog } from '../fixtures/device-metadata'
import {
  importMetadata,
  importMetadataEndpoint,
  mergeMetadataFiles,
  MAX_METADATA_BYTES,
} from '../../src/metadata/import'
import { activeCatalog } from '../../src/metadata/runtime'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { siteTypeID } from '../siteType'
import { initializeMetadataCatalog } from '../../src/metadata/initialize'

const device = catalog.devices.find(({ data }) => data.model === 'ACTIVE Shuttle')!
const manufacturer = catalog.manufacturers.find(({ id }) => id === device.manufacturer_id)!
const file = (content: unknown, name = 'metadata.json') => ({ name, content })
const uuid = () => {
  const value = randomUUID()
  return value.slice(0, 14) + '7' + value.slice(15)
}

describe('manufacturer and device JSON imports', () => {
  it('validates the current OTserver Metadata submodule export', () => {
    const dataDirectory = new URL('../../otserver-metadata/data/', import.meta.url)
    const files = readdirSync(dataDirectory)
      .filter((name) => name.startsWith('ot-') && name.endsWith('.json'))
      .map((name) => file(JSON.parse(readFileSync(new URL(name, dataDirectory), 'utf8')), name))

    const result = mergeMetadataFiles(
      { manufacturers: [], devices: [], groups: catalog.groups },
      files,
    )
    expect(result.counts.manufacturers.added).toBeGreaterThan(0)
    expect(result.counts.devices.added).toBeGreaterThan(0)
  })

  it('upserts complete records by ID, preserving absent records and ignoring JSON key order', () => {
    const updated = {
      ...structuredClone(device),
      data: { ...device.data, description: 'Updated catalog description' },
    }
    const result = mergeMetadataFiles(catalog, [file(updated)])
    expect(result.counts.devices).toEqual({ added: 0, updated: 1, unchanged: 0 })
    expect(result.catalog.devices).toHaveLength(catalog.devices.length)
    expect(result.catalog.manufacturers).toEqual(catalog.manufacturers)
    expect(
      mergeMetadataFiles(catalog, [
        file({
          ...manufacturer,
          data: { ...manufacturer.data, description: 'Manufacturer-only update' },
        }),
      ]).counts.manufacturers.updated,
    ).toBe(1)
    expect(result.catalog.devices.find(({ id }) => id === device.id)?.data.description).toBe(
      updated.data.description,
    )
    const reordered = {
      rules: updated.rules,
      data: updated.data,
      device_type_id: updated.device_type_id,
      manufacturer_id: updated.manufacturer_id,
      id: updated.id.toUpperCase(),
    }
    expect(
      mergeMetadataFiles(result.catalog, [file([reordered, reordered])]).counts.devices,
    ).toEqual({ added: 0, updated: 0, unchanged: 1 })
  })

  it('validates mixed single and multi-record files together, independent of selection order', () => {
    const name = `Import test ${randomUUID()}`
    const maker = {
      id: uuid(),
      data: { name },
      rules: { any: [{ field: 'manufacturer', operator: 'equals', value: name }] },
    }
    const product = {
      ...structuredClone(device),
      id: uuid(),
      manufacturer_id: maker.id,
      data: { device_type: device.data.device_type, model: 'Import test model' },
      rules: { all: [{ field: 'model', operator: 'equals', value: 'Import test model' }] },
    }
    const result = mergeMetadataFiles(catalog, [
      file([product], 'devices.json'),
      file(maker, 'manufacturer.json'),
    ])
    expect(result.counts.manufacturers.added).toBe(1)
    expect(result.counts.devices.added).toBe(1)
    expect(() => mergeMetadataFiles(catalog, [file(product)])).toThrow(
      'Unknown catalog manufacturer',
    )
    expect(mergeMetadataFiles(catalog, [file([product, maker])]).catalog).toEqual(result.catalog)
  })

  it('rejects invalid files, conflicting duplicate IDs, references and unsafe rules before any write', () => {
    for (const input of [
      undefined,
      [],
      Array.from({ length: 51 }, () => file(device)),
      [null],
      [file([])],
      [file({ id: 'bad' })],
      [file({ ...device, data: null })],
    ])
      expect(() => mergeMetadataFiles(catalog, input)).toThrow()
    expect(() =>
      mergeMetadataFiles(catalog, [
        file(device),
        file({ ...device, data: { ...device.data, description: 'Conflicting record' } }),
      ]),
    ).toThrow('conflicting duplicate ID')
    expect(() =>
      mergeMetadataFiles(catalog, [file({ ...device, manufacturer_id: uuid() })]),
    ).toThrow('Unknown catalog manufacturer')
    expect(() =>
      mergeMetadataFiles(catalog, [file({ ...device, device_type_id: uuid() })]),
    ).toThrow()
    expect(() =>
      mergeMetadataFiles(catalog, [
        file({
          ...device,
          rules: { all: [{ field: 'model', operator: 'regex', value: '(a+)+' }] },
        }),
      ]),
    ).toThrow('Unsafe catalog regular expression')
    expect(() =>
      mergeMetadataFiles(catalog, [
        file({
          ...manufacturer,
          data: { ...manufacturer.data, description: 'x'.repeat(MAX_METADATA_BYTES) },
        }),
      ]),
    ).toThrow('8 MiB')
  })

  it('recognizes the companion repository management-rules export as a separate contract', () => {
    const exportedRules = {
      version: 1,
      classes: [
        {
          deviceTypeID: '019a34b0-0000-7000-8000-000000000001',
          classKey: 'plc',
          name: 'PLC',
          priority: 10,
          rules: [{ conditions: [{ field: 'model', regex: '^PLC$' }] }],
        },
      ],
      coverage: { included: [], skipped: [] },
      catalogSha256: 'a'.repeat(64),
    }
    for (const name of ['management-asset-class-rules.json', 'renamed-export.json'])
      expect(() => mergeMetadataFiles(catalog, [file(exportedRules, name)])).toThrow(
        'separate Asset class rule export',
      )
  })

  it('applies an audited atomic catalog shared by matchers and workers, preserves it on failures and denies non-admin writes', async () => {
    const payload = await getPayload({ config })
    const role = await ensureAdminRole(payload)
    const admin = await payload.create({
      collection: 'users',
      data: {
        name: 'Catalog importer',
        email: `catalog-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: role.id,
      },
    })
    const writerRole = await payload.create({
      collection: 'user-roles',
      data: { name: `Catalog reader ${randomUUID()}` },
    })
    const writer = await payload.create({
      collection: 'users',
      data: {
        name: 'Catalog reader',
        email: `reader-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: writerRole.id,
      },
    })
    const user = { ...admin, collection: 'users' as const }
    const request = () => createLocalReq({ user }, payload)
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Catalog test ${randomUUID()}`, type: await siteTypeID(payload) },
    })
    let assetID: string | undefined
    try {
      const initial = await activeCatalog(payload)
      expect(initial.revision).toBe('unloaded')
      expect(initial.catalog.manufacturers).toEqual([])
      expect(initial.catalog.devices).toEqual([])
      expect(
        initial.match({ vendor: manufacturer.data.name, model: 'ACTIVE Shuttle' }).status,
      ).toBe('unmatched')
      await initializeMetadataCatalog(payload)
      expect((await payload.find({ collection: 'device-catalog', limit: 1 })).totalDocs).toBe(0)
      const ruleExport = {
        version: 1,
        classes: [],
        coverage: { included: [], skipped: [] },
        catalogSha256: 'a'.repeat(64),
      }
      await expect(
        importMetadata(await request(), [
          file(manufacturer, 'ot-manufacturers.json'),
          file(ruleExport, 'management-asset-class-rules.json'),
        ]),
      ).rejects.toThrow('separate Asset class rule export')
      expect((await payload.find({ collection: 'device-catalog', limit: 1 })).totalDocs).toBe(0)
      const updated = {
        ...structuredClone(device),
        data: { ...device.data, description: 'Imported product reference' },
      }
      const maker = {
        ...structuredClone(manufacturer),
        data: { ...manufacturer.data, description: 'Imported manufacturer reference' },
      }
      const result = await importMetadata(await request(), [
        file(updated, 'device.json'),
        file([maker], 'manufacturers.json'),
      ])
      expect(result).toMatchObject({
        changed: true,
        manufacturers: { added: 1 },
        devices: { added: 1 },
      })
      const active = await activeCatalog(payload)
      expect(active.revision).toBe(result.revision)
      await initializeMetadataCatalog(payload)
      expect((await activeCatalog(payload)).revision).toBe(result.revision)
      expect(active.catalog.devices.find(({ id }) => id === device.id)?.data.description).toBe(
        'Imported product reference',
      )
      expect(
        (
          await activeCatalog(
            Object.assign(Object.create(payload), {
              find: payload.find.bind(payload),
              findByID: payload.findByID.bind(payload),
            }),
          )
        ).revision,
      ).toBe(result.revision)
      const other = await ensureAssetClass(payload, 'other')
      const asset = await payload.create({
        collection: 'assets',
        depth: 0,
        data: {
          name: 'Imported catalog match',
          site: site.id,
          assetClass: other.id,
          vendor: manufacturer.data.name,
          model: 'ACTIVE Shuttle',
        } as RequiredDataFromCollectionSlug<'assets'>,
      })
      assetID = asset.id
      expect(asset.metadataMatch).toMatchObject({
        catalogRevision: result.revision,
        status: 'matched',
      })
      const audit = await payload.find({
        collection: 'audit-logs',
        where: { targetCollection: { equals: 'device-catalog' } },
        limit: 100,
      })
      expect(audit.docs.some(({ actorID }) => actorID === admin.id)).toBe(true)
      const queued = await payload.find({
        collection: 'payload-jobs',
        where: { 'input.catalogRevision': { equals: result.revision } },
        limit: 100,
      })
      expect(queued.docs.length).toBeGreaterThan(0)
      const queue = vi
        .spyOn(payload.jobs, 'queue')
        .mockRejectedValueOnce(new Error('Injected queue failure'))
      try {
        await expect(
          importMetadata(await request(), [
            file({ ...updated, data: { ...updated.data, description: 'Must roll back' } }),
          ]),
        ).rejects.toThrow('Injected queue failure')
      } finally {
        queue.mockRestore()
      }
      expect((await activeCatalog(payload)).revision).toBe(result.revision)
      await expect(
        importMetadata(await request(), [file({ ...updated, manufacturer_id: uuid() })]),
      ).rejects.toThrow()
      expect((await activeCatalog(payload)).revision).toBe(result.revision)
      const repeat = await importMetadata(await request(), [file(maker), file(updated)])
      expect(repeat.changed).toBe(false)
      expect(repeat.revision).toBe(result.revision)
      const bodyRequest = async (body?: string) => {
        const req = await request()
        req.headers.set('content-type', 'application/json')
        if (body !== undefined)
          Object.defineProperty(req, 'body', { value: new Blob([body]).stream() })
        return req
      }
      await expect(importMetadataEndpoint(await request())).rejects.toThrow('application/json')
      expect(
        await (
          (await importMetadataEndpoint(
            await bodyRequest(JSON.stringify({ files: [file(updated)] })),
          )) as Response
        ).json(),
      ).toMatchObject({ changed: false })
      await expect(importMetadataEndpoint(await bodyRequest())).rejects.toThrow('JSON request body')
      await expect(importMetadataEndpoint(await bodyRequest('{bad'))).rejects.toThrow(
        'Invalid JSON',
      )
      await expect(importMetadataEndpoint(await bodyRequest('null'))).rejects.toThrow(
        'Select between',
      )
      await expect(
        importMetadataEndpoint(await bodyRequest(' '.repeat(MAX_METADATA_BYTES + 64 * 1024 + 1))),
      ).rejects.toThrow('8 MiB')
      const nonAdmin = await createLocalReq({ user: { ...writer, collection: 'users' } }, payload)
      await expect(importMetadata(nonAdmin, [file(updated)])).rejects.toThrow('Administrator')
      await expect(importMetadataEndpoint(nonAdmin)).rejects.toThrow('Administrator')
      await expect(
        payload.find({
          collection: 'device-catalog',
          user: { ...writer, collection: 'users' },
          overrideAccess: false,
        }),
      ).rejects.toThrow()
      await expect(
        payload.update({
          collection: 'device-catalog',
          id: 'active',
          data: { revision: 'spoof' },
          user,
          overrideAccess: false,
        }),
      ).rejects.toThrow()
      await expect(
        payload.delete({ collection: 'device-catalog', id: 'active', user, overrideAccess: false }),
      ).rejects.toThrow()
      const anonymous = await createLocalReq({}, payload)
      await expect(importMetadata(anonymous, [file(updated)])).rejects.toThrow('Administrator')
      expect(initial.revision).not.toBe(result.revision)
      const concurrent = [
        file({ ...maker, data: { ...maker.data, description: 'Concurrent manufacturer update' } }),
        file({ ...updated, data: { ...updated.data, description: 'Concurrent device update' } }),
      ]
      const outcomes = await Promise.allSettled(
        concurrent.map(async (content) => importMetadata(await request(), [content])),
      )
      for (let index = 0; index < outcomes.length; index++) {
        if (outcomes[index].status === 'rejected') {
          expect((outcomes[index] as PromiseRejectedResult).reason.status).toBe(409)
          await importMetadata(await request(), [concurrent[index]])
        }
      }
      const combined = await activeCatalog(payload)
      expect(
        combined.catalog.manufacturers.find(({ id }) => id === manufacturer.id)?.data.description,
      ).toBe('Concurrent manufacturer update')
      expect(combined.catalog.devices.find(({ id }) => id === device.id)?.data.description).toBe(
        'Concurrent device update',
      )
    } finally {
      if (assetID) await payload.delete({ collection: 'assets', id: assetID, trash: true })
      const saved = await payload.find({
        collection: 'device-catalog',
        where: { id: { equals: 'active' } },
        limit: 1,
      })
      if (saved.docs.length) await payload.delete({ collection: 'device-catalog', id: 'active' })
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'users', id: writer.id })
      await payload.delete({ collection: 'user-roles', id: writerRole.id })
      await payload.delete({ collection: 'users', id: admin.id })
    }
  })
})
