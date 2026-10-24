import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { createLocalReq, getPayload, type Payload, type Where } from 'payload'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  defaultSiteTypes,
  initializeSiteTypes,
  isa95Elements,
  siteTypeField,
} from '../../src/collections/SiteTypes'
import { filterSiteParents } from '../../src/collections/Sites'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { performIdentityAction } from '../../src/identity/actions'
import { parseAssetSearch } from '../../src/search/assetLucene'
import { whereToLucene } from '../../src/search/whereToLucene'
import { purdueLabel } from '../../src/domain/purdue'
import PurdueView from '../../src/components/PurdueView'
import { siteTypeID } from '../siteType'
import type { Asset, Site, User } from '../../src/payload-types'

vi.mock('@payloadcms/ui', () => ({
  Button: ({ children, type }: { children: React.ReactNode; type: 'submit' }) =>
    createElement('button', { type }, children),
}))
vi.mock('@payloadcms/next/templates', () => ({
  DefaultTemplate: ({ children }: { children: React.ReactNode }) =>
    createElement('div', null, children),
}))

let payload: Payload
let plant: Site
let other: Site
let admin: User
let writer: User
let reader: User
let type: string
const childSites: string[] = []
const assets: string[] = []
const imports: string[] = []
const roles: string[] = []

const createChildSite = async (name: string, key = 'area', parent = plant.id) => {
  const result = await payload.create({
    collection: 'sites',
    data: { name, type: await siteTypeID(payload, key), parent },
  })
  childSites.push(result.id)
  return result
}

const createAsset = async (name: string, site = plant.id, levels?: Asset['purdueLevels']) => {
  const assetClass = (await payload.find({ collection: 'asset-classes', limit: 1 })).docs[0].id
  const result = await payload.create({
    collection: 'assets',
    data: {
      name,
      site,
      assetClass,
      status: 'unknown',
      criticality: 'medium',
      purdueLevels: levels,
    },
  })
  assets.push(result.id)
  return result
}

beforeAll(async () => {
  payload = await getPayload({ config })
  type = await siteTypeID(payload, 'area')
  plant = await payload.create({
    collection: 'sites',
    data: { name: `Hierarchy ${randomUUID()}`, type: await siteTypeID(payload) },
  })
  other = await payload.create({
    collection: 'sites',
    data: { name: `Other ${randomUUID()}`, type: await siteTypeID(payload) },
  })
  const users: User[] = []
  for (const access of ['admin', 'read-write', 'read'] as const) {
    const role =
      access === 'admin'
        ? await ensureAdminRole(payload)
        : await payload.create({
            collection: 'user-roles',
            data: { name: `${access} ${randomUUID()}`, permissions: [{ site: plant.id, access }] },
          })
    if (access !== 'admin') roles.push(role.id)
    users.push(
      await payload.create({
        collection: 'users',
        data: { email: `${randomUUID()}@example.test`, password: randomUUID(), role: role.id },
      }),
    )
  }
  ;[admin, writer, reader] = users
})

afterAll(async () => {
  for (const id of imports) await payload.delete({ collection: 'asset-imports', id })
  for (const id of assets) await payload.delete({ collection: 'assets', id })
  for (const id of [...childSites].reverse()) await payload.delete({ collection: 'sites', id })
  for (const user of [writer, reader, admin])
    await payload.delete({ collection: 'users', id: user.id })
  for (const id of roles) await payload.delete({ collection: 'user-roles', id })
  for (const site of [plant, other]) await payload.delete({ collection: 'sites', id: site.id })
})

describe('site catalogue, hierarchy, and Purdue classification', () => {
  it('seeds once, preserves edited defaults, and restricts catalogue administration', async () => {
    const before = await payload.count({ collection: 'site-types' })
    expect(before.totalDocs).toBeGreaterThanOrEqual(defaultSiteTypes.length)
    const blockedDefaults = await payload.find({
      collection: 'site-types',
      where: { blockImports: { equals: true } },
      pagination: false,
    })
    expect(blockedDefaults.docs.map(({ key }) => key).sort()).toEqual([
      'city',
      'continent',
      'country',
      'enterprise',
      'site',
    ])
    const mappedDefaults = await payload.find({
      collection: 'site-types',
      where: {
        key: {
          in: [
            'to-be-changed',
            'continent',
            'country',
            'region',
            'city',
            'site',
            'area',
            'production-line',
          ],
        },
      },
      pagination: false,
    })
    expect(
      Object.fromEntries(mappedDefaults.docs.map(({ key, isa95Element }) => [key, isa95Element])),
    ).toEqual({
      area: 'area',
      city: 'area',
      continent: 'enterprise',
      country: 'area',
      'production-line': 'production-line',
      region: 'area',
      site: 'site',
      'to-be-changed': 'site',
    })
    expect(defaultSiteTypes.every(({ isa95Element }) => isa95Element)).toBe(true)
    expect(new Set(isa95Elements.map(({ value }) => value)).size).toBe(isa95Elements.length)
    const countryID = await siteTypeID(payload, 'country')
    const country = await payload.findByID({ collection: 'site-types', id: countryID })
    try {
      await payload.update({
        collection: 'site-types',
        id: countryID,
        data: { name: 'Country (customized)', active: false, blockImports: false },
        overrideAccess: false,
        user: admin,
      })
      await initializeSiteTypes(payload)
      expect((await payload.count({ collection: 'site-types' })).totalDocs).toBe(before.totalDocs)
      expect(await payload.findByID({ collection: 'site-types', id: countryID })).toMatchObject({
        name: 'Country (customized)',
        active: false,
        blockImports: false,
      })
      await expect(payload.delete({ collection: 'site-types', id: countryID })).rejects.toThrow(
        'Retire built-in',
      )
      await expect(
        payload.create({ collection: 'sites', data: { name: 'Retired type', type: countryID } }),
      ).rejects.toThrow()
    } finally {
      await payload.update({
        collection: 'site-types',
        id: countryID,
        data: { name: country.name, active: true, blockImports: country.blockImports },
      })
    }
    expect(
      (await payload.find({ collection: 'site-types', overrideAccess: false, user: reader }))
        .totalDocs,
    ).toBe(before.totalDocs)
    for (const user of [writer, reader]) {
      await expect(
        payload.create({
          collection: 'site-types',
          overrideAccess: false,
          user,
          data: { name: 'Forbidden', key: randomUUID(), active: true, category: 'custom' },
        }),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        payload.update({
          collection: 'site-types',
          id: type,
          data: { active: false },
          overrideAccess: false,
          user,
        }),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        payload.delete({ collection: 'site-types', id: type, overrideAccess: false, user }),
      ).rejects.toMatchObject({ status: 403 })
    }
    await expect(
      payload.find({ collection: 'site-types', overrideAccess: false }),
    ).rejects.toMatchObject({ status: 403 })
    const scannerReq = await createLocalReq({ context: { otterScannerSiteID: plant.id } }, payload)
    await expect(
      payload.find({ collection: 'site-types', req: scannerReq, overrideAccess: false }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      payload.create({
        collection: 'sites',
        data: { name: 'Scanner-created area', type, parent: plant.id },
        req: scannerReq,
        overrideAccess: false,
      }),
    ).rejects.toMatchObject({ status: 403 })
  })

  it('protects referenced and retired types, rejects free text, and audits catalogue edits', async () => {
    const custom = await payload.create({
      collection: 'site-types',
      overrideAccess: false,
      user: admin,
      data: {
        name: `  Test   station ${randomUUID()}  `,
        key: randomUUID(),
        active: true,
        category: 'custom',
      },
    })
    const site = await payload.create({
      collection: 'sites',
      data: { name: 'Custom scope', type: custom.id },
      overrideAccess: false,
      user: admin,
    })
    try {
      expect(custom.name).toBe(custom.name.trim())
      await expect(
        payload.create({
          collection: 'site-types',
          data: {
            name: custom.name.toUpperCase(),
            key: randomUUID(),
            active: true,
            category: 'custom',
          },
        }),
      ).rejects.toThrow()
      await expect(payload.delete({ collection: 'site-types', id: custom.id })).rejects.toThrow(
        'Reassign',
      )
      await payload.update({
        collection: 'site-types',
        id: custom.id,
        data: { active: false, key: 'changed' },
        overrideAccess: false,
        user: admin,
      })
      expect((await payload.findByID({ collection: 'site-types', id: custom.id })).key).toBe(
        custom.key,
      )
      await payload.update({
        collection: 'sites',
        id: site.id,
        data: { description: 'Retired references still editable' },
        overrideAccess: false,
        user: admin,
      })
      await expect(
        payload.update({ collection: 'sites', id: plant.id, data: { type: custom.id } }),
      ).rejects.toThrow()
      await expect(
        payload.create({ collection: 'sites', data: { name: 'Invalid', type: 'Plant' } }),
      ).rejects.toThrow()
      const field = siteTypeField
      if (field.type !== 'relationship' || typeof field.filterOptions !== 'function')
        throw new Error('Expected relationship')
      const filter = await field.filterOptions({
        id: site.id,
        req: await createLocalReq({ user: admin }, payload),
      } as never)
      expect(filter).toEqual({ or: [{ active: { equals: true } }, { id: { equals: custom.id } }] })
      const audit = await payload.find({
        collection: 'audit-logs',
        where: {
          and: [
            { targetCollection: { equals: 'site-types' } },
            { documentID: { equals: custom.id } },
            { action: { equals: 'update' } },
          ],
        },
      })
      expect(audit.docs[0].actorID).toBe(admin.id)
    } finally {
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'site-types', id: custom.id })
    }
  })

  it('uses ordinary sites for production areas and cells with inherited permissions and exact scan scopes', async () => {
    const area = await createChildSite('Packaging')
    const line = await createChildSite('Line 2', 'production-line', area.id)
    const cell = await createChildSite('Filler', 'work-cell', line.id)
    const remote = await createChildSite('Other plant cell', 'work-cell', other.id)
    expect(cell.path).toBe(`${plant.path} / Packaging / Line 2 / Filler`)
    await payload.update({
      collection: 'sites',
      id: area.id,
      data: { name: 'Packing' },
      overrideAccess: false,
      user: writer,
    })
    expect((await payload.findByID({ collection: 'sites', id: cell.id })).path).toBe(
      `${plant.path} / Packing / Line 2 / Filler`,
    )
    await expect(
      payload.update({
        collection: 'sites',
        id: area.id,
        data: { parent: cell.id },
      }),
    ).rejects.toThrow()
    await expect(
      payload.update({
        collection: 'sites',
        id: line.id,
        data: { parent: remote.id },
        overrideAccess: false,
        user: writer,
      }),
    ).rejects.toThrow()
    await expect(payload.delete({ collection: 'sites', id: line.id })).rejects.toThrow(
      'Move or delete',
    )
    await expect(payload.delete({ collection: 'sites', id: plant.id })).rejects.toThrow(
      'child sites',
    )
    const visible = await payload.find({
      collection: 'sites',
      overrideAccess: false,
      user: reader,
    })
    expect(visible.docs.map(({ id }) => id)).toContain(cell.id)
    expect(visible.docs.map(({ id }) => id)).not.toContain(remote.id)
    await expect(
      payload.update({
        collection: 'sites',
        id: cell.id,
        data: { name: 'Forbidden' },
        overrideAccess: false,
        user: reader,
      }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      payload.create({
        collection: 'sites',
        data: { name: 'Forbidden', parent: other.id, type },
        overrideAccess: false,
        user: writer,
      }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      payload.delete({
        collection: 'sites',
        id: remote.id,
        overrideAccess: false,
        user: writer,
      }),
    ).rejects.toThrow()
    const asset = await createAsset('Filler PLC', line.id, ['1', '2'])
    await expect(
      payload.update({
        collection: 'assets',
        id: asset.id,
        data: { site: remote.id },
        overrideAccess: false,
        user: writer,
      }),
    ).rejects.toThrow()
    await performIdentityAction(
      asset.id,
      { action: 'transfer', site: cell.id, reason: 'Reassign within the site hierarchy' },
      await createLocalReq({ user: writer }, payload),
    )
    const changed = await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })
    expect(changed).toMatchObject({
      site: cell.id,
      uuid: asset.uuid,
      purdueLevels: ['1', '2'],
    })
    expect(changed.fieldProvenance).toMatchObject({
      purdueLevels: { quality: 'human' },
    })
    await payload.update({
      collection: 'assets',
      id: asset.id,
      data: { deletedAt: new Date().toISOString() },
      trash: true,
    })
    await expect(payload.delete({ collection: 'sites', id: cell.id })).rejects.toThrow('Trash')
    await payload.update({
      collection: 'assets',
      id: asset.id,
      data: { deletedAt: null },
      trash: true,
    })
    await performIdentityAction(
      asset.id,
      { action: 'transfer', site: other.id, reason: 'Move test hardware' },
      await createLocalReq({ user: admin }, payload),
    )
    expect(await payload.findByID({ collection: 'assets', id: asset.id, depth: 0 })).toMatchObject({
      site: other.id,
      uuid: asset.uuid,
    })
    const filter = await filterSiteParents({
      id: area.id,
      req: await createLocalReq({ user: writer }, payload),
    })
    expect(filter).toMatchObject({
      and: [
        { id: { not_in: expect.arrayContaining([area.id, line.id, cell.id]) } },
        { id: { in: expect.arrayContaining([plant.id, area.id, line.id, cell.id]) } },
      ],
    })
    const scannerSites = await payload.find({
      collection: 'sites',
      overrideAccess: false,
      req: await createLocalReq({ context: { otterScannerSiteID: plant.id } }, payload),
    })
    expect(scannerSites.docs.map(({ id }) => id)).toEqual([plant.id])
  })

  it('preserves Purdue classification across Otter imports into a production site', async () => {
    const importSite = await createChildSite('Import cell', 'work-cell')
    const readFile = (await import('node:fs/promises')).readFile
    const sample = JSON.parse(
      await readFile('tests/otserver_otter_files/OTserver-Otter-known-vulnerability.json', 'utf8'),
    )
    const upload = async () => {
      const data = Buffer.from(JSON.stringify(sample))
      const result = await payload.create({
        collection: 'asset-imports',
        data: {
          source: 'otserver-otter',
          sourceVersion: 'demo',
          status: 'pending',
          site: importSite.id,
        },
        file: {
          name: `${randomUUID()}.json`,
          data,
          mimetype: 'application/json',
          size: data.length,
        },
        overrideAccess: false,
        user: writer,
      })
      imports.push(result.id)
      return result
    }
    const first = await upload()
    expect(first.status).toBe('completed')
    const found = await payload.find({
      collection: 'assets',
      depth: 0,
      where: {
        and: [{ site: { equals: importSite.id } }, { importSource: { equals: 'otserver-otter' } }],
      },
    })
    expect(found.docs.length).toBeGreaterThan(0)
    assets.push(...found.docs.map(({ id }) => id))
    const device = found.docs[0]
    await payload.update({
      collection: 'assets',
      id: device.id,
      data: { purdueLevels: ['0', '1'] },
      overrideAccess: false,
      user: writer,
    })
    await payload.delete({ collection: 'asset-imports', id: first.id })
    imports.splice(imports.indexOf(first.id), 1)
    const repeated = await upload()
    expect(repeated.status).toBe('completed')
    expect(await payload.findByID({ collection: 'assets', id: device.id, depth: 0 })).toMatchObject(
      {
        uuid: device.uuid,
        site: importSite.id,
        purdueLevels: ['0', '1'],
        fieldProvenance: {
          purdueLevels: { quality: 'human' },
        },
      },
    )
    expect(
      (
        await payload.find({
          collection: 'assets',
          where: {
            and: [
              { site: { equals: importSite.id } },
              { importSource: { equals: 'otserver-otter' } },
            ],
          },
        })
      ).totalDocs,
    ).toBe(found.totalDocs)
  })

  it('serializes catalogue deletion with new site references', async () => {
    const custom = await payload.create({
      collection: 'site-types',
      data: {
        name: `Concurrent type ${randomUUID()}`,
        key: randomUUID(),
        category: 'custom',
        active: true,
      },
    })
    const typeRace = await Promise.allSettled([
      payload.create({
        collection: 'sites',
        data: { name: 'Racing site', parent: plant.id, type: custom.id },
      }),
      payload.delete({ collection: 'site-types', id: custom.id }),
    ])
    expect(typeRace.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    if (typeRace[0].status === 'fulfilled') {
      const site = typeRace[0].value as { id: string }
      childSites.push(site.id)
      expect(await payload.findByID({ collection: 'site-types', id: custom.id })).toBeTruthy()
      await payload.update({ collection: 'sites', id: site.id, data: { type } })
      await payload.delete({ collection: 'site-types', id: custom.id })
    }
  })

  it('filters classifications consistently and renders scoped counts including unclassified assets', async () => {
    const classified = await createAsset('Multi-function asset', plant.id, ['0', '3'])
    const unclassified = await createAsset('Unclassified asset', undefined, [])
    expect(purdueLabel(['0'])).toContain('Level 0')
    expect(purdueLabel([])).toBe('Unclassified')
    await expect(
      payload.update({
        collection: 'assets',
        id: classified.id,
        data: { purdueLevels: ['3.5'] as never },
      }),
    ).rejects.toThrow()
    const filters: Where[] = [{ purdueLevels: { equals: '0' } }, { site: { equals: plant.id } }]
    for (const where of filters) {
      const direct = await payload.find({
        collection: 'assets',
        where,
        overrideAccess: false,
        user: reader,
      })
      const searched = await payload.find({
        collection: 'assets',
        where: parseAssetSearch(whereToLucene(where)),
        overrideAccess: false,
        user: reader,
      })
      expect(searched.docs.map(({ id }) => id).sort()).toEqual(
        direct.docs.map(({ id }) => id).sort(),
      )
      expect(direct.docs.map(({ id }) => id)).toContain(classified.id)
    }
    const props = {
      payload,
      initPageResult: {
        req: await createLocalReq({ user: reader }, payload),
        visibleEntities: { collections: [], globals: [] },
      },
      searchParams: { site: plant.id },
    }
    const html = renderToStaticMarkup(await PurdueView(props as never))
    expect(html).toContain('Level 0')
    expect(html).toContain('Unclassified')
    expect(html).not.toContain(other.name)
    const links = [...html.matchAll(/href="([^"]*search=[^"]*)"/g)].map((match) =>
      match[1].replaceAll('&amp;', '&'),
    )
    expect(links).toHaveLength(7)
    const unclassifiedQuery = new URL(links.at(-1)!, 'http://localhost').searchParams.get('search')!
    const result = await payload.find({
      collection: 'assets',
      where: parseAssetSearch(unclassifiedQuery),
      overrideAccess: false,
      user: reader,
    })
    expect(result.docs.map(({ id }) => id)).toContain(unclassified.id)
    expect(result.docs.map(({ id }) => id)).not.toContain(classified.id)
    const inaccessible = renderToStaticMarkup(
      await PurdueView({ ...props, searchParams: { site: other.id } } as never),
    )
    expect(inaccessible).toContain('Select an accessible site')
    expect(inaccessible).not.toContain(other.name)
  })
})
