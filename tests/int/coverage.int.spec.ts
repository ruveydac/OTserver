import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

const ui = vi.hoisted(() => ({
  openModal: vi.fn(),
  setValue: vi.fn(),
}))

vi.mock('@payloadcms/ui', async () => {
  const { createElement } = await import('react')
  return {
    Button: ({ children, ...props }: Record<string, unknown>) => {
      delete props.buttonStyle
      return createElement('button', props, children as never)
    },
    ConfirmationModal: ({ body }: { body: unknown }) => createElement('div', null, body as never),
    CopyToClipboard: ({ defaultMessage }: { defaultMessage: string }) =>
      createElement('span', null, defaultMessage),
    DefaultListView: () => createElement('div', null, 'Default list'),
    useDocumentInfo: () => ({}),
    useField: () => ({ setValue: ui.setValue, value: 'nmap' }),
    useModal: () => ({ openModal: ui.openModal }),
  }
})

import {
  adminOnly,
  adminOrSelf,
  canAssignRoles,
  canReadInitialAdminRole,
  canCreateSite,
  canCreateSiteDocument,
  canCreateUser,
  canReadSiteDocuments,
  canReadSites,
  canWriteSiteDocuments,
  canWriteSites,
  enforceWritableParent,
  enforceWritableSite,
  filterWritableSites,
  getAuthorization,
  getSiteAndDescendantIDs,
  hideFromNonAdmins,
  relationshipID,
} from '../../src/access/authorization'
import {
  AssetFields,
  cleanCustomFieldValues,
  sanitizeCustomFieldValues,
} from '../../src/collections/AssetFields'
import { initializeAssetClasses } from '../../src/collections/AssetClasses'
import { AssetObservations } from '../../src/collections/AssetObservations'
import { Sites, filterSiteParents } from '../../src/collections/Sites'
import { TopologyLinks } from '../../src/collections/TopologyLinks'
import {
  UserRoles,
  ensureAdminRole,
  initializeAuthorization,
} from '../../src/collections/UserRoles'
import { Users } from '../../src/collections/Users'
import { Icon, Logo } from '../../src/components/Brand'
import BeforeDashboard from '../../src/components/BeforeDashboard'
import ImportInstructions from '../../src/components/ImportInstructions'
import LogoutButton from '../../src/components/LogoutButton'
import SiteTreeView, { buildSiteTree } from '../../src/components/SiteTreeView'
import { parseAssetSearch } from '../../src/search/assetLucene'
import { whereToLucene } from '../../src/search/whereToLucene'

const invoke = async (hook: unknown, args: unknown) =>
  (hook as (args: never) => unknown)(args as never)

const request = (role: Record<string, unknown> | undefined = undefined) => {
  const find = vi.fn(
    async ({
      collection,
      where,
    }: {
      collection: string
      where?: { parent?: { in?: unknown[] } }
    }) => {
      if (collection === 'user-roles') return { docs: role ? [role] : [] }
      const parents = (where?.parent?.in ?? []).map(String)
      return {
        docs: parents.includes('plant') ? [{ id: 'line' }, { id: 'plant' }] : [],
      }
    },
  )
  return {
    context: {},
    payload: { count: vi.fn(), create: vi.fn().mockResolvedValue({ id: 'admin-role' }), find },
    user: role ? { id: 'user-1', role: 'role-1' } : undefined,
  }
}

describe('site authorization', () => {
  it('resolves relationships, descendants, permissions, and the request cache', async () => {
    expect(relationshipID({ id: { id: 7 } })).toBe(7)
    expect(relationshipID(null)).toBeUndefined()

    const req = request({
      permissions: [
        { access: 'read-write', site: 'plant' },
        { access: 'read', site: { id: 'archive' } },
        { access: 'read', site: null },
      ],
    })
    expect(await getSiteAndDescendantIDs(['plant'], req as never)).toEqual(['plant', 'line'])
    const authorization = await getAuthorization(req as never)
    expect(authorization).toEqual({
      isAdmin: false,
      readableSiteIDs: ['plant', 'archive', 'line'],
      writableSiteIDs: ['plant', 'line'],
    })
    expect(await getAuthorization(req as never)).toBe(authorization)
    expect(req.payload.find).toHaveBeenCalledTimes(7)
  })

  it('handles anonymous, missing-role, and admin access', async () => {
    expect(await getAuthorization(request() as never)).toEqual({
      isAdmin: false,
      readableSiteIDs: [],
      writableSiteIDs: [],
    })
    const missing = request()
    missing.user = { id: 'user-1', role: 'missing' } as never
    expect(await getAuthorization(missing as never)).toMatchObject({ isAdmin: false })

    const admin = request({ isAdmin: true })
    expect(await adminOnly({ req: admin } as never)).toBe(true)
    expect(await adminOrSelf({ req: admin } as never)).toBe(true)
    expect(await canAssignRoles({ req: admin } as never)).toBe(true)
    expect(await canReadSites({ req: admin } as never)).toBe(true)
    expect(await canWriteSites({ req: admin } as never)).toBe(true)
    expect(await canReadSiteDocuments({ req: admin } as never)).toBe(true)
    expect(await canWriteSiteDocuments({ req: admin } as never)).toBe(true)
    expect(await filterWritableSites({ req: admin } as never)).toBe(true)
    expect(hideFromNonAdmins({ user: { role: { isAdmin: true } } })).toBe(false)
    expect(hideFromNonAdmins({ user: null })).toBe(true)
  })

  it('returns scoped filters and enforces writable sites', async () => {
    const req = request({ permissions: [{ access: 'read-write', site: 'plant' }] })
    expect(await adminOrSelf({ req } as never)).toEqual({ id: { equals: 'user-1' } })
    expect(await canReadSites({ req } as never)).toEqual({ id: { in: ['plant', 'line'] } })
    expect(await canWriteSites({ req } as never)).toEqual({ id: { in: ['plant', 'line'] } })
    expect(await canReadSiteDocuments({ req } as never)).toEqual({
      site: { in: ['plant', 'line'] },
    })
    expect(await canWriteSiteDocuments({ req } as never)).toEqual({
      site: { in: ['plant', 'line'] },
    })
    expect(await filterWritableSites({ req } as never)).toEqual({ id: { in: ['plant', 'line'] } })
    expect(await canCreateSite({ data: { parent: 'plant' }, req } as never)).toBe(true)
    expect(await canCreateSite({ data: { parent: 'other' }, req } as never)).toBe(false)
    expect(await canCreateSiteDocument({ data: { site: 'line' }, req } as never)).toBe(true)
    expect(await canCreateSiteDocument({ data: { site: 'other' }, req } as never)).toBe(false)
    expect(await canCreateSite({ req } as never)).toBe(true)
    expect(await canCreateSiteDocument({ req } as never)).toBe(true)

    await expect(invoke(enforceWritableSite, { data: { site: 'other' }, req })).rejects.toThrow(
      'write access',
    )
    await expect(invoke(enforceWritableParent, { data: { parent: 'other' }, req })).rejects.toThrow(
      'parent site',
    )
    expect(
      await invoke(enforceWritableSite, { data: {}, originalDoc: { site: 'plant' }, req }),
    ).toEqual({})
    expect(await invoke(enforceWritableParent, { data: {}, req })).toEqual({})
  })

  it('allows only the initial anonymous user creation', async () => {
    const req = request()
    req.payload.count
      .mockResolvedValueOnce({ totalDocs: 0 })
      .mockResolvedValueOnce({ totalDocs: 1 })
      .mockResolvedValueOnce({ totalDocs: 1 })
    expect(await canCreateUser({ req } as never)).toBe(true)
    expect(await canCreateUser({ req } as never)).toBe(false)
    expect(await canAssignRoles({ req } as never)).toBe(false)
    expect(await adminOrSelf({ req } as never)).toBe(false)

    const initialUserRequest = request()
    initialUserRequest.payload.count.mockResolvedValue({ totalDocs: 0 })
    expect(await canReadInitialAdminRole({ req: initialUserRequest } as never)).toEqual({
      isAdmin: { equals: true },
    })
    expect(await canAssignRoles({ req: initialUserRequest } as never)).toBe(true)
  })
})

describe('collection safety hooks', () => {
  it('filters parents and rejects hierarchy cycles and used-site deletion', async () => {
    const req = request({ permissions: [{ access: 'read-write', site: 'plant' }] })
    expect(await filterSiteParents({ id: 'plant', req } as never)).toEqual({
      and: [{ id: { not_in: ['plant', 'line'] } }, { id: { in: ['plant', 'line'] } }],
    })
    expect(await filterSiteParents({ req: request() } as never)).toBe(true)

    const cycleReq = {
      payload: { findByID: vi.fn().mockResolvedValue({ parent: 'site-1' }) },
    }
    await expect(
      invoke(Sites.hooks?.beforeChange?.[1], {
        data: { parent: 'site-2' },
        originalDoc: { id: 'site-1' },
        req: cycleReq,
      }),
    ).rejects.toThrow('own parent or descendant')
    expect(
      await invoke(Sites.hooks?.beforeChange?.[1], { data: {}, originalDoc: {}, req: cycleReq }),
    ).toEqual({})

    const deleteReq = { payload: { count: vi.fn().mockResolvedValue({ totalDocs: 0 }) } }
    await expect(
      invoke(Sites.hooks?.beforeDelete?.[0], { id: 'site-1', req: deleteReq }),
    ).resolves.toBeUndefined()
    deleteReq.payload.count.mockResolvedValueOnce({ totalDocs: 1 })
    await expect(
      invoke(Sites.hooks?.beforeDelete?.[0], { id: 'site-1', req: deleteReq }),
    ).rejects.toThrow('Move or delete')
  })

  it('protects field types and sanitizes configured custom values', async () => {
    expect(cleanCustomFieldValues(undefined, [])).toEqual({})
    expect(() => cleanCustomFieldValues([], [])).toThrow('must be an object')
    expect(() =>
      cleanCustomFieldValues({ number: Number.NaN }, [{ id: 'number', type: 'number' }]),
    ).toThrow('Invalid value')
    await expect(
      invoke(AssetFields.hooks?.beforeChange?.[0], {
        data: { type: 'number' },
        originalDoc: { type: 'text' },
      }),
    ).rejects.toThrow('cannot be changed')

    const data = { customFields: { known: 'value' }, untouched: true }
    const req = {
      payload: { find: vi.fn().mockResolvedValue({ docs: [{ id: 'known', type: 'text' }] }) },
    }
    expect(await invoke(sanitizeCustomFieldValues, { data, req })).toEqual(data)
  })

  it('protects the Admin role and assigns the first user', async () => {
    const protect = UserRoles.hooks?.beforeChange?.[0]
    expect(await invoke(protect, { context: {}, data: { name: 'Editor' } })).toEqual({
      isAdmin: false,
      name: 'Editor',
    })
    expect(
      await invoke(protect, { context: {}, data: {}, originalDoc: { isAdmin: true } }),
    ).toEqual({
      isAdmin: true,
      name: 'Admin',
      permissions: [],
    })

    const payload = {
      create: vi.fn().mockResolvedValue({ id: 'admin-role' }),
      find: vi
        .fn()
        .mockResolvedValueOnce({ docs: [] })
        .mockResolvedValueOnce({
          docs: [{ id: 'admin-role', isAdmin: true, name: 'Admin', permissions: [] }],
        })
        .mockResolvedValueOnce({ docs: [{ id: 'user-1' }] }),
      update: vi.fn(),
    }
    expect(await ensureAdminRole(payload as never)).toEqual({ id: 'admin-role' })
    await initializeAuthorization(payload as never)
    expect(payload.update).toHaveBeenCalledWith(expect.objectContaining({ id: 'user-1' }))

    const userReq = {
      payload: {
        count: vi.fn().mockResolvedValue({ totalDocs: 0 }),
        create: vi.fn(),
        find: vi.fn().mockResolvedValue({
          docs: [{ id: 'admin-role', isAdmin: true, name: 'Admin', permissions: [] }],
        }),
      },
    }
    expect(
      await invoke(Users.hooks?.beforeValidate?.[0], {
        data: { email: 'first@example.test' },
        operation: 'create',
        req: userReq,
      }),
    ).toMatchObject({ role: 'admin-role' })
    const roleField = Users.fields.find(
      (field) => field.type === 'relationship' && field.name === 'role',
    ) as {
      defaultValue: (args: { req: unknown }) => unknown
    }
    expect(await roleField.defaultValue({ req: userReq })).toBe('admin-role')
    expect(
      await invoke(Users.hooks?.beforeValidate?.[0], {
        data: {},
        operation: 'update',
        req: userReq,
      }),
    ).toEqual({})

    const repairedRole = {
      id: 'admin-role',
      isAdmin: false,
      name: 'Administrator',
      permissions: [],
    }
    const repairPayload = {
      find: vi.fn().mockResolvedValue({ docs: [repairedRole] }),
      update: vi.fn().mockResolvedValue({ ...repairedRole, isAdmin: true, name: 'Admin' }),
    }
    await ensureAdminRole(repairPayload as never)
    expect(repairPayload.update).toHaveBeenCalled()
  })

  it('seeds asset-class rules and migrates legacy asset fields', async () => {
    const updates: unknown[] = []
    const payload = {
      count: vi.fn().mockResolvedValue({ totalDocs: 1 }),
      find: vi.fn().mockImplementation(async ({ collection }: { collection: string }) => {
        if (collection === 'assets') {
          return {
            docs: [
              { id: 'asset-1', assetType: 'plc', fieldProvenance: { assetType: 'low' } },
              { id: 'asset-2', assetType: 42, fieldProvenance: [] },
            ],
          }
        }
        return { docs: [{ id: 'class-1', assignmentRules: [], ruleSeedVersion: 0 }] }
      }),
      update: vi.fn().mockImplementation(async (value: unknown) => {
        updates.push(value)
        return value
      }),
    }

    await initializeAssetClasses(payload as never)
    expect(updates.length).toBeGreaterThan(2)
    expect(updates.at(-1)).toMatchObject({
      data: { assetClass: 'class-1', assetType: null, fieldProvenance: {} },
      id: 'asset-2',
    })
  })

  it('keeps internal evidence collections immutable', async () => {
    for (const collection of [AssetObservations, TopologyLinks]) {
      expect(await invoke(collection.access?.create, {})).toBe(false)
      expect(await invoke(collection.access?.delete, {})).toBe(false)
      expect(await invoke(collection.access?.update, {})).toBe(false)
    }
    expect(Users.access?.admin?.({ req: { user: { id: '1' } } } as never)).toBe(true)
  })
})

describe('admin presentation', () => {
  it('renders dashboard metrics, actions, and recent assets', async () => {
    const payload = {
      count: vi
        .fn()
        .mockResolvedValueOnce({ totalDocs: 4 })
        .mockResolvedValueOnce({ totalDocs: 2 })
        .mockResolvedValueOnce({ totalDocs: 1 })
        .mockResolvedValueOnce({ totalDocs: 3 }),
      find: vi.fn().mockResolvedValue({
        docs: [
          {
            id: 'asset-1',
            ipAddress: '192.0.2.1',
            name: 'PLC',
            site: { id: 'site-1', name: 'Plant' },
            status: 'online',
            updatedAt: '2026-08-10',
          },
        ],
      }),
    }
    const view = await BeforeDashboard({
      payload: payload as never,
      permissions: {
        collections: {
          assets: { create: true },
          'asset-imports': { create: true },
          sites: { read: true },
        },
      } as never,
    })
    const html = renderToStaticMarkup(view)
    expect(html).toContain('Total assets</span><strong>4')
    expect(html).toContain('Manage sites')
    expect(html).toContain('PLC')
    expect(html).toContain('Plant')
  })

  it('renders empty dashboard and both site-list modes', async () => {
    const payload = {
      config: { routes: { admin: '/admin' } },
      count: vi.fn().mockResolvedValue({ totalDocs: 0 }),
      find: vi.fn().mockResolvedValue({ docs: [] }),
    }
    expect(renderToStaticMarkup(await BeforeDashboard({ payload: payload as never }))).toContain(
      'No assets yet',
    )
    expect(
      renderToStaticMarkup(await SiteTreeView({ enableRowSelections: false } as never)),
    ).toContain('Default list')
    expect(
      renderToStaticMarkup(
        await SiteTreeView({
          enableRowSelections: true,
          hasCreatePermission: false,
          newDocumentURL: '/admin/collections/sites/create',
          payload,
        } as never),
      ),
    ).toContain('No sites yet')
  })

  it('renders a site hierarchy and the small admin components', async () => {
    const sites = [
      { id: 'child', name: 'Line 2', parent: 'root', type: 'Line', updatedAt: '2026-08-10' },
      { id: 'root', name: 'Plant', parent: null, type: 'Plant', updatedAt: '2026-08-10' },
      { id: 'orphan', name: 'Remote', parent: 'missing', type: 'Site', updatedAt: '2026-08-10' },
    ]
    expect(buildSiteTree(sites as never).map(({ path }) => path)).toEqual([
      'Plant',
      'Plant / Line 2',
      'Remote',
    ])
    const view = await SiteTreeView({
      enableRowSelections: true,
      hasCreatePermission: true,
      newDocumentURL: '/admin/collections/sites/create',
      payload: {
        config: { routes: { admin: '/admin' } },
        find: vi.fn().mockResolvedValue({ docs: sites }),
      },
    } as never)
    const html = renderToStaticMarkup(view)
    expect(html).toContain('Add site')
    expect(html).toContain('Plant / Line 2')
    expect(html).toContain('View assets')
    expect(html).toContain('where%5Bsite%5D%5Bequals%5D=root')
    expect(renderToStaticMarkup(createElement(Icon))).toContain('OTserver')
    expect(renderToStaticMarkup(createElement(Logo))).toContain('otserver.org')
    expect(renderToStaticMarkup(createElement(LogoutButton))).toContain('Log out')
  })

  it('renders every import source and its selected state', () => {
    const html = renderToStaticMarkup(createElement(ImportInstructions))
    expect(html).toContain('Selected')
    expect(html).toContain('OTserver Scanner')
    expect(html).toContain('Copy command')
  })
})

describe('search edge cases', () => {
  it('serializes every graphical operator', () => {
    expect(whereToLucene()).toBe('')
    expect(whereToLucene({ and: [{}, { status: { equals: 'online' } }] })).toBe('status:"online"')
    expect(whereToLucene({ status: { in: ['online', 'offline'] } })).toBe(
      '(status:"online" OR status:"offline")',
    )
    expect(whereToLucene({ status: { not_in: ['offline'] } })).toBe('status:-"offline"')
    expect(whereToLucene({ protocols: { all: [{ value: 's7' }, { value: 'snmp' }] } })).toBe(
      '(protocols:"s7" AND protocols:"snmp")',
    )
    expect(whereToLucene({ osAccuracy: { greater_than: 1, less_than: 10 } })).toBe(
      '(osAccuracy:{1 TO *} AND osAccuracy:{* TO 10})',
    )
    expect(whereToLucene({ updatedAt: { less_than_equal: '2026-08-10' } })).toBe(
      String.raw`updatedAt:[* TO 2026\-08\-10]`,
    )
    expect(whereToLucene({ name: { not_like: 'PLC 1' } })).toBe('name:-*PLC\\ 1*')
    expect(whereToLucene({ ignored: [] } as never)).toBe('')
  })

  it('rejects unsafe or invalid Lucene features', () => {
    expect(parseAssetSearch('')).toEqual({})
    expect(parseAssetSearch('*')).toEqual({})
    expect(() => parseAssetSearch('x'.repeat(501))).toThrow('longer than 500')
    expect(() => parseAssetSearch('name:/PLC.*/')).toThrow('regular expressions')
    expect(() => parseAssetSearch('name:PLC~')).toThrow('fuzzy search')
    expect(() => parseAssetSearch('name:[A TO Z]')).toThrow('ranges are not supported')
    expect(() => parseAssetSearch('osAccuracy:[one TO 10]')).toThrow('valid number')
    expect(() => parseAssetSearch('lastSeen:[not-a-date TO *]')).toThrow('valid date')
  })
})
