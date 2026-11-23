import { randomUUID } from 'node:crypto'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { getPayload, type Payload } from 'payload'

import config from '@/payload.config'
import * as apiDocs from '@/apiDocs/openapi'
import { GET } from '@/app/(payload)/api-docs/openapi.json/route'
import ApiDocsView from '@/components/ApiDocsView'

vi.mock('@payloadcms/next/templates', () => ({
  DefaultTemplate: ({ children }: { children: React.ReactNode }) => children,
}))
vi.mock('@payloadcms/ui', () => ({
  Gutter: ({ children }: { children: React.ReactNode }) => children,
  Link: ({ children, href }: { children: React.ReactNode; href: string }) =>
    createElement('a', { href }, children),
}))

describe('API documentation', () => {
  let payload: Payload
  let roleID: string
  let userID: string
  const apiKey = randomUUID()

  beforeAll(async () => {
    payload = await getPayload({ config })
    const role = await payload.create({
      collection: 'user-roles',
      data: { name: `API documentation reader ${randomUUID()}`, permissions: [] },
    })
    roleID = role.id
    const user = await payload.create({
      collection: 'users',
      data: {
        apiKey,
        enableAPIKey: true,
        email: `api-docs-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: roleID,
      },
    })
    userID = user.id
  })

  afterAll(async () => {
    if (userID) await payload.delete({ collection: 'users', id: userID })
    if (roleID) await payload.delete({ collection: 'user-roles', id: roleID })
  })

  it('does not expose the plugin spec or docs UI without authentication', async () => {
    const configured = await config
    expect(configured.endpoints?.some(({ path }) => path === '/openapi.json')).toBe(false)
    expect(configured.endpoints?.some(({ path }) => path === '/docs')).toBe(false)

    for (const authorization of [undefined, 'Otter not-a-user']) {
      const response = await GET(
        new Request('http://localhost/api-docs/openapi.json', {
          headers: authorization ? { Authorization: authorization } : {},
        }),
      )
      expect(response.status).toBe(401)
      expect(response.headers.get('cache-control')).toBe('private, no-store')
    }
  })

  it('generates only the approved inventory reference for a non-admin user', async () => {
    const response = await GET(
      new Request('http://localhost/api-docs/openapi.json', {
        headers: { Authorization: `users API-Key ${apiKey}` },
      }),
    )
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('private, no-store')
    const document = await response.json()
    expect(document.openapi).toMatch(/^3\.1\./)
    expect(document.components.securitySchemes.PayloadToken).toMatchObject({
      type: 'apiKey',
      in: 'header',
      name: 'Authorization',
    })
    expect(document.components.schemas.SiteTypes).toMatchObject({
      type: 'object',
      description: 'Related document omitted from this inventory reference.',
    })
    expect(Object.keys(document.paths)).toContain('/api/assets')
    expect(Object.keys(document.paths)).toContain('/api/sites')
    expect(Object.keys(document.paths)).toContain('/api/asset-imports')
    expect(Object.keys(document.paths)).toEqual(
      expect.arrayContaining(['/api/asset-classes', '/api/tags']),
    )
    expect(
      Object.keys(document.paths).every((path) =>
        /^\/api\/(assets|sites|asset-classes|tags|tag-groups|asset-imports)(\/|$)/.test(path),
      ),
    ).toBe(true)
    const contents = JSON.stringify(document)
    expect(contents).not.toContain(apiKey)
    expect(contents).not.toContain('credentialHash')
    expect(contents).not.toContain('/api/otter/v1')
    expect(contents).not.toContain('/api/users')
    expect(contents).not.toContain('/api/payload-jobs')
    expect(contents).not.toContain('/api/audit-logs')
    for (const [, name] of contents.matchAll(/"#\/components\/schemas\/([^"]+)"/g))
      expect(document.components.schemas).toHaveProperty(name)
  })

  it('shows the generated endpoints and practical examples inside the admin view', async () => {
    await expect(
      ApiDocsView({
        payload,
        initPageResult: {
          req: { user: null },
          permissions: {},
          visibleEntities: { collections: [], globals: [] },
        },
      } as never),
    ).rejects.toThrow()

    await expect(
      ApiDocsView({
        payload,
        initPageResult: {
          req: { user: { otterScannerID: 'scanner-1' } },
          permissions: {},
          visibleEntities: { collections: [], globals: [] },
        },
      } as never),
    ).rejects.toThrow()

    const user = await payload.findByID({ collection: 'users', id: userID })
    const html = renderToStaticMarkup(
      await ApiDocsView({
        payload,
        initPageResult: {
          req: { user },
          permissions: {},
          visibleEntities: { collections: [], globals: [] },
        },
      } as never),
    )
    expect(html).toContain('API documentation')
    expect(html).toContain('POST')
    expect(html).toContain('/api/assets')
    expect(html).toContain('where[site][equals]')
    expect(html).toContain('/api-docs/openapi.json')
    expect(html).not.toContain('/api/otter/v1')
    expect((await apiDocs.getApiDocument(payload)).paths?.['/api/assets']).toBeDefined()
  })

  it('handles missing operation metadata and an empty OpenAPI paths object', async () => {
    const getApiDocument = vi.spyOn(apiDocs, 'getApiDocument')
    getApiDocument
      .mockReturnValueOnce({
        paths: {
          '/api/assets': {
            get: { summary: 'List assets' },
            post: {},
            patch: { summary: 42 },
            put: null,
            delete: 'invalid operation',
            options: { summary: 'Not an inventory method' },
          },
          '/empty': null,
        },
      } as never)
      .mockReturnValueOnce({ paths: null } as never)

    try {
      const user = await payload.findByID({ collection: 'users', id: userID })
      const props = {
        payload,
        initPageResult: {
          req: { user },
          permissions: {},
          visibleEntities: { collections: [], globals: [] },
        },
      } as never

      const html = renderToStaticMarkup(await ApiDocsView(props))
      expect(html).toContain('List assets')
      expect(html).toContain('invalid operation')
      expect(html).not.toContain('Not an inventory method')

      const emptyHtml = renderToStaticMarkup(await ApiDocsView(props))
      expect(emptyHtml).toContain('No inventory endpoints are available in this reference.')
    } finally {
      getApiDocument.mockRestore()
    }
  })

  it('rejects requests for an unconfigured OpenAPI plugin', () => {
    expect(() => apiDocs.getApiDocument({ config: {} } as Payload)).toThrow(
      'The OpenAPI plugin is not configured.',
    )
  })
})
