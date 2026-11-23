import { randomUUID } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createLocalReq, getPayload, handleEndpoints, type Payload } from 'payload'

import config from '@/payload.config'
import { GET as getApiDocs } from '@/app/(payload)/api-docs/openapi.json/route'
import { ensureAdminRole } from '@/collections/UserRoles'
import { siteTypeID } from '../siteType'

describe('MCP inventory access', () => {
  let payload: Payload
  let adminID: string
  let readerID: string
  let roleID: string
  let keyID: string
  let originalEnabled: boolean | null | undefined
  const sites: string[] = []
  const assets: string[] = []
  const key = randomUUID()
  const visibleName = `MCP visible ${randomUUID()}`
  const hiddenName = `MCP hidden ${randomUUID()}`

  const callMcp = async (authorization?: string, method = 'tools/list', params?: unknown) => {
    const request = new Request('http://localhost/api/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        ...(authorization ? { Authorization: authorization } : {}),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }),
    })
    const req = await createLocalReq(
      {
        req: {
          body: request.body,
          headers: request.headers,
          method: request.method,
          url: request.url,
        } as never,
      },
      payload,
    )
    const endpoint = payload.config.endpoints?.find(
      ({ method, path }) => method === 'post' && path === '/mcp',
    )
    if (!endpoint) throw new Error('MCP endpoint is missing.')
    return endpoint.handler(req)
  }

  const expectKeyRejectedOutsideMcp = async () => {
    const authorization = `payload-mcp-api-keys API-Key ${key}`
    const rest = await handleEndpoints({
      config: payload.config,
      path: '/api/asset-fields',
      request: new Request('http://localhost/api/asset-fields', {
        headers: { Authorization: authorization },
      }),
    })
    expect(rest.status).toBe(403)
    const docs = await getApiDocs(
      new Request('http://localhost/api-docs/openapi.json', {
        headers: { Authorization: authorization },
      }),
    )
    expect(docs.status).toBe(401)
  }

  beforeAll(async () => {
    payload = await getPayload({ config })
    expect(
      payload.config.collections.find(({ slug }) => slug === 'payload-mcp-api-keys')?.labels.plural,
    ).toBe('MCP keys')
    originalEnabled = (await payload.findGlobal({ slug: 'application-settings' })).mcpEnabled
    const type = await siteTypeID(payload)
    for (const name of ['Allowed', 'Other']) {
      const site = await payload.create({
        collection: 'sites',
        data: { name: `MCP ${name} ${randomUUID()}`, type },
      })
      sites.push(site.id)
    }
    const role = await payload.create({
      collection: 'user-roles',
      data: {
        name: `MCP reader ${randomUUID()}`,
        permissions: [{ site: sites[0], access: 'read' }],
      },
    })
    roleID = role.id
    const adminRole = await ensureAdminRole(payload)
    const admin = await payload.create({
      collection: 'users',
      data: {
        email: `mcp-admin-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: adminRole.id,
      },
    })
    adminID = admin.id
    const reader = await payload.create({
      collection: 'users',
      data: {
        email: `mcp-reader-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: roleID,
      },
    })
    readerID = reader.id
    const assetClass = (await payload.find({ collection: 'asset-classes', limit: 1 })).docs[0].id
    for (const [name, site] of [
      [visibleName, sites[0]],
      [hiddenName, sites[1]],
    ] as const) {
      const asset = await payload.create({
        collection: 'assets',
        data: { name, site, assetClass, status: 'unknown' },
      })
      assets.push(asset.id)
    }
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { mcpEnabled: false },
      overrideAccess: false,
      user: admin,
    })
  })

  afterAll(async () => {
    if (!payload) return
    if (adminID) {
      await payload.updateGlobal({
        slug: 'application-settings',
        data: { mcpEnabled: originalEnabled === true },
      })
    }
    if (keyID) await payload.delete({ collection: 'payload-mcp-api-keys', id: keyID })
    for (const id of assets) await payload.delete({ collection: 'assets', id })
    if (readerID) await payload.delete({ collection: 'users', id: readerID })
    if (adminID) await payload.delete({ collection: 'users', id: adminID })
    if (roleID) await payload.delete({ collection: 'user-roles', id: roleID })
    for (const id of sites) await payload.delete({ collection: 'sites', id })
  })

  it('defaults off and reserves key issuance for administrators', async () => {
    const reader = await payload.findByID({ collection: 'users', id: readerID })
    const admin = await payload.findByID({ collection: 'users', id: adminID })
    await expect(callMcp()).rejects.toMatchObject({ status: 401 })
    await expect(
      payload.updateGlobal({
        slug: 'application-settings',
        data: { mcpEnabled: true },
        overrideAccess: false,
        user: reader,
      }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      payload.create({
        collection: 'payload-mcp-api-keys',
        data: { user: readerID, apiKey: randomUUID(), label: 'Denied' },
        overrideAccess: false,
        user: reader,
      }),
    ).rejects.toMatchObject({ status: 403 })
    const created = await payload.create({
      collection: 'payload-mcp-api-keys',
      data: {
        user: readerID,
        apiKey: key,
        enableAPIKey: true,
        label: 'Site reader',
        assets: { find: true },
        sites: { find: true },
      },
      overrideAccess: false,
      user: admin,
    })
    keyID = created.id
    expect(created.user).toMatchObject({ id: readerID })
    await expect(
      payload.find({ collection: 'payload-mcp-api-keys', overrideAccess: false, user: reader }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      payload.find({ collection: 'users', overrideAccess: false, user: created }),
    ).rejects.toMatchObject({ status: 403 })
    const audit = await payload.find({
      collection: 'audit-logs',
      limit: 1,
      where: { targetCollection: { equals: 'payload-mcp-api-keys' } },
    })
    expect(audit.docs[0]).toMatchObject({ action: 'create', actorEmail: admin.email })
    expect(JSON.stringify(audit.docs[0])).not.toContain(key)
    await expect(callMcp(`Bearer ${key}`)).rejects.toMatchObject({ status: 401 })
    await expectKeyRejectedOutsideMcp()
  })

  it('enables read-only tools without expanding the key owner’s site scope', async () => {
    const admin = await payload.findByID({ collection: 'users', id: adminID })
    await payload.updateGlobal({
      slug: 'application-settings',
      data: { mcpEnabled: true },
      overrideAccess: false,
      user: admin,
    })
    await expect(callMcp()).rejects.toMatchObject({ status: 401 })
    await expect(callMcp('Bearer not-a-key')).rejects.toMatchObject({ status: 401 })

    const listed = await callMcp(`Bearer ${key}`)
    expect(listed.status).toBe(200)
    await expectKeyRejectedOutsideMcp()
    const listing = await listed.text()
    expect(listing).toContain('findAssets')
    expect(listing).toContain('findSites')
    expect(listing).not.toContain('createAssets')
    expect(listing).not.toContain('findUsers')

    const found = await callMcp(`Bearer ${key}`, 'tools/call', {
      name: 'findAssets',
      arguments: { where: JSON.stringify({ name: { contains: 'MCP ' } }) },
    })
    expect(found.status).toBe(200)
    const result = await found.text()
    expect(result).toContain(visibleName)
    expect(result).not.toContain(hiddenName)

    await payload.updateGlobal({
      slug: 'application-settings',
      data: { mcpEnabled: false },
      overrideAccess: false,
      user: admin,
    })
    await expect(callMcp(`Bearer ${key}`)).rejects.toMatchObject({ status: 401 })
  })
})
