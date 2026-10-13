import config from '@/payload.config'
import { randomBytes, randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { getPayload, type Payload } from 'payload'

import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { loadAssetPanel } from '../../src/application/assetPanel'

let payload: Payload
let assetClassID: string

beforeAll(async () => {
  payload = await getPayload({ config })
  assetClassID = (await ensureAssetClass(payload, 'other')).id
})

const randomMAC = () =>
  `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`

describe('asset panel read interface', () => {
  it('bounds panel page sizes and scopes legacy history without a UUID', async () => {
    const calls: { collection: string; limit?: number; where?: unknown }[] = []
    const payload = {
      count: vi.fn(async () => ({ totalDocs: 0 })),
      find: vi.fn(async (args: { collection: string; limit?: number; where?: unknown }) => {
        calls.push(args)
        return { docs: [], hasNextPage: false }
      }),
      findByID: vi.fn(async ({ collection }: { collection: string }) =>
        collection === 'sites'
          ? { id: 'site-1', name: 'Test site', path: 'Test site' }
          : { id: 'class-1', name: 'Other' },
      ),
    }
    const asset = { id: 'legacy-asset', site: 'site-1', assetClass: 'class-1', uuid: null }

    for (const [pageSize, expectedLimit] of [
      [0, 1],
      [101, 100],
      [1.5, 50],
    ]) {
      calls.length = 0
      await loadAssetPanel({
        asset: asset as never,
        payload: payload as never,
        historyPage: 1,
        discoveryPage: 1,
        topologyPage: 1,
        pageSize,
      })
      expect(calls.filter(({ collection }) => collection === 'audit-logs')[0]).toMatchObject({
        limit: expectedLimit,
        where: { asset: { equals: asset.id } },
      })
    }
  })

  it('paginates history and scopes related reads to the authorized site', async () => {
    let siteID: string | undefined
    let otherSiteID: string | undefined
    let roleID: string | undefined
    let userID: string | undefined
    const assetIDs: string[] = []

    try {
      const site = await payload.create({
        collection: 'sites',
        data: { name: `Asset panel ${randomUUID()}`, type: 'Plant' },
      })
      siteID = site.id
      const otherSite = await payload.create({
        collection: 'sites',
        data: { name: `Other panel ${randomUUID()}`, type: 'Plant' },
      })
      otherSiteID = otherSite.id
      const role = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Asset panel reader ${randomUUID()}`,
          permissions: [{ site: site.id, access: 'read' }],
        },
      })
      roleID = role.id
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `asset-panel-${randomUUID()}@example.test`,
          name: 'Asset panel reader',
          password: randomUUID(),
          role: role.id,
        },
      })
      userID = user.id
      const asset = await payload.create({
        collection: 'assets',
        data: {
          assetClass: assetClassID,
          criticality: 'medium',
          macAddress: randomMAC(),
          name: 'Panel asset',
          site: site.id,
          status: 'offline',
        },
      })
      assetIDs.push(asset.id)
      const foreign = await payload.create({
        collection: 'assets',
        data: {
          assetClass: assetClassID,
          criticality: 'medium',
          macAddress: randomMAC(),
          name: 'Foreign panel asset',
          site: otherSite.id,
          status: 'offline',
        },
      })
      assetIDs.push(foreign.id)
      await payload.update({ collection: 'assets', id: asset.id, data: { status: 'online' } })
      const readerAsset = await payload.findByID({
        collection: 'assets',
        id: asset.id,
        depth: 1,
        overrideAccess: false,
        user,
      })

      const firstPage = await loadAssetPanel({
        asset: readerAsset,
        payload,
        user,
        historyPage: 1,
        discoveryPage: 1,
        topologyPage: 1,
        pageSize: 1,
      })
      const secondPage = await loadAssetPanel({
        asset: readerAsset,
        payload,
        user,
        historyPage: 2,
        discoveryPage: 1,
        topologyPage: 1,
        pageSize: 1,
      })

      expect(firstPage.auditLogs).toMatchObject({ page: 1, totalPages: expect.any(Number) })
      expect(firstPage.auditLogs.totalPages).toBeGreaterThan(1)
      expect(firstPage.auditLogs.docs).toHaveLength(1)
      expect(secondPage.auditLogs.page).toBe(2)
      expect(secondPage.auditLogs.docs).toHaveLength(1)
      expect(firstPage.auditLogs.docs[0]?.id).not.toBe(secondPage.auditLogs.docs[0]?.id)
      expect(
        [...firstPage.auditLogs.docs, ...secondPage.auditLogs.docs].every(
          ({ assetID: target }) => target === asset.id,
        ),
      ).toBe(true)
      expect(firstPage.historyScopeTruncated).toBe(false)
    } finally {
      for (const assetID of assetIDs)
        await payload.delete({ collection: 'assets', id: assetID }).catch(() => {})
      for (const site of [siteID, otherSiteID])
        if (site) await payload.delete({ collection: 'sites', id: site }).catch(() => {})
      if (userID) await payload.delete({ collection: 'users', id: userID }).catch(() => {})
      if (roleID) await payload.delete({ collection: 'user-roles', id: roleID }).catch(() => {})
    }
  })
})
