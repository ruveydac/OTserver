import config from '@/payload.config'
import { randomBytes, randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { getPayload, type Payload } from 'payload'

import { getAuditChanges } from '../../src/collections/AuditLogs'
import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { ensureAdminRole } from '../../src/collections/UserRoles'

let payload: Payload
let plcClassID: string

describe('audit log', () => {
  beforeAll(async () => {
    payload = await getPayload({ config })
    plcClassID = (await ensureAssetClass(payload, 'plc')).id
  })

  it('records asset and configuration changes without secrets', async () => {
    expect(
      getAuditChanges(
        { password: 'old', status: 'offline' },
        { password: 'new', status: 'online' },
      ),
    ).toEqual({ status: { after: 'online', before: 'offline' } })

    const adminRole = await ensureAdminRole(payload)
    const password = randomUUID()
    const user = await payload.create({
      collection: 'users',
      data: {
        email: `audit-${randomUUID()}@example.test`,
        password,
        role: adminRole.id,
      },
    })
    await payload.login({
      collection: 'users',
      data: { email: user.email, password },
    })
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Audit site ${randomUUID()}`, type: 'Test site' },
      overrideAccess: false,
      user,
    })
    const asset = await payload.create({
      collection: 'assets',
      data: {
        assetClass: plcClassID,
        criticality: 'medium',
        macAddress: `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`,
        name: 'Audited PLC',
        site: site.id,
        status: 'offline',
      },
      overrideAccess: false,
      user,
    })
    const setting = await payload.create({
      collection: 'asset-fields',
      data: { label: `Audited field ${randomUUID()}`, type: 'text' },
      overrideAccess: false,
      user,
    })
    await payload.update({
      collection: 'asset-fields',
      data: { description: 'Tracked setting change' },
      id: setting.id,
      overrideAccess: false,
      user,
    })

    await payload.update({
      collection: 'assets',
      data: { status: 'online' },
      id: asset.id,
      overrideAccess: false,
      user,
    })
    const readerRole = await payload.create({
      collection: 'user-roles',
      data: {
        name: `Audit reader ${randomUUID()}`,
        permissions: [{ access: 'read', site: site.id }],
      },
      overrideAccess: false,
      user,
    })
    const reader = await payload.create({
      collection: 'users',
      data: {
        email: `audit-reader-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: readerRole.id,
      },
      overrideAccess: false,
      user,
    })
    const readerAssetLogs = await payload.find({
      collection: 'audit-logs',
      overrideAccess: false,
      pagination: false,
      sort: 'createdAt',
      user: reader,
      where: { assetID: { equals: asset.id } },
    })
    expect(readerAssetLogs.docs.map(({ action }) => action)).toEqual(['create', 'update'])
    const readerSettingLogs = await payload.find({
      collection: 'audit-logs',
      overrideAccess: false,
      user: reader,
      where: { documentID: { equals: setting.id } },
    })
    expect(readerSettingLogs.totalDocs).toBe(0)

    await payload.delete({
      collection: 'assets',
      id: asset.id,
      overrideAccess: false,
      user,
    })

    const assetLogs = await payload.find({
      collection: 'audit-logs',
      depth: 0,
      pagination: false,
      sort: 'createdAt',
      where: { assetID: { equals: asset.id } },
    })
    expect(assetLogs.docs.map(({ action }) => action)).toEqual(['create', 'update', 'delete'])
    expect(assetLogs.docs.every(({ asset: relatedAsset }) => relatedAsset === asset.id)).toBe(true)
    expect(assetLogs.docs.every(({ actorID }) => actorID === user.id)).toBe(true)
    expect(assetLogs.docs[1]?.changes).toMatchObject({
      status: { after: 'online', before: 'offline' },
    })

    const settingLogs = await payload.find({
      collection: 'audit-logs',
      where: {
        and: [
          { targetCollection: { equals: 'asset-fields' } },
          { documentID: { equals: setting.id } },
        ],
      },
      pagination: false,
      sort: 'createdAt',
    })
    expect(settingLogs.docs.map(({ action }) => action)).toEqual(['create', 'update'])
    expect(settingLogs.docs[1]?.changes).toMatchObject({
      description: { after: 'Tracked setting change' },
    })

    const loginLogs = await payload.find({
      collection: 'audit-logs',
      where: {
        and: [{ action: { equals: 'login' } }, { actorID: { equals: user.id } }],
      },
    })
    expect(loginLogs.totalDocs).toBe(1)

    await expect(
      payload.update({
        collection: 'audit-logs',
        data: { summary: 'tampered' },
        id: assetLogs.docs[0]!.id,
        overrideAccess: false,
        user,
      }),
    ).rejects.toThrow()

    await payload.delete({ collection: 'asset-fields', id: setting.id })
    await payload.delete({ collection: 'users', id: reader.id })
    await payload.delete({ collection: 'user-roles', id: readerRole.id })
    await payload.delete({ collection: 'sites', id: site.id })
    await payload.delete({ collection: 'users', id: user.id })

    const logs = await payload.find({
      collection: 'audit-logs',
      pagination: false,
      where: {
        or: [
          { actorID: { equals: user.id } },
          {
            documentID: {
              in: [asset.id, reader.id, readerRole.id, setting.id, site.id, user.id],
            },
          },
        ],
      },
    })
    for (const log of logs.docs) await payload.delete({ collection: 'audit-logs', id: log.id })
  })
})
