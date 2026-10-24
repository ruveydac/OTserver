import { randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { getPayload, type Payload } from 'payload'
import config from '@/payload.config'
import { siteTypeID } from '../siteType'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})

describe('Otter deletion', () => {
  it('deletes dependencies in order and preserves run history', async () => {
    const oldEncryptionKey = process.env.OTSERVER_OTTER_ENCRYPTION_KEY
    const siteName = `Otter deletion site ${randomUUID()}`
    const email = `otter-deletion-${randomUUID()}@example.test`
    const password = randomUUID()
    let siteID: string | undefined
    let roleID: string | undefined
    let userID: string | undefined
    let scannerID: string | undefined
    let profileID: string | undefined
    let scheduleID: string | undefined
    let historyRunID: string | undefined
    let queuedRunID: string | undefined

    try {
      process.env.OTSERVER_OTTER_ENCRYPTION_KEY = 'b'.repeat(64)
      const site = await payload.create({
        collection: 'sites',
        data: { name: siteName, type: await siteTypeID(payload) },
      })
      siteID = site.id
      const role = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Otter deletion role ${randomUUID()}`,
          otterConfig: true,
          permissions: [{ site: site.id, access: 'read-write' }],
        },
      })
      roleID = role.id
      const user = await payload.create({
        collection: 'users',
        data: { email, name: 'Otter deletion operator', password, role: role.id },
      })
      userID = user.id
      const scanner = await payload.create({
        collection: 'otter-scanners',
        data: { name: 'Deletion scanner', site: site.id, enabled: true },
        overrideAccess: true,
      })
      scannerID = scanner.id
      const profile = await payload.create({
        collection: 'otter-profiles',
        data: {
          name: 'Deletion configuration',
          site: site.id,
          scanner: scanner.id,
          configuration: { targets: ['192.0.2.10'] },
        },
        overrideAccess: false,
        user,
      })
      profileID = profile.id
      const schedule = await payload.create({
        collection: 'otter-schedules',
        data: {
          name: 'Deletion schedule',
          profile: profile.id,
          scheduleType: 'interval',
          intervalMinutes: 5,
          timezone: 'UTC',
        } as never,
        overrideAccess: false,
        user,
      })
      scheduleID = schedule.id
      const historyRun = await payload.create({
        collection: 'otter-runs',
        data: {
          name: 'Historical deletion run',
          site: site.id,
          scanner: scanner.id,
          profile: profile.id,
          schedule: schedule.id,
          status: 'completed',
          configSnapshot: { targets: ['192.0.2.10'] },
        },
        overrideAccess: true,
        user,
      })
      historyRunID = historyRun.id

      await expect(
        payload.delete({
          collection: 'otter-scanners',
          id: scanner.id,
          overrideAccess: false,
          user,
        }),
      ).rejects.toMatchObject({ status: 409 })
      await expect(
        payload.delete({
          collection: 'otter-profiles',
          id: profile.id,
          overrideAccess: false,
          user,
        }),
      ).rejects.toMatchObject({ status: 409 })

      await payload.delete({
        collection: 'otter-schedules',
        id: schedule.id,
        overrideAccess: false,
        user,
      })
      expect(
        await payload.findByID({
          collection: 'otter-runs',
          id: historyRun.id,
          depth: 0,
          overrideAccess: true,
        }),
      ).toMatchObject({ schedule: schedule.id })
      await payload.delete({
        collection: 'otter-profiles',
        id: profile.id,
        overrideAccess: false,
        user,
      })
      expect(
        await payload.findByID({
          collection: 'otter-runs',
          id: historyRun.id,
          depth: 0,
          overrideAccess: true,
        }),
      ).toMatchObject({ profile: profile.id })

      const queuedRun = await payload.create({
        collection: 'otter-runs',
        data: {
          name: 'Pending deletion run',
          site: site.id,
          scanner: scanner.id,
          status: 'queued',
        },
        overrideAccess: true,
        user,
      })
      queuedRunID = queuedRun.id
      await expect(
        payload.delete({
          collection: 'otter-scanners',
          id: scanner.id,
          overrideAccess: false,
          user,
        }),
      ).rejects.toMatchObject({ status: 409 })
      await payload.update({
        collection: 'otter-runs',
        id: queuedRun.id,
        data: { status: 'cancelled', completedAt: new Date().toISOString() },
        overrideAccess: true,
        user,
      })
      await payload.delete({
        collection: 'otter-scanners',
        id: scanner.id,
        overrideAccess: false,
        user,
      })

      expect(
        await payload.findByID({
          collection: 'otter-runs',
          id: historyRun.id,
          depth: 0,
          overrideAccess: true,
        }),
      ).toMatchObject({ scanner: scanner.id, profile: profile.id, schedule: schedule.id })
    } finally {
      if (queuedRunID)
        await payload
          .delete({ collection: 'otter-runs', id: queuedRunID, overrideAccess: true })
          .catch(() => {})
      if (historyRunID)
        await payload
          .delete({ collection: 'otter-runs', id: historyRunID, overrideAccess: true })
          .catch(() => {})
      if (scheduleID)
        await payload
          .delete({ collection: 'otter-schedules', id: scheduleID, overrideAccess: true })
          .catch(() => {})
      if (profileID)
        await payload
          .delete({ collection: 'otter-profiles', id: profileID, overrideAccess: true })
          .catch(() => {})
      if (scannerID)
        await payload
          .delete({ collection: 'otter-scanners', id: scannerID, overrideAccess: true })
          .catch(() => {})
      if (userID) await payload.delete({ collection: 'users', id: userID }).catch(() => {})
      if (roleID)
        await payload
          .delete({ collection: 'user-roles', id: roleID, overrideAccess: true })
          .catch(() => {})
      if (siteID) await payload.delete({ collection: 'sites', id: siteID }).catch(() => {})
      if (oldEncryptionKey === undefined) delete process.env.OTSERVER_OTTER_ENCRYPTION_KEY
      else process.env.OTSERVER_OTTER_ENCRYPTION_KEY = oldEncryptionKey
    }
  })
})
