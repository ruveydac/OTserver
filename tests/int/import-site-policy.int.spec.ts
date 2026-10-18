import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  createLocalReq,
  createPayloadRequest,
  getPayload,
  type Payload,
  type PayloadRequest,
} from 'payload'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import {
  assertSiteAllowsImports,
  filterImportSites,
  IMPORTS_BLOCKED_MESSAGE,
  importableSitesWhere,
} from '../../src/application/importSites'
import { executeQueuedImport, retryImport } from '../../src/application/queuedImports'
import { processImport } from '../../src/application/processImport'
import { inTransaction } from '../../src/integrations/payload/transactions'
import {
  createOtterScanner,
  enrollOtter,
  finishOtterRun,
  heartbeatOtterRun,
  otterOverview,
  pollOtter,
  reenrollOtterScanner,
  revokeOtterScanner,
  runOtterNow,
  startOtterRun,
} from '../../src/otter/controller'
import type { AssetImport, Site, SiteType, User } from '../../src/payload-types'

let payload: Payload
let blockedType: SiteType
let allowedType: SiteType
let parent: Site
let child: Site
let foreign: Site
let admin: User
let operator: User
let roleID: string
let jwt: string
const scanners: string[] = []
const imports: string[] = []
const oldURL = process.env.OTSERVER_PUBLIC_URL
const oldQueued = process.env.OTSERVER_QUEUED_IMPORTS

const request = async (route: string, token = jwt, body?: unknown, id?: string) => {
  const req = await createPayloadRequest({
    config: payload.config,
    request: new Request(`https://otserver.example/api${route}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        Origin: 'https://otserver.example',
        Authorization: token,
        'Content-Type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
  })
  if (id) req.routeParams = { id }
  return req
}

const nmap = Buffer.from(
  '<nmaprun scanner="nmap" version="7.95"><host><status state="up"/><address addr="192.0.2.42" addrtype="ipv4"/><address addr="02:00:00:12:34:56" addrtype="mac"/><hostnames><hostname name="Policy PLC"/></hostnames></host></nmaprun>',
)
const upload = async (
  site: string,
  source: AssetImport['source'] = 'nmap',
  queued = false,
  req?: PayloadRequest,
) => {
  const result = await payload.create({
    collection: 'asset-imports',
    data: {
      site,
      source,
      sourceVersion: 'test',
      status: 'pending',
      executionMode: queued ? 'queued' : 'sync',
    },
    file: {
      name: `${randomUUID()}.xml`,
      data: nmap,
      mimetype: 'application/xml',
      size: nmap.length,
    },
    overrideAccess: false,
    ...(req ? { req } : { user: operator }),
  })
  imports.push(result.id)
  return result
}

const setBlocked = (blockImports: boolean) =>
  payload.update({
    collection: 'site-types',
    id: allowedType.id,
    data: { blockImports },
    overrideAccess: false,
    user: admin,
  })

beforeAll(async () => {
  process.env.OTSERVER_PUBLIC_URL = 'https://otserver.example'
  process.env.OTSERVER_QUEUED_IMPORTS = 'on'
  payload = await getPayload({ config })
  blockedType = await payload.create({
    collection: 'site-types',
    data: {
      name: `Blocked type ${randomUUID()}`,
      key: randomUUID(),
      category: 'geographic',
      active: true,
      blockImports: true,
    },
  })
  allowedType = await payload.create({
    collection: 'site-types',
    data: {
      name: `Allowed type ${randomUUID()}`,
      key: randomUUID(),
      category: 'production',
      active: true,
    },
  })
  parent = await payload.create({
    collection: 'sites',
    data: { name: `Country ${randomUUID()}`, type: blockedType.id },
  })
  child = await payload.create({
    collection: 'sites',
    data: { name: 'Plant', type: allowedType.id, parent: parent.id },
  })
  foreign = await payload.create({
    collection: 'sites',
    data: { name: `Foreign ${randomUUID()}`, type: allowedType.id },
  })
  admin = await payload.create({
    collection: 'users',
    data: {
      email: `${randomUUID()}@example.test`,
      password: randomUUID(),
      role: (await ensureAdminRole(payload)).id,
    },
  })
  const role = await payload.create({
    collection: 'user-roles',
    data: {
      name: `Import policy operator ${randomUUID()}`,
      otterConfig: true,
      permissions: [{ site: parent.id, access: 'read-write' }],
    },
  })
  roleID = role.id
  const password = randomUUID()
  operator = await payload.create({
    collection: 'users',
    data: { email: `${randomUUID()}@example.test`, password, role: role.id },
  })
  jwt = `JWT ${(await payload.login({ collection: 'users', data: { email: operator.email, password } })).token}`
})

afterAll(async () => {
  for (const id of imports) await payload.delete({ collection: 'asset-imports', id })
  for (const collection of ['otter-runs', 'otter-schedules', 'otter-profiles'] as const)
    await payload.delete({ collection, where: { scanner: { in: scanners } } })
  for (const id of scanners) await payload.delete({ collection: 'otter-scanners', id })
  await payload.delete({ collection: 'assets', where: { site: { in: [parent.id, child.id] } } })
  for (const user of [operator, admin]) await payload.delete({ collection: 'users', id: user.id })
  await payload.delete({ collection: 'user-roles', id: roleID })
  for (const site of [child, parent, foreign])
    await payload.delete({ collection: 'sites', id: site.id })
  for (const type of [blockedType, allowedType])
    await payload.delete({ collection: 'site-types', id: type.id })
  if (oldURL === undefined) delete process.env.OTSERVER_PUBLIC_URL
  else process.env.OTSERVER_PUBLIC_URL = oldURL
  if (oldQueued === undefined) delete process.env.OTSERVER_QUEUED_IMPORTS
  else process.env.OTSERVER_QUEUED_IMPORTS = oldQueued
})

describe('site-type import restrictions', () => {
  it('inherits only the exact site type and filters destinations without altering inventory access', async () => {
    expect(allowedType.blockImports).toBe(false)
    const req = await createLocalReq({ user: operator }, payload)
    await expect(assertSiteAllowsImports(parent.id, req)).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    await expect(assertSiteAllowsImports({ id: child.id }, req)).resolves.toBeUndefined()
    await expect(assertSiteAllowsImports(foreign.id, req)).rejects.toThrow()
    const filtered = await payload.find({
      collection: 'sites',
      overrideAccess: false,
      user: operator,
      where: await filterImportSites('asset-imports')({ req } as never),
    })
    expect(filtered.docs.map(({ id }) => id)).toEqual([child.id])
    const all = await payload.find({ collection: 'sites', overrideAccess: false, user: operator })
    expect(all.docs.map(({ id }) => id)).toEqual(expect.arrayContaining([parent.id, child.id]))
    await expect(
      payload.update({
        collection: 'site-types',
        id: blockedType.id,
        data: { blockImports: false },
        overrideAccess: false,
        user: operator,
      }),
    ).rejects.toMatchObject({ status: 403 })
    const assetClass = (await payload.find({ collection: 'asset-classes', limit: 1 })).docs[0].id
    await payload.create({
      collection: 'assets',
      data: {
        name: 'Manually recorded asset',
        site: parent.id,
        assetClass,
        criticality: 'low',
        status: 'unknown',
      },
      overrideAccess: false,
      user: operator,
    })
    for (const source of ['proneta', 'nmap', 'otserver-otter'] as const)
      await expect(upload(parent.id, source)).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    await expect(upload(parent.id, 'nmap', true)).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    expect(
      (await payload.count({ collection: 'asset-imports', where: { site: { equals: parent.id } } }))
        .totalDocs,
    ).toBe(0)
    const imported = await upload(child.id)
    expect(imported.status).toBe('completed')
    expect(imported.createdAssets).toBe(1)
  })

  it('rechecks processing and site reclassification, and preserves existing uploads and history', async () => {
    const imported = await upload(child.id)
    const filepath = path.join(
      payload.collections['asset-imports'].config.upload.staticDir!,
      imported.filename!,
    )
    const originalBytes = await readFile(filepath)
    await payload.update({
      collection: 'sites',
      id: child.id,
      data: { type: blockedType.id },
      overrideAccess: false,
      user: operator,
    })
    try {
      await expect(upload(child.id)).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await expect(
        payload.update({
          collection: 'asset-imports',
          id: imported.id,
          data: {},
          file: {
            name: 'replacement.xml',
            data: Buffer.from('replacement'),
            mimetype: 'application/xml',
            size: 11,
          },
          overrideAccess: false,
          user: operator,
        }),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      expect(await readFile(filepath)).toEqual(originalBytes)
      const req = await createLocalReq({ user: operator }, payload)
      await expect(
        inTransaction(req, () =>
          processImport({ doc: imported, data: nmap, req, throwValidationErrors: true }),
        ),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      expect(
        (
          await payload.findByID({
            collection: 'asset-imports',
            id: imported.id,
            overrideAccess: false,
            user: operator,
          })
        ).status,
      ).toBe('completed')
      await payload.update({
        collection: 'asset-imports',
        id: imported.id,
        data: { name: 'Reviewed historical import' },
        overrideAccess: false,
        user: operator,
      })
      const filter = await filterImportSites('asset-imports')({
        id: imported.id,
        req: await createLocalReq({ user: operator }, payload),
      } as never)
      expect(filter).toMatchObject({
        and: [expect.anything(), { or: [importableSitesWhere, { id: { equals: child.id } }] }],
      })
    } finally {
      await payload.update({ collection: 'sites', id: child.id, data: { type: allowedType.id } })
    }
  })

  it('fails queued work and retries with a useful reason when a type becomes blocked', async () => {
    const imported = await upload(child.id, 'nmap', true)
    const stored = await payload.findByID({
      collection: 'asset-imports',
      id: imported.id,
      depth: 0,
    })
    await setBlocked(true)
    try {
      await expect(executeQueuedImport(payload, imported.id, stored.jobID!, 0)).rejects.toThrow(
        IMPORTS_BLOCKED_MESSAGE,
      )
      const failed = await payload.findByID({ collection: 'asset-imports', id: imported.id })
      expect(failed).toMatchObject({ status: 'failed', error: IMPORTS_BLOCKED_MESSAGE })
      await expect(
        retryImport(await request(`/asset-imports/${imported.id}/retry`, jwt, {}, imported.id)),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    } finally {
      await setBlocked(false)
    }
    await retryImport(await request(`/asset-imports/${imported.id}/retry`, jwt, {}, imported.id))
    const retry = await payload.findByID({ collection: 'asset-imports', id: imported.id, depth: 0 })
    await executeQueuedImport(payload, imported.id, retry.jobID!, 0)
    expect((await payload.findByID({ collection: 'asset-imports', id: imported.id })).status).toBe(
      'completed',
    )
  })

  it('blocks Otter enrollment and work, pauses queued schedules, and cancels active runs', async () => {
    await expect(
      createOtterScanner(
        await request('/otter/v1/scanners', jwt, { name: 'Blocked scanner', site: parent.id }),
      ),
    ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    const enrollment = await (
      await createOtterScanner(
        await request('/otter/v1/scanners', jwt, { name: 'Policy scanner', site: child.id }),
      )
    ).json()
    const scannerID = enrollment.scanner.id as string
    scanners.push(scannerID)
    await setBlocked(true)
    await expect(
      enrollOtter(await request('/otter/v1/enroll', '', { token: enrollment.enrollmentToken })),
    ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    await setBlocked(false)
    const enrolled = await (
      await enrollOtter(
        await request('/otter/v1/enroll', '', { token: enrollment.enrollmentToken }),
      )
    ).json()
    const machine = `Otter ${enrolled.credential}`
    const profile = await payload.create({
      collection: 'otter-profiles',
      data: {
        name: 'Policy configuration',
        site: child.id,
        scanner: scannerID,
        configuration: { targets: ['192.0.2.42'] },
      },
      overrideAccess: false,
      user: operator,
    })
    const schedule = await payload.create({
      collection: 'otter-schedules',
      data: {
        name: 'Policy schedule',
        site: child.id,
        scanner: scannerID,
        profile: profile.id,
        scheduleType: 'interval',
        intervalMinutes: 5,
        timezone: 'UTC',
        enabled: true,
      },
      overrideAccess: false,
      user: operator,
    })
    await payload.update({
      collection: 'otter-schedules',
      id: schedule.id,
      data: { nextRunAt: new Date(Date.now() - 60000).toISOString() },
      context: { otterSchedulerUpdate: true },
    })
    const pending = await (
      await runOtterNow(await request('/otter/v1/runs', jwt, { scannerID, profileID: profile.id }))
    ).json()
    await setBlocked(true)
    try {
      const overview = await (await otterOverview(await request('/otter/v1/overview'))).json()
      expect(overview.writableSites).toEqual([])
      expect(overview.sites.map((site: { id: string }) => site.id)).toContain(child.id)
      expect(overview.scanners.map((scanner: { id: string }) => scanner.id)).toContain(scannerID)
      expect(
        await (await pollOtter(await request('/otter/v1/poll', machine, {}))).json(),
      ).toMatchObject({ action: 'idle' })
      expect(
        (
          await payload.count({
            collection: 'otter-runs',
            where: { scanner: { equals: scannerID } },
          })
        ).totalDocs,
      ).toBe(1)
      expect((await payload.findByID({ collection: 'otter-runs', id: pending.id })).status).toBe(
        'queued',
      )
      await expect(
        runOtterNow(await request('/otter/v1/runs', jwt, { scannerID, profileID: profile.id })),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await expect(
        payload.create({
          collection: 'otter-profiles',
          data: {
            name: 'Blocked configuration',
            site: child.id,
            scanner: scannerID,
            configuration: { targets: ['192.0.2.42'] },
          },
          overrideAccess: false,
          user: operator,
        }),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await expect(
        payload.create({
          collection: 'otter-schedules',
          data: {
            name: 'Blocked schedule',
            site: child.id,
            scanner: scannerID,
            profile: profile.id,
            scheduleType: 'interval',
            intervalMinutes: 5,
            timezone: 'UTC',
          },
          overrideAccess: false,
          user: operator,
        }),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await expect(
        reenrollOtterScanner(
          await request(`/otter/v1/scanners/${scannerID}/reenroll`, jwt, {}, scannerID),
        ),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await expect(
        upload(child.id, 'otserver-otter', false, await request('/asset-imports', machine, {})),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
      await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: { name: 'Reviewed configuration' },
        overrideAccess: false,
        user: operator,
      })
      await payload.update({
        collection: 'otter-scanners',
        id: scannerID,
        data: { name: 'Reviewed scanner' },
        overrideAccess: false,
        user: operator,
      })
      await payload.update({
        collection: 'otter-schedules',
        id: schedule.id,
        data: { enabled: false },
        overrideAccess: false,
        user: operator,
      })
      await expect(
        payload.update({
          collection: 'otter-schedules',
          id: schedule.id,
          data: { enabled: true },
          overrideAccess: false,
          user: operator,
        }),
      ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    } finally {
      await setBlocked(false)
    }
    expect(
      await (await pollOtter(await request('/otter/v1/poll', machine, {}))).json(),
    ).toMatchObject({ action: 'run', run: { id: pending.id } })
    await setBlocked(true)
    await expect(
      startOtterRun(await request(`/otter/v1/runs/${pending.id}/start`, machine, {}, pending.id)),
    ).rejects.toThrow(IMPORTS_BLOCKED_MESSAGE)
    expect(
      await (await pollOtter(await request('/otter/v1/poll', machine, {}))).json(),
    ).toMatchObject({ action: 'cancel', runID: pending.id })
    await finishOtterRun(
      await request(
        `/otter/v1/runs/${pending.id}/finish`,
        machine,
        { status: 'cancelled' },
        pending.id,
      ),
    )
    expect(await payload.findByID({ collection: 'otter-runs', id: pending.id })).toMatchObject({
      status: 'cancelled',
      message: IMPORTS_BLOCKED_MESSAGE,
    })
    await setBlocked(false)
    const running = await (
      await runOtterNow(await request('/otter/v1/runs', jwt, { scannerID, profileID: profile.id }))
    ).json()
    await pollOtter(await request('/otter/v1/poll', machine, {}))
    await startOtterRun(
      await request(`/otter/v1/runs/${running.id}/start`, machine, {}, running.id),
    )
    await setBlocked(true)
    expect(
      await (
        await heartbeatOtterRun(
          await request(
            `/otter/v1/runs/${running.id}/heartbeat`,
            machine,
            { progress: 10 },
            running.id,
          ),
        )
      ).json(),
    ).toMatchObject({ cancelRequested: true })
    await finishOtterRun(
      await request(
        `/otter/v1/runs/${running.id}/finish`,
        machine,
        { status: 'cancelled' },
        running.id,
      ),
    )
    await revokeOtterScanner(
      await request(`/otter/v1/scanners/${scannerID}/revoke`, jwt, {}, scannerID),
    )
    await setBlocked(false)
  })
})
