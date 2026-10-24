import { createPayloadRequest, getPayload, type Payload, type PayloadRequest } from 'payload'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { beforeAll, describe, expect, it } from 'vitest'
import config from '@/payload.config'
import { siteTypeID } from '../siteType'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { executeQueuedImport } from '../../src/application/queuedImports'
import { decryptOtterCredentials } from '../../src/otter/security'
import { relationshipID } from '../../src/access/authorization'
import { isRunLeaseExpired } from '../../src/otter/runLease'
import {
  cancelOtterRun,
  createOtterScanner,
  enrollOtter,
  expireOtterLeases,
  finishOtterRun,
  getOtterScanner,
  heartbeatOtterRun,
  otterOverview,
  pollOtter,
  reenrollOtterScanner,
  revokeOtterScanner,
  rotateOtterCredential,
  runOtterNow,
  saveOtterCredentials,
  startOtterRun,
} from '../../src/otter/controller'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})

const request = async (
  path: string,
  options: { body?: unknown; token?: string; method?: string; origin?: string; url?: string } = {},
) => {
  const {
    body,
    token,
    method = 'POST',
    origin = 'https://otserver.example',
    url = `https://otserver.example/api${path}`,
  } = options
  const request = new Request(url, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(origin ? { Origin: origin } : {}),
      ...(token ? { Authorization: token } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  return createPayloadRequest({ config: payload.config, request })
}

const routeRequest = async (
  path: string,
  id: string,
  token: string,
  body?: unknown,
  origin = '',
) => {
  const req = await request(path, { body, token, origin })
  ;(req as PayloadRequest & { routeParams?: Record<string, string> }).routeParams = { id }
  return req
}

describe('Otter management controller', () => {
  it('enrolls once, delivers encrypted profile credentials, and completes a managed run', async () => {
    const oldURL = process.env.OTSERVER_PUBLIC_URL
    const oldKey = process.env.OTSERVER_OTTER_ENCRYPTION_KEY
    const oldQueuedImports = process.env.OTSERVER_QUEUED_IMPORTS
    process.env.OTSERVER_PUBLIC_URL = 'https://otserver.example'
    process.env.OTSERVER_OTTER_ENCRYPTION_KEY = 'b'.repeat(64)
    const siteName = `Otter site ${randomUUID()}`
    const roleName = `Otter role ${randomUUID()}`
    const email = `otter-${randomUUID()}@example.test`
    const readerEmail = `otter-reader-${randomUUID()}@example.test`
    const password = randomUUID()
    let siteID: string | undefined
    let otherSiteID: string | undefined
    let roleID: string | undefined
    let userID: string | undefined
    let readerRoleID: string | undefined
    let readerID: string | undefined
    let adminID: string | undefined
    let scannerID: string | undefined
    let foreignScannerID: string | undefined
    let profileID: string | undefined
    let foreignProfileID: string | undefined
    let runID: string | undefined
    let queuedCancelID: string | undefined
    let scheduledRunID: string | undefined
    let oneTimeScheduleID: string | undefined
    let oneTimeRunID: string | undefined
    let revokedRunID: string | undefined
    let reenrollRunID: string | undefined
    let foreignRunID: string | undefined
    let expiredRunID: string | undefined
    let badSnapshotRunID: string | undefined
    let noSecretRunID: string | undefined
    let fallbackFailureRunID: string | undefined
    let scheduleID: string | undefined
    let importID: string | undefined
    let queuedImportID: string | undefined
    let customFieldID: string | undefined

    try {
      const site = await payload.create({
        collection: 'sites',
        data: { name: siteName, type: await siteTypeID(payload) },
      })
      siteID = site.id
      const otherSite = await payload.create({
        collection: 'sites',
        data: { name: `Other Otter site ${randomUUID()}`, type: await siteTypeID(payload) },
      })
      otherSiteID = otherSite.id
      const role = await payload.create({
        collection: 'user-roles',
        data: {
          name: roleName,
          otterConfig: true,
          permissions: [{ site: site.id, access: 'read-write' }],
        },
      })
      roleID = role.id
      const user = await payload.create({
        collection: 'users',
        data: { email, name: 'Otter operator', password, role: role.id },
      })
      userID = user.id
      const login = await payload.login({ collection: 'users', data: { email, password } })
      const readerRole = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Otter site writer without config ${randomUUID()}`,
          permissions: [{ site: site.id, access: 'read-write' }],
        },
      })
      readerRoleID = readerRole.id
      const reader = await payload.create({
        collection: 'users',
        data: { email: readerEmail, name: 'Site writer', password, role: readerRole.id },
      })
      readerID = reader.id
      const readerLogin = await payload.login({
        collection: 'users',
        data: { email: readerEmail, password },
      })
      await expect(
        otterOverview(
          await request('/otter/v1/overview', { method: 'GET', token: `JWT ${readerLogin.token}` }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      const adminRole = await ensureAdminRole(payload)
      const adminEmail = `otter-admin-${randomUUID()}@example.test`
      const admin = await payload.create({
        collection: 'users',
        data: {
          email: adminEmail,
          name: 'Otter administrator',
          password,
          role: adminRole.id,
        },
      })
      adminID = admin.id
      const adminLogin = await payload.login({
        collection: 'users',
        data: { email: adminEmail, password },
      })

      const configuredURL = process.env.OTSERVER_PUBLIC_URL
      delete process.env.OTSERVER_PUBLIC_URL
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Plant Otter', site: site.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 503 })
      process.env.OTSERVER_PUBLIC_URL = configuredURL
      for (const invalidControllerURL of [
        'http://scanner-host.example',
        'https://user:password@otserver.example',
        'https://otserver.example?query=not-allowed',
        'https://otserver.example#fragment',
      ]) {
        process.env.OTSERVER_PUBLIC_URL = invalidControllerURL
        await expect(
          createOtterScanner(
            await request('/otter/v1/scanners', {
              body: { name: 'Plant Otter', site: site.id },
              token: `JWT ${login.token}`,
              origin: new URL(invalidControllerURL).origin,
            }),
          ),
        ).rejects.toMatchObject({ status: 503 })
      }
      process.env.OTSERVER_PUBLIC_URL = configuredURL
      process.env.OTSERVER_PUBLIC_URL = 'http://scanner-host.example'
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Plant Otter', site: site.id },
            token: `JWT ${login.token}`,
            origin: 'http://scanner-host.example',
          }),
        ),
      ).rejects.toMatchObject({ status: 503 })
      process.env.OTSERVER_PUBLIC_URL = configuredURL

      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Plant Otter', site: site.id },
            token: `JWT ${login.token}`,
            origin: 'https://attacker.example',
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Plant Otter', site: site.id },
            token: `JWT ${login.token}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', { body: { name: 'Plant Otter', site: site.id } }),
        ),
      ).rejects.toMatchObject({ status: 401 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: ' ', site: site.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'n'.repeat(121), site: site.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'bad\nname', site: site.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'No site', site: '' },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Cross-site form', site: site.id },
            token: `JWT ${login.token}`,
            origin: 'https://attacker.example',
            url: 'http://localhost:3000/api/otter/v1/scanners',
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'x'.repeat(33_000), site: site.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 413 })
      const declaredLargeBody = await createPayloadRequest({
        config: payload.config,
        request: new Request('https://otserver.example/api/otter/v1/scanners', {
          method: 'POST',
          headers: {
            Authorization: `JWT ${login.token}`,
            'Content-Length': '40000',
            'Content-Type': 'application/json',
            Origin: 'https://otserver.example',
          },
          body: '{}',
        }),
      })
      await expect(createOtterScanner(declaredLargeBody)).rejects.toMatchObject({ status: 413 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', { body: null, token: `JWT ${login.token}` }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        createOtterScanner(await request('/otter/v1/scanners', { token: `JWT ${login.token}` })),
      ).rejects.toMatchObject({ status: 400 })
      const invalidJSON = await createPayloadRequest({
        config: payload.config,
        request: new Request('https://otserver.example/api/otter/v1/scanners', {
          method: 'POST',
          headers: {
            Authorization: `JWT ${login.token}`,
            'Content-Type': 'application/json',
            Origin: 'https://otserver.example',
          },
          body: '{',
        }),
      })
      await expect(createOtterScanner(invalidJSON)).rejects.toMatchObject({ status: 400 })

      process.env.OTSERVER_PUBLIC_URL = 'http://127.0.0.1:3000'
      const createResponse = await createOtterScanner(
        await request('/otter/v1/scanners', {
          body: { name: 'Plant Otter', site: site.id },
          token: `JWT ${login.token}`,
          origin: 'http://localhost:3000',
          url: 'http://127.0.0.1:3000/api/otter/v1/scanners',
        }),
      )
      expect(createResponse.status).toBe(201)
      const created = (await createResponse.json()) as {
        enrollmentToken: string
        scanner: { id: string }
      }
      scannerID = created.scanner.id
      expect(created).toMatchObject({ controllerUrl: 'http://127.0.0.1:3000' })

      const foreignScanner = await payload.create({
        collection: 'otter-scanners',
        data: { name: 'Other scanner', site: site.id, enabled: true },
        overrideAccess: true,
        user,
      })
      foreignScannerID = foreignScanner.id

      const enrollmentAttempts = await Promise.all(
        Array.from({ length: 2 }, () =>
          request('/otter/v1/enroll', {
            body: {
              token: created.enrollmentToken,
              version: '0.9.0',
              capabilities: ['scan-v2', 'controller-v1'],
              interfaces: ['eth0'],
              computerName: 'otter-host-1',
              networkAdapters: [
                {
                  name: 'eth0',
                  friendlyName: 'Ethernet',
                  description: 'Industrial network adapter',
                  macAddress: '00:11:22:33:44:55',
                  ipAddresses: ['192.0.2.10', '2001:db8::10'],
                },
              ],
            },
            origin: '',
          }),
        ),
      )
      const enrollmentResults = await Promise.allSettled(
        enrollmentAttempts.map((req) => enrollOtter(req)),
      )
      const successfulEnrollments = enrollmentResults.filter(
        (result): result is PromiseFulfilledResult<Response> => result.status === 'fulfilled',
      )
      expect(successfulEnrollments).toHaveLength(1)
      expect(enrollmentResults.filter((result) => result.status === 'rejected')).toHaveLength(1)
      const enrollmentResponse = successfulEnrollments[0]!.value
      expect(enrollmentResponse.status).toBe(201)
      const enrollment = (await enrollmentResponse.json()) as { credential: string }
      expect(
        await payload.findByID({ collection: 'otter-scanners', id: scannerID!, depth: 0 }),
      ).toMatchObject({
        computerName: 'otter-host-1',
        version: '0.9.0',
        interfaces: ['eth0'],
        networkAdapters: [
          {
            name: 'eth0',
            friendlyName: 'Ethernet',
            macAddress: '00:11:22:33:44:55',
            ipAddresses: ['192.0.2.10', '2001:db8::10'],
          },
        ],
      })
      const scannerDetails = await getOtterScanner(
        await routeRequest('/otter/v1/scanners', scannerID!, `JWT ${login.token}`),
      )
      expect(await scannerDetails.json()).toMatchObject({
        id: scannerID,
        computerName: 'otter-host-1',
        networkAdapters: [expect.objectContaining({ name: 'eth0' })],
      })
      await expect(
        getOtterScanner(
          await routeRequest('/otter/v1/scanners', scannerID!, `JWT ${readerLogin.token}`),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        enrollOtter(await request('/otter/v1/enroll', { body: { token: 42 }, origin: '' })),
      ).rejects.toMatchObject({ status: 401 })
      await expect(
        createOtterScanner(
          await request('/otter/v1/scanners', {
            body: { name: 'Machine cannot enroll', site: site.id },
            token: `Otter ${enrollment.credential}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        enrollOtter(
          await request('/otter/v1/enroll', {
            body: { token: created.enrollmentToken },
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 401 })
      await expect(
        runOtterNow(
          await request('/otter/v1/runs', {
            body: { scannerID, profileID: 42 },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })

      const customField = await payload.create({
        collection: 'asset-fields',
        data: { label: `Otter override ${randomUUID()}`, type: 'number' },
      })
      customFieldID = customField.id
      const profile = await payload.create({
        collection: 'otter-profiles',
        data: {
          name: 'Line A',
          site: site.id,
          scanner: scannerID,
          configuration: { targets: ['192.0.2.10'], interface: 'eth0', noSnmp: false },
          assetOverrides: { assetOwner: 'Central owner' },
          customFieldOverrides: { [customField.id]: 7 },
        },
        overrideAccess: false,
        user,
      })
      profileID = profile.id
      expect(profile.credentialsConfigured).toBe(true)
      expect(profile.encryptedCredentials).toBeUndefined()
      const storedProfile = await payload.findByID({
        collection: 'otter-profiles',
        id: profile.id,
        depth: 0,
      })
      expect(decryptOtterCredentials(storedProfile.encryptedCredentials)).toEqual({
        snmp: [{ version: '2c', community: 'public' }],
      })
      await expect(
        payload.update({
          collection: 'otter-profiles',
          id: profile.id,
          data: { customFieldOverrides: { [customField.id]: 'invalid number' } },
          overrideAccess: false,
          user,
        }),
      ).rejects.toThrow(/Invalid value for custom field/)
      await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: { site: otherSite.id },
        context: { otterCredentialWrite: true },
        overrideAccess: true,
        user: admin,
      })
      await expect(
        runOtterNow(
          await request('/otter/v1/runs', {
            body: { scannerID, profileID: profile.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: { site: site.id },
        context: { otterCredentialWrite: true },
        overrideAccess: true,
        user: admin,
      })
      const foreignProfile = await payload.create({
        collection: 'otter-profiles',
        data: {
          name: 'Other scanner profile',
          site: site.id,
          scanner: foreignScanner.id,
          configuration: { targets: ['192.0.2.11'] },
        },
        overrideAccess: true,
        user,
      })
      foreignProfileID = foreignProfile.id
      await expect(
        payload.update({
          collection: 'otter-scanners',
          id: scannerID,
          data: { profile: foreignProfile.id } as never,
          overrideAccess: false,
          user,
        }),
      ).rejects.toThrow(/Otter Configurations/i)
      await expect(
        payload.update({
          collection: 'otter-scanners',
          id: scannerID,
          data: { network: { targets: ['192.0.2.20'], interface: 'eth1' } } as never,
          overrideAccess: false,
          user,
        }),
      ).rejects.toThrow(/Otter Configurations/i)
      await expect(
        payload.update({
          collection: 'otter-scanners',
          id: scannerID,
          data: { name: 'Unauthorized edit' },
          overrideAccess: false,
          user: reader,
        }),
      ).rejects.toThrow()
      const configuredScanner = await payload.update({
        collection: 'otter-scanners',
        id: scannerID,
        data: { enabled: false, computerName: 'spoofed-host' },
        overrideAccess: false,
        user,
      })
      expect(configuredScanner.enabled).toBe(true)
      expect(configuredScanner.computerName).not.toBe('spoofed-host')
      await expect(
        runOtterNow(
          await request('/otter/v1/runs', {
            body: { scannerID },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      const defaultRun = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      const defaultRunID = ((await defaultRun.json()) as { id: string }).id
      const snapshot = await payload.findByID({
        collection: 'otter-runs',
        id: defaultRunID,
        depth: 0,
      })
      expect(snapshot.profile).toBe(profile.id)
      expect(snapshot.configSnapshot).toMatchObject({
        targets: ['192.0.2.10'],
        interface: 'eth0',
        noSnmp: false,
      })
      expect(snapshot.importOverridesSnapshot).toMatchObject({
        assetOverrides: { assetOwner: 'Central owner' },
      })
      expect(decryptOtterCredentials(snapshot.encryptedCredentialsSnapshot)).toEqual({
        snmp: [{ version: '2c', community: 'public' }],
      })
      await payload.delete({ collection: 'otter-runs', id: defaultRunID })
      await expect(
        runOtterNow(
          await request('/otter/v1/runs', {
            body: { scannerID, profileID: foreignProfile.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 403 })
      const foreignRun = await payload.create({
        collection: 'otter-runs',
        data: {
          name: 'Foreign scanner run',
          site: site.id,
          scanner: foreignScanner.id,
          status: 'assigned',
        },
        overrideAccess: true,
        user,
      })
      foreignRunID = foreignRun.id
      await expect(
        startOtterRun(
          await routeRequest(
            '/otter/v1/runs/start',
            foreignRun.id,
            `Otter ${enrollment.credential}`,
          ),
        ),
      ).rejects.toMatchObject({ status: 404 })
      const credentialResponse = await saveOtterCredentials(
        await routeRequest(
          `/otter/v1/profiles/${profile.id}/credentials`,
          profile.id,
          `JWT ${login.token}`,
          { credentials: { snmp: [{ version: '2c', community: 'managed-secret' }] } },
          'https://otserver.example',
        ),
      )
      expect(credentialResponse.status).toBe(200)
      const readableProfile = await payload.findByID({
        collection: 'otter-profiles',
        id: profile.id,
        depth: 0,
        overrideAccess: false,
        user,
      })
      expect(readableProfile.encryptedCredentials).toBeUndefined()
      expect(readableProfile.credentialsConfigured).toBe(true)
      const editedProfile = await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: { name: 'Line A updated' },
        overrideAccess: false,
        user,
      })
      expect(editedProfile.credentialsConfigured).toBe(true)

      const runResponse = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      expect(runResponse.status).toBe(201)
      const createdRun = (await runResponse.json()) as { id: string }
      runID = createdRun.id
      await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: {
          assetOverrides: { assetOwner: 'Future owner' },
          customFieldOverrides: { [customField.id]: 9 },
        },
        overrideAccess: false,
        user,
      })

      const poll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {
            version: '0.9.0',
            capabilities: ['scan-v2', 'controller-v1'],
            interfaces: ['eth0'],
            computerName: 'otter-host-2',
            networkAdapters: [
              {
                name: 'eth0',
                friendlyName: 'Ethernet',
                description: 'Industrial network adapter',
                macAddress: '00:11:22:33:44:55',
                ipAddresses: ['192.0.2.11'],
              },
            ],
          },
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      const assignment = (await poll.json()) as {
        action: string
        run: {
          id: string
          leaseExpiresAt: string
          credentials: { snmp: Array<{ community: string }> }
          configuration: object
        }
      }
      expect(assignment.action).toBe('run')
      expect(assignment.run.id).toBe(runID)
      const assignedRun = await payload.findByID({ collection: 'otter-runs', id: runID, depth: 0 })
      expect(assignment.run.leaseExpiresAt).toBe(assignedRun.leaseExpiresAt)
      expect(Date.parse(assignedRun.leaseExpiresAt!) - Date.parse(assignedRun.assignedAt!)).toBe(
        30 * 60_000,
      )
      const assignedDeadline = Date.parse(assignedRun.leaseExpiresAt!)
      expect(isRunLeaseExpired(assignedRun, new Date(assignedDeadline - 1))).toBe(false)
      expect(isRunLeaseExpired(assignedRun, new Date(assignedDeadline))).toBe(true)
      await expireOtterLeases(payload, new Date(Date.parse(assignedRun.assignedAt!) + 5 * 60_000))
      expect(
        await payload.findByID({ collection: 'otter-runs', id: runID, depth: 0 }),
      ).toMatchObject({
        status: 'assigned',
      })
      expect(assignment.run.configuration).toMatchObject({
        serverUrl: 'http://127.0.0.1:3000',
        site: site.id,
        targets: ['192.0.2.10'],
      })
      expect(assignment.run.credentials.snmp[0].community).toBe('managed-secret')
      expect(
        await payload.findByID({ collection: 'otter-scanners', id: scannerID!, depth: 0 }),
      ).toMatchObject({
        computerName: 'otter-host-2',
        networkAdapters: [{ ipAddresses: ['192.0.2.11'] }],
      })
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: { version: 12 },
            token: `Otter ${enrollment.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: {
              networkAdapters: [
                {
                  name: 'eth0',
                  friendlyName: 'Ethernet',
                  description: 'Adapter',
                  macAddress: 'invalid',
                  ipAddresses: [],
                },
              ],
            },
            token: `Otter ${enrollment.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: { capabilities: 'not a list' },
            token: `Otter ${enrollment.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })

      const scanData = JSON.parse(
        await readFile(
          'tests/otserver_otter_files/OTserver-Otter-known-vulnerability.json',
          'utf8',
        ),
      ) as { devices: unknown[]; links?: unknown[] }
      scanData.devices = []
      scanData.links = []
      const file = Buffer.from(JSON.stringify(scanData))
      const importReq = await request('/asset-imports', {
        token: `Otter ${enrollment.credential}`,
      })
      const imported = await payload.create({
        collection: 'asset-imports',
        data: {
          sourceVersion: 'managed-test',
          otterRun: runID,
          assetOverrides: { assetOwner: 'must be discarded' },
          customFieldOverrides: {
            [customField.id]: 'scanner-supplied invalid number must be discarded',
          },
        } as never,
        file: { data: file, mimetype: 'application/json', name: 'managed.json', size: file.length },
        overrideAccess: false,
        req: importReq,
      })
      importID = imported.id
      expect(imported).toMatchObject({
        site: expect.objectContaining({ id: site.id }),
        source: 'otserver-otter',
        scanner: scannerID,
        otterRun: runID,
        status: 'completed',
      })
      expect(imported.assetOverrides).toEqual({ assetOwner: 'Central owner' })
      expect(imported.customFieldOverrides).toEqual({ [customField.id]: 7 })
      expect(imported.name).toContain(
        `Otter — ${configuredScanner.name} — ${site.path || site.name} — `,
      )
      expect(imported.name).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
      process.env.OTSERVER_QUEUED_IMPORTS = 'on'
      const queuedImport = await payload.create({
        collection: 'asset-imports',
        data: {
          executionMode: 'queued',
          sourceVersion: 'managed-test',
          otterRun: runID,
        } as never,
        file: {
          data: file,
          mimetype: 'application/json',
          name: 'managed-queued.json',
          size: file.length,
        },
        overrideAccess: false,
        req: await request('/asset-imports', { token: `Otter ${enrollment.credential}` }),
      })
      queuedImportID = queuedImport.id
      const queuedDocument = await payload.findByID({
        collection: 'asset-imports',
        id: queuedImport.id,
        depth: 0,
        overrideAccess: true,
      })
      expect(queuedDocument).toMatchObject({ executorType: 'otter', status: 'pending' })
      expect(queuedDocument.processingInput).toMatchObject({
        assetOverrides: { assetOwner: 'Central owner' },
        customFieldOverrides: { [customField.id]: 7 },
      })
      await executeQueuedImport(payload, queuedImport.id, queuedDocument.jobID!, 0)
      expect(
        await payload.findByID({
          collection: 'asset-imports',
          id: queuedImport.id,
          depth: 0,
          overrideAccess: true,
        }),
      ).toMatchObject({ status: 'completed', duplicateOf: importID })
      delete process.env.OTSERVER_QUEUED_IMPORTS

      const started = await startOtterRun(
        await routeRequest('/otter/v1/runs/start', runID, `Otter ${enrollment.credential}`),
      )
      expect(started.status).toBe(200)
      const startedRun = await payload.findByID({ collection: 'otter-runs', id: runID, depth: 0 })
      expect(Date.parse(startedRun.leaseExpiresAt!) - Date.parse(startedRun.startedAt!)).toBe(
        30 * 60_000,
      )
      const repeatedStart = await startOtterRun(
        await routeRequest('/otter/v1/runs/start', runID, `Otter ${enrollment.credential}`),
      )
      expect(await repeatedStart.json()).toMatchObject({ status: 'running' })
      await expect(
        heartbeatOtterRun(
          await routeRequest('/otter/v1/runs/heartbeat', runID, `Otter ${enrollment.credential}`, {
            progress: 101,
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      const beforeHeartbeat = Date.now()
      const heartbeat = await heartbeatOtterRun(
        await routeRequest('/otter/v1/runs/heartbeat', runID, `Otter ${enrollment.credential}`, {
          progress: 50,
        }),
      )
      const heartbeatResult = (await heartbeat.json()) as {
        cancelRequested: boolean
        leaseExpiresAt: string
      }
      expect(heartbeatResult.cancelRequested).toBe(false)
      expect(Date.parse(heartbeatResult.leaseExpiresAt)).toBeGreaterThanOrEqual(
        beforeHeartbeat + 30 * 60_000,
      )
      expect(Date.parse(heartbeatResult.leaseExpiresAt)).toBeLessThanOrEqual(
        Date.now() + 30 * 60_000,
      )
      expect(
        await payload.findByID({ collection: 'otter-runs', id: runID, depth: 0 }),
      ).toMatchObject({
        leaseExpiresAt: heartbeatResult.leaseExpiresAt,
      })
      const heartbeatWithoutProgress = await heartbeatOtterRun(
        await routeRequest('/otter/v1/runs/heartbeat', runID, `Otter ${enrollment.credential}`, {}),
      )
      expect(await heartbeatWithoutProgress.json()).toMatchObject({ cancelRequested: false })
      await expect(
        finishOtterRun(
          await routeRequest('/otter/v1/runs/finish', runID, `Otter ${enrollment.credential}`, {
            status: 'completed',
            importID: 'not-this-run',
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      const finished = await finishOtterRun(
        await routeRequest('/otter/v1/runs/finish', runID, `Otter ${enrollment.credential}`, {
          status: 'completed',
          importID,
        }),
      )
      expect(await finished.json()).toMatchObject({ status: 'completed' })
      await expect(
        finishOtterRun(
          await routeRequest('/otter/v1/runs/finish', runID, `Otter ${enrollment.credential}`, {
            status: 'unknown',
          }),
        ),
      ).rejects.toMatchObject({ status: 400 })
      await expect(
        startOtterRun(
          await routeRequest('/otter/v1/runs/start', runID, `Otter ${enrollment.credential}`),
        ),
      ).rejects.toMatchObject({ status: 409 })
      const repeatedFinish = await finishOtterRun(
        await routeRequest('/otter/v1/runs/finish', runID, `Otter ${enrollment.credential}`, {
          status: 'completed',
        }),
      )
      expect(await repeatedFinish.json()).toMatchObject({ status: 'completed' })
      await expect(
        heartbeatOtterRun(
          await routeRequest(
            '/otter/v1/runs/heartbeat',
            runID,
            `Otter ${enrollment.credential}`,
            {},
          ),
        ),
      ).rejects.toMatchObject({ status: 409 })
      const cancelCompleted = await cancelOtterRun(
        await routeRequest(
          '/otter/v1/runs/cancel',
          runID,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      expect(await cancelCompleted.json()).toMatchObject({ status: 'completed' })
      await payload.update({
        collection: 'otter-scanners',
        id: scannerID,
        data: { currentRun: runID },
        overrideAccess: true,
      })
      const staleAssignmentPoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      expect(await staleAssignmentPoll.json()).toMatchObject({ action: 'idle' })

      const badSnapshotRun = await payload.create({
        collection: 'otter-runs',
        data: {
          name: 'Invalid snapshot',
          site: site.id,
          scanner: scannerID,
          status: 'queued',
          configSnapshot: null,
        },
        overrideAccess: true,
        user,
      })
      badSnapshotRunID = badSnapshotRun.id
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: {},
            token: `Otter ${enrollment.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 500 })
      expect(
        await payload.findByID({ collection: 'otter-runs', id: badSnapshotRun.id, depth: 0 }),
      ).toMatchObject({ status: 'queued' })
      await payload.delete({
        collection: 'otter-runs',
        id: badSnapshotRun.id,
        overrideAccess: true,
      })
      badSnapshotRunID = undefined

      const leaseRun = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      expiredRunID = ((await leaseRun.json()) as { id: string }).id
      await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      await payload.update({
        collection: 'otter-runs',
        id: expiredRunID,
        data: { status: 'running', leaseExpiresAt: '2000-01-01T00:00:00.000Z' },
        overrideAccess: true,
      })
      await expect(
        startOtterRun(
          await routeRequest(
            '/otter/v1/runs/start',
            expiredRunID,
            `Otter ${enrollment.credential}`,
          ),
        ),
      ).rejects.toMatchObject({ status: 409 })
      await expect(
        heartbeatOtterRun(
          await routeRequest(
            '/otter/v1/runs/heartbeat',
            expiredRunID,
            `Otter ${enrollment.credential}`,
            {},
          ),
        ),
      ).rejects.toMatchObject({ status: 409 })
      await expect(
        finishOtterRun(
          await routeRequest(
            '/otter/v1/runs/finish',
            expiredRunID,
            `Otter ${enrollment.credential}`,
            {
              status: 'completed',
            },
          ),
        ),
      ).rejects.toMatchObject({ status: 409 })
      await expect(
        payload.create({
          collection: 'asset-imports',
          data: { otterRun: expiredRunID, sourceVersion: 'managed-test' } as never,
          file: {
            data: file,
            mimetype: 'application/json',
            name: 'expired.json',
            size: file.length,
          },
          overrideAccess: false,
          req: await request('/asset-imports', { token: `Otter ${enrollment.credential}` }),
        }),
      ).rejects.toMatchObject({ status: 409 })
      expect(
        await payload.findByID({ collection: 'otter-runs', id: expiredRunID, depth: 0 }),
      ).toMatchObject({ status: 'running', leaseExpiresAt: '2000-01-01T00:00:00.000Z' })
      await expireOtterLeases(payload)
      expect(
        await payload.findByID({ collection: 'otter-runs', id: expiredRunID, depth: 0 }),
      ).toMatchObject({ status: 'expired', message: expect.stringContaining('no heartbeat') })
      expect(
        await payload.findByID({ collection: 'otter-scanners', id: scannerID!, depth: 0 }),
      ).toMatchObject({ currentRun: null })
      const expiredPoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      expect(await expiredPoll.json()).toMatchObject({ action: 'idle' })
      expect(
        await payload.findByID({ collection: 'otter-runs', id: expiredRunID, depth: 0 }),
      ).toMatchObject({ status: 'expired', message: expect.stringContaining('no heartbeat') })

      const queuedToCancel = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      queuedCancelID = ((await queuedToCancel.json()) as { id: string }).id
      await expect(
        finishOtterRun(
          await routeRequest(
            '/otter/v1/runs/finish',
            queuedCancelID,
            `Otter ${enrollment.credential}`,
            {
              status: 'completed',
            },
          ),
        ),
      ).rejects.toMatchObject({ status: 409 })
      const cancelledQueued = await cancelOtterRun(
        await routeRequest(
          '/otter/v1/runs/cancel',
          queuedCancelID,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      expect(await cancelledQueued.json()).toMatchObject({ status: 'cancelled' })

      const schedule = await payload.create({
        collection: 'otter-schedules',
        data: {
          name: 'Every five minutes',
          site: otherSite.id,
          scanner: foreignScanner.id,
          profile: profile.id,
          scheduleType: 'interval',
          intervalMinutes: 5,
          timezone: 'UTC',
          enabled: true,
        },
        overrideAccess: false,
        user,
      })
      scheduleID = schedule.id
      expect(relationshipID(schedule.site)).toBe(site.id)
      expect(relationshipID(schedule.scanner)).toBe(scannerID)
      await expect(
        payload.create({
          collection: 'otter-schedules',
          data: {
            name: 'Unauthorized schedule',
            profile: profile.id,
            scheduleType: 'interval',
            intervalMinutes: 5,
          } as never,
          overrideAccess: false,
          user: reader,
        }),
      ).rejects.toThrow()
      await expect(
        payload.delete({
          collection: 'otter-profiles',
          id: profile.id,
          overrideAccess: false,
          user,
        }),
      ).rejects.toMatchObject({ status: 409 })
      const disabledSchedule = await payload.update({
        collection: 'otter-schedules',
        id: schedule.id,
        data: { enabled: false },
        overrideAccess: false,
        user,
      })
      expect(disabledSchedule.nextRunAt).toBeNull()
      await payload.update({
        collection: 'otter-schedules',
        id: schedule.id,
        data: { enabled: true },
        overrideAccess: false,
        user,
      })
      await payload.update({
        collection: 'otter-schedules',
        id: schedule.id,
        context: { otterSchedulerUpdate: true },
        data: { nextRunAt: '2000-01-01T00:00:00.000Z' },
        overrideAccess: true,
      })
      const scheduledPolls = await Promise.allSettled(
        Array.from({ length: 2 }, async () =>
          pollOtter(
            await request('/otter/v1/poll', {
              body: { version: '0.9.0', capabilities: ['scan-v2'], interfaces: ['eth0'] },
              token: `Otter ${enrollment.credential}`,
              origin: '',
            }),
          ),
        ),
      )
      const successfulPolls = scheduledPolls.filter(
        (result): result is PromiseFulfilledResult<Response> => result.status === 'fulfilled',
      )
      expect(successfulPolls.length).toBeGreaterThan(0)
      const scheduledAssignments = await Promise.all(
        successfulPolls.map(
          async ({ value }) => (await value.json()) as { action: string; run: { id: string } },
        ),
      )
      const scheduledAssignment = scheduledAssignments[0]!
      for (const assignment of scheduledAssignments)
        expect(assignment).toMatchObject({ action: 'run', run: { id: scheduledAssignment.run.id } })
      scheduledRunID = scheduledAssignment.run.id
      expect(scheduledAssignment.action).toBe('run')
      const scheduledOccurrences = await payload.find({
        collection: 'otter-runs',
        depth: 0,
        limit: 10,
        overrideAccess: true,
        where: { schedule: { equals: schedule.id } },
      })
      expect(scheduledOccurrences.docs).toHaveLength(1)
      expect(scheduledOccurrences.docs[0]?.scheduleOccurrenceKey).toEqual(expect.any(String))
      expect(
        await payload.findByID({
          collection: 'otter-runs',
          id: scheduledAssignment.run.id,
          depth: 0,
        }),
      ).toMatchObject({ schedule: schedule.id, status: 'assigned' })
      const repeatedPoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: { version: '0.9.0', capabilities: ['scan-v2'], interfaces: ['eth0'] },
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      expect((await repeatedPoll.json()).run.id).toBe(scheduledAssignment.run.id)
      const cancellation = await cancelOtterRun(
        await routeRequest(
          '/otter/v1/runs/cancel',
          scheduledAssignment.run.id,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      expect(await cancellation.json()).toMatchObject({ status: 'cancel-requested' })
      const cancellationPoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      expect(await cancellationPoll.json()).toMatchObject({
        action: 'cancel',
        runID: scheduledAssignment.run.id,
      })
      const cancellationHeartbeat = await heartbeatOtterRun(
        await routeRequest(
          '/otter/v1/runs/heartbeat',
          scheduledAssignment.run.id,
          `Otter ${enrollment.credential}`,
          {},
        ),
      )
      expect(await cancellationHeartbeat.json()).toMatchObject({ cancelRequested: true })
      const cancelled = await finishOtterRun(
        await routeRequest(
          '/otter/v1/runs/finish',
          scheduledAssignment.run.id,
          `Otter ${enrollment.credential}`,
          { status: 'cancelled' },
        ),
      )
      expect(await cancelled.json()).toMatchObject({ status: 'cancelled' })
      await payload.update({
        collection: 'otter-schedules',
        id: schedule.id,
        data: { enabled: false },
        overrideAccess: false,
        user,
      })
      const oneTimeSchedule = await payload.create({
        collection: 'otter-schedules',
        data: {
          name: 'One time catch-up',
          profile: profile.id,
          scheduleType: 'once',
          runAt: '2000-01-01T00:00:00.000Z',
          timezone: 'UTC',
          enabled: true,
        } as never, // Site and scanner are supplied by the selected configuration.
        overrideAccess: false,
        user,
      })
      oneTimeScheduleID = oneTimeSchedule.id
      expect(relationshipID(oneTimeSchedule.site)).toBe(site.id)
      expect(relationshipID(oneTimeSchedule.scanner)).toBe(scannerID)
      const oneTimePoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      const oneTimeAssignment = (await oneTimePoll.json()) as { run: { id: string } }
      oneTimeRunID = oneTimeAssignment.run.id
      const oneTimeFinish = await finishOtterRun(
        await routeRequest(
          '/otter/v1/runs/finish',
          oneTimeRunID,
          `Otter ${enrollment.credential}`,
          { status: 'partial', message: 'Some protocols did not respond.' },
        ),
      )
      expect(await oneTimeFinish.json()).toMatchObject({ status: 'partial' })
      await payload.update({
        collection: 'otter-schedules',
        id: oneTimeSchedule.id,
        context: { otterSchedulerUpdate: true },
        data: { enabled: true, nextRunAt: '2000-01-01T00:00:00.000Z' },
        overrideAccess: true,
      })
      const duplicateOccurrencePoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      expect(await duplicateOccurrencePoll.json()).toMatchObject({ action: 'idle' })

      const rotation = await rotateOtterCredential(
        await request('/otter/v1/credentials/rotate', {
          token: `Otter ${enrollment.credential}`,
          origin: '',
        }),
      )
      const rotated = (await rotation.json()) as { credential: string }
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: {},
            token: `Otter ${enrollment.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 401 })
      const runBeforeRevocation = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      revokedRunID = ((await runBeforeRevocation.json()) as { id: string }).id
      await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${rotated.credential}`,
          origin: '',
        }),
      )
      const revoked = await revokeOtterScanner(
        await routeRequest(
          '/otter/v1/scanners/revoke',
          scannerID,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      expect(await revoked.json()).toMatchObject({ revoked: true })
      expect(
        await payload.findByID({ collection: 'otter-runs', id: revokedRunID, depth: 0 }),
      ).toMatchObject({ status: 'cancelled' })
      await expect(
        runOtterNow(
          await request('/otter/v1/runs', {
            body: { scannerID, profileID: profile.id },
            token: `JWT ${login.token}`,
          }),
        ),
      ).rejects.toMatchObject({ status: 409 })
      const reenrollment = await reenrollOtterScanner(
        await routeRequest(
          '/otter/v1/scanners/reenroll',
          scannerID,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      const newEnrollment = (await reenrollment.json()) as { enrollmentToken: string }
      const reissued = await enrollOtter(
        await request('/otter/v1/enroll', {
          body: { token: newEnrollment.enrollmentToken },
          origin: '',
        }),
      )
      expect(reissued.status).toBe(201)
      const reissuedCredential = (await reissued.json()) as { credential: string }
      const idle = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${reissuedCredential.credential}`,
          origin: '',
        }),
      )
      expect(await idle.json()).toMatchObject({ action: 'idle' })
      const runForReenrollment = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      reenrollRunID = ((await runForReenrollment.json()) as { id: string }).id
      await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${reissuedCredential.credential}`,
          origin: '',
        }),
      )
      const reenrollmentWithActiveRun = await reenrollOtterScanner(
        await routeRequest(
          '/otter/v1/scanners/reenroll',
          scannerID,
          `JWT ${login.token}`,
          undefined,
          'https://otserver.example',
        ),
      )
      expect(reenrollmentWithActiveRun.status).toBe(200)
      expect(
        await payload.findByID({ collection: 'otter-runs', id: reenrollRunID, depth: 0 }),
      ).toMatchObject({ status: 'cancelled' })
      const finalEnrollment = (await reenrollmentWithActiveRun.json()) as {
        enrollmentToken: string
      }
      const finalCredentialResponse = await enrollOtter(
        await request('/otter/v1/enroll', {
          body: { token: finalEnrollment.enrollmentToken },
          origin: '',
        }),
      )
      const finalCredential = (await finalCredentialResponse.json()) as { credential: string }
      await saveOtterCredentials(
        await routeRequest(
          `/otter/v1/profiles/${profile.id}/credentials`,
          profile.id,
          `JWT ${login.token}`,
          { clear: true },
          'https://otserver.example',
        ),
      )
      const clearedProfile = await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        data: { name: 'Line A after clearing credentials' },
        overrideAccess: false,
        user,
      })
      expect(clearedProfile.credentialsConfigured).toBe(false)
      const noSecretRun = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      noSecretRunID = ((await noSecretRun.json()) as { id: string }).id
      const encryptionKey = process.env.OTSERVER_OTTER_ENCRYPTION_KEY
      delete process.env.OTSERVER_OTTER_ENCRYPTION_KEY
      const noSecretPoll = await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${finalCredential.credential}`,
          origin: '',
        }),
      )
      process.env.OTSERVER_OTTER_ENCRYPTION_KEY = encryptionKey
      const noSecretAssignment = (await noSecretPoll.json()) as {
        run: { id: string; credentials: object }
      }
      expect(noSecretAssignment.run.id).toBe(noSecretRunID)
      expect(noSecretAssignment.run.credentials).toEqual({})
      await finishOtterRun(
        await routeRequest(
          '/otter/v1/runs/finish',
          noSecretRunID,
          `Otter ${finalCredential.credential}`,
          { status: 'failed', message: 'No target responded.' },
        ),
      )
      expect(
        await payload.findByID({ collection: 'otter-runs', id: noSecretRunID, depth: 0 }),
      ).toMatchObject({ status: 'failed', message: 'No target responded.' })
      const fallbackFailure = await runOtterNow(
        await request('/otter/v1/runs', {
          body: { scannerID, profileID: profile.id },
          token: `JWT ${login.token}`,
        }),
      )
      fallbackFailureRunID = ((await fallbackFailure.json()) as { id: string }).id
      await pollOtter(
        await request('/otter/v1/poll', {
          body: {},
          token: `Otter ${finalCredential.credential}`,
          origin: '',
        }),
      )
      await finishOtterRun(
        await routeRequest(
          '/otter/v1/runs/finish',
          fallbackFailureRunID,
          `Otter ${finalCredential.credential}`,
          { status: 'failed', message: '   ' },
        ),
      )
      expect(
        await payload.findByID({ collection: 'otter-runs', id: fallbackFailureRunID, depth: 0 }),
      ).toMatchObject({
        status: 'failed',
        message: 'Scanner reported a failure without diagnostic details.',
      })
      await expect(
        pollOtter(
          await request('/otter/v1/poll', {
            body: {},
            token: `Otter ${rotated.credential}`,
            origin: '',
          }),
        ),
      ).rejects.toMatchObject({ status: 401 })

      const overview = await otterOverview(
        await request('/otter/v1/overview', { method: 'GET', token: `JWT ${login.token}` }),
      )
      const overviewData = (await overview.json()) as {
        scanners: Array<{ id: string; name: string }>
        runs: Array<{ id: string; status: string }>
      }
      expect(overviewData.scanners).toEqual(
        expect.arrayContaining([expect.objectContaining({ id: scannerID, name: 'Plant Otter' })]),
      )
      expect(overviewData.runs).toEqual(
        expect.arrayContaining([expect.objectContaining({ id: runID, status: 'completed' })]),
      )
      const adminOverview = await otterOverview(
        await request('/otter/v1/overview', { method: 'GET', token: `JWT ${adminLogin.token}` }),
      )
      expect(await adminOverview.json()).toMatchObject({
        controllerUrl: 'http://127.0.0.1:3000',
        scanners: expect.arrayContaining([
          expect.objectContaining({ id: scannerID, site: site.id, enrolled: true }),
        ]),
      })
    } finally {
      if (oldQueuedImports === undefined) delete process.env.OTSERVER_QUEUED_IMPORTS
      else process.env.OTSERVER_QUEUED_IMPORTS = oldQueuedImports
      if (queuedImportID)
        await payload
          .delete({ collection: 'asset-imports', id: queuedImportID, overrideAccess: true })
          .catch(() => {})
      if (importID)
        await payload
          .delete({ collection: 'asset-imports', id: importID, overrideAccess: true })
          .catch(() => {})
      if (revokedRunID)
        await payload
          .delete({ collection: 'otter-runs', id: revokedRunID, overrideAccess: true })
          .catch(() => {})
      if (expiredRunID)
        await payload
          .delete({ collection: 'otter-runs', id: expiredRunID, overrideAccess: true })
          .catch(() => {})
      if (fallbackFailureRunID)
        await payload
          .delete({ collection: 'otter-runs', id: fallbackFailureRunID, overrideAccess: true })
          .catch(() => {})
      if (badSnapshotRunID)
        await payload
          .delete({ collection: 'otter-runs', id: badSnapshotRunID, overrideAccess: true })
          .catch(() => {})
      if (noSecretRunID)
        await payload
          .delete({ collection: 'otter-runs', id: noSecretRunID, overrideAccess: true })
          .catch(() => {})
      if (foreignRunID)
        await payload
          .delete({ collection: 'otter-runs', id: foreignRunID, overrideAccess: true })
          .catch(() => {})
      if (scheduledRunID)
        await payload
          .delete({ collection: 'otter-runs', id: scheduledRunID, overrideAccess: true })
          .catch(() => {})
      if (oneTimeRunID)
        await payload
          .delete({ collection: 'otter-runs', id: oneTimeRunID, overrideAccess: true })
          .catch(() => {})
      if (reenrollRunID)
        await payload
          .delete({ collection: 'otter-runs', id: reenrollRunID, overrideAccess: true })
          .catch(() => {})
      if (queuedCancelID)
        await payload
          .delete({ collection: 'otter-runs', id: queuedCancelID, overrideAccess: true })
          .catch(() => {})
      if (scheduleID)
        await payload
          .delete({ collection: 'otter-schedules', id: scheduleID, overrideAccess: true })
          .catch(() => {})
      if (oneTimeScheduleID)
        await payload
          .delete({ collection: 'otter-schedules', id: oneTimeScheduleID, overrideAccess: true })
          .catch(() => {})
      if (runID)
        await payload
          .delete({ collection: 'otter-runs', id: runID, overrideAccess: true })
          .catch(() => {})
      if (profileID)
        await payload
          .delete({ collection: 'otter-profiles', id: profileID, overrideAccess: true })
          .catch(() => {})
      if (foreignProfileID)
        await payload
          .delete({ collection: 'otter-profiles', id: foreignProfileID, overrideAccess: true })
          .catch(() => {})
      if (customFieldID)
        await payload
          .delete({ collection: 'asset-fields', id: customFieldID, overrideAccess: true })
          .catch(() => {})
      if (scannerID)
        await payload
          .delete({ collection: 'otter-scanners', id: scannerID, overrideAccess: true })
          .catch(() => {})
      if (foreignScannerID)
        await payload
          .delete({ collection: 'otter-scanners', id: foreignScannerID, overrideAccess: true })
          .catch(() => {})
      if (userID) await payload.delete({ collection: 'users', id: userID }).catch(() => {})
      if (readerID) await payload.delete({ collection: 'users', id: readerID }).catch(() => {})
      if (adminID) await payload.delete({ collection: 'users', id: adminID }).catch(() => {})
      if (roleID) await payload.delete({ collection: 'user-roles', id: roleID }).catch(() => {})
      if (readerRoleID)
        await payload.delete({ collection: 'user-roles', id: readerRoleID }).catch(() => {})
      if (siteID) await payload.delete({ collection: 'sites', id: siteID }).catch(() => {})
      if (otherSiteID)
        await payload.delete({ collection: 'sites', id: otherSiteID }).catch(() => {})
      if (oldURL === undefined) delete process.env.OTSERVER_PUBLIC_URL
      else process.env.OTSERVER_PUBLIC_URL = oldURL
      if (oldKey === undefined) delete process.env.OTSERVER_OTTER_ENCRYPTION_KEY
      else process.env.OTSERVER_OTTER_ENCRYPTION_KEY = oldKey
    }
  })
})
