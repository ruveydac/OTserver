import { randomBytes, randomUUID } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { createLocalReq, getPayload, type Payload } from 'payload'
import config from '@/payload.config'
import type { Asset, User } from '@/payload-types'
import { ensureAdminRole } from '@/collections/UserRoles'
import { hardwareKey, normalizeIdentity, OT_NAMESPACE, slotUUID, uuidV5 } from '@/identity/keys'
import {
  endpointEvidence,
  expandPhysicalEvidence,
  observationIdentity,
  serviceEvidence,
} from '@/identity/evidence'
import { identityAction, migrateIdentity, performIdentityAction } from '@/identity/actions'
import { idOf } from '@/identity/access'
import { assetHistoryScope } from '@/identity/relationships'
import { suggestAdjacentInterfaces, suggestAttachmentChange } from '@/identity/reconcile'
import { findAssemblyVulnerabilities } from '@/vulnerabilities/match'
import { parseOTserverOtter } from '@/importers/otserverOtter'
import DeviceIdentity from '@/components/DeviceIdentity'
import { renderToStaticMarkup } from 'react-dom/server'

vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: vi.fn() }) }))

const mac = () => `02:${randomBytes(5).toString('hex').match(/../g)!.join(':')}`.toUpperCase()
const serial = () => randomBytes(4).toString('hex').toUpperCase()

describe('device identity', () => {
  it('uses canonical, vendor-scoped keys and keeps slots independent from installed modules', () => {
    expect(uuidV5('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'www.example.com')).toBe(
      '2ed6657d-e927-568b-95e1-2665a8aea6a2',
    )
    const identity = {
      authority: 'cip',
      manufacturer: '1',
      scope: 'cpu' as const,
      serial: '000000AB',
    }
    expect(hardwareKey(identity)).toBe(hardwareKey({ ...identity, serial: '000000ab' }))
    expect(hardwareKey(identity)).not.toBe(hardwareKey({ ...identity, scope: 'adapter' }))
    expect(hardwareKey(identity)).not.toBe(hardwareKey({ ...identity, manufacturer: '2' }))
    expect(slotUUID(OT_NAMESPACE, ' 0/1 ')).toBe(slotUUID(OT_NAMESPACE, '0/1'))
    expect(() => uuidV5('bad', 'x')).toThrow('namespace')
    expect(() => slotUUID(OT_NAMESPACE, '')).toThrow('slot')
    for (const value of [
      '',
      '00000000',
      'FFFFFFFF',
      'unknown',
      'n/a',
      'a\nserial',
      'a'.repeat(201),
    ])
      expect(() => normalizeIdentity({ ...identity, serial: value })).toThrow()
    expect(() => normalizeIdentity({ ...identity, manufacturer: '0' })).toThrow('CIP')
    expect(() => normalizeIdentity({ ...identity, serial: 'not-hex' })).toThrow('CIP')
    expect(
      normalizeIdentity({
        authority: ' Vendor ',
        manufacturer: 'ACME',
        scope: 'module',
        serial: '001a',
        productScope: ' X ',
      }),
    ).toEqual({
      authority: 'vendor',
      manufacturer: 'acme',
      scope: 'module',
      serial: '001a',
      productScope: 'X',
    })
  })

  it('extracts qualified v2 identities, conserves endpoint ambiguity, and preserves ENTITY-MIB containment', () => {
    const observation = {
      source: 'ethernet-ip',
      observedAt: '2026-09-01T00:00:00Z',
      quality: 'high' as const,
      fields: { serialNumber: '000000AB' },
      raw: { vendorId: 1, deviceType: 12, serialNumber: '000000AB' },
    }
    expect(observationIdentity(observation)?.scope).toBe('adapter')
    expect(observationIdentity({ ...observation, raw: {} })).toBeUndefined()
    expect(
      observationIdentity({
        ...observation,
        fields: { serialNumber: '00000000' },
        raw: { vendorId: 1, deviceType: 12, serialNumber: '00000000' },
      }),
    ).toBeUndefined()
    expect(observationIdentity({ ...observation, source: 'unknown' })).toBeUndefined()
    const address = mac()
    expect(
      endpointEvidence({ macAddress: address, ipAddresses: ['bad', '192.0.2.1'] })[0].addresses,
    ).toEqual([{ address: '192.0.2.1' }])
    expect(
      endpointEvidence({
        macAddress: address,
        interfaces: [{ key: 'ifIndex:1', ipAddresses: ['192.0.2.2'] }, { macAddress: 'bad' }],
      }),
    ).toHaveLength(2)
    const port = { key: 'tcp:44818', source: 'ethernet-ip' }
    expect(
      serviceEvidence({
        ports: [port, { key: 'port:1' }],
        observations: [{ source: 'ethernet-ip', ipAddress: '192.0.2.1' }],
      }),
    ).toHaveLength(1)
    expect(
      serviceEvidence({
        ports: [port],
        observations: [
          { source: 'ethernet-ip', ipAddress: '192.0.2.1' },
          { source: 'ethernet-ip', ipAddress: '192.0.2.2' },
        ],
      }),
    ).toEqual([])
    const root = '1.3.6.1.2.1.47.1.1.1.1.'
    const raw = Object.fromEntries(
      Object.entries({
        '4.1': 0,
        '5.1': 3,
        '11.1': 'CHASSIS001',
        '12.1': 'ACME',
        '13.1': 'Rack',
        '4.2': 1,
        '5.2': 9,
        '11.2': 'MODULE001',
        '12.2': 'ACME',
        '13.2': 'CPU',
      }).map(([key, value]) => [root + key, value]),
    )
    const entities = expandPhysicalEvidence({
      name: 'rack',
      macAddress: address,
      observations: [{ ...observation, source: 'snmp', fields: {}, raw }],
    })
    expect(entities).toHaveLength(2)
    expect(entities[0].identity?.scope).toBe('chassis')
    expect(entities[1].parentComponentRef).toBe(entities[0].componentRef)
    expect(entities[1].macAddress).toBeUndefined()
    expect(entities[1].slotPath).toBeUndefined()
    const separate = expandPhysicalEvidence({
      name: 'adapter',
      macAddress: address,
      observations: [
        observation,
        {
          ...observation,
          source: 's7',
          fields: { serialNumber: 'CPU001' },
          raw: { module: '6ES7-CPU' },
        },
      ],
    })
    expect(separate.map((item) => item.identity?.scope)).toEqual(['adapter', 'cpu'])
  })

  let payload: Payload
  let user: User
  const siteIDs: string[] = []
  const userIDs: string[] = []
  const roleIDs: string[] = []
  const vulnerabilityIDs: string[] = []
  beforeAll(async () => {
    payload = await getPayload({ config })
    user = await payload.create({
      collection: 'users',
      data: {
        email: `identity-${randomUUID()}@example.test`,
        password: randomUUID(),
        name: 'Identity admin',
        role: (await ensureAdminRole(payload)).id,
      },
    })
  }, 60000)
  afterAll(async () => {
    for (const id of vulnerabilityIDs) await payload.delete({ collection: 'vulnerabilities', id })
    for (const id of userIDs) await payload.delete({ collection: 'users', id })
    for (const id of roleIDs) await payload.delete({ collection: 'user-roles', id })
    for (const site of siteIDs) {
      for (const collection of [
        'service-bindings',
        'asset-installations',
        'asset-identifiers',
        'identity-cases',
        'network-endpoints',
        'asset-observations',
        'topology-links',
        'asset-imports',
        'assets',
      ] as const)
        await payload.delete({
          collection,
          where: { site: { equals: site } },
          overrideAccess: true,
        })
      await payload.delete({ collection: 'sites', id: site })
    }
    if (user) await payload.delete({ collection: 'users', id: user.id })
  }, 60000)

  const site = async () => {
    const value = await payload.create({
      collection: 'sites',
      data: { name: `Identity ${randomUUID()}`, type: 'Test' },
      user,
      overrideAccess: false,
    })
    siteIDs.push(value.id)
    return value.id
  }
  const asset = async (site: string, data: Partial<Asset> = {}) =>
    payload.create({
      collection: 'assets',
      data: {
        name: `Device ${randomUUID()}`,
        site,
        status: 'unknown',
        criticality: 'medium',
        ...data,
      } as never,
      user,
      overrideAccess: false,
    })
  const action = async (id: string, data: Record<string, unknown>, actor = user) =>
    performIdentityAction(
      id,
      { reason: 'Verified maintenance record', ...data },
      await createLocalReq({ user: actor }, payload),
    )
  const scan = (
    hardwareSerial: string,
    addresses: [string, string][],
    at = '2026-09-10T10:00:00Z',
  ) => ({
    format: 'otserver-scan',
    schemaVersion: 2,
    scanner: { name: 'OTserver Otter', version: '0.4' },
    scan: {
      id: randomUUID(),
      startedAt: at,
      finishedAt: at,
      targets: addresses.map(([, ip]) => ip),
      interface: { id: 'test', name: 'test' },
    },
    devices: addresses.map(([macAddress, ipAddress]) => ({
      macAddress,
      macAddresses: [macAddress],
      ipAddresses: [ipAddress],
      interfaces: [],
      ports: [{ key: 'tcp:44818', source: 'ethernet-ip' }],
      observations: [
        {
          source: 'ethernet-ip',
          observedAt: at,
          ipAddress,
          fields: {
            vendor: 'Rockwell Automation',
            model: '1756-EN2T',
            serialNumber: hardwareSerial,
            ipAddress,
            macAddress,
            firmwareVersion: '3.1',
          },
          raw: { vendorId: 1, deviceType: 12, serialNumber: hardwareSerial },
          warnings: [],
        },
      ],
    })),
    links: [],
    unresolved: [],
    warnings: [],
    errors: [],
  })
  const upload = async (site: string, value: unknown, actor = user) => {
    const data = Buffer.from(JSON.stringify(value))
    return payload.create({
      collection: 'asset-imports',
      data: {
        site,
        source: 'otserver-otter',
        sourceVersion: '0.4',
        status: 'pending',
      },
      file: { data, name: `${randomUUID()}.json`, mimetype: 'application/json', size: data.length },
      user: actor,
      overrideAccess: false,
    })
  }

  it('converges dual-homed hardware, replays safely, preserves human fields and old observations, and records replacement', async () => {
    const siteID = await site()
    const hardwareSerial = serial()
    const firstMAC = mac(),
      secondMAC = mac()
    const input = scan(hardwareSerial, [
      [firstMAC, '192.0.2.1'],
      [secondMAC, '198.51.100.1'],
    ])
    const imported = await upload(siteID, input)
    expect(imported.status).toBe('completed')
    expect(imported.createdAssets).toBe(1)
    expect(imported.appliedKey).toBeTruthy()
    const inventory = await payload.find({
      collection: 'assets',
      where: { site: { equals: siteID } },
      depth: 0,
    })
    expect(inventory.docs).toHaveLength(1)
    const device = inventory.docs[0]
    expect(device.networkMACs?.map(({ address }) => address).sort()).toEqual(
      [firstMAC, secondMAC].sort(),
    )
    const endpoints = await payload.find({
      collection: 'network-endpoints',
      where: { asset: { equals: device.id } },
      depth: 0,
    })
    expect(endpoints.docs).toHaveLength(2)
    const services = await payload.find({
      collection: 'service-bindings',
      where: { asset: { equals: device.id } },
    })
    expect(services.docs).toHaveLength(2)
    expect(idOf((await upload(siteID, input)).duplicateOf)).toBe(imported.id)
    expect(
      (
        await payload.count({
          collection: 'asset-observations',
          where: { asset: { equals: device.id } },
        })
      ).totalDocs,
    ).toBe(2)
    await payload.update({
      collection: 'assets',
      id: device.id,
      data: { name: 'Human baseline' },
      user,
      overrideAccess: false,
    })
    await upload(siteID, scan(hardwareSerial, [[firstMAC, '192.0.2.2']], '2026-09-11T10:00:00Z'))
    await upload(siteID, scan(hardwareSerial, [[firstMAC, '192.0.2.99']], '2026-09-01T10:00:00Z'))
    expect(await payload.findByID({ collection: 'assets', id: device.id })).toMatchObject({
      name: 'Human baseline',
      ipAddress: '192.0.2.2',
    })
    const replacementSerial = serial()
    await upload(siteID, scan(replacementSerial, [[firstMAC, '192.0.2.2']], '2026-09-12T10:00:00Z'))
    const cases = await payload.find({
      collection: 'identity-cases',
      depth: 0,
      where: { site: { equals: siteID } },
    })
    expect(cases.docs[0].kind).toBe('replacement')
    const replacement = idOf(cases.docs[0].candidate)
    expect(await payload.findByID({ collection: 'assets', id: device.id })).toMatchObject({
      serialNumber: hardwareSerial,
      lifecycle: 'active',
    })
    await action(device.id, { action: 'replace', target: replacement })
    expect(await payload.findByID({ collection: 'assets', id: device.id, depth: 0 })).toMatchObject(
      { lifecycle: 'replaced', replacedBy: replacement },
    )
    expect(await payload.findByID({ collection: 'assets', id: replacement })).toMatchObject({
      serialNumber: replacementSerial,
      baselined: false,
    })
    expect(
      (
        await payload.find({
          collection: 'network-endpoints',
          where: { asset: { equals: device.id } },
        })
      ).docs.every(({ endedAt }) => endedAt),
    ).toBe(true)
    const history = await payload.find({
      collection: 'audit-logs',
      where: { asset: { equals: device.id } },
      pagination: false,
    })
    expect(JSON.stringify(history.docs)).toContain('identity.replace')
    expect(
      (
        await payload.count({
          collection: 'asset-observations',
          where: { asset: { equals: device.id } },
        })
      ).totalDocs,
    ).toBeGreaterThan(2)
  })

  it('supports MAC-free modules, slot movement, cycle guards, merge/split, lifecycle and explicit transfer', async () => {
    const siteID = await site(),
      destination = await site()
    const rack = await asset(siteID, { physicalKind: 'chassis' })
    const component = await asset(siteID, { physicalKind: 'module' })
    const installed = await payload.create({
      collection: 'asset-installations',
      data: {
        site: siteID,
        parent: rack.id,
        module: component.id,
        slotPath: '0/1',
        installedAt: '2026-09-01T00:00:00Z',
      },
      user,
      overrideAccess: false,
    })
    expect(installed.slotUUID).toBe(slotUUID(rack.uuid!, '0/1'))
    await expect(
      payload.create({
        collection: 'asset-installations',
        data: {
          site: siteID,
          parent: component.id,
          module: rack.id,
          slotPath: '0/2',
          installedAt: '2026-09-02T00:00:00Z',
        },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('ancestor')
    await expect(action(component.id, { action: 'transfer', site: destination })).rejects.toThrow(
      'installations',
    )
    await payload.update({
      collection: 'asset-installations',
      id: installed.id,
      data: { removedAt: '2026-09-03T00:00:00Z' },
      user,
      overrideAccess: false,
    })
    const moved = await payload.create({
      collection: 'asset-installations',
      data: {
        site: siteID,
        parent: rack.id,
        module: component.id,
        slotPath: '0/3',
        installedAt: '2026-09-03T00:00:00Z',
      },
      user,
      overrideAccess: false,
    })
    expect(idOf(moved.module)).toBe(component.id)
    const source = await asset(siteID, { macAddress: mac(), ipAddress: '192.0.2.1' })
    const target = await asset(siteID)
    await action(source.id, { action: 'merge', target: target.id })
    expect(idOf((await payload.findByID({ collection: 'assets', id: source.id })).mergedInto)).toBe(
      target.id,
    )
    const endpoints = await payload.find({
      collection: 'network-endpoints',
      depth: 0,
      where: { asset: { equals: target.id } },
    })
    const split = await action(target.id, {
      action: 'split',
      endpoints: [endpoints.docs[0].id],
      name: 'Separated hardware',
    })
    expect(split.target).toBeTruthy()
    await expect(
      payload.update({
        collection: 'assets',
        id: split.target!,
        data: { site: destination },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('Transfer')
    await action(split.target!, { action: 'transfer', site: destination })
    expect(idOf((await payload.findByID({ collection: 'assets', id: split.target! })).site)).toBe(
      destination,
    )
    await action(split.target!, { action: 'retire' })
    await action(split.target!, { action: 'restore' })
    expect((await payload.findByID({ collection: 'assets', id: split.target! })).lifecycle).toBe(
      'active',
    )
  })

  it('protects restricted-site identities and requires both-site write permission for transfers', async () => {
    const first = await site(),
      second = await site()
    const hardwareSerial = serial()
    await upload(first, scan(hardwareSerial, [[mac(), '192.0.2.1']]))
    const role = await payload.create({
      collection: 'user-roles',
      data: {
        name: `Identity writer ${randomUUID()}`,
        permissions: [{ site: second, access: 'read-write' }],
      },
    })
    roleIDs.push(role.id)
    const writer = await payload.create({
      collection: 'users',
      data: {
        name: 'Scoped writer',
        email: `${randomUUID()}@example.test`,
        password: randomUUID(),
        role: role.id,
      },
    })
    userIDs.push(writer.id)
    expect(
      (await upload(second, scan(hardwareSerial, [[mac(), '192.0.2.1']]), writer)).createdAssets,
    ).toBe(0)
    const cases = await payload.find({
      collection: 'identity-cases',
      where: { site: { equals: second } },
      user: writer,
      overrideAccess: false,
    })
    expect(cases.docs[0]).toMatchObject({ kind: 'cross-site' })
    expect(cases.docs[0].candidate).toBeFalsy()
    const own = await asset(second)
    await expect(action(own.id, { action: 'transfer', site: first }, writer)).rejects.toThrow(
      'destination',
    )
    const other = await asset(first)
    await expect(
      payload.create({
        collection: 'asset-identifiers',
        data: {
          site: second,
          asset: other.id,
          authority: 'cip',
          manufacturer: '1',
          scope: 'cpu',
          serial: serial(),
          state: 'accepted',
        },
        user: writer,
        overrideAccess: false,
      }),
    ).rejects.toThrow()
    await expect(migrateIdentity(await createLocalReq({ user: writer }, payload))).rejects.toThrow(
      'Administrator',
    )
  })

  it('keeps conflicting and revoked claims out of descriptive merging and validates lifecycle actions', async () => {
    const siteID = await site()
    const identitySerial = serial(),
      address = mac()
    await upload(siteID, scan(identitySerial, [[address, '192.0.2.11']]))
    const identifiers = await payload.find({
      collection: 'asset-identifiers',
      depth: 0,
      where: { site: { equals: siteID } },
    })
    const key = identifiers.docs[0]
    const id = idOf(key.asset)
    await expect(
      payload.update({
        collection: 'assets',
        id,
        data: { serialNumber: 'changed' },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('revoke')
    await expect(
      payload.update({
        collection: 'asset-identifiers',
        id: key.id,
        data: { serial: serial() },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('Revoke')
    const unknown = scan(identitySerial, [[address, '192.0.2.11']])
    unknown.devices[0].observations[0].raw = {} as never
    unknown.devices[0].observations[0].fields.serialNumber = 'UNQUALIFIED'
    unknown.devices[0].observations[0].fields.firmwareVersion = '99.0'
    await upload(siteID, unknown)
    expect((await payload.findByID({ collection: 'assets', id })).serialNumber).toBe(identitySerial)
    await payload.update({
      collection: 'asset-identifiers',
      id: key.id,
      data: { state: 'contested' },
      user,
      overrideAccess: false,
    })
    const contested = scan(identitySerial, [[address, '192.0.2.11']])
    contested.devices[0].observations[0].fields.firmwareVersion = '100.0'
    await upload(siteID, contested)
    expect((await payload.findByID({ collection: 'assets', id })).firmwareVersion).toBe('3.1')
    await action(id, { action: 'retire' })
    await payload.update({
      collection: 'asset-identifiers',
      id: key.id,
      data: { state: 'revoked' },
      user,
      overrideAccess: false,
    })
    await upload(siteID, scan(identitySerial, [[address, '192.0.2.11']]))
    expect((await payload.findByID({ collection: 'assets', id })).lifecycle).toBe('retired')
    await expect(action(id, { action: 'invalid' })).rejects.toThrow('Unknown')
    await expect(action(id, { action: 'restore', reason: '' })).rejects.toThrow('reason')
    await expect(action(id, { action: 'merge', target: id })).rejects.toThrow('different')
    await expect(action(id, { action: 'merge' })).rejects.toThrow('two active')
    await expect(action(id, { action: 'split', endpoints: ['missing'] })).rejects.toThrow(
      'current endpoints',
    )
    await expect(action(id, { action: 'close-endpoint', endpoint: 'missing' })).rejects.toThrow(
      'current endpoint',
    )
    await action(id, { action: 'restore' })
    const fresh = await asset(siteID, { macAddress: mac(), ipAddress: '192.0.2.12' })
    const endpoint = (
      await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { asset: { equals: fresh.id } },
      })
    ).docs[0]
    const closed = await identityAction(
      await createLocalReq(
        {
          user,
          req: {
            routeParams: { id: fresh.id },
            json: async () => ({
              action: 'close-endpoint',
              endpoint: endpoint.id,
              reason: 'Cable removed',
            }),
          },
        },
        payload,
      ),
    )
    expect(closed.status).toBe(200)
    await expect(
      payload.update({
        collection: 'network-endpoints',
        id: endpoint.id,
        data: { name: 'changed' },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('Historical')
    await expect(identityAction(await createLocalReq({}, payload))).rejects.toThrow(
      'Authentication',
    )
    await expect(asset(siteID, { lifecycle: 'merged' })).rejects.toThrow('New hardware')
  })

  it('prevents concurrent graph cycles, scopes MACs by exact site, and retries collector conflicts safely', async () => {
    const siteID = await site()
    const nodes: Asset[] = []
    for (let i = 0; i < 4; i++) nodes.push(await asset(siteID))
    const install = (parent: Asset, child: Asset) =>
      payload.create({
        collection: 'asset-installations',
        user,
        overrideAccess: false,
        data: {
          site: siteID,
          parent: parent.id,
          module: child.id,
          installedAt: '2026-09-01T00:00:00Z',
        },
      })
    await install(nodes[3], nodes[0])
    await install(nodes[1], nodes[2])
    const graphRace = await Promise.allSettled([
      install(nodes[0], nodes[1]),
      install(nodes[2], nodes[3]),
    ])
    expect(graphRace.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    const hardwareSerial = serial()
    const files = [
      scan(hardwareSerial, [[mac(), '192.0.2.1']]),
      scan(hardwareSerial, [[mac(), '198.51.100.1']]),
    ]
    const uploads = await Promise.allSettled(files.map((file) => upload(siteID, file)))
    for (const [index, result] of uploads.entries())
      if (result.status === 'rejected') await upload(siteID, files[index])
    const key = (
      await payload.find({
        collection: 'asset-identifiers',
        depth: 0,
        where: { serial: { equals: hardwareSerial } },
      })
    ).docs[0]
    expect(
      (
        await payload.count({
          collection: 'network-endpoints',
          where: { asset: { equals: idOf(key.asset) } },
        })
      ).totalDocs,
    ).toBe(2)
    const unqualified = scan(serial(), [[mac(), '192.0.2.10']])
    unqualified.devices[0].observations[0].raw = {} as never
    unqualified.devices[0].observations[0].fields.serialNumber = ''
    await upload(siteID, unqualified)
    await upload(siteID, { ...unqualified, scan: { ...unqualified.scan, id: randomUUID() } })
    expect(
      (
        await payload.count({
          collection: 'network-endpoints',
          where: {
            and: [
              { site: { equals: siteID } },
              { macAddress: { equals: unqualified.devices[0].macAddress } },
            ],
          },
        })
      ).totalDocs,
    ).toBe(1)
    const otherSite = await site()
    await upload(otherSite, { ...unqualified, scan: { ...unqualified.scan, id: randomUUID() } })
    expect(
      (
        await payload.count({
          collection: 'network-endpoints',
          where: { macAddress: { equals: unqualified.devices[0].macAddress } },
        })
      ).totalDocs,
    ).toBe(2)
  })

  it('migrates idempotently and retains module-specific vulnerability and topology evidence', async () => {
    const siteID = await site()
    const rack = await asset(siteID, { physicalKind: 'chassis', slotCapacity: 4 })
    const component = await asset(siteID, {
      name: 'Installed CPU',
      physicalKind: 'module',
      vendor: 'Exampleindustrial',
      model: 'Identity Test Controller',
      firmwareVersion: '3.1',
    })
    const installation = await payload.create({
      collection: 'asset-installations',
      user,
      overrideAccess: false,
      data: {
        site: siteID,
        parent: rack.id,
        module: component.id,
        slotPath: '1',
        installedAt: '2026-09-01T00:00:00Z',
      },
    })
    await expect(
      payload.create({
        collection: 'asset-installations',
        user,
        overrideAccess: false,
        data: {
          site: siteID,
          parent: rack.id,
          module: (await asset(siteID)).id,
          slotPath: '4',
          installedAt: '2026-09-01T00:00:00Z',
        },
      }),
    ).rejects.toThrow('capacity')
    const cpe = 'cpe:2.3:a:exampleindustrial:identity_test_controller:3.1:*:*:*:*:*:*:*'
    const vulnerability = await payload.create({
      collection: 'vulnerabilities',
      data: {
        cve: 'CVE-2099-19999',
        products: ['identitytestcontroller'],
        productTokens: ['identity', 'test', 'controller'],
        affected: [
          {
            part: 'a',
            vendor: 'exampleindustrial',
            product: 'identity_test_controller',
            version: '3.1',
            cpe,
          },
        ],
      },
    })
    vulnerabilityIDs.push(vulnerability.id)
    const matches = await findAssemblyVulnerabilities(payload, rack, { user })
    expect(matches).toHaveLength(1)
    expect(matches[0]).toMatchObject({
      cpe,
      components: [{ id: component.id, name: 'Installed CPU', version: '3.1' }],
    })
    const panel = renderToStaticMarkup(await DeviceIdentity({ asset: rack, payload, user }))
    expect(panel).toContain('Installed CPU')
    expect(panel).toContain('Slot 1')
    expect(panel).toContain('Reconcile identity')
    await payload.update({
      collection: 'asset-installations',
      id: installation.id,
      data: { removedAt: new Date().toISOString() },
      user,
      overrideAccess: false,
    })
    expect(await findAssemblyVulnerabilities(payload, rack, { user })).toEqual([])
    await expect(
      payload.update({
        collection: 'asset-installations',
        id: installation.id,
        data: { slotPath: '2' },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow()
    const legacy: Asset[] = []
    for (const imported of [true, false]) {
      legacy.push(
        await payload.create({
          collection: 'assets',
          context: { assetImport: true },
          user,
          overrideAccess: false,
          data: {
            name: imported ? 'Legacy imported' : 'Legacy human',
            site: siteID,
            macAddress: mac(),
            ipAddress: imported ? '192.0.2.20' : '192.0.2.21',
            status: 'unknown',
            criticality: 'medium',
            ...(imported
              ? {
                  lastSeen: '2026-09-08T00:00:00Z',
                  fieldProvenance: { ipAddress: { quality: 'high', source: 'proneta' } },
                }
              : { networkMask: '255.255.255.0' }),
          } as never,
        }),
      )
    }
    const before = await payload.count({ collection: 'network-endpoints' })
    const request = (apply = false) =>
      createLocalReq({ user, req: { json: async () => ({ page: 1, apply }) } }, payload)
    expect(await (await migrateIdentity(await request())).json()).toMatchObject({ dryRun: true })
    await migrateIdentity(await request(true))
    await migrateIdentity(await request(true))
    expect((await payload.findByID({ collection: 'assets', id: rack.id })).uuid).toBe(rack.uuid)
    expect((await payload.count({ collection: 'network-endpoints' })).totalDocs).toBe(
      before.totalDocs + 2,
    )
    const migrated = await payload.find({
      collection: 'network-endpoints',
      depth: 0,
      where: { asset: { in: legacy.map(({ id }) => id) } },
    })
    expect(migrated.docs.find(({ asset }) => idOf(asset) === legacy[0].id)).toMatchObject({
      firstSeen: '2026-09-08T00:00:00.000Z',
      lastSeen: '2026-09-08T00:00:00.000Z',
      fieldProvenance: { addresses: { quality: 'high', source: 'proneta' } },
    })
    expect(
      migrated.docs.find(({ asset }) => idOf(asset) === legacy[1].id)?.fieldProvenance,
    ).toMatchObject({ addresses: { quality: 'human', source: 'human' } })
    expect((await assetHistoryScope(rack.id, payload, user)).assets).toMatchObject({
      asset: { in: [rack.id] },
    })
  })

  it('preserves MAC-free unresolved v2 evidence and offers weak clues only for review', async () => {
    const siteID = await site()
    const noMAC = scan(serial(), [])
    const root = '1.3.6.1.2.1.47.1.1.1.1.'
    const observation = {
      source: 'snmp',
      observedAt: '2026-09-10T00:00:00Z',
      fields: {},
      raw: {
        [`${root}4.1`]: 0,
        [`${root}5.1`]: 3,
        [`${root}11.1`]: 'Chassis-' + serial(),
        [`${root}12.1`]: 'Acme',
      },
      warnings: [],
    }
    const input = { ...noMAC, unresolved: [observation, { fields: {} }] }
    expect(parseOTserverOtter(JSON.stringify(input)).assets[0].macAddress).toBeUndefined()
    const imported = await upload(siteID, input)
    expect(imported.createdAssets).toBe(1)
    expect(imported.warnings).toContain('reconciliation')
    const prefix =
      `00:11:22:${randomBytes(2).toString('hex').match(/../g)!.join(':')}`.toUpperCase()
    const first = await asset(siteID, { macAddress: `${prefix}:10` }),
      second = await asset(siteID, { macAddress: `${prefix}:11` })
    const req = await createLocalReq({ user }, payload)
    await suggestAdjacentInterfaces(second, `${prefix}:11`, req)
    const neighbor = await payload.create({
      collection: 'topology-links',
      data: {
        site: siteID,
        import: imported.id,
        localAsset: first.id,
        remoteAsset: second.id,
        local: { macAddress: `${prefix}:10`, portId: '1' },
        remote: { macAddress: `${prefix}:11` },
        source: 'lldp',
        observedAt: '2026-09-10T00:00:00Z',
      },
    })
    expect(neighbor.id).toBeTruthy()
    const third = await asset(siteID)
    await suggestAttachmentChange(
      siteID,
      first.id,
      third.id,
      '1',
      '2026-09-11T00:00:00Z',
      await createLocalReq({ user }, payload),
    )
    const cases = await payload.find({
      collection: 'identity-cases',
      where: { site: { equals: siteID } },
    })
    expect(cases.docs.filter(({ confidence }) => confidence === 1)).toHaveLength(2)
    expect((await payload.findByID({ collection: 'assets', id: second.id })).lifecycle).toBe(
      'active',
    )
  })

  it('preserves human endpoint addresses and newer interface observations when qualifying legacy hardware', async () => {
    const siteID = await site()
    const device = await asset(siteID, {
      name: 'Manually baselined interface',
      macAddress: mac(),
      ipAddress: '192.0.2.80',
    })
    const hardwareSerial = serial()
    await upload(siteID, scan(hardwareSerial, [[device.macAddress!, '192.0.2.81']]))
    expect((await payload.findByID({ collection: 'assets', id: device.id })).ipAddress).toBe(
      '192.0.2.80',
    )
    const endpoint = (
      await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { asset: { equals: device.id } },
      })
    ).docs[0]
    await payload.update({
      collection: 'network-endpoints',
      id: endpoint.id,
      user,
      overrideAccess: false,
      data: { lastSeen: '2026-09-13T00:00:00Z', name: 'Operator confirmed interface' },
    })
    await upload(
      siteID,
      scan(hardwareSerial, [[device.macAddress!, '192.0.2.82']], '2026-09-12T00:00:00Z'),
    )
    expect(
      await payload.findByID({ collection: 'network-endpoints', id: endpoint.id }),
    ).toMatchObject({
      name: 'Operator confirmed interface',
      lastSeen: '2026-09-13T00:00:00.000Z',
      addresses: [{ address: '192.0.2.80' }],
    })
    expect(
      (await payload.count({ collection: 'assets', where: { site: { equals: siteID } } }))
        .totalDocs,
    ).toBe(1)
  })

  it('imports SNMP containment without mixing chassis and CPU descriptors, and reviews module moves', async () => {
    const siteID = await site()
    const chassisSerial = 'RACK-' + serial(),
      moduleSerial = 'CPU-' + serial()
    const input = scan(serial(), [[mac(), '192.0.2.70']])
    const root = '1.3.6.1.2.1.47.1.1.1.1.'
    const observedAt = '2026-09-10T00:00:00Z'
    const observation = {
      source: 'snmp',
      observedAt,
      fields: { ipAddress: '192.0.2.70' },
      warnings: [],
      raw: {
        [`${root}4.1`]: 0,
        [`${root}5.1`]: 3,
        [`${root}11.1`]: chassisSerial,
        [`${root}12.1`]: 'Acme',
        [`${root}13.1`]: 'Industrial rack',
        [`${root}4.2`]: 1,
        [`${root}5.2`]: 9,
        [`${root}6.2`]: 0,
        [`${root}11.2`]: moduleSerial,
        [`${root}12.2`]: 'Acme',
        [`${root}13.2`]: 'CPU module',
        [`${root}9.2`]: '1.2.3',
      },
    }
    const frame = {
      ...input,
      devices: [
        {
          ...input.devices[0],
          ports: [],
          observations: [
            observation,
            {
              source: 's7',
              observedAt,
              fields: { model: 'Unidentified CPU', firmwareVersion: '9.9.9' },
              raw: {},
              warnings: [],
            },
          ],
        },
      ],
    }
    expect((await upload(siteID, frame)).createdAssets).toBe(2)
    const inventory = await payload.find({
      collection: 'assets',
      depth: 0,
      where: { site: { equals: siteID } },
    })
    const chassis = inventory.docs.find(({ serialNumber }) => serialNumber === chassisSerial)!
    const cpu = inventory.docs.find(({ serialNumber }) => serialNumber === moduleSerial)!
    expect(chassis.physicalKind).toBe('chassis')
    expect(chassis.firmwareVersion).toBeFalsy()
    expect(cpu.firmwareVersion).toBe('1.2.3')
    expect(cpu.macAddress).toBeFalsy()
    const installed = await payload.find({
      collection: 'asset-installations',
      depth: 0,
      where: { module: { equals: cpu.id } },
    })
    expect(installed.docs[0]).toMatchObject({ parent: chassis.id, slotPath: '0' })
    const next = structuredClone(frame)
    next.scan.id = randomUUID()
    const nextObservation = next.devices[0].observations[0] as typeof observation
    nextObservation.raw[`${root}6.2`] = 1
    nextObservation.observedAt = '2026-09-11T00:00:00Z'
    await upload(siteID, next)
    next.scan.id = randomUUID()
    await upload(siteID, next)
    expect(
      (await payload.findByID({ collection: 'asset-installations', id: installed.docs[0].id }))
        .slotPath,
    ).toBe('0')
    expect(
      (await payload.find({ collection: 'identity-cases', where: { asset: { equals: cpu.id } } }))
        .docs,
    ).toHaveLength(1)
    expect(
      (await payload.count({ collection: 'assets', where: { site: { equals: siteID } } }))
        .totalDocs,
    ).toBe(2)
  })

  it('reconciles installed hardware, rolls back invalid splits, and preserves scoped history after transfer', async () => {
    const origin = await site(),
      destination = await site()
    const rack = await asset(origin, { physicalKind: 'chassis' })
    const rackTarget = await asset(origin, { physicalKind: 'chassis' })
    const oldCPU = await asset(origin, {
      physicalKind: 'module',
      macAddress: mac(),
      ipAddress: '192.0.2.40',
    })
    const newCPU = await asset(origin, { physicalKind: 'module', baselined: true })
    const keyFor = (id: string, scope: 'module' | 'chassis' = 'module') =>
      payload.create({
        collection: 'asset-identifiers',
        user,
        overrideAccess: false,
        data: {
          site: origin,
          asset: id,
          authority: 'verified-manufacturer',
          manufacturer: 'acme',
          serial: serial(),
          scope,
          state: 'accepted',
        },
      })
    const oldKey = await keyFor(oldCPU.id),
      newKey = await keyFor(newCPU.id)
    await keyFor(rack.id, 'chassis')
    await expect(action(oldCPU.id, { action: 'merge', target: newCPU.id })).rejects.toThrow(
      'Conflicting',
    )
    await expect(action(rackTarget.id, { action: 'merge', target: newCPU.id })).rejects.toThrow(
      'component kinds',
    )
    await expect(action(newCPU.id, { action: 'transfer', site: origin })).rejects.toThrow(
      'different destination',
    )
    await expect(
      action(newCPU.id, { action: 'merge', target: (await asset(destination)).id }),
    ).rejects.toThrow('same site')
    const placement = await payload.create({
      collection: 'asset-installations',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        parent: rack.id,
        module: oldCPU.id,
        slotPath: '0',
        installedAt: '2026-09-01T00:00:00Z',
      },
    })
    const endpoint = (
      await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { asset: { equals: oldCPU.id } },
      })
    ).docs[0]
    await payload.create({
      collection: 'service-bindings',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        asset: oldCPU.id,
        endpoint: endpoint.id,
        transport: 'ethernet',
        protocol: 'profinet',
        firstSeen: new Date().toISOString(),
      },
    })
    await expect(
      payload.create({
        collection: 'service-bindings',
        user,
        overrideAccess: false,
        data: {
          site: origin,
          asset: newCPU.id,
          endpoint: endpoint.id,
          transport: 'tcp',
          port: 102,
          protocol: 's7',
          firstSeen: new Date().toISOString(),
        },
      }),
    ).rejects.toThrow('endpoint’s asset')
    await expect(
      payload.create({
        collection: 'service-bindings',
        user,
        overrideAccess: false,
        data: {
          site: origin,
          asset: oldCPU.id,
          endpoint: endpoint.id,
          transport: 'tcp',
          port: 102.5,
          protocol: 's7',
          firstSeen: new Date().toISOString(),
        },
      }),
    ).rejects.toThrow('integers')
    await expect(
      payload.update({
        collection: 'network-endpoints',
        id: endpoint.id,
        data: { endedAt: new Date().toISOString() },
        user,
        overrideAccess: false,
      }),
    ).rejects.toThrow('identity action')
    await action(oldCPU.id, { action: 'replace', target: newCPU.id })
    expect(
      (await payload.findByID({ collection: 'asset-installations', id: placement.id })).removedAt,
    ).toBeTruthy()
    await action(rack.id, { action: 'merge', target: rackTarget.id })
    const installed = (
      await payload.find({
        collection: 'asset-installations',
        depth: 0,
        where: { and: [{ module: { equals: newCPU.id } }, { removedAt: { exists: false } }] },
      })
    ).docs[0]
    expect(idOf(installed.parent)).toBe(rackTarget.id)
    const currentEndpoint = (
      await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { and: [{ asset: { equals: newCPU.id } }, { endedAt: { exists: false } }] },
      })
    ).docs[0]
    await payload.create({
      collection: 'service-bindings',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        asset: newCPU.id,
        endpoint: currentEndpoint.id,
        transport: 'tcp',
        port: 102,
        protocol: 's7',
        address: '192.0.2.40',
        firstSeen: new Date().toISOString(),
      },
    })
    await payload.create({
      collection: 'network-endpoints',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        asset: newCPU.id,
        interfaceKey: 'ifIndex:1',
        addresses: [],
        firstSeen: new Date().toISOString(),
      },
    })
    await payload.create({
      collection: 'network-endpoints',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        asset: rackTarget.id,
        interfaceKey: 'ifIndex:1',
        addresses: [{ address: '2001:db8::1' }],
        firstSeen: new Date().toISOString(),
      },
    })
    await payload.create({
      collection: 'identity-cases',
      user,
      overrideAccess: false,
      data: {
        site: origin,
        asset: newCPU.id,
        candidate: oldCPU.id,
        kind: 'replacement',
        reason: 'Confirm maintenance baseline',
        status: 'open',
      },
    })
    const role = await payload.create({
      collection: 'user-roles',
      data: {
        name: `Identity reader ${randomUUID()}`,
        permissions: [{ site: origin, access: 'read' }],
      },
    })
    roleIDs.push(role.id)
    const reader = await payload.create({
      collection: 'users',
      data: { email: `${randomUUID()}@example.test`, password: randomUUID(), role: role.id },
    })
    userIDs.push(reader.id)
    await expect(action(newCPU.id, { action: 'retire' }, reader)).rejects.toThrow('Write access')
    const panels: string[] = []
    for (const [id, actor] of [
      [rack.id, user],
      [oldCPU.id, user],
      [newCPU.id, user],
      [newCPU.id, reader],
    ] as const) {
      const current = await payload.findByID({ collection: 'assets', id, depth: 0 })
      panels.push(
        renderToStaticMarkup(await DeviceIdentity({ asset: current, payload, user: actor })),
      )
    }
    expect(panels[0]).toContain('Merged into')
    expect(panels[1]).toContain('Replaced by')
    expect(panels[1]).toContain('(historical)')
    expect(panels[2]).toContain('ifIndex:1')
    expect(panels[2]).toContain('Confirm maintenance baseline')
    expect(panels[3]).not.toContain('Reconcile identity or lifecycle')
    expect(
      renderToStaticMarkup(
        await DeviceIdentity({
          asset: { ...rackTarget, uuid: null, physicalKind: null, lifecycle: null },
          payload,
          user: reader,
        }),
      ),
    ).toContain('migration required')
    await payload.update({
      collection: 'asset-installations',
      id: installed.id,
      data: { removedAt: new Date().toISOString() },
      user,
      overrideAccess: false,
    })
    await action(newCPU.id, { action: 'transfer', site: destination })
    expect(
      idOf((await payload.findByID({ collection: 'asset-identifiers', id: newKey.id })).site),
    ).toBe(destination)
    const oldHistory = await payload.find({
      collection: 'audit-logs',
      depth: 0,
      pagination: false,
      user: reader,
      overrideAccess: false,
      where: { assetID: { equals: newCPU.id } },
    })
    expect(oldHistory.docs.length).toBeGreaterThan(0)
    expect(oldHistory.docs.every(({ site }) => idOf(site) === origin)).toBe(true)
    const target = await asset(destination)
    const movable = (
      await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { and: [{ asset: { equals: newCPU.id } }, { endedAt: { exists: false } }] },
      })
    ).docs[0]
    await expect(
      action(newCPU.id, {
        action: 'split',
        target: target.id,
        endpoints: [movable.id],
        identifiers: [oldKey.id],
      }),
    ).rejects.toThrow('source asset')
    expect(
      idOf((await payload.findByID({ collection: 'network-endpoints', id: movable.id })).asset),
    ).toBe(newCPU.id)
    await action(newCPU.id, {
      action: 'split',
      target: target.id,
      endpoints: [movable.id],
      identifiers: [newKey.id],
    })
    expect(
      idOf((await payload.findByID({ collection: 'asset-identifiers', id: newKey.id })).asset),
    ).toBe(target.id)
  }, 60000)
})
