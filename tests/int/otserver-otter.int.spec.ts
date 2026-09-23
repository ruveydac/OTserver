import config from '@/payload.config'
import { randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { getPayload, handleEndpoints, type Payload } from 'payload'

import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import { parseOTserverOtter } from '../../src/importers/otserverOtter'

const randomMAC = () =>
  `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`

const exportFile = (localMAC: string, remoteMAC: string) => ({
  format: 'otserver-scan',
  schemaVersion: 2,
  scanner: { name: 'OTserver Otter', version: '0.2.0', npcapVersion: '1.83' },
  scan: {
    id: randomUUID(),
    startedAt: '2026-08-10T10:00:00Z',
    finishedAt: '2026-08-10T10:01:00Z',
    targets: ['192.0.2.0/24'],
    interface: {
      id: 'test',
      name: 'Test adapter',
      macAddress: localMAC,
      addresses: ['192.0.2.1/24'],
    },
    partial: true,
  },
  devices: [
    {
      macAddress: localMAC,
      macAddresses: [localMAC],
      ipAddresses: ['192.0.2.10'],
      interfaces: [
        {
          key: 'ifIndex:1',
          source: 'snmp',
          name: 'eth0',
          description: 'Control interface',
          macAddress: localMAC,
          ipAddresses: [],
          adminStatus: 'up',
          operStatus: 'up',
          speed: 1_000_000_000,
          mtu: 1500,
          raw: { ifType: 6 },
        },
      ],
      ports: [
        {
          key: 'udp:137',
          source: 'netbios',
          interfaceKey: 'ifIndex:1',
          portId: '137',
          description: 'NetBIOS Name Service',
          macAddress: localMAC,
          vlans: [10],
          raw: { state: 'open' },
        },
      ],
      observations: [
        {
          source: 'arp',
          observedAt: '2026-08-10T10:00:05Z',
          ipAddress: '192.0.2.10',
          macAddress: localMAC,
          fields: {
            description: 'ARP description',
            firmwareVersion: 'ARP-FW',
            gatewayAddress: '192.0.2.1',
            hardwareVersion: 'ARP-HW',
            ipAddress: '192.0.2.10',
            lastSeen: '2026-08-10T10:00:05Z',
            location: 'ARP location',
            macAddress: localMAC,
            model: 'ARP model',
            name: 'ARP name',
            networkMask: '255.255.255.0',
            operatingSystem: 'ARP OS',
            osAccuracy: 60,
            protocols: ['other'],
            serialNumber: 'ARP-SERIAL',
            status: 'online',
          },
          raw: { ouiVendor: 'Siemens AG' },
          warnings: ['ARP warning'],
        },
        {
          source: 'netbios',
          observedAt: '2026-08-10T10:00:06Z',
          ipAddress: '192.0.2.10',
          fields: {
            name: 'MAIN-PLC',
            protocols: ['netbios'],
          },
          raw: {
            names: [{ name: 'MAIN-PLC', suffix: 0, flags: 1024, group: false }],
            workgroup: 'OTLAB',
            unitId: '00:00:00:00:00:00',
          },
          warnings: [],
        },
        {
          source: 'profinet-dcp',
          observedAt: '2026-08-10T10:00:10Z',
          fields: {
            macAddress: localMAC,
            model: 'SIMATIC S7-1500 CPU',
            name: 'Main PLC',
            protocols: ['profinet'],
          },
          raw: { deviceId: 1 },
          warnings: [],
        },
        {
          source: 'niagara-fox',
          observedAt: '2026-08-10T10:00:20Z',
          fields: {
            macAddress: localMAC,
            operatingSystem: 'Embedded Linux',
            protocols: ['niagara-fox'],
          },
          raw: { ports: [] },
          warnings: [],
        },
        {
          source: 'opc-ua',
          observedAt: '2026-08-10T10:00:25Z',
          fields: {
            macAddress: localMAC,
            name: 'LAB-ASSET-1',
            model: 'OPC UA Lab Device',
            serialNumber: 'OPCLAB0001',
            firmwareVersion: '2.1.0',
            location: 'Plant1/Line3/Cell2',
            description: 'Test Device',
            status: 'online',
            protocols: ['opc-ua'],
          },
          raw: {
            endpointUrl: 'opc.tcp://192.0.2.10:4840',
            applicationUri: 'urn:otserver:lab:opcua:server',
            userTokenPolicies: ['anonymous'],
          },
          warnings: [],
        },
        {
          source: 'dnp3',
          observedAt: '2026-08-10T10:00:26Z',
          fields: { macAddress: localMAC, protocols: ['dnp3'] },
          raw: { masterAddress: 1, outstationAddress: 1 },
          warnings: [],
        },
        {
          source: 'iec61850',
          observedAt: '2026-08-10T10:00:27Z',
          fields: { macAddress: localMAC, hardwareVersion: 'HW-2', protocols: ['iec61850'] },
          raw: { logicalDevices: ['LD0'] },
          warnings: [],
        },
      ],
    },
    {
      macAddress: remoteMAC,
      macAddresses: [remoteMAC],
      ipAddresses: [],
      interfaces: [],
      ports: [],
      observations: [
        {
          source: 's7',
          observedAt: '2026-08-10T10:00:11Z',
          fields: {
            macAddress: remoteMAC,
            name: 'Remote IO',
            protocols: ['s7', 'ethernet-ip', 'ethernet-ip'],
          },
          raw: {},
          warnings: [],
        },
      ],
    },
  ],
  links: [
    {
      source: 'lldp',
      observedAt: '2026-08-10T10:00:30Z',
      local: {
        macAddress: localMAC,
        stationName: 'Main PLC',
        interfaceKey: 'ifIndex:1',
        portId: '1',
        portMac: localMAC,
      },
      remote: {
        macAddress: remoteMAC,
        stationName: 'Remote IO',
        interfaceKey: 'ifIndex:2',
        portId: '2',
        portMac: remoteMAC,
      },
      raw: { chassisIdSubtype: 4 },
    },
  ],
  unresolved: [
    {
      source: 'unknown',
      observedAt: '2026-08-10T10:00:40Z',
      ipAddress: '198.51.100.10',
      macAddress: remoteMAC,
      fields: { name: 'Unresolved target' },
      raw: ['opaque'],
      warnings: ['Unresolved warning'],
    },
  ],
  warnings: ['Scan warning'],
  errors: ['Scan error'],
})

type MutableExport = {
  [key: string]: unknown
  devices: Array<{
    [key: string]: unknown
    macAddress: string
    observations?: Array<{
      [key: string]: unknown
      fields?: Record<string, unknown>
      observedAt?: unknown
      source?: unknown
    }>
  }>
  errors: unknown[]
  links: Array<{
    [key: string]: unknown
    local: { macAddress: unknown }
    observedAt: unknown
    source: unknown
  }>
  warnings: unknown[]
}

const mutableExport = (localMAC: string, remoteMAC: string) =>
  exportFile(localMAC, remoteMAC) as unknown as MutableExport

describe('OTserver Otter importer', () => {
  it('accepts the minimal known-vulnerability PLC fixture', async () => {
    const input = await readFile(
      new URL('../otserver_otter_files/OTserver-Otter-known-vulnerability.json', import.meta.url),
      'utf8',
    )
    const result = parseOTserverOtter(input)

    expect(result.assets).toHaveLength(1)
    expect(result.assets[0]).toMatchObject({
      firmwareVersion: 'V2.8.0',
      model: 'SIMATIC S7-1500 CPU',
      name: 'Demo S7-1500 PLC',
      vendor: 'Siemens AG',
    })
    expect(result.assets[0].observations?.[1]).toMatchObject({
      fields: { protocols: ['netbios'] },
      ports: [{ key: 'udp:137', source: 'netbios' }],
      quality: 'medium',
      raw: { unitId: '00:00:00:00:00:00', workgroup: 'OTLAB' },
      source: 'netbios',
    })
  })

  it('validates scanner files and rejects exported credentials', () => {
    const file = exportFile(randomMAC(), randomMAC())
    expect(parseOTserverOtter(JSON.stringify(file)).assets).toHaveLength(2)
    expect(
      parseOTserverOtter(JSON.stringify(file)).assets[0].observations?.map(
        ({ fields, quality, source }) => [source, quality, fields.protocols],
      ),
    ).toEqual([
      ['arp', 'medium', ['other']],
      ['netbios', 'medium', ['netbios']],
      ['profinet-dcp', 'high', ['profinet']],
      ['niagara-fox', 'medium', ['niagara-fox']],
      ['opc-ua', 'medium', ['opc-ua']],
      ['dnp3', 'medium', ['dnp3']],
      ['iec61850', 'medium', ['iec61850']],
    ])
    expect(() => parseOTserverOtter(JSON.stringify({ ...file, schemaVersion: 1 }))).toThrow(
      'schemaVersion 2',
    )
    expect(() => parseOTserverOtter(JSON.stringify({ ...file, community: 'public' }))).toThrow(
      'secret-like field',
    )
  })

  it('validates identities, observations, links, and untrusted field types', () => {
    expect(() => parseOTserverOtter('{')).toThrow('not valid JSON')
    expect(() =>
      parseOTserverOtter(JSON.stringify({ format: 'otserver-scan', schemaVersion: 2 })),
    ).toThrow('metadata are required')

    const localMAC = randomMAC()
    const remoteMAC = randomMAC()
    const cleaned = mutableExport(localMAC, remoteMAC)
    cleaned.devices = [
      {
        interfaces: 'invalid',
        macAddress: localMAC.toLowerCase().replaceAll(':', '-'),
        observations: [
          {
            fields: {
              gatewayAddress: 'invalid',
              ipAddress: '999.1.1.1',
              lastSeen: 'not-a-date',
              macAddress: remoteMAC,
              name: 42,
              networkMask: false,
              osAccuracy: 101,
              protocols: ['s7', 's7', 'invalid', 1],
              status: 'broken',
              unknown: 'discarded',
            },
            observedAt: '2026-08-10T10:00:00Z',
            source: 'future-protocol',
            warnings: ['kept', 1],
          },
        ],
        ports: null,
      },
    ]
    cleaned.links = []
    cleaned.warnings = ['warning', 1]
    cleaned.errors = ['error', false]
    const result = parseOTserverOtter(JSON.stringify(cleaned))
    expect(result.assets[0]).toMatchObject({
      macAddress: localMAC,
      name: localMAC,
      observations: [
        {
          fields: { macAddress: localMAC, protocols: ['s7'] },
          interfaces: [],
          ports: [],
          quality: 'low',
          source: 'unknown',
          warnings: ['kept'],
        },
      ],
    })
    expect(result.warnings).toEqual(['warning', 'error'])

    const duplicate = mutableExport(localMAC, remoteMAC)
    duplicate.devices[1].macAddress = localMAC
    expect(() => parseOTserverOtter(JSON.stringify(duplicate))).toThrow('Duplicate device MAC')

    const noObservations = mutableExport(localMAC, remoteMAC)
    noObservations.devices = [{ macAddress: localMAC }]
    expect(() => parseOTserverOtter(JSON.stringify(noObservations))).toThrow('has no observations')

    const badObservation = mutableExport(localMAC, remoteMAC)
    badObservation.devices[0].observations![0].observedAt = 'invalid'
    expect(() => parseOTserverOtter(JSON.stringify(badObservation))).toThrow(
      'observedAt is invalid',
    )

    const badLinkMAC = mutableExport(localMAC, remoteMAC)
    badLinkMAC.links[0].local.macAddress = 'invalid'
    expect(() => parseOTserverOtter(JSON.stringify(badLinkMAC))).toThrow('local.macAddress')

    const badLinkDate = mutableExport(localMAC, remoteMAC)
    badLinkDate.links[0].observedAt = 'invalid'
    expect(() => parseOTserverOtter(JSON.stringify(badLinkDate))).toThrow('links[0].observedAt')

    const unknownLinkSource = mutableExport(localMAC, remoteMAC)
    unknownLinkSource.links[0].source = 1
    expect(parseOTserverOtter(JSON.stringify(unknownLinkSource)).links?.[0].source).toBe('unknown')
  })

  it('imports every contract shape and supported asset field while merging by quality', async () => {
    const payload: Payload = await getPayload({ config })
    const localMAC = randomMAC()
    const remoteMAC = randomMAC()
    let siteID: string | undefined
    let userID: string | undefined
    let importID: string | undefined

    try {
      const adminRole = await ensureAdminRole(payload)
      const plcClass = await ensureAssetClass(payload, 'plc')
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `scanner-${randomUUID()}@example.test`,
          name: 'Scanner test',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id
      const site = await payload.create({
        collection: 'sites',
        data: { name: `Scanner site ${randomUUID()}`, type: 'Test' },
        overrideAccess: false,
        user,
      })
      siteID = site.id
      const file = exportFile(localMAC, remoteMAC)
      const data = Buffer.from(JSON.stringify(file))
      const imported = await payload.create({
        collection: 'asset-imports',
        data: {
          site: siteID,
          source: 'otserver-otter',
          sourceVersion: 'unknown',
          status: 'pending',
        },
        file: { data, mimetype: 'text/plain', name: 'scan.json', size: data.length },
        overrideAccess: false,
        user,
      })
      importID = imported.id
      expect(imported).toMatchObject({
        createdAssets: 2,
        scanMetadata: { scan: file.scan, scanner: file.scanner },
        skippedAssets: 3,
        sourceVersion: '0.2.0',
        status: 'completed',
        unresolved: file.unresolved,
        warnings: 'Scan warning\nScan error\n1 observation(s) require identity reconciliation.',
      })

      const assets = await payload.find({
        collection: 'assets',
        depth: 0,
        pagination: false,
        where: { site: { equals: siteID } },
      })
      const localAsset = assets.docs.find(({ macAddress }) => macAddress === localMAC)
      expect(localAsset).toMatchObject({
        assetClass: plcClass.id,
        description: 'Test Device',
        fieldProvenance: {
          assetClass: { quality: 'medium', source: 'asset-class-rule' },
          vendor: { quality: 'medium', source: 'arp' },
        },
        firmwareVersion: '2.1.0',
        gatewayAddress: '192.0.2.1',
        hardwareVersion: 'HW-2',
        ipAddress: '192.0.2.10',
        lastSeen: '2026-08-10T10:00:27.000Z',
        location: 'Plant1/Line3/Cell2',
        macAddress: localMAC,
        model: 'SIMATIC S7-1500 CPU',
        name: 'Main PLC',
        networkMask: '255.255.255.0',
        operatingSystem: 'Embedded Linux',
        osAccuracy: 60,
        protocols: ['other', 'netbios', 'profinet', 'niagara-fox', 'opc-ua', 'dnp3', 'iec61850'],
        serialNumber: 'OPCLAB0001',
        status: 'online',
        vendor: 'Siemens AG',
      })
      expect(assets.docs.find(({ macAddress }) => macAddress === remoteMAC)?.protocols).toEqual([
        's7',
        'ethernet-ip',
      ])
      const endpoints = await payload.find({
        collection: 'network-endpoints',
        depth: 0,
        where: { asset: { equals: localAsset!.id } },
      })
      expect(endpoints.docs[0]).toMatchObject({
        addresses: [
          {
            address: '192.0.2.10',
            gatewayAddress: '192.0.2.1',
            networkMask: '255.255.255.0',
          },
        ],
        interfaceKey: 'ifIndex:1',
        macAddress: localMAC,
        source: 'snmp',
      })
      const services = await payload.find({
        collection: 'service-bindings',
        depth: 0,
        where: { asset: { equals: localAsset!.id } },
      })
      expect(services.docs[0]).toMatchObject({
        address: '192.0.2.10',
        port: 137,
        protocol: 'netbios',
        source: 'netbios',
        transport: 'udp',
      })
      const observations = await payload.find({
        collection: 'asset-observations',
        depth: 0,
        pagination: false,
        where: { import: { equals: importID } },
      })
      expect(observations.docs).toHaveLength(8)
      expect(observations.docs.find(({ source }) => source === 'arp')).toMatchObject({
        fields: {
          description: 'ARP description',
          firmwareVersion: 'ARP-FW',
          gatewayAddress: '192.0.2.1',
          hardwareVersion: 'ARP-HW',
          ipAddress: '192.0.2.10',
          lastSeen: '2026-08-10T10:00:05Z',
          location: 'ARP location',
          macAddress: localMAC,
          model: 'ARP model',
          name: 'ARP name',
          networkMask: '255.255.255.0',
          operatingSystem: 'ARP OS',
          osAccuracy: 60,
          protocols: ['other'],
          serialNumber: 'ARP-SERIAL',
          status: 'online',
          vendor: 'Siemens AG',
        },
        interfaces: file.devices[0].interfaces,
        ports: file.devices[0].ports,
        quality: 'medium',
        raw: { ouiVendor: 'Siemens AG' },
        warnings: ['ARP warning'],
      })
      expect(observations.docs.find(({ source }) => source === 'netbios')).toMatchObject({
        fields: { name: 'MAIN-PLC', protocols: ['netbios'] },
        ports: [{ key: 'udp:137', source: 'netbios' }],
        quality: 'medium',
        raw: { unitId: '00:00:00:00:00:00', workgroup: 'OTLAB' },
      })
      expect(observations.docs.map(({ quality }) => quality)).toEqual(
        expect.arrayContaining(['high', 'medium']),
      )
      const links = await payload.find({
        collection: 'topology-links',
        depth: 0,
        where: { import: { equals: importID } },
      })
      expect(links.docs[0]).toMatchObject({
        local: file.links[0].local,
        localAsset: expect.any(String),
        observedAt: '2026-08-10T10:00:30.000Z',
        raw: file.links[0].raw,
        remote: file.links[0].remote,
        remoteAsset: expect.any(String),
        source: 'lldp',
      })
    } finally {
      if (importID) {
        await payload.delete({
          collection: 'asset-observations',
          overrideAccess: true,
          where: { import: { equals: importID } },
        })
        await payload.delete({
          collection: 'topology-links',
          overrideAccess: true,
          where: { import: { equals: importID } },
        })
        await payload.delete({ collection: 'asset-imports', id: importID })
      }
      if (siteID) {
        const assets = await payload.find({
          collection: 'assets',
          depth: 0,
          pagination: false,
          where: { site: { equals: siteID } },
        })
        for (const asset of assets.docs)
          await payload.delete({ collection: 'assets', id: asset.id })
        await payload.delete({ collection: 'sites', id: siteID })
      }
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })

  it('normalizes legacy REST uploads while preserving permissions and audit identity', async () => {
    const payload: Payload = await getPayload({ config })
    const apiKey = randomUUID()
    const localMAC = randomMAC()
    const remoteMAC = randomMAC()
    let importID: string | undefined
    let roleID: string | undefined
    let userID: string | undefined
    const siteIDs: string[] = []

    const upload = async (site: string) => {
      const form = new FormData()
      form.append(
        '_payload',
        JSON.stringify({
          site,
          source: 'otserver-scanner',
          sourceVersion: '0.2.0',
          status: 'pending',
        }),
      )
      form.append(
        'file',
        new Blob([JSON.stringify(exportFile(localMAC, remoteMAC))], { type: 'application/json' }),
        'scan.json',
      )
      return handleEndpoints({
        config,
        path: '/api/asset-imports',
        request: new Request('http://localhost/api/asset-imports', {
          body: form,
          headers: { Authorization: `users API-Key ${apiKey}` },
          method: 'POST',
        }),
      })
    }

    try {
      const writableSite = await payload.create({
        collection: 'sites',
        data: { name: `API key site ${randomUUID()}`, type: 'Test' },
      })
      siteIDs.push(writableSite.id)
      const blockedSite = await payload.create({
        collection: 'sites',
        data: { name: `Blocked API key site ${randomUUID()}`, type: 'Test' },
      })
      siteIDs.push(blockedSite.id)
      const role = await payload.create({
        collection: 'user-roles',
        data: {
          name: `API key writer ${randomUUID()}`,
          permissions: [{ access: 'read-write', site: writableSite.id }],
        },
      })
      roleID = role.id
      const user = await payload.create({
        collection: 'users',
        data: {
          apiKey,
          email: `api-key-${randomUUID()}@example.test`,
          enableAPIKey: true,
          name: 'API key scanner user',
          password: randomUUID(),
          role: role.id,
        },
      })
      userID = user.id

      const visibleUser = await handleEndpoints({
        config,
        path: `/api/users/${user.id}`,
        request: new Request(`http://localhost/api/users/${user.id}`, {
          headers: { Authorization: `users API-Key ${apiKey}` },
        }),
      })
      expect(visibleUser.status).toBe(200)
      expect(JSON.stringify(await visibleUser.json())).not.toContain(apiKey)

      const response = await upload(writableSite.id)
      expect(response.status).toBe(201)
      const result = (await response.json()) as {
        doc: {
          createdAssets: number
          id: string
          source: string
          status: string
          updatedAssets: number
        }
      }
      importID = result.doc.id
      expect(result.doc).toMatchObject({
        createdAssets: 2,
        source: 'otserver-otter',
        status: 'completed',
        updatedAssets: 0,
      })

      const audit = await payload.find({
        collection: 'audit-logs',
        limit: 1,
        where: {
          and: [
            { targetCollection: { equals: 'asset-imports' } },
            { documentID: { equals: importID } },
            { actorID: { equals: user.id } },
          ],
        },
      })
      expect(audit.docs[0]?.actorEmail).toBe(user.email)
      expect((await upload(blockedSite.id)).status).toBe(403)

      await payload.update({
        collection: 'user-roles',
        data: { permissions: [{ access: 'read', site: writableSite.id }] },
        id: role.id,
      })
      expect((await upload(writableSite.id)).status).toBe(403)

      await payload.update({
        collection: 'users',
        data: { enableAPIKey: false },
        id: user.id,
      })
      expect((await upload(writableSite.id)).status).toBe(403)
    } finally {
      if (importID) {
        await payload.delete({
          collection: 'asset-observations',
          overrideAccess: true,
          where: { import: { equals: importID } },
        })
        await payload.delete({
          collection: 'topology-links',
          overrideAccess: true,
          where: { import: { equals: importID } },
        })
        await payload.delete({ collection: 'asset-imports', id: importID })
      }
      for (const site of siteIDs) {
        const assets = await payload.find({
          collection: 'assets',
          depth: 0,
          pagination: false,
          where: { site: { equals: site } },
        })
        for (const asset of assets.docs)
          await payload.delete({ collection: 'assets', id: asset.id })
      }
      if (userID) await payload.delete({ collection: 'users', id: userID })
      if (roleID) await payload.delete({ collection: 'user-roles', id: roleID })
      for (const site of siteIDs) await payload.delete({ collection: 'sites', id: site })
    }
  })
})
