import { describe, expect, it, vi } from 'vitest'
import {
  endpointEvidence,
  expandPhysicalEvidence,
  observationIdentity,
  serviceEvidence,
} from '@/identity/evidence'
import {
  endpointBindingKey,
  hardwareKey,
  normalizeIdentity,
  OT_NAMESPACE,
  record,
  scopedKey,
  slotUUID,
  text,
} from '@/identity/keys'
import { importObservedAt, descriptiveFields } from '@/identity/reconcile'
import { expandNetworkWhere, parseAssetSearch } from '@/search/assetLucene'

vi.mock('@payloadcms/ui', () => ({ DefaultListView: () => null }))
vi.mock('@payloadcms/next/templates', () => ({ DefaultTemplate: () => null }))

describe('identity evidence boundaries', () => {
  it('distinguishes issuer scopes and device-local interface references', () => {
    const identity = {
      authority: 'cip',
      manufacturer: '1',
      scope: 'cpu' as const,
      serial: '00000042',
    }
    expect(hardwareKey({ ...identity, manufacturer: '001' })).toBe(hardwareKey(identity))
    expect(() => normalizeIdentity({ ...identity, manufacturer: '65536' })).toThrow('CIP')
    expect(() => normalizeIdentity({ ...identity, manufacturer: 'text' })).toThrow('CIP')
    expect(() => normalizeIdentity({ ...identity, authority: '' })).toThrow('manufacturer')
    expect(() => normalizeIdentity({ ...identity, scope: 'wrong' as never })).toThrow('scope')
    expect(() => slotUUID(OT_NAMESPACE, 'x'.repeat(101))).toThrow('slot')
    expect(record([])).toEqual({})
    expect(text(1)).toBe('')
    expect(endpointBindingKey('site-a', undefined, 'device-a', 'ifIndex:1')).not.toBe(
      endpointBindingKey('site-a', undefined, 'device-b', 'ifIndex:1'),
    )
    expect(endpointBindingKey('site-a', '00:11:22:33:44:55', 'device-a', '')).toBe(
      endpointBindingKey('site-a', '00:11:22:33:44:55', 'device-b', ''),
    )
    expect(endpointBindingKey('site-a', '00:11:22:33:44:55', 'device-a', '')).not.toBe(
      endpointBindingKey('site-b', '00:11:22:33:44:55', 'device-a', ''),
    )
    expect(scopedKey('site-a', '192.0.2.1')).not.toBe(scopedKey('site-b', '192.0.2.1'))
  })

  it('does not mistake malformed or partial protocol values for physical identity', () => {
    const macAddress = '00:11:22:33:44:55'
    const base = {
      source: 'ethernet-ip',
      observedAt: '2026-09-01T00:00:00Z',
      quality: 'high' as const,
      fields: { macAddress, serialNumber: '00000042', vendor: 'Acme' },
      raw: {
        vendorId: 1,
        deviceType: 14,
        serialNumber: '00000042',
        observationId: 'df4f3d70-dd8a-4454-85de-034211f4742d',
        subject: { kind: 'device', macAddress },
        serialClaim: {
          scope: 'cpu',
          issuer: 'Acme',
          manufacturerId: 1,
          original: '00000042',
        },
      },
    }
    expect(observationIdentity(base)?.scope).toBe('cpu')
    expect(
      observationIdentity({
        ...base,
        raw: {
          ...base.raw,
          deviceType: 2,
          serialClaim: { ...base.raw.serialClaim, scope: 'device' },
        },
      })?.scope,
    ).toBe('device')
    expect(
      observationIdentity({
        ...base,
        raw: {
          ...base.raw,
          serialClaim: { ...base.raw.serialClaim, scope: 'adapter' },
        },
      }),
    ).toBeUndefined()
    expect(observationIdentity({ ...base, raw: { ...base.raw, vendorId: 0 } })).toBeUndefined()
    expect(observationIdentity({ ...base, raw: { ...base.raw, vendorId: 1.5 } })).toBeUndefined()
    expect(
      observationIdentity({ ...base, raw: { ...base.raw, serialNumber: '00000043' } }),
    ).toBeUndefined()
    expect(observationIdentity({ ...base, source: 's7', raw: { module: '' } })).toBeUndefined()
    expect(
      observationIdentity({ ...base, source: 's7', fields: {}, raw: { module: '6ES7' } }),
    ).toBeUndefined()
    const noObservations = expandPhysicalEvidence({ name: 'Imported legacy device' })
    expect(noObservations).toEqual([{ name: 'Imported legacy device' }])
    const root = '1.3.6.1.2.1.47.1.1.1.1.'
    const raw = {
      unrelated: 'ignored',
      observationId: 'df4f3d70-dd8a-4454-85de-034211f4742d',
      subject: { kind: 'device', macAddress: '00:11:22:33:44:55' },
      physicalEntities: [
        {
          ref: 'entity:2',
          entPhysicalIndex: '2',
          class: 'module',
          parentRef: null,
          serialClaim: {
            scope: 'module',
            componentRef: 'entity:2',
            issuer: 'Acme',
            original: 'MODULE42',
          },
        },
      ],
      [`${root}5.1`]: 6,
      [`${root}5.2`]: 9,
      [`${root}11.2`]: 'MODULE42',
      [`${root}12.2`]: 'Acme',
      [`${root}4.2`]: 99,
      [`${root}6.2`]: 0,
      [`${root}5.3`]: 9,
      [`${root}11.3`]: 'unknown',
      [`${root}12.3`]: 'Acme',
    }
    const items = expandPhysicalEvidence({
      name: 'Adapter',
      macAddress,
      observations: [base, { ...base, source: 'snmp', raw }],
    })
    expect(items).toHaveLength(2)
    expect(items[1]).toMatchObject({
      name: 'MODULE42',
      slotPath: '0',
      identity: { scope: 'module' },
    })
    expect(items[1].parentComponentRef).toBeUndefined()
    expect(items[1].macAddress).toBeUndefined()
    expect(importObservedAt({ name: 'Unknown' }, '2026-09-10T00:00:00Z')).toBe(
      '2026-09-10T00:00:00Z',
    )
    expect(
      importObservedAt(
        {
          name: 'Known',
          lastSeen: 'bad',
          observations: [{ ...base, observedAt: '2026-09-10T00:00:00Z' }],
        },
        '2026-09-11T00:00:00Z',
      ),
    ).toBe('2026-09-10T00:00:00.000Z')
    expect(
      descriptiveFields({
        serialNumber: 'X',
        macAddress: '00:11:22:33:44:55',
        site: 'site',
        lastSeen: 'old',
        identity: {},
      }),
    ).toEqual({ serialNumber: 'X' })
  })

  it('does not promote PROFINET component serial claims to device identity', () => {
    const base = {
      source: 'profinet-dcp',
      observedAt: '2026-09-01T00:00:00Z',
      quality: 'high' as const,
      fields: { serialNumber: 'S C-V1X40202' },
      raw: {
        pnioRecords: [
          {
            index: '0xAFF0',
            parsed: {
              blockType: 32,
              manufacturerId: '002A',
              manufacturerName: 'Siemens AG',
              serialNumber: 'S C-V1X40202',
            },
          },
        ],
      },
    }
    expect(observationIdentity(base)).toBeUndefined()
    const im5 = {
      ...base,
      fields: { serialNumber: 'A1B2C3' },
      raw: {
        pnioRecords: [
          {
            index: '0xAFF5',
            parsed: {
              blockType: 37,
              im5Data: [{ vendorId: '0102', vendorName: 'Acme', imSerialNumber: 'A1B2C3' }],
            },
          },
        ],
      },
    }
    expect(observationIdentity(im5)).toBeUndefined()
    expect(observationIdentity({ ...base, fields: { serialNumber: 'S C-OTHER' } })).toBeUndefined()
    expect(
      observationIdentity({
        ...base,
        raw: {
          pnioRecords: [{ parsed: { manufacturerName: 'Siemens AG', serialNumber: 'S C-OTHER' } }],
        },
      }),
    ).toBeUndefined()
    expect(
      observationIdentity({
        ...base,
        raw: {
          pnioRecords: [{ parsed: { manufacturerId: '0', serialNumber: 'S C-V1X40202' } }],
        },
      }),
    ).toBeUndefined()
    expect(observationIdentity({ ...base, raw: {} })).toBeUndefined()
    const split = expandPhysicalEvidence({
      name: 'PLC',
      macAddress: '00:11:22:33:44:55',
      observations: [
        base,
        {
          ...base,
          source: 's7',
          raw: {
            module: '6ES7',
            observationId: 'df4f3d70-dd8a-4454-85de-034211f4742d',
            subject: { kind: 'device', macAddress: '00:11:22:33:44:55' },
            serialClaim: {
              scope: 'cpu',
              issuer: 'Siemens',
              original: 'S C-V1X40202',
              encoding: 's7-szl-text',
              normalizationVersion: 1,
            },
          },
        },
      ],
    })
    expect(split).toHaveLength(1)
    expect(split[0].identity).toEqual({
      authority: 'siemens',
      manufacturer: 'siemens',
      scope: 'cpu',
      serial: 'S C-V1X40202',
    })
  })

  it('uses only qualified unique SNMP chassis roots for device identity', () => {
    const root = '1.3.6.1.2.1.47.1.1.1.1.'
    const macAddress = '00:11:22:33:44:55'
    const entity = (index: string, className: string, serial: string) => ({
      ref: `entity:${index}`,
      entPhysicalIndex: index,
      class: className,
      parentRef: null,
      serialClaim: {
        scope: className,
        componentRef: `entity:${index}`,
        issuer: 'Acme',
        original: serial,
      },
    })
    const observation = (classes: Array<[string, number, string, string]>, selected?: string) => {
      const raw: Record<string, unknown> = {
        observationId: 'df4f3d70-dd8a-4454-85de-034211f4742d',
        subject: { kind: 'device', macAddress },
        physicalEntities: classes.map(([index, , className, serial]) =>
          entity(index, className, serial),
        ),
      }
      for (const [index, classID, , serial] of classes) {
        raw[`${root}4.${index}`] = 0
        raw[`${root}5.${index}`] = classID
        raw[`${root}11.${index}`] = serial
        raw[`${root}12.${index}`] = 'Acme'
      }
      if (selected) {
        raw.identityComponentRef = `entity:${selected}`
        raw.serialClaim = {
          scope: classes.find(([index]) => index === selected)?.[2],
          componentRef: `entity:${selected}`,
          issuer: 'Acme',
          original: classes.find(([index]) => index === selected)?.[3],
        }
      }
      return {
        source: 'snmp',
        observedAt: '2026-09-01T00:00:00Z',
        quality: 'high' as const,
        fields: { ipAddress: '192.0.2.10' },
        raw,
      }
    }

    const unique = expandPhysicalEvidence({
      name: 'Switch',
      macAddress,
      observations: [observation([['1', 3, 'chassis', 'ROOT1']], '1')],
    })
    expect(unique[0].identity).toEqual({
      authority: 'entity-mib',
      manufacturer: 'acme',
      scope: 'chassis',
      serial: 'ROOT1',
    })

    const moduleOnly = expandPhysicalEvidence({
      name: 'Switch',
      macAddress,
      observations: [observation([['1', 9, 'module', 'MODULE1']])],
    })
    expect(moduleOnly[0].identity).toBeUndefined()
    expect(moduleOnly[1]).toMatchObject({ identity: { scope: 'module', serial: 'MODULE1' } })

    const ambiguous = expandPhysicalEvidence({
      name: 'Switch',
      macAddress,
      observations: [
        observation([
          ['1', 3, 'chassis', 'ROOT1'],
          ['2', 11, 'stack', 'ROOT2'],
        ]),
      ],
    })
    expect(ambiguous[0].identity).toBeUndefined()
  })

  it('retains component identity when an SNMP module is qualified', () => {
    const component = expandPhysicalEvidence({
      name: 'Adapter',
      macAddress: '00:11:22:33:44:55',
      observations: [
        {
          source: 'snmp',
          observedAt: '2026-09-01T00:00:00Z',
          quality: 'high',
          fields: { ipAddress: '192.0.2.10' },
          raw: {
            observationId: 'df4f3d70-dd8a-4454-85de-034211f4742d',
            subject: { kind: 'device', macAddress: '00:11:22:33:44:55' },
            physicalEntities: [
              {
                ref: 'entity:2',
                entPhysicalIndex: '2',
                class: 'module',
                serialClaim: {
                  scope: 'module',
                  componentRef: 'entity:2',
                  issuer: 'Acme',
                  original: 'MODULE42',
                },
              },
            ],
            '1.3.6.1.2.1.47.1.1.1.1.4.2': 99,
            '1.3.6.1.2.1.47.1.1.1.1.5.2': 9,
            '1.3.6.1.2.1.47.1.1.1.1.11.2': 'MODULE42',
            '1.3.6.1.2.1.47.1.1.1.1.12.2': 'Acme',
          },
        },
      ],
    })
    expect(component[1]).toMatchObject({
      identity: {
        authority: 'entity-mib',
        manufacturer: 'acme',
        scope: 'module',
        serial: 'MODULE42',
      },
    })
  })

  it('retains interface address evidence without inventing listener associations', () => {
    const mac = '00:11:22:33:44:55'
    const endpoints = endpointEvidence({
      macAddress: mac,
      interfaces: [
        null,
        {},
        { key: 'bad', macAddress: 'invalid' },
        { macAddress: mac, key: 'ifIndex:1', source: 'snmp', ipAddresses: ['192.0.2.1', 1, 'bad'] },
      ],
    })
    expect(endpoints).toEqual([
      {
        macAddress: mac,
        interfaceKey: 'ifIndex:1',
        source: 'snmp',
        addresses: [{ address: '192.0.2.1' }],
      },
    ])
    expect(serviceEvidence({ ports: [{ key: 'tcp:65536' }], observations: [] })).toEqual([])
    expect(
      serviceEvidence({
        ports: [{ key: 'udp:44818', source: 'ethernet-ip' }],
        observations: [{ source: 'ethernet-ip', fields: { ipAddress: '192.0.2.1' } }],
      }),
    ).toEqual([
      {
        address: '192.0.2.1',
        transport: 'udp',
        port: 44818,
        protocol: 'ethernet-ip',
        source: 'ethernet-ip',
      },
    ])
    expect(serviceEvidence({ ports: [{ key: 'tcp:102', source: 's7' }] })).toEqual([])
    expect(serviceEvidence({})).toEqual([])
  })

  it('searches all current addresses consistently, including exclusions', () => {
    expect(expandNetworkWhere({ macAddress: { not_equals: '00:11:22:33:44:55' } })).toEqual({
      and: [
        { macAddress: { not_equals: '00:11:22:33:44:55' } },
        { 'networkMACs.address': { not_equals: '00:11:22:33:44:55' } },
      ],
    })
    expect(expandNetworkWhere({ ipAddress: { exists: false } })).toHaveProperty('and')
    expect(
      expandNetworkWhere({
        or: [{ ipAddress: { equals: '192.0.2.1' } }, { name: { equals: 'PLC' } }],
      }),
    ).toHaveProperty('or')
    expect(parseAssetSearch('lifecycle:active AND catalog:"6ES7"')).toHaveProperty('and')
  })
})
