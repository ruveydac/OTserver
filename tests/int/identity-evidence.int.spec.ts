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
import { addEndpointTopology } from '@/components/TopologyView'

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
    expect(endpointBindingKey('network', undefined, 'device-a', 'ifIndex:1')).not.toBe(
      endpointBindingKey('network', undefined, 'device-b', 'ifIndex:1'),
    )
    expect(endpointBindingKey('network', '00:11:22:33:44:55', 'device-a', '')).toBe(
      endpointBindingKey('network', '00:11:22:33:44:55', 'device-b', ''),
    )
    expect(scopedKey('context-a', '192.0.2.1')).not.toBe(scopedKey('context-b', '192.0.2.1'))
  })

  it('does not mistake malformed or partial protocol values for physical identity', () => {
    const base = {
      source: 'ethernet-ip',
      observedAt: '2026-09-01T00:00:00Z',
      quality: 'high' as const,
      fields: { serialNumber: '00000042' },
      raw: { vendorId: 1, deviceType: 14, serialNumber: '00000042' },
    }
    expect(observationIdentity(base)?.scope).toBe('cpu')
    expect(observationIdentity({ ...base, raw: { ...base.raw, deviceType: 2 } })?.scope).toBe(
      'device',
    )
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
      macAddress: '00:11:22:33:44:55',
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

  it('searches all current addresses consistently, including exclusions, and shows explicit network scopes', () => {
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
    const graph = addEndpointTopology(
      {
        nodes: [
          { id: 'a', label: 'Dual-homed CPU', type: 'asset' },
          { id: 'inferred', label: 'old', type: 'layer2' },
        ],
        edges: [],
      },
      [
        { id: 'e1', asset: 'a', context: 'n1', contextName: 'Control', addresses: ['192.0.2.1'] },
        {
          id: 'e2',
          asset: 'a',
          context: 'n2',
          contextName: 'Management',
          mac: '00:11:22:33:44:55',
          addresses: ['198.51.100.1'],
        },
        { id: 'e3', asset: 'hidden', context: 'n1', contextName: 'Control', addresses: [] },
      ],
    )
    expect(graph.nodes).toHaveLength(3)
    expect(graph.edges).toHaveLength(2)
    expect(graph.nodes[0].ipAddress).toBe('192.0.2.1, 198.51.100.1')
    expect(addEndpointTopology(graph, [])).toBe(graph)
  })
})
