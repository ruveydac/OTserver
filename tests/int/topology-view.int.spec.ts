import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { getPayload, type Payload } from 'payload'

import TopologyView, {
  buildTopologyGraph,
  computeSubnet,
  endpointPort,
  ipv4ToInt,
  maskToPrefix,
} from '../../src/components/TopologyView'
import { ensureAdminRole } from '../../src/collections/UserRoles'

vi.mock('@payloadcms/ui', () => ({ DefaultListView: () => null }))
vi.mock('@payloadcms/next/templates', () => ({
  DefaultTemplate: ({ children }: { children?: unknown }) => children ?? null,
}))

describe('topology graph building', () => {
  it('computes subnet addresses from IP and mask', () => {
    expect(computeSubnet('192.168.10.42', '255.255.255.0')).toEqual({
      network: '192.168.10.0',
      prefix: 24,
    })
    expect(computeSubnet('10.0.5.7', '255.255.0.0')).toEqual({
      network: '10.0.0.0',
      prefix: 16,
    })
    expect(computeSubnet('172.16.3.200', '255.255.255.128')).toEqual({
      network: '172.16.3.128',
      prefix: 25,
    })
    expect(computeSubnet('not-an-ip', '255.255.255.0')).toBeNull()
    expect(computeSubnet('192.168.1.1', 'invalid')).toBeNull()
    expect(computeSubnet('2001:db8::1', '255.255.255.0')).toBeNull()
  })

  it('parses IPv4 addresses and masks', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0)
    expect(ipv4ToInt('255.255.255.255')).toBe(4294967295)
    expect(ipv4ToInt('192.168.1.1')).toBe(3232235777)
    expect(ipv4ToInt('256.1.1.1')).toBeNull()
    expect(ipv4ToInt('1.2.3')).toBeNull()
    expect(maskToPrefix(0xffffff00)).toBe(24)
    expect(maskToPrefix(0xffff0000)).toBe(16)
    expect(maskToPrefix(0x80000000)).toBe(1)
    expect(maskToPrefix(0)).toBe(0)
  })

  it('extracts port labels from link endpoints', () => {
    expect(endpointPort({ portId: 'eth0' })).toBe('eth0')
    expect(endpointPort({ portId: '' })).toBeUndefined()
    expect(endpointPort({ other: 'value' })).toBeUndefined()
    expect(endpointPort(null)).toBeUndefined()
    expect(endpointPort('string')).toBeUndefined()
  })

  it('builds nodes from assets and edges from resolved topology links', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: '192.168.1.10',
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'PLC-1',
        networkMask: '255.255.255.0',
        status: 'online',
      },
      {
        id: 'a2',
        ipAddress: '192.168.1.20',
        macAddress: 'AA:BB:CC:DD:EE:02',
        name: 'PLC-2',
        networkMask: '255.255.255.0',
        status: 'offline',
      },
      {
        id: 'a3',
        ipAddress: '10.0.0.1',
        macAddress: 'AA:BB:CC:DD:EE:03',
        name: 'Switch-1',
        networkMask: '255.0.0.0',
        status: 'online',
      },
    ]
    const links = [
      {
        id: 'l1',
        local: { macAddress: 'AA:BB:CC:DD:EE:01', portId: 'port1' },
        localAsset: 'a1',
        remote: { macAddress: 'AA:BB:CC:DD:EE:03' },
        remoteAsset: 'a3',
        source: 'lldp',
      },
      {
        id: 'l2',
        local: { macAddress: 'AA:BB:CC:DD:EE:02' },
        localAsset: 'a2',
        remote: { macAddress: 'AA:BB:CC:DD:EE:03', portId: 'port2' },
        remoteAsset: 'a3',
        source: 'snmp',
      },
    ]

    const { edges, nodes } = buildTopologyGraph(assets, links)

    expect(nodes).toHaveLength(3)
    expect(nodes[0]).toMatchObject({ id: 'a1', label: 'PLC-1', status: 'online' })
    expect(nodes.find(({ id }) => id === 'a3')?.type).toBe('switch')

    const explicitEdges = edges.filter((e) => e.type === 'explicit')
    expect(explicitEdges).toHaveLength(2)
    expect(explicitEdges[0]).toMatchObject({
      label: 'port1',
      source: 'a1',
      sourceProtocol: 'lldp',
      target: 'a3',
    })
    expect(explicitEdges[1]).toMatchObject({ label: 'port2', source: 'a2', target: 'a3' })
  })

  it('deduplicates edges between the same asset pair', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: null,
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'A',
        networkMask: null,
        status: 'online',
      },
      {
        id: 'a2',
        ipAddress: null,
        macAddress: 'AA:BB:CC:DD:EE:02',
        name: 'B',
        networkMask: null,
        status: 'online',
      },
    ]
    const links = [
      { id: 'l1', local: {}, localAsset: 'a1', remote: {}, remoteAsset: 'a2', source: 'lldp' },
      { id: 'l2', local: {}, localAsset: 'a2', remote: {}, remoteAsset: 'a1', source: 'lldp' },
      { id: 'l3', local: {}, localAsset: 'a1', remote: {}, remoteAsset: 'a1', source: 'lldp' },
    ]

    const { edges } = buildTopologyGraph(assets, links)
    const explicitEdges = edges.filter((e) => e.type === 'explicit')
    expect(explicitEdges).toHaveLength(1)
  })

  it('bundles distinct parallel port links without counting repeated observations twice', () => {
    const assets = [
      { id: 'a1', name: 'Switch' },
      { id: 'a2', name: 'PLC' },
    ]
    const links = [
      {
        id: 'l1',
        local: { portId: 'Gi1' },
        localAsset: 'a1',
        remote: { portId: 'eth0' },
        remoteAsset: 'a2',
        source: 'lldp',
      },
      {
        id: 'l2',
        local: { portId: 'eth1' },
        localAsset: 'a2',
        remote: { portId: 'Gi2' },
        remoteAsset: 'a1',
        source: 'lldp',
      },
      {
        id: 'l3',
        local: { portId: 'eth0' },
        localAsset: 'a2',
        remote: { portId: 'Gi1' },
        remoteAsset: 'a1',
        source: 'snmp',
      },
    ]

    const explicitEdges = buildTopologyGraph(assets, links).edges.filter(
      ({ type }) => type === 'explicit',
    )

    expect(explicitEdges).toHaveLength(1)
    expect(explicitEdges[0]).toMatchObject({
      count: 2,
      label: '2 links: Gi1 - eth0, Gi2 - eth1',
      source: 'a1',
      target: 'a2',
    })
  })

  it('skips links with unresolved asset references', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: null,
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'A',
        networkMask: null,
        status: 'online',
      },
    ]
    const links = [
      { id: 'l1', local: {}, localAsset: 'a1', remote: {}, remoteAsset: null, source: 'lldp' },
      { id: 'l2', local: {}, localAsset: 'missing', remote: {}, remoteAsset: 'a1', source: 'lldp' },
    ]

    const { edges } = buildTopologyGraph(assets, links)
    expect(edges.filter((e) => e.type === 'explicit')).toHaveLength(0)
  })

  it('creates a layer 2 domain from assets observed by ARP in the same scan', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: '192.168.1.10',
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'A',
        networkMask: '255.255.255.0',
        status: 'online',
      },
      {
        id: 'a2',
        ipAddress: '192.168.1.20',
        macAddress: 'AA:BB:CC:DD:EE:02',
        name: 'B',
        networkMask: '255.255.255.0',
        status: 'online',
      },
      {
        id: 'a3',
        ipAddress: '192.168.1.30',
        macAddress: 'AA:BB:CC:DD:EE:03',
        name: 'C',
        networkMask: '255.255.255.0',
        status: 'online',
      },
      {
        id: 'a4',
        ipAddress: '10.0.0.1',
        macAddress: 'AA:BB:CC:DD:EE:04',
        name: 'D',
        networkMask: '255.0.0.0',
        status: 'online',
      },
    ]

    const arp = [
      { asset: 'a1', import: 'scan-1' },
      { asset: 'a2', import: 'scan-1' },
      { asset: 'a3', import: 'scan-1' },
      { asset: 'a4', import: 'scan-2' },
    ]
    const { edges, nodes } = buildTopologyGraph(assets, [], arp)

    const layer2Nodes = nodes.filter((n) => n.type === 'layer2')
    expect(layer2Nodes).toHaveLength(1)
    expect(layer2Nodes[0].label).toBe('Inferred network (192.168.1.0/24)')

    const layer2Edges = edges.filter((e) => e.type === 'layer2')
    expect(layer2Edges).toHaveLength(3)
    expect(layer2Edges.every((e) => e.source === layer2Nodes[0].id)).toBe(true)
  })

  it('keeps one inferred connection per component already joined by recorded links', () => {
    const assets = [
      { assetClass: 'network-device', id: 'core', name: 'Core Switch' },
      { id: 'hmi', name: 'Offline HMI' },
      { id: 'plc', name: 'PLC' },
      { id: 'robot', name: 'Maintenance Robot' },
      { id: 'router', name: 'Edge Router' },
    ]
    const links = [
      {
        id: 'l1',
        local: {},
        localAsset: 'router',
        remote: {},
        remoteAsset: 'core',
        source: 'lldp',
      },
      {
        id: 'l2',
        local: {},
        localAsset: 'core',
        remote: {},
        remoteAsset: 'plc',
        source: 'snmp',
      },
      {
        id: 'l3',
        local: {},
        localAsset: 'hmi',
        remote: {},
        remoteAsset: 'robot',
        source: 'profinet-dcp',
      },
    ]
    const arp = assets.map(({ id }) => ({ asset: id, import: 'scan-1' }))

    const graph = buildTopologyGraph(assets, links, arp)
    const inferredEdges = graph.edges.filter(({ type }) => type === 'layer2')

    expect(graph.edges.filter(({ type }) => type === 'explicit')).toHaveLength(3)
    expect(inferredEdges).toHaveLength(5)
    expect(
      inferredEdges
        .filter(({ redundant }) => !redundant)
        .map(({ target }) => target)
        .sort(),
    ).toEqual(['core', 'hmi'])

    const reordered = buildTopologyGraph(
      [...assets].reverse(),
      [...links].reverse(),
      [...arp].reverse(),
    )
    expect(
      reordered.edges
        .filter(({ redundant, type }) => type === 'layer2' && !redundant)
        .map(({ target }) => target)
        .sort(),
    ).toEqual(['core', 'hmi'])
  })

  it('hides an inferred network whose members are all connected by recorded links', () => {
    const assets = ['a', 'b', 'c'].map((id) => ({ id, name: id }))
    const links = [
      { id: 'l1', local: {}, localAsset: 'a', remote: {}, remoteAsset: 'b', source: 'lldp' },
      { id: 'l2', local: {}, localAsset: 'b', remote: {}, remoteAsset: 'c', source: 'lldp' },
      { id: 'l3', local: {}, localAsset: 'c', remote: {}, remoteAsset: 'a', source: 'lldp' },
    ]
    const arp = assets.map(({ id }) => ({ asset: id, import: 'scan-1' }))

    const { edges } = buildTopologyGraph(assets, links, arp)

    expect(edges.filter(({ type }) => type === 'explicit')).toHaveLength(3)
    expect(edges.filter(({ type }) => type === 'layer2').every(({ redundant }) => redundant)).toBe(
      true,
    )
  })

  it('does not reduce inferred connections using a path outside their network domain', () => {
    const assets = ['a', 'b', 'outside'].map((id) => ({ id, name: id }))
    const links = [
      {
        id: 'l1',
        local: {},
        localAsset: 'a',
        remote: {},
        remoteAsset: 'outside',
        source: 'lldp',
      },
      {
        id: 'l2',
        local: {},
        localAsset: 'outside',
        remote: {},
        remoteAsset: 'b',
        source: 'lldp',
      },
    ]

    const { edges } = buildTopologyGraph(assets, links, [
      { asset: 'a', import: 'scan-1' },
      { asset: 'b', import: 'scan-1' },
    ])

    expect(edges.filter(({ type }) => type === 'layer2').every(({ redundant }) => !redundant)).toBe(
      true,
    )
  })

  it('does not create a layer 2 node for a single ARP observation', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: '192.168.1.10',
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'A',
        networkMask: '255.255.255.0',
        status: 'online',
      },
    ]

    const { edges, nodes } = buildTopologyGraph(assets, [], [{ asset: 'a1', import: 'scan-1' }])
    expect(nodes.filter((n) => n.type === 'layer2')).toHaveLength(0)
    expect(edges.filter((e) => e.type === 'layer2')).toHaveLength(0)
  })

  it('merges overlapping ARP scans into one layer 2 domain', () => {
    const assets = ['a1', 'a2', 'a3'].map((id) => ({ id, name: id }))
    const { edges, nodes } = buildTopologyGraph(
      assets,
      [],
      [
        { asset: 'a1', import: 'scan-1' },
        { asset: 'a2', import: 'scan-1' },
        { asset: 'a2', import: 'scan-2' },
        { asset: 'a3', import: 'scan-2' },
      ],
    )

    expect(nodes.filter(({ type }) => type === 'layer2')).toHaveLength(1)
    expect(edges.filter(({ type }) => type === 'layer2')).toHaveLength(3)
  })

  it('renders an asset used as a gateway as a router', () => {
    const assets = [
      {
        gatewayAddress: '192.168.1.1',
        id: 'host',
        ipAddress: '192.168.1.10',
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: 'Host',
      },
      {
        id: 'gateway',
        ipAddress: '192.168.1.1',
        macAddress: 'AA:BB:CC:DD:EE:02',
        name: 'Gateway',
      },
    ]

    const { nodes } = buildTopologyGraph(assets, [])
    expect(nodes.find(({ id }) => id === 'gateway')?.type).toBe('router')
  })

  it('falls back to MAC address when asset has no name', () => {
    const assets = [
      {
        id: 'a1',
        ipAddress: null,
        macAddress: 'AA:BB:CC:DD:EE:01',
        name: null,
        networkMask: null,
        status: null,
      },
    ]

    const { nodes } = buildTopologyGraph(assets, [])
    expect(nodes[0].label).toBe('AA:BB:CC:DD:EE:01')
  })
})

describe('topology view registration and site visibility', () => {
  let payload: Payload

  beforeAll(async () => {
    payload = await getPayload({ config })
  })

  it('registers the topology view and nav link in admin config', async () => {
    const resolvedConfig = await config
    const adminComponents = resolvedConfig.admin?.components
    expect(adminComponents?.afterNavLinks).toContain('@/components/TopologyNavLink')

    const views = adminComponents?.views as Record<string, unknown> | undefined
    expect(views).toBeDefined()
    const customView = (views as { custom?: { Component: string; path: string } }).custom
    expect(customView).toMatchObject({ Component: '@/components/TopologyView', path: '/topology' })
  })

  it('forwards permissions and visible entities from initPageResult to the admin template', async () => {
    let userID: string | undefined
    try {
      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `topology-nav-${randomUUID()}@example.test`,
          name: 'Topology nav',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const permissions = { collections: { sites: { read: true } } }
      const visibleEntities = { collections: ['sites'], globals: [] }

      const element = await TopologyView({
        initPageResult: { permissions, req: { user }, visibleEntities },
        payload,
        user,
      } as never)

      expect(element.props.permissions).toBe(permissions)
      expect(element.props.visibleEntities).toBe(visibleEntities)
    } finally {
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })

  it('returns all sites for an admin user with site-scoped access control', async () => {
    let siteAID: string | undefined
    let siteBID: string | undefined
    let userID: string | undefined

    try {
      const adminRole = await ensureAdminRole(payload)
      const user = await payload.create({
        collection: 'users',
        data: {
          email: `topology-admin-${randomUUID()}@example.test`,
          name: 'Topology admin',
          password: randomUUID(),
          role: adminRole.id,
        },
      })
      userID = user.id

      const siteA = await payload.create({
        collection: 'sites',
        data: { name: `Topology site A ${randomUUID()}`, type: 'Plant' },
      })
      siteAID = siteA.id

      const siteB = await payload.create({
        collection: 'sites',
        data: { name: `Topology site B ${randomUUID()}`, type: 'Area' },
      })
      siteBID = siteB.id

      const result = await payload.find({
        collection: 'sites',
        depth: 0,
        overrideAccess: false,
        pagination: false,
        sort: 'name',
        user,
      })

      const siteIds = result.docs.map((site) => String(site.id))
      expect(siteIds).toContain(siteAID)
      expect(siteIds).toContain(siteBID)
    } finally {
      if (siteAID) await payload.delete({ collection: 'sites', id: siteAID })
      if (siteBID) await payload.delete({ collection: 'sites', id: siteBID })
      if (userID) await payload.delete({ collection: 'users', id: userID })
    }
  })
})
