import type { AdminViewServerProps } from 'payload'
import type { DefaultTemplateProps } from '@payloadcms/next/templates'
import { DefaultTemplate } from '@payloadcms/next/templates'

import { SiteSelector } from './SiteSelector'
import { TopologyCanvas } from './TopologyCanvas'
import type { GraphEdge, GraphNode } from './TopologyCanvas'

import './index.scss'

export const ipv4ToInt = (ip: string): number | null => {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    const num = Number(part)
    if (!Number.isInteger(num) || num < 0 || num > 255) return null
    result = (result << 8) | num
  }
  return result >>> 0
}

export const intToIpv4 = (num: number): string =>
  [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.')

export const maskToPrefix = (mask: number): number => {
  let count = 0
  let m = mask
  while (m & 0x80000000) {
    count++
    m = (m << 1) >>> 0
  }
  return count
}

export const computeSubnet = (
  ipAddress: string,
  networkMask: string,
): { network: string; prefix: number } | null => {
  const ip = ipv4ToInt(ipAddress)
  const mask = ipv4ToInt(networkMask)
  if (ip === null || mask === null) return null
  const network = (ip & mask) >>> 0
  return { network: intToIpv4(network), prefix: maskToPrefix(mask) }
}

export const endpointPort = (endpoint: unknown): string | undefined => {
  if (!endpoint || typeof endpoint !== 'object') return undefined
  const port = (endpoint as Record<string, unknown>).portId
  return typeof port === 'string' && port ? port : undefined
}

type AssetRecord = {
  assetClass?: null | string
  gatewayAddress?: null | string
  id: string
  ipAddress?: null | string
  macAddress?: null | string
  name?: null | string
  networkMask?: null | string
  status?: null | string
}

type EndpointRecord = {
  id: string
  asset: string
  context: string
  contextName: string
  mac?: string
  addresses: string[]
}

export const addEndpointTopology = (
  graph: { edges: GraphEdge[]; nodes: GraphNode[] },
  endpoints: EndpointRecord[],
) => {
  if (!endpoints.length) return graph
  const nodes = graph.nodes.filter((node) => node.type !== 'layer2')
  const edges = graph.edges.filter((edge) => edge.type !== 'layer2')
  const assets = new Set(nodes.map(({ id }) => id))
  const contexts = new Set<string>()
  for (const endpoint of endpoints) {
    if (!assets.has(endpoint.asset)) continue
    const id = `network-context-${endpoint.context}`
    if (!contexts.has(id)) {
      contexts.add(id)
      nodes.push({ id, type: 'layer2', label: `Network scope: ${endpoint.contextName}` })
    }
    edges.push({
      id: `endpoint-${endpoint.id}`,
      source: endpoint.asset,
      target: id,
      type: 'layer2',
      label: [endpoint.mac, ...endpoint.addresses].filter(Boolean).join(' · '),
    })
  }
  for (const node of nodes.filter(({ type }) => type !== 'layer2')) {
    const addresses = [
      ...new Set(
        endpoints.filter(({ asset }) => asset === node.id).flatMap(({ addresses }) => addresses),
      ),
    ]
    if (addresses.length) node.ipAddress = addresses.join(', ')
  }
  return { nodes, edges }
}

type LinkRecord = {
  id: string
  local: unknown
  localAsset?: null | string
  remote: unknown
  remoteAsset?: null | string
  source: string
}

type ArpRecord = {
  asset?: null | string
  import?: null | string
}

type ExplicitConnection = {
  id: string
  pair: string
  source: string
  sourcePort?: string
  sourceProtocol: string
  target: string
  targetPort?: string
}

export const buildTopologyGraph = (
  assetDocs: AssetRecord[],
  linkDocs: LinkRecord[],
  arpDocs: ArpRecord[] = [],
): { edges: GraphEdge[]; nodes: GraphNode[] } => {
  const assetIds = new Set(assetDocs.map((asset) => String(asset.id)))
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const explicitConnections = new Map<string, ExplicitConnection>()
  for (const link of linkDocs) {
    const localId = link.localAsset ? String(link.localAsset) : null
    const remoteId = link.remoteAsset ? String(link.remoteAsset) : null
    if (!localId || !remoteId || !assetIds.has(localId) || !assetIds.has(remoteId)) continue
    if (localId === remoteId) continue

    const localPort = endpointPort(link.local)
    const remotePort = endpointPort(link.remote)
    const [source, sourcePort, target, targetPort] =
      localId < remoteId
        ? [localId, localPort, remoteId, remotePort]
        : [remoteId, remotePort, localId, localPort]
    const pair = JSON.stringify([source, target])
    const key = JSON.stringify([source, sourcePort ?? null, target, targetPort ?? null])
    const connection = {
      id: String(link.id),
      pair,
      source,
      sourcePort,
      sourceProtocol: link.source,
      target,
      targetPort,
    }
    const existing = explicitConnections.get(key)
    if (!existing || connection.id.localeCompare(existing.id) < 0)
      explicitConnections.set(key, connection)
  }

  const connectionsByPair = new Map<string, ExplicitConnection[]>()
  for (const connection of explicitConnections.values()) {
    const connections = connectionsByPair.get(connection.pair) ?? []
    connections.push(connection)
    connectionsByPair.set(connection.pair, connections)
  }

  const explicitNeighbors = new Map<string, Set<string>>()
  for (const connections of connectionsByPair.values()) {
    connections.sort((left, right) => left.id.localeCompare(right.id))
    const [{ source, sourceProtocol, target }] = connections
    const labels = connections.map(({ sourcePort, targetPort }) =>
      sourcePort && targetPort
        ? `${sourcePort} - ${targetPort}`
        : sourcePort || targetPort || 'ports unknown',
    )
    const label =
      connections.length === 1
        ? labels[0] === 'ports unknown'
          ? undefined
          : labels[0]
        : `${connections.length} links: ${labels.join(', ')}`
    const sourceNeighbors = explicitNeighbors.get(source) ?? new Set<string>()
    const targetNeighbors = explicitNeighbors.get(target) ?? new Set<string>()
    sourceNeighbors.add(target)
    targetNeighbors.add(source)
    explicitNeighbors.set(source, sourceNeighbors)
    explicitNeighbors.set(target, targetNeighbors)
    edges.push({
      count: connections.length,
      id: `link-${connections[0].id}`,
      label,
      source,
      sourceProtocol,
      target,
      type: 'explicit',
    })
  }

  const gatewayAddresses = new Set(
    assetDocs.flatMap(({ gatewayAddress }) => (gatewayAddress ? [gatewayAddress] : [])),
  )
  for (const asset of assetDocs) {
    const type =
      asset.ipAddress && gatewayAddresses.has(asset.ipAddress)
        ? 'router'
        : asset.assetClass === 'network-device' ||
            (explicitNeighbors.get(String(asset.id))?.size ?? 0) > 1
          ? 'switch'
          : 'asset'
    nodes.push({
      id: String(asset.id),
      ipAddress: asset.ipAddress ?? undefined,
      label: asset.name || asset.macAddress || String(asset.id),
      status: asset.status ?? undefined,
      type,
    })
  }

  const membersByImport = new Map<string, Set<string>>()
  for (const observation of arpDocs) {
    const assetId = observation.asset ? String(observation.asset) : ''
    const importId = observation.import ? String(observation.import) : ''
    if (!assetIds.has(assetId) || !importId) continue
    const members = membersByImport.get(importId) ?? new Set<string>()
    members.add(assetId)
    membersByImport.set(importId, members)
  }

  const parent = new Map<string, string>()
  const root = (id: string): string => {
    const next = parent.get(id)
    if (!next || next === id) return id
    const result = root(next)
    parent.set(id, result)
    return result
  }
  for (const members of membersByImport.values()) {
    const [first, ...rest] = [...members].sort()
    if (!first) continue
    if (!parent.has(first)) parent.set(first, first)
    for (const member of rest) {
      if (!parent.has(member)) parent.set(member, member)
      parent.set(root(member), root(first))
    }
  }

  const layer2Domains = new Map<string, string[]>()
  for (const assetId of parent.keys()) {
    const domain = root(assetId)
    const members = layer2Domains.get(domain) ?? []
    members.push(assetId)
    layer2Domains.set(domain, members)
  }

  const assetsById = new Map(assetDocs.map((asset) => [String(asset.id), asset]))
  const nodesById = new Map(nodes.map((node) => [node.id, node]))
  for (const members of layer2Domains.values()) {
    if (members.length < 2) continue
    members.sort()
    const subnets = new Set(
      members.flatMap((id) => {
        const asset = assetsById.get(id)
        if (!asset?.ipAddress || !asset.networkMask) return []
        const subnet = computeSubnet(asset.ipAddress, asset.networkMask)
        return subnet ? [`${subnet.network}/${subnet.prefix}`] : []
      }),
    )
    const networkId = `layer2-${members[0]}`
    nodes.push({
      id: networkId,
      label: subnets.size === 1 ? `Inferred network (${[...subnets][0]})` : 'Inferred network',
      type: 'layer2',
    })

    const memberSet = new Set(members)
    const neighbors = new Map(members.map((member) => [member, new Set<string>()]))
    for (const edge of edges) {
      if (edge.type !== 'explicit' || !memberSet.has(edge.source) || !memberSet.has(edge.target))
        continue
      neighbors.get(edge.source)!.add(edge.target)
      neighbors.get(edge.target)!.add(edge.source)
    }
    const remaining = new Set(members)
    const components: string[][] = []
    while (remaining.size) {
      const first = remaining.values().next().value as string
      const component: string[] = []
      const pending = [first]
      remaining.delete(first)
      while (pending.length) {
        const member = pending.shift()!
        component.push(member)
        for (const neighbor of neighbors.get(member) ?? []) {
          if (!remaining.delete(neighbor)) continue
          pending.push(neighbor)
        }
      }
      components.push(component)
    }
    const representatives = new Set<string>()
    if (components.length > 1) {
      const rank: Record<GraphNode['type'], number> = { switch: 0, router: 1, asset: 2, layer2: 3 }
      for (const component of components) {
        component.sort((left, right) => {
          const typeRank = rank[nodesById.get(left)!.type] - rank[nodesById.get(right)!.type]
          return typeRank || left.localeCompare(right)
        })
        representatives.add(component[0])
      }
    }
    for (const memberId of members) {
      edges.push({
        id: `${networkId}-${memberId}`,
        redundant: !representatives.has(memberId),
        source: networkId,
        target: memberId,
        type: 'layer2',
      })
    }
  }

  return { edges, nodes }
}

const TopologyView = async (props: AdminViewServerProps) => {
  const { payload } = props
  const user = props.user ?? props.initPageResult?.req?.user
  const adminRoute = payload.config.routes.admin

  const templateProps = {
    i18n: props.i18n,
    locale: props.locale,
    params: props.params,
    payload,
    permissions: props.initPageResult?.permissions,
    req: props.initPageResult?.req,
    searchParams: props.searchParams,
    user,
    viewType: props.viewType,
    visibleEntities: props.initPageResult?.visibleEntities ?? { collections: [], globals: [] },
  } as DefaultTemplateProps

  const sites = await payload.find({
    collection: 'sites',
    depth: 0,
    overrideAccess: false,
    pagination: false,
    sort: 'name',
    user,
  })

  const selectedSiteParam = props.searchParams?.site
  const selectedSiteId = Array.isArray(selectedSiteParam) ? selectedSiteParam[0] : selectedSiteParam

  const siteOptions = sites.docs.map((site) => ({
    id: String(site.id),
    name: site.name,
  }))

  if (!selectedSiteId) {
    return (
      <DefaultTemplate {...templateProps}>
        <main className="topology-view">
          <header className="topology-view__header">
            <h1>Network topology</h1>
            <p>Select a site to display its discovered network architecture.</p>
          </header>
          <SiteSelector adminRoute={adminRoute} sites={siteOptions} />
        </main>
      </DefaultTemplate>
    )
  }

  const [assets, links, arpObservations, endpoints] = await Promise.all([
    payload.find({
      collection: 'assets',
      depth: 1,
      overrideAccess: false,
      pagination: false,
      select: {
        assetClass: true,
        gatewayAddress: true,
        ipAddress: true,
        macAddress: true,
        name: true,
        networkMask: true,
        status: true,
      },
      user,
      where: {
        and: [
          { site: { equals: selectedSiteId } },
          { lifecycle: { not_in: ['merged', 'replaced', 'retired'] } },
        ],
      },
    }),
    payload.find({
      collection: 'topology-links',
      depth: 0,
      overrideAccess: false,
      pagination: false,
      sort: '-observedAt',
      user,
      where: { site: { equals: selectedSiteId } },
    }),
    payload.find({
      collection: 'asset-observations',
      depth: 0,
      overrideAccess: false,
      pagination: false,
      select: { asset: true, import: true },
      user,
      where: {
        and: [{ site: { equals: selectedSiteId } }, { source: { equals: 'arp' } }],
      },
    }),
    payload.find({
      collection: 'network-endpoints',
      depth: 1,
      pagination: false,
      overrideAccess: false,
      user,
      where: { and: [{ site: { equals: selectedSiteId } }, { endedAt: { exists: false } }] },
    }),
  ])

  const assetDocs = assets.docs.map((asset) => ({
    assetClass:
      asset.assetClass && typeof asset.assetClass === 'object' ? asset.assetClass.legacyKey : null,
    gatewayAddress: asset.gatewayAddress,
    id: String(asset.id),
    ipAddress: asset.ipAddress,
    macAddress: asset.macAddress,
    name: asset.name,
    networkMask: asset.networkMask,
    status: asset.status,
  }))

  const linkDocs = links.docs.map((link) => ({
    id: String(link.id),
    local: link.local,
    localAsset: link.localAsset ? String(link.localAsset) : null,
    remote: link.remote,
    remoteAsset: link.remoteAsset ? String(link.remoteAsset) : null,
    source: link.source,
  }))

  const arpDocs = arpObservations.docs.map((observation) => ({
    asset: observation.asset ? String(observation.asset) : null,
    import: observation.import ? String(observation.import) : null,
  }))
  const { edges, nodes } = addEndpointTopology(
    buildTopologyGraph(assetDocs, linkDocs, arpDocs),
    endpoints.docs.map((endpoint) => ({
      id: endpoint.id,
      asset: typeof endpoint.asset === 'object' ? endpoint.asset?.id || '' : endpoint.asset || '',
      context:
        typeof endpoint.networkContext === 'object'
          ? endpoint.networkContext.id
          : endpoint.networkContext,
      contextName:
        typeof endpoint.networkContext === 'object'
          ? endpoint.networkContext.name
          : endpoint.networkContext,
      mac: endpoint.macAddress || undefined,
      addresses: (endpoint.addresses || []).map(({ address }) => address),
    })),
  )

  const selectedSite = siteOptions.find((site) => site.id === selectedSiteId)

  return (
    <DefaultTemplate {...templateProps}>
      <main className="topology-view">
        <header className="topology-view__header">
          <h1>Network topology</h1>
          <SiteSelector
            adminRoute={adminRoute}
            selectedSiteId={selectedSiteId}
            sites={siteOptions}
          />
          {selectedSite && (
            <span className="topology-view__site-label">
              {selectedSite.name} · {nodes.filter((n) => n.type !== 'layer2').length} assets ·{' '}
              {edges
                .filter((edge) => edge.type === 'explicit')
                .reduce((total, edge) => total + (edge.count ?? 1), 0)}{' '}
              links
            </span>
          )}
        </header>
        {nodes.length === 0 ? (
          <div className="topology-view__empty">
            <p>No assets found in this site.</p>
          </div>
        ) : (
          <TopologyCanvas adminRoute={adminRoute} edges={edges} nodes={nodes} />
        )}
      </main>
    </DefaultTemplate>
  )
}

export default TopologyView
