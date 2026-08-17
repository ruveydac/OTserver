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
  id: string
  ipAddress?: null | string
  macAddress?: null | string
  name?: null | string
  networkMask?: null | string
  status?: null | string
}

type LinkRecord = {
  id: string
  local: unknown
  localAsset?: null | string
  remote: unknown
  remoteAsset?: null | string
  source: string
}

export const buildTopologyGraph = (
  assetDocs: AssetRecord[],
  linkDocs: LinkRecord[],
): { edges: GraphEdge[]; nodes: GraphNode[] } => {
  const assetIds = new Set(assetDocs.map((asset) => String(asset.id)))
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []

  for (const asset of assetDocs) {
    nodes.push({
      id: String(asset.id),
      ipAddress: asset.ipAddress ?? undefined,
      label: asset.name || asset.macAddress || String(asset.id),
      status: asset.status ?? undefined,
      type: 'asset',
    })
  }

  const seenEdges = new Set<string>()
  for (const link of linkDocs) {
    const localId = link.localAsset ? String(link.localAsset) : null
    const remoteId = link.remoteAsset ? String(link.remoteAsset) : null
    if (!localId || !remoteId || !assetIds.has(localId) || !assetIds.has(remoteId)) continue
    if (localId === remoteId) continue

    const key = localId < remoteId ? `${localId}-${remoteId}` : `${remoteId}-${localId}`
    if (seenEdges.has(key)) continue
    seenEdges.add(key)

    const port = endpointPort(link.local) ?? endpointPort(link.remote)
    edges.push({
      id: `link-${link.id}`,
      label: port,
      source: localId,
      sourceProtocol: link.source,
      target: remoteId,
      type: 'explicit',
    })
  }

  const subnetGroups = new Map<string, string[]>()
  for (const asset of assetDocs) {
    if (!asset.ipAddress || !asset.networkMask) continue
    const subnet = computeSubnet(asset.ipAddress, asset.networkMask)
    if (!subnet) continue
    const key = `${subnet.network}/${subnet.prefix}`
    const group = subnetGroups.get(key) ?? []
    group.push(String(asset.id))
    subnetGroups.set(key, group)
  }

  for (const [subnetKey, members] of subnetGroups) {
    if (members.length < 2) continue
    const switchId = `subnet-${subnetKey}`
    nodes.push({ id: switchId, label: subnetKey, subnet: subnetKey, type: 'switch' })
    for (const memberId of members) {
      edges.push({
        id: `subnet-${switchId}-${memberId}`,
        source: memberId,
        target: switchId,
        type: 'subnet',
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

  const [assets, links] = await Promise.all([
    payload.find({
      collection: 'assets',
      depth: 0,
      overrideAccess: false,
      pagination: false,
      select: {
        gatewayAddress: true,
        ipAddress: true,
        macAddress: true,
        name: true,
        networkMask: true,
        status: true,
      },
      user,
      where: { site: { equals: selectedSiteId } },
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
  ])

  const assetDocs = assets.docs.map((asset) => ({
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

  const { edges, nodes } = buildTopologyGraph(assetDocs, linkDocs)

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
              {selectedSite.name} · {nodes.filter((n) => n.type === 'asset').length} assets ·{' '}
              {edges.filter((e) => e.type === 'explicit').length} links
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
