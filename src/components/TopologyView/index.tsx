import type { AdminViewServerProps } from 'payload'
import type { DefaultTemplateProps } from '@payloadcms/next/templates'
import { DefaultTemplate } from '@payloadcms/next/templates'

import { SiteSelector } from './SiteSelector'
import { TopologyCanvas } from './TopologyCanvas'
import { buildTopologyGraph } from './graph'

import './index.scss'

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
  const filterParam = props.searchParams?.filter
  const assetFilter = (Array.isArray(filterParam) ? filterParam[0] : filterParam)
    ?.trim()
    .slice(0, 100)

  const siteOptions = sites.docs.map((site) => ({
    id: String(site.id),
    name: site.path || site.name,
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

  const assets = await payload.find({
    collection: 'assets',
    depth: 1,
    overrideAccess: false,
    limit: 2001,
    pagination: false,
    sort: 'id',
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
        ...(assetFilter
          ? [
              {
                or: [
                  { name: { contains: assetFilter } },
                  { ipAddress: { contains: assetFilter } },
                  { macAddress: { contains: assetFilter } },
                ],
              },
            ]
          : []),
      ],
    },
  })

  if (assets.docs.length > 2000) {
    return (
      <DefaultTemplate {...templateProps}>
        <main className="topology-view">
          <header className="topology-view__header">
            <h1>Network topology</h1>
            <SiteSelector
              adminRoute={adminRoute}
              filter={assetFilter}
              selectedSiteId={selectedSiteId}
              sites={siteOptions}
            />
          </header>
          <div className="topology-view__empty">
            <p>
              This scope contains more than 2,000 assets. Filter by asset name, IP address, or MAC
              address to display a bounded view.
            </p>
          </div>
        </main>
      </DefaultTemplate>
    )
  }

  const assetIDs = assets.docs.map(({ id }) => id)
  const [links, arpObservations] = await Promise.all([
    payload.find({
      collection: 'topology-links',
      depth: 0,
      limit: 10001,
      overrideAccess: false,
      sort: '-observedAt',
      user,
      where: {
        and: [
          { site: { equals: selectedSiteId } },
          { localAsset: { in: assetIDs } },
          { remoteAsset: { in: assetIDs } },
        ],
      },
    }),
    payload.find({
      collection: 'asset-observations',
      depth: 0,
      limit: 10001,
      overrideAccess: false,
      sort: '-observedAt',
      select: { asset: true, import: true },
      user,
      where: {
        and: [
          { site: { equals: selectedSiteId } },
          { asset: { in: assetIDs } },
          { source: { equals: 'arp' } },
        ],
      },
    }),
  ])

  const evidenceWasBounded = links.docs.length > 10000 || arpObservations.docs.length > 10000

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

  const linkDocs = links.docs.slice(0, 10000).map((link) => ({
    id: String(link.id),
    local: link.local,
    localAsset: link.localAsset ? String(link.localAsset) : null,
    remote: link.remote,
    remoteAsset: link.remoteAsset ? String(link.remoteAsset) : null,
  }))

  const arpDocs = arpObservations.docs.slice(0, 10000).map((observation) => ({
    asset: observation.asset ? String(observation.asset) : null,
    import: observation.import ? String(observation.import) : null,
  }))
  const { edges, nodes } = buildTopologyGraph(assetDocs, linkDocs, arpDocs)

  const selectedSite = siteOptions.find((site) => site.id === selectedSiteId)

  return (
    <DefaultTemplate {...templateProps}>
      <main className="topology-view">
        <header className="topology-view__header">
          <h1>Network topology</h1>
          <SiteSelector
            adminRoute={adminRoute}
            filter={assetFilter}
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
          <span className="topology-view__site-label">
            Scope: exact site “{selectedSite?.name || selectedSiteId}”
            {assetFilter ? `, assets matching “${assetFilter}”` : ''}.
            {evidenceWasBounded
              ? ' Showing the newest 10,000 matching topology/evidence records.'
              : ''}
          </span>
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
