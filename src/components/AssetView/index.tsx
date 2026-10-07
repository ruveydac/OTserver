import Link from 'next/link'
import type { DocumentViewServerProps } from 'payload'
import type { ReactNode } from 'react'

import CopyButton from '@/components/AssetView/CopyButton'
import DensityToggle from '@/components/AssetView/DensityToggle'
import {
  criticalityLabels,
  formatDateTime,
  protocolLabels,
  statusLabels,
} from '@/components/labels'
import DeviceIdentity from '@/components/DeviceIdentity'
import { assetHistoryScope } from '@/identity/relationships'
import type { Asset, AssetObservation, AuditLog, TopologyLink } from '@/payload-types'
import { bySeverity, findAssemblyVulnerabilities } from '@/vulnerabilities/match'
import { documentClientProps } from '@/integrations/payload/admin'

import './index.scss'

const MAX_LISTED_VULNERABILITIES = 5
const vulnerabilitySeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED'] as const

type VulnerabilitySeverity = (typeof vulnerabilitySeverities)[number]

const tabs = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Network' },
  { id: 'hardware', label: 'Hardware' },
  { id: 'security', label: 'Security' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'history', label: 'History' },
] as const

type Tab = (typeof tabs)[number]['id']

type Detail = {
  key?: string
  label: string
  value: ReactNode
  wide?: boolean
}

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const array = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

const firstParam = (value: unknown): string | undefined => {
  const item = Array.isArray(value) ? value[0] : value
  return typeof item === 'string' ? item : undefined
}

const relationID = (value: unknown): string | undefined => {
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  const item = record(value)
  return item.id === undefined ? undefined : String(item.id)
}

const relationLabel = (value: unknown, fallback = 'Unavailable') => {
  const item = record(value)
  if (typeof item.name === 'string' && item.name) return item.name
  if (typeof item.path === 'string' && item.path) return item.path
  return relationID(value) || fallback
}

const cvssBand = (score: number): Exclude<VulnerabilitySeverity, 'UNRATED'> =>
  score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW'

const matchSeverity = (match: { cvssScore?: null | number; cvssSeverity?: null | string }) => {
  const reported = match.cvssSeverity?.toUpperCase()
  if (vulnerabilitySeverities.includes(reported as VulnerabilitySeverity)) {
    return reported as VulnerabilitySeverity
  }
  return match.cvssScore == null ? 'UNRATED' : cvssBand(match.cvssScore)
}

const auditValue = (value: unknown) =>
  value !== null && typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')

const auditField = (value: string) =>
  value
    .replaceAll(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/^./, (character) => character.toUpperCase())

const fieldValue = (asset: Asset, field: string, value: ReactNode) => {
  const provenance = record(record(asset.fieldProvenance)[field])
  if (!provenance.quality && !provenance.source) return value

  return (
    <span className="asset-view__provenanced-value">
      <span>{value}</span>
      <small>
        {typeof provenance.quality === 'string' ? provenance.quality : 'recorded'}
        {typeof provenance.source === 'string' ? ` · ${provenance.source}` : ''}
      </small>
    </span>
  )
}

const copyValue = (value?: null | string) =>
  value ? (
    <span className="asset-view__copy-value">
      <code>{value}</code>
      <CopyButton value={value} />
    </span>
  ) : undefined

const Section = ({
  details,
  title,
  wide,
}: {
  details: Detail[]
  title: string
  wide?: boolean
}) => (
  <section
    className={wide ? 'asset-view__section asset-view__section--wide' : 'asset-view__section'}
  >
    <div className="asset-view__section-heading">
      <h2>{title}</h2>
      <span>
        {details.length} item{details.length === 1 ? '' : 's'}
      </span>
    </div>
    <dl className="asset-view__details">
      {details.map(({ key, label, value, wide: wideDetail }, index) => (
        <div
          className={
            wideDetail ? 'asset-view__detail asset-view__detail--wide' : 'asset-view__detail'
          }
          key={key || `${label}-${index}`}
        >
          <dt>{label}</dt>
          <dd>{value === null || value === undefined || value === '' ? '—' : value}</dd>
        </div>
      ))}
    </dl>
  </section>
)

const InspectorCard = ({ children, title }: { children: ReactNode; title: string }) => (
  <section className="asset-view__inspector-card">
    <div className="asset-view__section-heading">
      <h2>{title}</h2>
    </div>
    {children}
  </section>
)

const auditChanges = (log: AuditLog) => {
  const changes = record(log.changes)
  return Object.entries(changes).flatMap(([field, value]) => {
    const change = record(value)
    const before = Object.hasOwn(change, 'before') ? auditValue(change.before) : undefined
    const after = Object.hasOwn(change, 'after') ? auditValue(change.after) : 'removed'
    return [`${auditField(field)}: ${before ? `${before} → ` : ''}${after}`]
  })
}

const auditDetails = (log: AuditLog): Detail => {
  const changes = record(log.changes)

  return {
    key: log.id,
    label: formatDateTime(log.createdAt),
    value: (
      <div className="asset-view__audit-entry">
        <p>
          <strong>{log.action[0]?.toUpperCase() + log.action.slice(1)}</strong>
          {' by '}
          {log.actorName || log.actorEmail || 'System'}
        </p>
        {Object.entries(changes).length ? (
          <ul>
            {Object.entries(changes).map(([field, value]) => {
              const change = record(value)
              const hasBefore = Object.hasOwn(change, 'before')
              const hasAfter = Object.hasOwn(change, 'after')

              return (
                <li key={field}>
                  <strong>{auditField(field)}:</strong>{' '}
                  {hasBefore ? `${auditValue(change.before)} → ` : ''}
                  {hasAfter ? auditValue(change.after) : 'removed'}
                </li>
              )
            })}
          </ul>
        ) : (
          <span>No field changes recorded.</span>
        )}
      </div>
    ),
    wide: true,
  }
}

const observationDetails = (observation: AssetObservation, open = false): Detail => {
  const warnings = array(observation.warnings)
  const evidence = {
    fields: observation.fields,
    interfaces: observation.interfaces,
    ports: observation.ports,
    warnings: observation.warnings,
    raw: observation.raw,
  }

  return {
    key: observation.id,
    label: `${observation.source} · ${formatDateTime(observation.observedAt)}`,
    value: (
      <details className="asset-view__evidence" open={open}>
        <summary>
          <span>{observation.quality} quality evidence</span>
          {warnings.length ? (
            <span>
              {warnings.length} warning{warnings.length === 1 ? '' : 's'}
            </span>
          ) : null}
        </summary>
        <pre>{JSON.stringify(evidence, null, 2)}</pre>
      </details>
    ),
    wide: true,
  }
}

const topologyPeer = (link: TopologyLink, assetID: string) => {
  const localID = relationID(link.localAsset)
  return String(localID) === String(assetID)
    ? { asset: link.remoteAsset, data: link.remote }
    : { asset: link.localAsset, data: link.local }
}

const topologyDetails = (link: TopologyLink, assetID: string, adminRoute: string): Detail => {
  const peer = topologyPeer(link, assetID)
  const peerID = relationID(peer.asset)
  const peerLabel = relationLabel(peer.asset, relationLabel(peer.data, 'Unresolved peer'))
  const peerValue =
    peerID && typeof peer.asset === 'object' ? (
      <Link href={`${adminRoute}/collections/assets/${peerID}`}>{peerLabel}</Link>
    ) : (
      peerLabel
    )

  return {
    key: link.id,
    label: `${link.source} · ${formatDateTime(link.observedAt)}`,
    value: (
      <div className="asset-view__topology-entry">
        <strong>{peerValue}</strong>
        <span>{JSON.stringify(peer.data)}</span>
      </div>
    ),
    wide: true,
  }
}

const VulnerabilityList = ({
  assetURL,
  matches,
}: {
  assetURL: string
  matches: ReturnType<typeof findAssemblyVulnerabilities> extends Promise<infer T> ? T : never
}) => {
  const visible = matches.slice(0, MAX_LISTED_VULNERABILITIES)

  if (!matches.length) return <span>None matched</span>

  return (
    <>
      <ul className="asset-view__vulnerabilities">
        {visible.map((match) => {
          const score = match.cvssScore ?? undefined
          const band = matchSeverity(match)
          return (
            <li key={match.cve}>
              {match.cve}
              {band === 'UNRATED' ? null : (
                <span className={`asset-view__severity--${band.toLowerCase()}`} title={band}>
                  {score ?? band}
                </span>
              )}
              {match.knownExploited ? <span className="asset-view__exploited">KEV</span> : null}
            </li>
          )
        })}
      </ul>
      <Link href={`${assetURL}/vulnerabilities`}>
        {matches.length > visible.length
          ? `View all ${matches.length} matches`
          : 'View match details'}
      </Link>
    </>
  )
}

const AssetView = async (props: DocumentViewServerProps) => {
  if (props.routeSegments.at(-1) === 'create') {
    const { DefaultEditView } = await import('@payloadcms/ui')
    return <DefaultEditView {...documentClientProps(props)} />
  }

  const asset = props.doc as Asset
  const adminRoute = props.payload.config.routes.admin
  const apiRoute = props.payload.config.routes.api || '/api'
  const assetURL = `${adminRoute}/collections/assets/${asset.id}`
  const selectedParam = firstParam(props.searchParams?.tab)
  const selectedTab: Tab = tabs.some(({ id }) => id === selectedParam)
    ? (selectedParam as Tab)
    : 'overview'
  const historyPageParam = firstParam(props.searchParams?.historyPage)
  const requestedHistoryPage = Number(historyPageParam)
  const historyPage =
    Number.isInteger(requestedHistoryPage) && requestedHistoryPage > 0 ? requestedHistoryPage : 1
  const populatedSite = typeof asset.site === 'object' ? asset.site : undefined
  const populatedAssetClass = typeof asset.assetClass === 'object' ? asset.assetClass : undefined
  const siteID = relationID(asset.site)
  const assetClassID = relationID(asset.assetClass)
  const historyScope = asset.uuid
    ? await assetHistoryScope(asset.id, props.payload, props.user)
    : {
        assets: { asset: { equals: asset.id } },
        observations: { asset: { equals: asset.id } },
      }
  const customFields = record(asset.customFields)
  const endpointCountRequest = props.payload.count
    ? props.payload.count({
        collection: 'network-endpoints',
        overrideAccess: false,
        user: props.user,
        where: { and: [{ asset: { equals: asset.id } }, { endedAt: { exists: false } }] },
      })
    : Promise.resolve({ totalDocs: asset.networkAddresses?.length || 0 })
  const siteRequest =
    populatedSite?.path || !siteID
      ? Promise.resolve(populatedSite)
      : props.payload.findByID({
          collection: 'sites',
          depth: 0,
          disableErrors: true,
          id: siteID,
          overrideAccess: false,
          select: { name: true, path: true },
          user: props.user,
        })
  const assetClassRequest =
    populatedAssetClass?.name || !assetClassID
      ? Promise.resolve(populatedAssetClass)
      : props.payload.findByID({
          collection: 'asset-classes',
          depth: 0,
          disableErrors: true,
          id: assetClassID,
          overrideAccess: false,
          select: { name: true },
          user: props.user,
        })

  const [
    definitions,
    auditLogs,
    observations,
    topologyLinks,
    vulnerabilityMatches,
    endpointCount,
    loadedSite,
    loadedAssetClass,
  ] = await Promise.all([
    props.payload.find({
      collection: 'asset-fields',
      depth: 0,
      overrideAccess: false,
      pagination: false,
      sort: 'label',
      user: props.user,
    }),
    props.payload.find({
      collection: 'audit-logs',
      depth: 0,
      limit: 50,
      overrideAccess: false,
      page: historyPage,
      sort: '-createdAt',
      user: props.user,
      where: historyScope.assets,
    }),
    props.payload.find({
      collection: 'asset-observations',
      depth: 0,
      limit: 20,
      overrideAccess: false,
      sort: '-observedAt',
      user: props.user,
      where: historyScope.observations,
    }),
    props.payload.find({
      collection: 'topology-links',
      depth: 0,
      limit: 20,
      overrideAccess: false,
      sort: '-observedAt',
      user: props.user,
      where: {
        or: [{ localAsset: { equals: asset.id } }, { remoteAsset: { equals: asset.id } }],
      },
    }),
    findAssemblyVulnerabilities(props.payload, asset, { user: props.user }),
    endpointCountRequest,
    siteRequest,
    assetClassRequest,
  ])

  const matches = vulnerabilityMatches.slice().sort(bySeverity)
  const severityCounts = Object.fromEntries(
    vulnerabilitySeverities.map((severity) => [severity, 0]),
  ) as Record<VulnerabilitySeverity, number>
  for (const match of matches) severityCounts[matchSeverity(match)] += 1
  const site = loadedSite || populatedSite
  const assetClass = loadedAssetClass || populatedAssetClass
  const siteName = site?.path || site?.name
  const endpointTotal = endpointCount.totalDocs || 0
  const latestObservation = observations.docs[0]
  const tabURL = (tab: Tab, page?: number) =>
    `${assetURL}?tab=${tab}${page ? `&historyPage=${page}` : ''}`
  const recordLinks = () =>
    tabs.map(({ id, label }) => (
      <Link
        aria-current={selectedTab === id ? 'page' : undefined}
        className={
          selectedTab === id ? 'asset-view__tab asset-view__tab--active' : 'asset-view__tab'
        }
        href={tabURL(id)}
        key={id}
      >
        {label}
        {id === 'security' && matches.length ? <span>{matches.length}</span> : null}
      </Link>
    ))

  const overview = (
    <>
      <Section
        details={[
          {
            label: 'Site',
            value: site ? (
              <Link href={`${adminRoute}/collections/sites/${site.id}`}>{siteName}</Link>
            ) : (
              relationID(asset.site)
            ),
          },
          {
            label: 'Asset class',
            value: assetClass ? (
              <Link href={`${adminRoute}/collections/asset-classes/${assetClass.id}`}>
                {assetClass.name}
              </Link>
            ) : (
              relationID(asset.assetClass)
            ),
          },
          { label: 'Asset owner', value: fieldValue(asset, 'assetOwner', asset.assetOwner) },
          { label: 'Physical location', value: fieldValue(asset, 'location', asset.location) },
          {
            label: 'Description',
            value: asset.description || 'No description provided.',
            wide: true,
          },
          { label: 'Notes', value: asset.notes, wide: true },
        ]}
        title="Identity"
      />
      <Section
        details={[
          { label: 'IP address', value: copyValue(asset.ipAddress) },
          { label: 'MAC address', value: copyValue(asset.macAddress) },
          { label: 'Network mask', value: copyValue(asset.networkMask) },
          { label: 'Gateway address', value: copyValue(asset.gatewayAddress) },
          {
            label: 'Recorded addresses',
            value: asset.networkAddresses?.map(({ address }) => address).join(', '),
          },
        ]}
        title="Network snapshot"
      />
      <Section
        details={[
          { label: 'Vendor', value: fieldValue(asset, 'vendor', asset.vendor) },
          { label: 'Model', value: fieldValue(asset, 'model', asset.model) },
          {
            label: 'Operating system',
            value: fieldValue(asset, 'operatingSystem', asset.operatingSystem),
          },
          {
            label: 'OS confidence',
            value:
              asset.osAccuracy === null || asset.osAccuracy === undefined
                ? undefined
                : `${asset.osAccuracy}%`,
          },
          { label: 'Serial number', value: copyValue(asset.serialNumber) },
          {
            label: 'Firmware version',
            value: fieldValue(asset, 'firmwareVersion', asset.firmwareVersion),
          },
        ]}
        title="Device snapshot"
      />
      <Section
        details={[
          { label: 'Recorded status', value: statusLabels[asset.status] },
          { label: 'Criticality', value: criticalityLabels[asset.criticality] },
          {
            label: 'Protocols',
            value: asset.protocols?.map((protocol) => protocolLabels[protocol]).join(', '),
          },
          { label: 'Last seen', value: formatDateTime(asset.lastSeen) },
          {
            label: 'Potential vulnerabilities',
            value: <VulnerabilityList assetURL={assetURL} matches={matches} />,
            wide: true,
          },
        ]}
        title="Operational posture"
      />
      {definitions.docs.length ? (
        <Section
          details={definitions.docs.map((definition) => {
            const value = customFields[String(definition.id)]
            const displayValue =
              definition.type === 'checkbox' && typeof value === 'boolean'
                ? value
                  ? 'Yes'
                  : 'No'
                : definition.type === 'date' && typeof value === 'string'
                  ? formatDateTime(value)
                  : typeof value === 'string' || typeof value === 'number'
                    ? value
                    : undefined
            return { label: definition.label, value: displayValue }
          })}
          title="Custom fields"
        />
      ) : null}
      <Section
        details={
          topologyLinks.docs.length
            ? topologyLinks.docs
                .slice(0, 5)
                .map((link) => topologyDetails(link, asset.id, adminRoute))
            : [{ label: 'Connections', value: 'No topology links recorded yet.', wide: true }]
        }
        title="Observed connections"
        wide
      />
    </>
  )

  const network = (
    <>
      <Section
        details={[
          { label: 'Primary IP address', value: copyValue(asset.ipAddress) },
          { label: 'Network mask', value: copyValue(asset.networkMask) },
          { label: 'Gateway', value: copyValue(asset.gatewayAddress) },
          { label: 'Primary MAC address', value: copyValue(asset.macAddress) },
          {
            label: 'Protocols',
            value: asset.protocols?.map((protocol) => protocolLabels[protocol]).join(', '),
          },
          { label: 'Current endpoint bindings', value: endpointTotal },
        ]}
        title="Network parameters"
      />
      {props.user ? (
        <DeviceIdentity asset={asset} payload={props.payload} user={props.user} view="network" />
      ) : null}
      <Section
        details={
          topologyLinks.docs.length
            ? topologyLinks.docs.map((link) => topologyDetails(link, asset.id, adminRoute))
            : [{ label: 'Connections', value: 'No topology links recorded yet.', wide: true }]
        }
        title="Observed topology"
        wide
      />
    </>
  )

  const hardware = (
    <>
      <Section
        details={[
          { label: 'Vendor', value: fieldValue(asset, 'vendor', asset.vendor) },
          { label: 'Model', value: fieldValue(asset, 'model', asset.model) },
          {
            label: 'Catalog / part number',
            value: fieldValue(asset, 'catalogNumber', asset.catalogNumber),
          },
          { label: 'Serial number', value: copyValue(asset.serialNumber) },
          {
            label: 'Hardware version',
            value: fieldValue(asset, 'hardwareVersion', asset.hardwareVersion),
          },
          {
            label: 'Firmware version',
            value: fieldValue(asset, 'firmwareVersion', asset.firmwareVersion),
          },
          {
            label: 'Operating system',
            value: fieldValue(asset, 'operatingSystem', asset.operatingSystem),
          },
          {
            label: 'OS confidence',
            value: asset.osAccuracy == null ? undefined : `${asset.osAccuracy}%`,
          },
          { label: 'Physical kind', value: asset.physicalKind },
          { label: 'Slot capacity', value: asset.slotCapacity },
          { label: 'Hardware UUID', value: copyValue(asset.uuid) },
          { label: 'Baseline', value: asset.baselined ? 'Baselined' : 'Not baselined' },
        ]}
        title="Hardware record"
      />
      {props.user ? (
        <DeviceIdentity asset={asset} payload={props.payload} user={props.user} view="hardware" />
      ) : null}
      <Section
        details={[
          { label: 'Notes', value: asset.notes, wide: true },
          { label: 'Created', value: formatDateTime(asset.createdAt) },
          { label: 'Updated', value: formatDateTime(asset.updatedAt) },
        ]}
        title="Record metadata"
      />
    </>
  )

  const security = (
    <>
      <section className="asset-view__section asset-view__section--wide">
        <div className="asset-view__section-heading">
          <h2>Vulnerability severity</h2>
          <span>{matches.length} total</span>
        </div>
        <dl className="asset-view__severity-summary">
          {vulnerabilitySeverities.map((severity) => (
            <div
              className={`asset-view__severity-count asset-view__severity-count--${severity.toLowerCase()}`}
              key={severity}
            >
              <dt>{severity === 'UNRATED' ? 'Unrated' : severity.toLowerCase()}</dt>
              <dd>{severityCounts[severity]}</dd>
            </div>
          ))}
        </dl>
      </section>
      <Section
        details={[
          {
            label: 'Catalog result',
            value:
              asset.vulnerabilityCount == null
                ? 'Not evaluated'
                : `${asset.vulnerabilityCount} potential matches`,
          },
          { label: 'Vendor', value: asset.vendor },
          {
            label: 'Product data',
            value: [asset.model, asset.operatingSystem, asset.catalogNumber]
              .filter(Boolean)
              .join(' · '),
          },
          {
            label: 'Version data',
            value: [asset.firmwareVersion, asset.hardwareVersion].filter(Boolean).join(' · '),
          },
          {
            label: 'Scope',
            value: 'Recorded asset metadata and active installed modules; no active probe was run.',
            wide: true,
          },
        ]}
        title="Security assessment"
      />
      <Section
        details={
          matches.length
            ? matches.map((match) => {
                const severity = matchSeverity(match)
                return {
                  key: match.cve,
                  label: match.cve,
                  value: (
                    <div className="asset-view__vulnerability-match">
                      <div className="asset-view__vulnerability-flags">
                        <span className={`asset-view__severity--${severity.toLowerCase()}`}>
                          {severity === 'UNRATED'
                            ? 'Unrated'
                            : `${severity}${match.cvssScore == null ? '' : ` ${match.cvssScore}`}`}
                        </span>
                        {match.knownExploited ? (
                          <span className="asset-view__exploited">Known exploited</span>
                        ) : null}
                      </div>
                      <span>
                        {match.matchedVendor} {match.matchedProduct} · {match.versionEvidence}{' '}
                        {match.version} satisfies {match.constraint}
                      </span>
                    </div>
                  ),
                  wide: true,
                }
              })
            : [
                {
                  label: 'Matches',
                  value: 'No catalog entry matched the recorded vendor, model, and version data.',
                  wide: true,
                },
              ]
        }
        title="Potential vulnerability matches"
        wide
      />
      <p className="asset-view__note">
        These are catalog matches, not validated findings. The asset was not probed for a
        vulnerability. <Link href={`${assetURL}/vulnerabilities`}>View full match details</Link>
      </p>
    </>
  )

  const discovery = (
    <Section
      details={
        observations.docs.length
          ? observations.docs.map((observation, index) =>
              observationDetails(observation, index === 0),
            )
          : [{ label: 'Evidence', value: 'No scanner evidence recorded yet.', wide: true }]
      }
      title="Discovery evidence"
      wide
    />
  )

  const history = (
    <>
      <Section
        details={
          auditLogs.docs.length
            ? auditLogs.docs.map(auditDetails)
            : [{ label: 'History', value: 'No changes recorded yet.', wide: true }]
        }
        title="Change history"
        wide
      />
      {auditLogs.totalPages > 1 ? (
        <nav aria-label="Change history pages" className="asset-view__pagination">
          {auditLogs.hasPrevPage ? (
            <Link href={tabURL('history', historyPage - 1)}>← Newer</Link>
          ) : (
            <span />
          )}
          <span>
            History page {auditLogs.page} of {auditLogs.totalPages}
          </span>
          {auditLogs.hasNextPage ? (
            <Link href={tabURL('history', historyPage + 1)}>Older →</Link>
          ) : null}
        </nav>
      ) : null}
    </>
  )

  const mainContent =
    selectedTab === 'network'
      ? network
      : selectedTab === 'hardware'
        ? hardware
        : selectedTab === 'security'
          ? security
          : selectedTab === 'discovery'
            ? discovery
            : selectedTab === 'history'
              ? history
              : overview

  return (
    <main className="asset-view" data-density="comfortable">
      <nav aria-label="Asset breadcrumb" className="asset-view__breadcrumbs">
        <Link href={`${adminRoute}/collections/assets`}>Assets</Link>
        <span>›</span>
        {site ? (
          <Link href={`${adminRoute}/collections/sites/${site.id}`}>{siteName}</Link>
        ) : (
          <span>Unassigned site</span>
        )}
        <span>›</span>
        <strong>{asset.name}</strong>
      </nav>

      <header className="asset-view__header">
        <div className="asset-view__header-main">
          <div>
            <p className="asset-view__eyebrow">Industrial asset</p>
            <h1>{asset.name}</h1>
            <p className="asset-view__subtitle">
              {[asset.vendor, asset.model, assetClass?.name].filter(Boolean).join(' · ') ||
                'Device details recorded by OTserver'}
            </p>
          </div>
          <div className="asset-view__actions">
            <Link
              className="asset-view__secondary-action"
              href={`${apiRoute}/assets/export-csv?where[id][equals]=${encodeURIComponent(asset.id)}`}
            >
              Export CSV
            </Link>
            <DensityToggle />
            <Link className="asset-view__edit" href={`${assetURL}/edit`}>
              Edit asset
            </Link>
          </div>
        </div>
        <div className="asset-view__badges">
          <span className={`asset-view__badge status-tone status-tone--${asset.status}`}>
            {statusLabels[asset.status]}
          </span>
          <span className={`asset-view__badge asset-view__badge--${asset.criticality}`}>
            {criticalityLabels[asset.criticality]} criticality
          </span>
          <span className="asset-view__badge">{asset.lifecycle || 'active'}</span>
          {asset.replacedBy ? (
            <span className="asset-view__badge">Replacement recorded</span>
          ) : null}
          {asset.mergedInto ? <span className="asset-view__badge">Merged record</span> : null}
        </div>
      </header>

      <section aria-label="Asset summary" className="asset-view__metrics">
        <Link className="asset-view__metric" href={tabURL('discovery')}>
          <span>Last seen</span>
          <strong>{formatDateTime(asset.lastSeen)}</strong>
          <small>Recorded observation time</small>
        </Link>
        <Link className="asset-view__metric" href={tabURL('hardware')}>
          <span>Firmware</span>
          <strong>{asset.firmwareVersion || 'Not recorded'}</strong>
          <small>
            {asset.hardwareVersion
              ? `Hardware ${asset.hardwareVersion}`
              : 'No update status available'}
          </small>
        </Link>
        <Link className="asset-view__metric" href={tabURL('network')}>
          <span>Current endpoints</span>
          <strong>{endpointTotal}</strong>
          <small>{endpointTotal === 1 ? 'active binding' : 'active bindings'}</small>
        </Link>
        <Link className="asset-view__metric" href={tabURL('security')}>
          <span>Potential vulnerabilities</span>
          <strong>{asset.vulnerabilityCount == null ? '—' : matches.length}</strong>
          <small>{asset.vulnerabilityCount == null ? 'Not evaluated' : 'Catalog matches'}</small>
        </Link>
      </section>

      <nav aria-label="Asset sections" className="asset-view__tabs">
        {recordLinks()}
      </nav>

      <div className="asset-view__workspace">
        <div className="asset-view__main">{mainContent}</div>
        <aside aria-label="Asset context" className="asset-view__inspector">
          <InspectorCard title="Discovery snapshot">
            <dl className="asset-view__compact-details">
              <div>
                <dt>Last import</dt>
                <dd>{formatDateTime(asset.lastImportedAt)}</dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>{asset.importSource || 'Not recorded'}</dd>
              </div>
              <div>
                <dt>Latest evidence</dt>
                <dd>
                  {latestObservation
                    ? `${latestObservation.source} · ${latestObservation.quality} quality`
                    : 'No evidence recorded'}
                </dd>
              </div>
              {latestObservation && array(latestObservation.warnings).length ? (
                <div>
                  <dt>Warnings</dt>
                  <dd>{array(latestObservation.warnings).length} recorded</dd>
                </div>
              ) : null}
            </dl>
            <Link className="asset-view__inspector-link" href={tabURL('discovery')}>
              Open discovery evidence →
            </Link>
          </InspectorCard>

          <InspectorCard title="Observed connections">
            {topologyLinks.docs.length ? (
              <ul className="asset-view__inspector-list">
                {topologyLinks.docs.slice(0, 4).map((link) => {
                  const peer = topologyPeer(link, asset.id)
                  const peerID = relationID(peer.asset)
                  const label = relationLabel(
                    peer.asset,
                    relationLabel(peer.data, 'Unresolved peer'),
                  )
                  return (
                    <li key={link.id}>
                      {peerID && typeof peer.asset === 'object' ? (
                        <Link href={`${adminRoute}/collections/assets/${peerID}`}>{label}</Link>
                      ) : (
                        <strong>{label}</strong>
                      )}
                      <small>
                        {link.source} · {formatDateTime(link.observedAt)}
                      </small>
                    </li>
                  )
                })}
              </ul>
            ) : (
              <p className="asset-view__muted">No topology links recorded yet.</p>
            )}
            <Link className="asset-view__inspector-link" href={tabURL('network')}>
              Open network context →
            </Link>
          </InspectorCard>

          <InspectorCard title="Recent activity">
            {auditLogs.docs.length ? (
              <ul className="asset-view__inspector-list">
                {auditLogs.docs.slice(0, 5).map((log) => (
                  <li key={log.id}>
                    <strong>{log.action[0]?.toUpperCase() + log.action.slice(1)}</strong>
                    <small>
                      {log.actorName || log.actorEmail || 'System'} ·{' '}
                      {formatDateTime(log.createdAt)}
                    </small>
                    {auditChanges(log)
                      .slice(0, 1)
                      .map((change) => (
                        <span key={change}>{change}</span>
                      ))}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="asset-view__muted">No changes recorded yet.</p>
            )}
            <Link className="asset-view__inspector-link" href={tabURL('history')}>
              Open full history →
            </Link>
          </InspectorCard>
        </aside>
      </div>
    </main>
  )
}

export default AssetView
