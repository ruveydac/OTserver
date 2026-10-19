import Link from 'next/link'
import type { DocumentViewServerProps } from 'payload'
import type { ReactNode } from 'react'

import CopyButton from '@/components/AssetView/CopyButton'
import DensityToggle from '@/components/AssetView/DensityToggle'
import AssetVulnerabilityReviewActions from '@/components/AssetVulnerabilityReviewActions'
import { VULNERABILITY_PAGE_SIZE } from '@/components/AssetVulnerabilitiesView'
import {
  criticalityLabels,
  formatDateTime,
  protocolLabels,
  statusLabels,
} from '@/components/labels'
import DeviceIdentity from '@/components/DeviceIdentity'
import { loadAssetPanel } from '@/application/assetPanel'
import type { Asset, AssetObservation, AuditLog, TopologyLink } from '@/payload-types'
import type { VulnerabilityMatch } from '@/vulnerabilities/matching'
import { bySeverity } from '@/vulnerabilities/match'
import { documentClientProps } from '@/integrations/payload/admin'
import { purdueLabel } from '@/domain/purdue'
import { getAuthorization } from '@/access/authorization'
import { idOf } from '@/identity/access'
import { NO_LONGER_MATCHES_MESSAGE } from '@/vulnerabilities/reviews'

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

const pageNumber = (value: unknown) => {
  const page = Number(firstParam(value))
  return Number.isSafeInteger(page) && page > 0 ? page : 1
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

const PageNavigation = ({
  currentPage,
  href,
  label,
  totalPages,
}: {
  currentPage: number
  href: (page: number) => string
  label: string
  totalPages: number
}) =>
  totalPages > 1 ? (
    <nav aria-label={label} className="asset-view__pagination">
      {currentPage > 1 ? <Link href={href(currentPage - 1)}>← Newer</Link> : <span />}
      <span>
        {label} page {currentPage} of {totalPages}
      </span>
      {currentPage < totalPages ? <Link href={href(currentPage + 1)}>Older →</Link> : null}
    </nav>
  ) : null

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
  matches: VulnerabilityMatch[]
}) => {
  const visible = matches.slice(0, MAX_LISTED_VULNERABILITIES)

  if (!matches.length) return <span>No open findings</span>

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
          ? `View all ${matches.length} open findings`
          : 'View vulnerability review'}
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
  const historyPage = pageNumber(props.searchParams?.historyPage)
  const discoveryPage = pageNumber(props.searchParams?.discoveryPage)
  const topologyPage = pageNumber(props.searchParams?.topologyPage)
  const populatedSite = typeof asset.site === 'object' ? asset.site : undefined
  const populatedAssetClass = typeof asset.assetClass === 'object' ? asset.assetClass : undefined
  const customFields = record(asset.customFields)
  const {
    definitions,
    auditLogs,
    observations,
    topologyLinks,
    vulnerabilityFindings,
    resolvedVulnerabilities,
    endpointCount,
    loadedSite,
    loadedAssetClass,
    historyScopeTruncated,
  } = await loadAssetPanel({
    asset,
    payload: props.payload,
    user: props.initPageResult.req.user ?? undefined,
    historyPage,
    discoveryPage,
    topologyPage,
    pageSize: 50,
  })

  const request = props.initPageResult.req
  const authorization = await getAuthorization(request)
  const canReviewVulnerabilities = Boolean(
    authorization.isAdmin || authorization.writableSiteIDs.includes(idOf(asset.site)),
  )
  const findings = vulnerabilityFindings
    .slice()
    .sort(
      (left, right) =>
        bySeverity(left.match, right.match) || left.assetName.localeCompare(right.assetName),
    )
  const matches = findings.map(({ match }) => match)
  const severityCounts = Object.fromEntries(
    vulnerabilitySeverities.map((severity) => [severity, 0]),
  ) as Record<VulnerabilitySeverity, number>
  for (const match of matches) severityCounts[matchSeverity(match)] += 1
  const severityParam = firstParam(props.searchParams?.severity)?.toUpperCase()
  const selectedSeverity = vulnerabilitySeverities.find((severity) => severity === severityParam)
  const filteredFindings = selectedSeverity
    ? findings.filter(({ match }) => matchSeverity(match) === selectedSeverity)
    : findings
  const vulnerabilityPages = Math.max(
    1,
    Math.ceil(filteredFindings.length / VULNERABILITY_PAGE_SIZE),
  )
  const vulnerabilityPage = Math.min(
    pageNumber(props.searchParams?.vulnerabilityPage),
    vulnerabilityPages,
  )
  const vulnerabilityOffset = (vulnerabilityPage - 1) * VULNERABILITY_PAGE_SIZE
  const visibleFindings = filteredFindings.slice(
    vulnerabilityOffset,
    vulnerabilityOffset + VULNERABILITY_PAGE_SIZE,
  )
  const descriptionCVEs = [...new Set(visibleFindings.map(({ match }) => match.cve))]
  const descriptions =
    selectedTab === 'security' && descriptionCVEs.length
      ? await props.payload.find({
          collection: 'vulnerabilities',
          depth: 0,
          limit: VULNERABILITY_PAGE_SIZE,
          pagination: false,
          overrideAccess: false,
          req: request,
          select: { cve: true, description: true, kevName: true },
          where: { cve: { in: descriptionCVEs } },
        })
      : undefined
  const descriptionByCVE = new Map(
    (descriptions?.docs ?? []).map((entry) => [
      entry.cve,
      (entry.description?.trim() || entry.kevName?.trim() || 'No description available.').replace(
        /\s+/g,
        ' ',
      ),
    ]),
  )
  const securityURL = (severity?: VulnerabilitySeverity, page = 1) =>
    `${assetURL}?tab=security${severity ? `&severity=${severity}` : ''}${page > 1 ? `&vulnerabilityPage=${page}` : ''}`
  const site = loadedSite || populatedSite
  const assetClass = loadedAssetClass || populatedAssetClass
  const siteName = site?.path || site?.name
  const endpointTotal = endpointCount.totalDocs || 0
  const latestObservation = observations.docs[0]
  const tabURL = (tab: Tab, page?: number) =>
    `${assetURL}?tab=${tab}${page ? `&historyPage=${page}` : ''}`
  const pageURL = (tab: Tab, parameter: string, page: number) =>
    `${assetURL}?tab=${tab}&${parameter}=${page}`
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
            label: 'Purdue levels',
            value: fieldValue(asset, 'purdueLevels', purdueLabel(asset.purdueLevels)),
          },
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
            label: 'OS detection confidence (%)',
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
            label: 'Open vulnerability findings',
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
      {definitions.hasNextPage ? (
        <p role="status">Only the first {definitions.limit} custom field definitions are shown.</p>
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
      {topologyLinks.totalPages > 1 ? (
        <PageNavigation
          currentPage={topologyPage}
          href={(page) => pageURL('overview', 'topologyPage', page)}
          label="Topology"
          totalPages={topologyLinks.totalPages}
        />
      ) : null}
    </>
  )

  const network = (
    <>
      <Section
        details={[
          { label: 'Primary IP address', value: copyValue(asset.ipAddress) },
          { label: 'Network mask', value: copyValue(asset.networkMask) },
          { label: 'Gateway address', value: copyValue(asset.gatewayAddress) },
          { label: 'Primary MAC address', value: copyValue(asset.macAddress) },
          {
            label: 'Protocols',
            value: asset.protocols?.map((protocol) => protocolLabels[protocol]).join(', '),
          },
          { label: 'Current endpoint bindings', value: endpointTotal },
        ]}
        title="Network parameters"
      />
      {props.initPageResult.req.user ? (
        <DeviceIdentity
          asset={asset}
          payload={props.payload}
          user={props.initPageResult.req.user}
          view="network"
        />
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
      <PageNavigation
        currentPage={topologyPage}
        href={(page) => pageURL('network', 'topologyPage', page)}
        label="Topology"
        totalPages={topologyLinks.totalPages}
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
            label: 'OS detection confidence (%)',
            value: asset.osAccuracy == null ? undefined : `${asset.osAccuracy}%`,
          },
          { label: 'Physical kind', value: asset.physicalKind },
          { label: 'Slot capacity', value: asset.slotCapacity },
          { label: 'Hardware UUID', value: copyValue(asset.uuid) },
          { label: 'Baseline', value: asset.baselined ? 'Baselined' : 'Not baselined' },
        ]}
        title="Hardware record"
      />
      {props.initPageResult.req.user ? (
        <DeviceIdentity
          asset={asset}
          payload={props.payload}
          user={props.initPageResult.req.user}
          view="hardware"
        />
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
          <h2>Open vulnerability severity</h2>
          <span>{findings.length} total</span>
        </div>
        <p className="asset-view__security-help">
          Filter open findings by severity. Counts include this asset and its active installed
          modules.
        </p>
        <nav aria-label="Filter open findings by severity" className="asset-view__severity-summary">
          <Link
            aria-current={!selectedSeverity ? 'page' : undefined}
            className="asset-view__severity-count"
            href={securityURL()}
            scroll={false}
          >
            <span>All severities</span>
            <strong>{findings.length}</strong>
          </Link>
          {vulnerabilitySeverities.map((severity) => (
            <Link
              aria-current={selectedSeverity === severity ? 'page' : undefined}
              className={`asset-view__severity-count asset-view__severity-count--${severity.toLowerCase()}`}
              href={securityURL(severity)}
              key={severity}
              scroll={false}
            >
              <span>{severity[0] + severity.slice(1).toLowerCase()}</span>
              <strong>{severityCounts[severity]}</strong>
            </Link>
          ))}
        </nav>
      </section>
      <section
        aria-labelledby="open-vulnerability-findings"
        className="asset-view__section asset-view__security-findings"
      >
        <div className="asset-view__section-heading">
          <h2 id="open-vulnerability-findings">Open vulnerability findings</h2>
          {selectedSeverity ? (
            <Link href={securityURL()} scroll={false}>
              Clear severity filter
            </Link>
          ) : null}
        </div>
        <p className="asset-view__security-help" role="status">
          {filteredFindings.length
            ? `Showing ${vulnerabilityOffset + 1}–${vulnerabilityOffset + visibleFindings.length} of ${filteredFindings.length} ${selectedSeverity ? `${selectedSeverity.toLowerCase()} ` : ''}open ${filteredFindings.length === 1 ? 'finding' : 'findings'}. Known exploited first, then highest CVSS.`
            : selectedSeverity
              ? `No ${selectedSeverity.toLowerCase()} open findings. Select another severity or clear the filter.`
              : asset.vulnerabilityCount == null
                ? 'No findings are available. The asset has not been evaluated against a usable vulnerability catalog.'
                : 'No open vulnerability findings for this asset or its active installed modules.'}
        </p>
        <ul className="asset-view__vulnerabilities">
          {visibleFindings.map((finding) => {
            const { match } = finding
            const severity = matchSeverity(match)
            const description = descriptionByCVE.get(match.cve) || 'No description available.'
            const detailPage = Math.floor(findings.indexOf(finding) / VULNERABILITY_PAGE_SIZE) + 1
            const detailURL = `${assetURL}/vulnerabilities?page=${detailPage}#finding-${finding.assetID}:${match.cve}`
            return (
              <li key={`${finding.assetID}:${match.cve}`}>
                <div className="asset-view__vulnerability-match">
                  <div className="asset-view__vulnerability-flags">
                    <h3 className="asset-view__vulnerability-title">
                      <Link href={detailURL}>{match.cve}</Link>
                    </h3>
                    <span className={`asset-view__severity--${severity.toLowerCase()}`}>
                      {severity === 'UNRATED'
                        ? 'Unrated'
                        : `${severity}${match.cvssScore == null ? '' : ` ${match.cvssScore}`}`}
                    </span>
                    {match.knownExploited ? (
                      <span className="asset-view__exploited">Known exploited</span>
                    ) : null}
                    <span className="asset-view__review-status">
                      {finding.status === 'confirmed'
                        ? `Confirmed${finding.reviewerName ? ` by ${finding.reviewerName}` : ''}`
                        : 'Unconfirmed'}
                    </span>
                    {finding.assessment === 'no-longer-matches' ? (
                      <span
                        aria-label={NO_LONGER_MATCHES_MESSAGE}
                        className="asset-view__match-warning"
                        role="img"
                        tabIndex={0}
                        title={NO_LONGER_MATCHES_MESSAGE}
                      >
                        !
                      </span>
                    ) : null}
                  </div>
                  <p className="asset-view__vulnerability-description">
                    {description.length > 280
                      ? `${description.slice(0, 280).replace(/\s+\S*$/, '')}…`
                      : description}
                  </p>
                  <p className="asset-view__match-reason">
                    Affected hardware:{' '}
                    <Link href={`${adminRoute}/collections/assets/${finding.assetID}`}>
                      {finding.assetName}
                    </Link>
                  </p>
                  <p className="asset-view__match-reason">
                    {finding.assessment === 'matched'
                      ? 'Matching evidence'
                      : 'Original matching evidence'}
                    : {match.matchedVendor} {match.matchedProduct} · {match.versionEvidence}{' '}
                    {match.version} satisfies {match.constraint}
                  </p>
                  {finding.assessment === 'unknown' ? (
                    <p role="note">Unable to reassess: {finding.assessmentMessage}</p>
                  ) : null}
                  {finding.assessment === 'no-longer-matches' ? (
                    <p role="note">{NO_LONGER_MATCHES_MESSAGE}</p>
                  ) : null}
                  <Link className="asset-view__finding-details" href={detailURL}>
                    Full details for {match.cve}
                  </Link>
                  {canReviewVulnerabilities ? (
                    <AssetVulnerabilityReviewActions
                      api={apiRoute}
                      assetID={finding.assetID}
                      assetName={finding.assetName}
                      cve={match.cve}
                      revision={finding.revision}
                      status={finding.status}
                    />
                  ) : null}
                </div>
              </li>
            )
          })}
        </ul>
        {vulnerabilityPages > 1 ? (
          <nav aria-label="Open vulnerability finding pages" className="asset-view__pagination">
            {vulnerabilityPage > 1 ? (
              <Link
                href={`${securityURL(selectedSeverity, vulnerabilityPage - 1)}#open-vulnerability-findings`}
              >
                Previous
              </Link>
            ) : null}
            <span>
              Page {vulnerabilityPage} of {vulnerabilityPages}
            </span>
            {vulnerabilityPage < vulnerabilityPages ? (
              <Link
                href={`${securityURL(selectedSeverity, vulnerabilityPage + 1)}#open-vulnerability-findings`}
              >
                Next
              </Link>
            ) : null}
          </nav>
        ) : null}
        <p className="asset-view__security-help">
          Catalog matches are unconfirmed until reviewed. The asset was not probed for a
          vulnerability. Dismissed and resolved findings are excluded from these counts.
        </p>
      </section>
      <Section
        details={[
          {
            label: 'Open finding count',
            value:
              asset.vulnerabilityCount == null
                ? 'Not evaluated'
                : `${asset.vulnerabilityCount} open ${asset.vulnerabilityCount === 1 ? 'finding' : 'findings'}`,
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
        title="Purdue classification"
        details={[
          {
            label: 'Functional levels',
            value: fieldValue(asset, 'purdueLevels', purdueLabel(asset.purdueLevels)),
          },
          {
            label: 'Site overview',
            value: (
              <Link
                href={`${adminRoute}/purdue?site=${encodeURIComponent(relationID(asset.site) || '')}`}
              >
                View Purdue classification for this site
              </Link>
            ),
          },
        ]}
      />
      <Section
        details={
          resolvedVulnerabilities.length
            ? resolvedVulnerabilities.map((review) => ({
                key: `${review.assetID}:${review.cve}`,
                label: `${review.cve} · ${review.assetName}`,
                value: (
                  <div className="asset-view__vulnerability-match">
                    <span>
                      Resolved by {review.reviewerName || 'a user'} on{' '}
                      {formatDateTime(review.decidedAt)}
                    </span>
                    {canReviewVulnerabilities ? (
                      <AssetVulnerabilityReviewActions
                        api={props.payload.config.routes.api || '/api'}
                        assetID={review.assetID}
                        assetName={review.assetName}
                        cve={review.cve}
                        revision={review.revision}
                        status="resolved"
                      />
                    ) : null}
                  </div>
                ),
                wide: true,
              }))
            : [{ label: 'History', value: 'No vulnerabilities have been resolved.', wide: true }]
        }
        title="Resolved vulnerability history"
        wide
      />
      <p className="asset-view__note">
        <Link href={`${assetURL}/vulnerabilities`}>View full review details</Link>
      </p>
    </>
  )

  const discovery = (
    <>
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
      <PageNavigation
        currentPage={discoveryPage}
        href={(page) => pageURL('discovery', 'discoveryPage', page)}
        label="Discovery evidence"
        totalPages={observations.totalPages}
      />
    </>
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
              Export diagnostic CSV
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
          <span>Open vulnerability findings</span>
          <strong>{asset.vulnerabilityCount == null ? '—' : matches.length}</strong>
          <small>
            {asset.vulnerabilityCount == null ? 'Not evaluated' : 'Unconfirmed and confirmed'}
          </small>
        </Link>
      </section>

      <nav aria-label="Asset sections" className="asset-view__tabs">
        {recordLinks()}
      </nav>
      {historyScopeTruncated ? (
        <p role="status">
          History is bounded to 200 merged records and 200 related endpoints. Some earlier entries
          may be outside this view.
        </p>
      ) : null}

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
