import Link from 'next/link'
import type { DocumentViewServerProps } from 'payload'

import { getAuthorization } from '@/access/authorization'
import { formatDateTime } from '@/components/labels'
import AssetVulnerabilityReviewActions from '@/components/AssetVulnerabilityReviewActions'
import { idOf } from '@/identity/access'
import type { Asset } from '@/payload-types'
import { loadAssetVulnerabilityReviews, NO_LONGER_MATCHES_MESSAGE } from '@/vulnerabilities/reviews'
import { bySeverity } from '@/vulnerabilities/match'

import './AssetView/index.scss'

export const VULNERABILITY_PAGE_SIZE = 25
const AssetVulnerabilitiesView = async (props: DocumentViewServerProps) => {
  const asset = props.doc as Asset
  const request = props.initPageResult.req
  const user = request.user ?? undefined
  const adminRoute = props.payload.config.routes.admin
  const apiRoute = props.payload.config.routes.api || '/api'
  const assetURL = `${adminRoute}/collections/assets/${asset.id}`
  const requestedPage = Number(props.searchParams?.page)
  const authorization = await getAuthorization(request)
  const canReview = Boolean(
    authorization.isAdmin || authorization.writableSiteIDs.includes(idOf(asset.site)),
  )
  const { findings: allFindings, resolved } = await loadAssetVulnerabilityReviews(
    props.payload,
    asset,
    { req: request },
  )
  const findings = allFindings
    .slice()
    .sort(
      (left, right) =>
        bySeverity(left.match, right.match) || left.assetName.localeCompare(right.assetName),
    )
  const pages = Math.max(1, Math.ceil(findings.length / VULNERABILITY_PAGE_SIZE))
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1
  const visible = findings.slice(
    (page - 1) * VULNERABILITY_PAGE_SIZE,
    page * VULNERABILITY_PAGE_SIZE,
  )
  const cves = [
    ...new Set([...visible.map(({ match }) => match.cve), ...resolved.map(({ cve }) => cve)]),
  ]

  const [feeds, vulnerabilities] = await Promise.all([
    props.payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      disableErrors: true,
      overrideAccess: false,
      pagination: false,
      user,
    }),
    cves.length
      ? props.payload.find({
          collection: 'vulnerabilities',
          depth: 0,
          overrideAccess: false,
          pagination: false,
          user,
          where: { cve: { in: cves } },
        })
      : Promise.resolve(undefined),
  ])
  const details = new Map((vulnerabilities?.docs ?? []).map((doc) => [doc.cve, doc]))
  const title = (cve: string) => (
    <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} rel="noreferrer" target="_blank">
      {cve}
    </a>
  )

  return (
    <main className="asset-view">
      <div className="asset-view__back">
        <Link href={`${assetURL}?tab=security`}>← {asset.name}: Security</Link>
      </div>

      <header className="asset-view__header">
        <div className="asset-view__header-main">
          <div>
            <p className="asset-view__eyebrow">Vulnerability review</p>
            <h1>
              {findings.length} open vulnerability {findings.length === 1 ? 'finding' : 'findings'}
            </h1>
            <p>
              Review catalog matches for this asset and its active installed modules. Confirmation
              records a human review; it does not mean the device was tested.
            </p>
          </div>
          <div className="asset-view__actions">
            <Link className="asset-view__edit" href={assetURL}>
              Asset details
            </Link>
          </div>
        </div>
      </header>

      <p className="asset-view__warning" role="note">
        Catalog matches are unconfirmed until reviewed. OTserver does not probe devices for these
        vulnerabilities.
      </p>

      <div className="asset-view__grid">
        {feeds.docs.length ? (
          <section className="asset-view__section asset-view__section--wide">
            <h2>Catalog</h2>
            <dl className="asset-view__details">
              {feeds.docs.map((feed) => (
                <div className="asset-view__detail" key={feed.id}>
                  <dt>{feed.source}</dt>
                  <dd>
                    {feed.status}
                    {feed.lastSyncedAt
                      ? ` · synchronized ${formatDateTime(feed.lastSyncedAt)}`
                      : ''}
                    {feed.documentCount ? ` · ${feed.documentCount} entries` : ''}
                    {feed.error ? ` · ${feed.error}` : ''}
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        ) : null}

        <section className="asset-view__section asset-view__section--wide">
          <h2>Open findings</h2>
          {!visible.length ? (
            <p>No open vulnerability findings for this asset or its active installed modules.</p>
          ) : (
            <ul className="asset-view__vulnerabilities">
              {visible.map((finding) => {
                const { match } = finding
                const detail = details.get(match.cve)
                const reviewID = `${finding.assetID}:${match.cve}`
                return (
                  <li id={`finding-${reviewID}`} key={reviewID}>
                    <p className="asset-view__vulnerability-title">
                      {title(match.cve)}
                      {match.cvssSeverity ? (
                        <span
                          className={`asset-view__severity--${match.cvssSeverity.toLowerCase()}`}
                        >
                          {match.cvssSeverity}
                          {match.cvssScore ? ` ${match.cvssScore}` : ''}
                        </span>
                      ) : null}
                      {match.knownExploited ? (
                        <span className="asset-view__exploited">Known exploited</span>
                      ) : null}
                      {finding.status === 'confirmed' ? (
                        <span className="asset-view__review-status">
                          Confirmed{finding.reviewerName ? ` by ${finding.reviewerName}` : ''}
                        </span>
                      ) : null}
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
                    </p>
                    <p>{detail?.description || detail?.kevName || 'No description available.'}</p>
                    <p className="asset-view__match-reason">
                      Affected hardware:{' '}
                      <Link href={`${adminRoute}/collections/assets/${finding.assetID}`}>
                        {finding.assetName}
                      </Link>
                    </p>
                    <p className="asset-view__match-reason">
                      Matched {match.matchedVendor} {match.matchedProduct} · {match.versionEvidence}{' '}
                      {match.version} satisfies {match.constraint}
                    </p>
                    {finding.assessment === 'unknown' ? (
                      <p className="asset-view__match-reason" role="note">
                        Unable to reassess: {finding.assessmentMessage}
                      </p>
                    ) : null}
                    {finding.assessment === 'no-longer-matches' ? (
                      <p className="asset-view__match-reason" role="note">
                        {NO_LONGER_MATCHES_MESSAGE}
                      </p>
                    ) : null}
                    {match.cpe ? (
                      <p className="asset-view__match-reason">
                        Catalog CPE: <code>{match.cpe}</code>
                      </p>
                    ) : null}
                    {detail?.kevRequiredAction ? (
                      <p className="asset-view__match-reason">
                        CISA action: {detail.kevRequiredAction}
                      </p>
                    ) : null}
                    {detail?.icsAdvisory?.length ? (
                      <p className="asset-view__match-reason">
                        CISA ICS advisory {detail.icsAdvisory.join(', ')}
                        {detail.icsSectors?.length
                          ? ` · sectors: ${detail.icsSectors.join(', ')}`
                          : ''}
                        {detail.icsHeadquarters ? ` · vendor HQ: ${detail.icsHeadquarters}` : ''}
                      </p>
                    ) : null}
                    {canReview ? (
                      <AssetVulnerabilityReviewActions
                        api={apiRoute}
                        assetID={finding.assetID}
                        assetName={finding.assetName}
                        cve={match.cve}
                        revision={finding.revision}
                        status={finding.status}
                      />
                    ) : null}
                  </li>
                )
              })}
            </ul>
          )}
          {pages > 1 ? (
            <nav aria-label="Open vulnerability findings" className="asset-view__pagination">
              {page > 1 ? (
                <Link href={`${assetURL}/vulnerabilities?page=${page - 1}`}>← Previous</Link>
              ) : (
                <span />
              )}
              <span>
                Page {page} of {pages}
              </span>
              {page < pages ? (
                <Link href={`${assetURL}/vulnerabilities?page=${page + 1}`}>Next →</Link>
              ) : null}
            </nav>
          ) : null}
        </section>

        <section className="asset-view__section asset-view__section--wide">
          <h2>Resolved history</h2>
          {resolved.length ? (
            <ul className="asset-view__vulnerabilities">
              {resolved.map((item) => {
                const match = item.evidence?.match
                return (
                  <li key={`${item.assetID}:${item.cve}`}>
                    <p className="asset-view__vulnerability-title">
                      {title(item.cve)} <span className="asset-view__review-status">Resolved</span>
                    </p>
                    <p>
                      {item.reviewerName || 'A user'} resolved this finding on{' '}
                      {formatDateTime(item.decidedAt)}.
                    </p>
                    <p className="asset-view__match-reason">
                      Affected hardware:{' '}
                      <Link href={`${adminRoute}/collections/assets/${item.assetID}`}>
                        {item.assetName}
                      </Link>
                      {match
                        ? ` · Originally matched ${match.matchedVendor} ${match.matchedProduct}, ${match.versionEvidence} ${match.version} satisfied ${match.constraint}.`
                        : ''}
                    </p>
                    {canReview ? (
                      <AssetVulnerabilityReviewActions
                        api={apiRoute}
                        assetID={item.assetID}
                        assetName={item.assetName}
                        cve={item.cve}
                        revision={item.revision}
                        status="resolved"
                      />
                    ) : null}
                  </li>
                )
              })}
            </ul>
          ) : (
            <p>
              No vulnerabilities have been resolved for this asset or its active installed modules.
            </p>
          )}
        </section>
      </div>
    </main>
  )
}

export default AssetVulnerabilitiesView
