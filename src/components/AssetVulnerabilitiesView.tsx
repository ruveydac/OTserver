import Link from 'next/link'
import type { DocumentViewServerProps } from 'payload'

import { formatDateTime } from '@/components/labels'
import { findAssetVulnerabilities } from '@/vulnerabilities/match'
import type { Asset } from '@/payload-types'

import './AssetView/index.scss'

const PAGE_SIZE = 25

const AssetVulnerabilitiesView = async (props: DocumentViewServerProps) => {
  const asset = props.doc as Asset
  const adminRoute = props.payload.config.routes.admin
  const assetURL = `${adminRoute}/collections/assets/${asset.id}`
  const page = Math.max(1, Number(props.searchParams?.page) || 1)

  const matches = (await findAssetVulnerabilities(props.payload, asset, { user: props.user })).sort(
    (left, right) =>
      Number(right.knownExploited) - Number(left.knownExploited) ||
      (right.cvssScore ?? 0) - (left.cvssScore ?? 0) ||
      left.cve.localeCompare(right.cve),
  )
  const pages = Math.max(1, Math.ceil(matches.length / PAGE_SIZE))
  const visible = matches.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const [feeds, vulnerabilities] = await Promise.all([
    props.payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      disableErrors: true,
      overrideAccess: false,
      pagination: false,
      user: props.user,
    }),
    visible.length
      ? props.payload.find({
          collection: 'vulnerabilities',
          depth: 0,
          overrideAccess: false,
          pagination: false,
          user: props.user,
          where: { cve: { in: visible.map((match) => match.cve) } },
        })
      : Promise.resolve(undefined),
  ])
  const details = new Map((vulnerabilities?.docs ?? []).map((doc) => [doc.cve, doc]))
  const hasMetadata = Boolean(asset.vendor && (asset.model || asset.operatingSystem))

  return (
    <main className="asset-view">
      <div className="asset-view__back">
        <Link href={assetURL}>← {asset.name}</Link>
      </div>

      <header className="asset-view__header">
        <div>
          <p className="asset-view__eyebrow">Vulnerability lookup</p>
          <h1>{matches.length} potential vulnerabilities</h1>
          <p>
            Matched against the downloaded CISA KEV and NVD catalogs using the vendor, model,
            operating system, and version data recorded for this asset.
          </p>
        </div>
        <div className="asset-view__actions">
          <Link className="asset-view__edit" href={assetURL}>
            Asset details
          </Link>
        </div>
      </header>

      <p className="asset-view__warning" role="note">
        These entries are <strong>not validated</strong>. They were found by comparing catalog
        product and version data with the recorded asset data — no vulnerability check was run
        against the device.
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
          <h2>Matches</h2>
          {!hasMetadata ? (
            <p>
              This asset has no vendor and model or operating system data, so no catalog entry can
              be matched. Record device details to get a lookup.
            </p>
          ) : !visible.length ? (
            <p>No catalog entry matched the recorded vendor, model, and version data.</p>
          ) : (
            <ul className="asset-view__vulnerabilities">
              {visible.map((match) => {
                const detail = details.get(match.cve)
                return (
                  <li key={match.cve}>
                    <p className="asset-view__vulnerability-title">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${match.cve}`}
                        rel="noreferrer"
                        target="_blank"
                      >
                        {match.cve}
                      </a>
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
                    </p>
                    <p>{detail?.description || detail?.kevName || 'No description available.'}</p>
                    <p className="asset-view__match-reason">
                      Matched {match.matchedVendor} {match.matchedProduct} · {match.versionEvidence}{' '}
                      {match.version} satisfies {match.constraint}
                    </p>
                    {detail?.kevRequiredAction ? (
                      <p className="asset-view__match-reason">
                        CISA action: {detail.kevRequiredAction}
                      </p>
                    ) : null}
                  </li>
                )
              })}
            </ul>
          )}
          {pages > 1 ? (
            <p className="asset-view__pagination">
              {page > 1 ? (
                <Link href={`${assetURL}/vulnerabilities?page=${page - 1}`}>← Previous</Link>
              ) : null}
              <span>
                Page {page} of {pages}
              </span>
              {page < pages ? (
                <Link href={`${assetURL}/vulnerabilities?page=${page + 1}`}>Next →</Link>
              ) : null}
            </p>
          ) : null}
        </section>
      </div>
    </main>
  )
}

export default AssetVulnerabilitiesView
