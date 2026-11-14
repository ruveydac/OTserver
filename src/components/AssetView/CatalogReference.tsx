import type { Asset } from '@/payload-types'
import { metadataLicense, type MetadataMatch } from '@/metadata/catalog'
import { unloadedCatalog, type ActiveCatalog } from '@/metadata/runtime'

const safeURL = (value: unknown) => {
  if (typeof value !== 'string') return undefined
  try {
    const url = new URL(value)
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password
      ? url.href
      : undefined
  } catch {
    return undefined
  }
}

const labelFor = (key: string) =>
  key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())

const valueFor = (key: string, value: unknown) => {
  if (typeof value === 'string') {
    const href = /url|website/i.test(key) ? safeURL(value) : undefined
    return href ? (
      <a href={href} target="_blank" rel="noopener noreferrer">
        {key === 'website'
          ? 'Manufacturer website'
          : key === 'source_url'
            ? 'Publisher source'
            : value}
      </a>
    ) : (
      value
    )
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (
    Array.isArray(value) &&
    value.every((item) => ['string', 'number', 'boolean'].includes(typeof item))
  ) {
    if (/url/i.test(key))
      return (
        <ul>
          {value.map((item) => {
            const href = safeURL(item)
            return (
              <li key={String(item)}>
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer">
                    {String(item)}
                  </a>
                ) : (
                  String(item)
                )}
              </li>
            )
          })}
        </ul>
      )
    return value.map(String).join(', ')
  }
  return <pre>{JSON.stringify(value, null, 2)}</pre>
}

// Long strings and block values (URL lists, JSON) span the grid like wide details elsewhere.
const isWideValue = (key: string, value: unknown) =>
  (typeof value === 'string' && value.length > 80) ||
  (typeof value === 'object' && (Array.isArray(value) ? /url/i.test(key) : true))

const dataDetails = (data: Record<string, unknown>) => (
  <dl className="asset-view__details">
    {Object.entries(data)
      .filter(([key, value]) => key !== 'evidence_json' && value !== undefined && value !== null)
      .map(([key, value]) => (
        <div
          className={
            isWideValue(key, value)
              ? 'asset-view__detail asset-view__detail--wide'
              : 'asset-view__detail'
          }
          key={key}
        >
          <dt>{labelFor(key)}</dt>
          <dd>{valueFor(key, value)}</dd>
        </div>
      ))}
  </dl>
)

const evidenceDetails = (label: string, evidence: unknown) => (
  <details className="asset-view__evidence">
    <summary>{label}</summary>
    <pre>{JSON.stringify(evidence, null, 2)}</pre>
  </details>
)

const catalogCard = 'asset-view__section asset-view__section--wide asset-view__catalog-reference'

export default function CatalogReference({
  asset,
  snapshot,
}: {
  asset: Asset
  snapshot?: Pick<ActiveCatalog, 'catalog' | 'revision'>
}) {
  const referenceCatalog = snapshot?.catalog ?? unloadedCatalog.catalog
  const revision = snapshot?.revision ?? unloadedCatalog.revision
  const match = asset.metadataMatch as MetadataMatch | null | undefined
  const current = match?.catalogRevision === revision
  const products = current
    ? referenceCatalog.devices.filter(({ id }) => match.products?.some((item) => item.id === id))
    : []
  const manufacturers = current
    ? referenceCatalog.manufacturers.filter(({ id }) => match.manufacturerIDs?.includes(id))
    : []
  const status =
    revision === 'unloaded'
      ? 'No device catalog has been imported. An administrator can import manufacturer and device JSON under Settings > Device catalog.'
      : !match
        ? 'Catalog matching has not run for this asset yet.'
        : !current
          ? 'Catalog evidence is from an older revision. Background reclassification will refresh it.'
          : match.status === 'ambiguous'
            ? 'Conflicting catalog candidates. No catalog class is assigned automatically.'
            : !products.length
              ? 'No product matches the recorded manufacturer and product qualifiers.'
              : 'Reference capabilities describe the product, not enabled services, installed updates, or its deployed function.'
  return (
    <>
      <section className={catalogCard}>
        <div className="asset-view__section-heading">
          <h2>Connected manufacturer and device information</h2>
          {products.length ? (
            <span>
              {products.length} catalog candidate{products.length === 1 ? '' : 's'}
            </span>
          ) : null}
        </div>
        <p className="asset-view__muted" role="status">
          {status}
        </p>
        <dl className="asset-view__details">
          <div className="asset-view__detail">
            <dt>Catalog revision</dt>
            <dd>
              <code>{match?.catalogRevision || revision}</code>
            </dd>
          </div>
        </dl>
      </section>
      {manufacturers.map((manufacturer) => (
        <section className={catalogCard} key={manufacturer.id}>
          <div className="asset-view__section-heading">
            <h2>{manufacturer.data.name}</h2>
            <span>Manufacturer</span>
          </div>
          <dl className="asset-view__details">
            <div className="asset-view__detail">
              <dt>Manufacturer ID</dt>
              <dd>
                <code>{manufacturer.id}</code>
              </dd>
            </div>
          </dl>
          {dataDetails(manufacturer.data)}
          {evidenceDetails('Manufacturer match evidence', {
            match: match?.manufacturerEvidence,
            source: manufacturer.data.evidence_json,
          })}
        </section>
      ))}
      {products.slice(0, 20).map((product) => {
        const evidence = match?.products.find(({ id }) => id === product.id)
        const manufacturerID = evidence?.manufacturerID || product.manufacturer_id
        return (
          <section className={catalogCard} key={product.id}>
            <div className="asset-view__section-heading">
              <h2>{String(product.data.model || product.data.product_family || product.id)}</h2>
              <span>Device</span>
            </div>
            <dl className="asset-view__details">
              <div className="asset-view__detail">
                <dt>Device ID</dt>
                <dd>
                  <code>{product.id}</code>
                </dd>
              </div>
              <div className="asset-view__detail">
                <dt>Manufacturer ID</dt>
                <dd>
                  <code>{manufacturerID || 'Unavailable'}</code>
                </dd>
              </div>
              <div className="asset-view__detail">
                <dt>Device type ID</dt>
                <dd>
                  <code>{product.device_type_id}</code>
                </dd>
              </div>
            </dl>
            {dataDetails(product.data)}
            {evidenceDetails('Match and source evidence', {
              match: evidence?.evidence,
              manufacturer: match?.manufacturerEvidence,
              source: product.data.evidence_json,
            })}
          </section>
        )
      })}
      {products.length > 20 ? (
        <p role="status">Only the first 20 catalog candidates are shown.</p>
      ) : null}
      <p className="asset-view__note">
        Metadata schemas: {metadataLicense.attribution}.{' '}
        <a href={metadataLicense.licenseURL} target="_blank" rel="noopener noreferrer">
          {metadataLicense.license}
        </a>
        .
      </p>
    </>
  )
}
