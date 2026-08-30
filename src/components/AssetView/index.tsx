import Link from 'next/link'
import type { DocumentViewClientProps, DocumentViewServerProps } from 'payload'
import type { ReactNode } from 'react'

import {
  criticalityLabels,
  formatDateTime,
  protocolLabels,
  statusLabels,
} from '@/components/labels'
import type { Asset, AuditLog } from '@/payload-types'

import './index.scss'

type Detail = {
  key?: string
  label: string
  value: ReactNode
  wide?: boolean
}

const auditValue = (value: unknown) =>
  value !== null && typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')

const auditField = (value: string) =>
  value
    .replaceAll(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/^./, (character) => character.toUpperCase())

const auditDetails = (log: AuditLog): Detail => {
  const changes =
    log.changes && typeof log.changes === 'object' && !Array.isArray(log.changes) ? log.changes : {}

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
              const change =
                value && typeof value === 'object' && !Array.isArray(value)
                  ? (value as { after?: unknown; before?: unknown })
                  : {}
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
    <h2>{title}</h2>
    <dl className="asset-view__details">
      {details.map(({ key, label, value, wide: wideDetail }) => (
        <div
          className={
            wideDetail ? 'asset-view__detail asset-view__detail--wide' : 'asset-view__detail'
          }
          key={key || label}
        >
          <dt>{label}</dt>
          <dd>{value === null || value === undefined || value === '' ? '—' : value}</dd>
        </div>
      ))}
    </dl>
  </section>
)

const AssetView = async (props: DocumentViewServerProps) => {
  if (props.routeSegments.at(-1) === 'create') {
    const { DefaultEditView } = await import('@payloadcms/ui')
    const clientProps: DocumentViewClientProps = {
      BeforeDocumentControls: props.BeforeDocumentControls,
      Description: props.Description,
      documentSubViewType: props.documentSubViewType,
      EditMenuItems: props.EditMenuItems,
      formState: props.formState,
      LivePreview: props.LivePreview,
      PreviewButton: props.PreviewButton,
      PublishButton: props.PublishButton,
      SaveButton: props.SaveButton,
      SaveDraftButton: props.SaveDraftButton,
      Status: props.Status,
      UnpublishButton: props.UnpublishButton,
      Upload: props.Upload,
      UploadControls: props.UploadControls,
      viewType: props.viewType,
    }
    return <DefaultEditView {...clientProps} />
  }

  const asset = props.doc as Asset
  const adminRoute = props.payload.config.routes.admin
  const assetURL = `${adminRoute}/collections/assets/${asset.id}`
  const site = typeof asset.site === 'object' ? asset.site : undefined
  const assetClass = typeof asset.assetClass === 'object' ? asset.assetClass : undefined
  const customFields =
    asset.customFields &&
    typeof asset.customFields === 'object' &&
    !Array.isArray(asset.customFields)
      ? (asset.customFields as Record<string, unknown>)
      : {}
  const [definitions, auditLogs, observations, topologyLinks] = await Promise.all([
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
      overrideAccess: false,
      pagination: false,
      sort: '-createdAt',
      user: props.user,
      where: { asset: { equals: asset.id } },
    }),
    props.payload.find({
      collection: 'asset-observations',
      depth: 0,
      limit: 20,
      overrideAccess: false,
      sort: '-observedAt',
      user: props.user,
      where: { asset: { equals: asset.id } },
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
  ])

  return (
    <main className="asset-view">
      <div className="asset-view__back">
        <Link href={`${adminRoute}/collections/assets`}>← All assets</Link>
      </div>

      <header className="asset-view__header">
        <div>
          <p className="asset-view__eyebrow">OT asset</p>
          <h1>{asset.name}</h1>
          <p>{asset.description || 'No description provided.'}</p>
        </div>
        <div className="asset-view__actions">
          <span className={`asset-view__status asset-view__status--${asset.status}`}>
            {statusLabels[asset.status]}
          </span>
          <Link className="asset-view__edit" href={`${assetURL}/edit`}>
            Edit asset
          </Link>
        </div>
      </header>

      <div className="asset-view__grid">
        <Section
          details={[
            { label: 'Name', value: asset.name },
            {
              label: 'Site',
              value: site ? (
                <Link href={`${adminRoute}/collections/sites/${site.id}`}>{site.name}</Link>
              ) : typeof asset.site === 'string' ? (
                asset.site
              ) : undefined,
            },
            {
              label: 'Asset class',
              value: assetClass ? (
                <Link href={`${adminRoute}/collections/asset-classes/${assetClass.id}`}>
                  {assetClass.name}
                </Link>
              ) : typeof asset.assetClass === 'string' ? (
                asset.assetClass
              ) : undefined,
            },
            { label: 'Asset owner', value: asset.assetOwner },
            { label: 'Physical location', value: asset.location },
            { label: 'Description', value: asset.description, wide: true },
          ]}
          title="Identity"
        />
        <Section
          details={[
            { label: 'IP address', value: asset.ipAddress },
            { label: 'MAC address', value: asset.macAddress },
            { label: 'Network mask', value: asset.networkMask },
            { label: 'Gateway address', value: asset.gatewayAddress },
          ]}
          title="Network"
        />
        <Section
          details={[
            { label: 'Vendor', value: asset.vendor },
            { label: 'Model', value: asset.model },
            { label: 'Operating system', value: asset.operatingSystem },
            {
              label: 'OS confidence',
              value:
                asset.osAccuracy === null || asset.osAccuracy === undefined
                  ? undefined
                  : `${asset.osAccuracy}%`,
            },
            { label: 'Serial number', value: asset.serialNumber },
            { label: 'Firmware version', value: asset.firmwareVersion },
          ]}
          title="Device"
        />
        <Section
          details={[
            { label: 'Status', value: statusLabels[asset.status] },
            { label: 'Criticality', value: criticalityLabels[asset.criticality] },
            {
              label: 'Protocols',
              value: asset.protocols?.map((protocol) => protocolLabels[protocol]).join(', '),
            },
            { label: 'Last seen', value: formatDateTime(asset.lastSeen) },
          ]}
          title="Operations"
        />
        {definitions.docs.length ? (
          <Section
            details={definitions.docs.map((definition) => {
              const value = customFields[String(definition.id)]
              return {
                label: definition.label,
                value:
                  definition.type === 'checkbox' && typeof value === 'boolean'
                    ? value
                      ? 'Yes'
                      : 'No'
                    : definition.type === 'date' && typeof value === 'string'
                      ? formatDateTime(value)
                      : typeof value === 'string' || typeof value === 'number'
                        ? value
                        : undefined,
              }
            })}
            title="Custom fields"
          />
        ) : null}
        <Section
          details={[
            { label: 'Import source', value: asset.importSource },
            { label: 'Source version', value: asset.sourceVersion },
            { label: 'Last imported', value: formatDateTime(asset.lastImportedAt) },
          ]}
          title="Discovery"
        />
        <Section
          details={
            observations.docs.length
              ? observations.docs.map((observation) => ({
                  key: observation.id,
                  label: `${observation.source} · ${formatDateTime(observation.observedAt)}`,
                  value: (
                    <details>
                      <summary>{observation.quality} quality evidence</summary>
                      <pre>
                        {JSON.stringify(
                          {
                            fields: observation.fields,
                            interfaces: observation.interfaces,
                            ports: observation.ports,
                            raw: observation.raw,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  ),
                  wide: true,
                }))
              : [{ label: 'Evidence', value: 'No scanner evidence recorded yet.', wide: true }]
          }
          title="Otter evidence"
          wide
        />
        <Section
          details={
            topologyLinks.docs.length
              ? topologyLinks.docs.map((link) => {
                  const localID =
                    typeof link.localAsset === 'object' ? link.localAsset?.id : link.localAsset
                  const peer = String(localID) === String(asset.id) ? link.remote : link.local
                  return {
                    key: link.id,
                    label: `${link.source} · ${formatDateTime(link.observedAt)}`,
                    value: <pre>{JSON.stringify(peer, null, 2)}</pre>,
                    wide: true,
                  }
                })
              : [{ label: 'Connections', value: 'No topology links recorded yet.', wide: true }]
          }
          title="Topology"
          wide
        />
        <Section
          details={[
            { label: 'Record ID', value: asset.id },
            { label: 'Created', value: formatDateTime(asset.createdAt) },
            { label: 'Updated', value: formatDateTime(asset.updatedAt) },
            { label: 'Notes', value: asset.notes, wide: true },
          ]}
          title="Record"
        />
        <Section
          details={
            auditLogs.docs.length
              ? auditLogs.docs.map(auditDetails)
              : [{ label: 'History', value: 'No changes recorded yet.', wide: true }]
          }
          title="Change history"
          wide
        />
      </div>
    </main>
  )
}

export default AssetView
