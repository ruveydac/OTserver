import Link from 'next/link'
import type { Payload, SanitizedPermissions } from 'payload'

import type { User } from '@/payload-types'

import './index.scss'

const statusLabels = {
  maintenance: 'Maintenance',
  offline: 'Offline',
  online: 'Online',
  unknown: 'Unknown',
}

const BeforeDashboard = async ({
  payload,
  permissions,
  user,
}: {
  payload: Payload
  permissions?: SanitizedPermissions
  user?: User
}) => {
  const [total, online, offline, sites, recent] = await Promise.all([
    payload.count({ collection: 'assets', overrideAccess: false, user }),
    payload.count({
      collection: 'assets',
      overrideAccess: false,
      user,
      where: { status: { equals: 'online' } },
    }),
    payload.count({
      collection: 'assets',
      overrideAccess: false,
      user,
      where: { status: { equals: 'offline' } },
    }),
    payload.count({ collection: 'sites', overrideAccess: false, user }),
    payload.find({
      collection: 'assets',
      limit: 6,
      overrideAccess: false,
      select: {
        ipAddress: true,
        name: true,
        site: true,
        status: true,
        updatedAt: true,
      },
      sort: '-updatedAt',
      user,
    }),
  ])

  const metrics = [
    { label: 'Total assets', value: total.totalDocs },
    { label: 'Online', value: online.totalDocs },
    { label: 'Offline', value: offline.totalDocs },
    { label: 'Sites', value: sites.totalDocs },
  ]
  const canCreateAssets = Boolean(permissions?.collections?.assets?.create)
  const canCreateImports = Boolean(permissions?.collections?.['asset-imports']?.create)
  const canReadSites = Boolean(permissions?.collections?.sites?.read)

  return (
    <section className="before-dashboard">
      <header className="before-dashboard__hero">
        <div>
          <p className="before-dashboard__eyebrow">OT inventory</p>
          {/* ponytail: render otserver.svg logo */}
          <img src="/otserver.svg" alt="OTserver" className="before-dashboard__logo" />
          <p>
            Track industrial devices, network identities, ownership data, and operational state.
          </p>
        </div>
        {canReadSites || canCreateImports || canCreateAssets ? (
          <div className="before-dashboard__actions">
            {canReadSites ? (
              <Link
                className="before-dashboard__button before-dashboard__button--secondary"
                href="/admin/collections/sites"
              >
                Manage sites
              </Link>
            ) : null}
            {canCreateImports ? (
              <Link
                className="before-dashboard__button before-dashboard__button--secondary"
                href="/admin/collections/asset-imports/create"
              >
                Import discovery XML
              </Link>
            ) : null}
            {canCreateAssets ? (
              <Link className="before-dashboard__button" href="/admin/collections/assets/create">
                Add asset
              </Link>
            ) : null}
          </div>
        ) : null}
      </header>

      <div className="before-dashboard__metrics">
        {metrics.map((metric) => (
          <div className="before-dashboard__metric" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
          </div>
        ))}
      </div>

      <div className="before-dashboard__recent">
        <div className="before-dashboard__section-heading">
          <div>
            <h2>Recently updated</h2>
            <p>Your latest inventory changes.</p>
          </div>
          <Link href="/admin/collections/assets">All assets →</Link>
        </div>

        {recent.docs.length ? (
          <div className="before-dashboard__table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Status</th>
                  <th>IP address</th>
                  <th>Site</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {recent.docs.map((asset) => {
                  const status = asset.status || 'unknown'
                  const site = typeof asset.site === 'object' ? asset.site : undefined

                  return (
                    <tr key={asset.id}>
                      <td>
                        <Link href={`/admin/collections/assets/${asset.id}`}>{asset.name}</Link>
                      </td>
                      <td>
                        <span
                          className={`before-dashboard__status before-dashboard__status--${status}`}
                        >
                          {statusLabels[status]}
                        </span>
                      </td>
                      <td>{asset.ipAddress}</td>
                      <td>
                        {site ? (
                          <Link href={`/admin/collections/sites/${site.id}`}>{site.name}</Link>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td>{new Date(asset.updatedAt).toLocaleDateString()}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="before-dashboard__empty">
            <strong>No assets yet</strong>
            <p>Add your first device to start the OT inventory.</p>
            {canCreateAssets ? (
              <Link href="/admin/collections/assets/create">Add first asset</Link>
            ) : null}
          </div>
        )}
      </div>
    </section>
  )
}

export default BeforeDashboard
