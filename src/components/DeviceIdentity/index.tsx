import Link from 'next/link'
import { createLocalReq, type Payload, type TypedUser } from 'payload'
import type { Asset } from '@/payload-types'
import { getAuthorization } from '@/access/authorization'
import { idOf } from '@/identity/access'
import { formatDateTime } from '@/components/labels'
import IdentityActions from './Actions'
import './index.scss'

export default async function DeviceIdentity({
  asset,
  payload,
  user,
}: {
  asset: Asset
  payload: Payload
  user: TypedUser
}) {
  const admin = payload.config.routes.admin
  const site = idOf(asset.site)
  const authorization = await getAuthorization(await createLocalReq({ user }, payload))
  const writable = authorization.isAdmin || authorization.writableSiteIDs.includes(site)
  const [endpoints, services, identifiers, installations, cases, targets, sites] =
    await Promise.all([
      payload.find({
        collection: 'network-endpoints',
        where: { asset: { equals: asset.id } },
        depth: 1,
        pagination: false,
        overrideAccess: false,
        user,
      }),
      payload.find({
        collection: 'service-bindings',
        where: { asset: { equals: asset.id } },
        depth: 0,
        pagination: false,
        overrideAccess: false,
        user,
      }),
      payload.find({
        collection: 'asset-identifiers',
        where: { asset: { equals: asset.id } },
        depth: 0,
        pagination: false,
        overrideAccess: false,
        user,
      }),
      payload.find({
        collection: 'asset-installations',
        where: { or: [{ parent: { equals: asset.id } }, { module: { equals: asset.id } }] },
        depth: 1,
        pagination: false,
        overrideAccess: false,
        user,
      }),
      payload.find({
        collection: 'identity-cases',
        where: { or: [{ asset: { equals: asset.id } }, { candidate: { equals: asset.id } }] },
        depth: 0,
        pagination: false,
        overrideAccess: false,
        user,
      }),
      writable
        ? payload.find({
            collection: 'assets',
            where: {
              and: [
                { site: { equals: site } },
                { id: { not_equals: asset.id } },
                { lifecycle: { equals: 'active' } },
              ],
            },
            depth: 0,
            pagination: false,
            overrideAccess: false,
            user,
          })
        : Promise.resolve({ docs: [] }),
      writable
        ? payload.find({
            collection: 'sites',
            where: authorization.isAdmin ? {} : { id: { in: authorization.writableSiteIDs } },
            depth: 0,
            pagination: false,
            overrideAccess: false,
            user,
          })
        : Promise.resolve({ docs: [] }),
    ])
  const recordLink = (collection: string, id: string, label: string) => (
    <Link href={`${admin}/collections/${collection}/${id}`}>{label}</Link>
  )
  return (
    <section className="asset-view__section asset-view__section--wide device-identity">
      <h2>Physical identity</h2>
      <p>
        <code>{asset.uuid || 'Legacy record — migration required'}</code> ·{' '}
        {asset.physicalKind || 'unknown'} · {asset.lifecycle || 'active'} ·{' '}
        {asset.baselined ? 'Baselined' : 'Unbaselined'}
      </p>
      {asset.mergedInto ? (
        <p>
          Merged into {recordLink('assets', idOf(asset.mergedInto), idOf(asset.mergedInto))}.
          Original evidence remains in this record.
        </p>
      ) : null}
      {asset.replacedBy ? (
        <p>Replaced by {recordLink('assets', idOf(asset.replacedBy), idOf(asset.replacedBy))}.</p>
      ) : null}
      <h3>Hardware identifiers</h3>
      {identifiers.docs.length ? (
        <ul>
          {identifiers.docs.map((identifier) => (
            <li key={identifier.id}>
              {recordLink(
                'asset-identifiers',
                identifier.id,
                `${identifier.authority} / ${identifier.manufacturer} / ${identifier.scope} / ${identifier.serial}`,
              )}{' '}
              — {identifier.state}
            </li>
          ))}
        </ul>
      ) : (
        <p>Provisional identity. No accepted hardware key has been recorded.</p>
      )}
      <h3>Network endpoints</h3>
      <ul>
        {endpoints.docs.map((endpoint) => (
          <li key={endpoint.id}>
            {recordLink(
              'network-endpoints',
              endpoint.id,
              endpoint.macAddress || endpoint.interfaceKey || endpoint.id,
            )}{' '}
            ·{' '}
            {typeof endpoint.networkContext === 'object'
              ? endpoint.networkContext?.name || 'Unavailable network scope'
              : endpoint.networkContext}
            {' · '}
            {endpoint.addresses?.map(({ address }) => address).join(', ') || 'No recorded IP'}
            {' · '}
            {endpoint.endedAt
              ? `Ended ${formatDateTime(endpoint.endedAt)}`
              : `${endpoint.reachability} · last seen ${formatDateTime(endpoint.lastSeen)}`}
          </li>
        ))}
      </ul>
      <h3>Service bindings</h3>
      <ul>
        {services.docs.map((service) => (
          <li key={service.id}>
            {recordLink(
              'service-bindings',
              service.id,
              `${service.protocol} · ${service.address || 'address unknown'} · ${service.transport}/${service.port ?? '—'}`,
            )}
            {service.endedAt ? ' (historical)' : ''}
          </li>
        ))}
      </ul>
      <h3>Chassis and modules</h3>
      <ul>
        {installations.docs.map((installation) => {
          const peer =
            idOf(installation.parent) === asset.id ? installation.module : installation.parent
          return (
            <li key={installation.id}>
              {idOf(peer)
                ? recordLink(
                    'assets',
                    idOf(peer),
                    peer && typeof peer === 'object' ? peer.name : idOf(peer),
                  )
                : 'Unavailable component'}
              {' · '}
              {recordLink(
                'asset-installations',
                installation.id,
                installation.slotPath ? `Slot ${installation.slotPath}` : 'Position not reported',
              )}
              {installation.removedAt
                ? ` · removed ${formatDateTime(installation.removedAt)}`
                : ' · installed'}
            </li>
          )
        })}
      </ul>
      {cases.docs.length ? (
        <>
          <h3>Identity review</h3>
          <ul>
            {cases.docs.map((item) => (
              <li key={item.id}>
                {recordLink('identity-cases', item.id, `${item.kind} — ${item.reason}`)} (
                {item.status})
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {writable ? (
        <>
          <p>
            <Link href={`${admin}/collections/asset-identifiers/create`}>
              Record verified hardware identity
            </Link>
            {' · '}
            <Link href={`${admin}/collections/network-endpoints/create`}>Add endpoint</Link>
            {' · '}
            <Link href={`${admin}/collections/asset-installations/create`}>Install a module</Link>
          </p>
          <IdentityActions
            assetID={asset.id}
            apiRoute={payload.config.routes.api}
            endpoints={endpoints.docs
              .filter(({ endedAt }) => !endedAt)
              .map((endpoint) => ({
                id: endpoint.id,
                label: endpoint.macAddress || endpoint.interfaceKey || endpoint.id,
              }))}
            identifiers={identifiers.docs.map((identifier) => ({
              id: identifier.id,
              label: `${identifier.scope}: ${identifier.serial}`,
            }))}
            targets={targets.docs.map((target) => ({ id: target.id, label: target.name }))}
            sites={sites.docs
              .filter(({ id }) => id !== site)
              .map((site) => ({ id: site.id, label: site.name }))}
          />
        </>
      ) : null}
    </section>
  )
}
