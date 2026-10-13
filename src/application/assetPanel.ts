import type { Payload, TypedUser } from 'payload'
import type { Asset } from '../payload-types'
import { assetHistoryScope } from '../identity/relationships'
import { findAssemblyVulnerabilities } from '../vulnerabilities/match'

export const loadAssetPanel = async ({
  asset,
  payload,
  user,
  historyPage,
  discoveryPage,
  topologyPage,
  pageSize,
}: {
  asset: Asset
  payload: Payload
  user?: TypedUser
  historyPage: number
  discoveryPage: number
  topologyPage: number
  pageSize: number
}) => {
  const limit = Number.isInteger(pageSize) ? Math.max(1, Math.min(pageSize, 100)) : 50
  const site = typeof asset.site === 'object' ? asset.site : undefined
  const assetClass = typeof asset.assetClass === 'object' ? asset.assetClass : undefined
  const siteID = typeof asset.site === 'object' ? asset.site.id : asset.site
  const assetClassID = typeof asset.assetClass === 'object' ? asset.assetClass.id : asset.assetClass
  const historyScope = asset.uuid
    ? await assetHistoryScope(asset.id, payload, user)
    : {
        assets: { asset: { equals: asset.id } },
        observations: { asset: { equals: asset.id } },
        truncated: false,
      }

  const siteRequest =
    site?.path || !siteID
      ? Promise.resolve(site)
      : payload.findByID({
          collection: 'sites',
          depth: 0,
          disableErrors: true,
          id: String(siteID),
          overrideAccess: false,
          select: { name: true, path: true },
          user,
        })
  const assetClassRequest =
    assetClass?.name || !assetClassID
      ? Promise.resolve(assetClass)
      : payload.findByID({
          collection: 'asset-classes',
          depth: 0,
          disableErrors: true,
          id: String(assetClassID),
          overrideAccess: false,
          select: { name: true },
          user,
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
    payload.find({
      collection: 'asset-fields',
      depth: 0,
      limit,
      overrideAccess: false,
      select: { label: true, type: true },
      sort: 'label',
      user,
    }),
    payload.find({
      collection: 'audit-logs',
      depth: 0,
      limit,
      overrideAccess: false,
      page: historyPage,
      sort: '-createdAt',
      user,
      where: historyScope.assets,
    }),
    payload.find({
      collection: 'asset-observations',
      depth: 0,
      limit,
      overrideAccess: false,
      page: discoveryPage,
      sort: '-observedAt',
      user,
      where: historyScope.observations,
    }),
    payload.find({
      collection: 'topology-links',
      depth: 0,
      limit,
      overrideAccess: false,
      page: topologyPage,
      sort: '-observedAt',
      user,
      where: {
        or: [{ localAsset: { equals: asset.id } }, { remoteAsset: { equals: asset.id } }],
      },
    }),
    findAssemblyVulnerabilities(payload, asset, { user }),
    payload.count({
      collection: 'network-endpoints',
      overrideAccess: false,
      user,
      where: { and: [{ asset: { equals: asset.id } }, { endedAt: { exists: false } }] },
    }),
    siteRequest,
    assetClassRequest,
  ])

  return {
    definitions,
    auditLogs,
    observations,
    topologyLinks,
    vulnerabilityMatches,
    endpointCount,
    loadedSite,
    loadedAssetClass,
    historyScopeTruncated: historyScope.truncated,
  }
}
