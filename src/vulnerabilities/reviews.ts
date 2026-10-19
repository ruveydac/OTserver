import { APIError, type PayloadHandler, type PayloadRequest, type Payload } from 'payload'
import { writeAudit } from '../collections/AuditLogs'
import type { Asset } from '../payload-types'
import { idOf, requireWritableAsset } from '../identity/access'
import { lockIdentityAssets } from '../identity/relationships'
import { inTransaction } from '../integrations/payload/transactions'
import {
  catalogIsLoaded,
  findAssemblyVulnerabilityGroups,
  findAssetVulnerabilities,
  matchAssetVulnerabilities,
  searchTokens,
  distinctive,
  text,
  versionEvidence,
  refreshAssetVulnerabilityCount,
} from './match'
import type { AssetMatchInput, VulnerabilityCandidate, VulnerabilityMatch } from './matching'

type ReviewStatus = 'confirmed' | 'dismissed' | 'resolved'
type ReviewAction = 'confirm' | 'dismiss' | 'resolve' | 'reopen'
type Review = {
  id: string
  asset: string | { id: string }
  cve: string
  status: ReviewStatus
  revision: number
  decidedAt: string
  reviewerID: string
  reviewerName?: string | null
  site: string | { id: string }
  evidence?: { asset?: AssetMatchInput; match?: VulnerabilityMatch } | null
}

const CVE = /^CVE-\d{4}-\d{4,19}$/
export const NO_LONGER_MATCHES_MESSAGE =
  'This vulnerability no longer matches the asset’s recorded product and version data. It may be resolved. Verify the device before marking it resolved.'

const allReviews = async (
  payload: Payload,
  assetIDs: string[],
  access: { req?: PayloadRequest; user?: PayloadRequest['user'] },
) => {
  if (!assetIDs.length) return [] as Review[]
  const user = access.req?.user ?? access.user ?? undefined
  const reviews: Review[] = []
  let after: string | undefined
  for (;;) {
    const result = await payload.find({
      collection: 'asset-vulnerability-reviews',
      depth: 0,
      limit: 100,
      pagination: false,
      overrideAccess: user || access.req ? false : true,
      ...(user ? { user } : {}),
      ...(access.req ? { req: access.req } : {}),
      select: {
        asset: true,
        cve: true,
        decidedAt: true,
        evidence: true,
        id: true,
        revision: true,
        reviewerID: true,
        reviewerName: true,
        site: true,
        status: true,
      },
      sort: 'id',
      where: {
        and: [{ asset: { in: assetIDs } }, ...(after ? [{ id: { greater_than: after } }] : [])],
      },
    })
    reviews.push(...(result.docs as Review[]))
    if (result.docs.length < 100) break
    after = result.docs.at(-1)!.id
  }
  return reviews
}

type Assessment = 'matched' | 'no-longer-matches' | 'unknown'
type Finding = {
  assetID: string
  assetName: string
  assessment: Assessment
  assessmentMessage?: string
  match: VulnerabilityMatch
  revision: number
  status: 'unconfirmed' | 'confirmed'
  reviewerName?: string | null
  decidedAt?: string
}

const snapshotMatch = (review: Review): VulnerabilityMatch | undefined => review.evidence?.match

const reassessConfirmedReview = async (
  payload: Payload,
  asset: AssetMatchInput,
  cve: string,
  user?: PayloadRequest['user'],
  req?: PayloadRequest,
) => {
  const unknown = (message: string) => ({ assessment: 'unknown' as const, message })
  if (!(await catalogIsLoaded(payload, req)))
    return unknown('The vulnerability catalog is not available.')
  const result = await payload.find({
    collection: 'vulnerabilities',
    depth: 0,
    limit: 1,
    pagination: false,
    overrideAccess: user || req ? false : true,
    ...(user ? { user } : {}),
    ...(req ? { req } : {}),
    select: {
      affected: true,
      cve: true,
      cvssScore: true,
      cvssSeverity: true,
      knownExploited: true,
    },
    where: { cve: { equals: cve } },
  })
  const candidate = result.docs[0] as VulnerabilityCandidate | undefined
  if (!candidate)
    return unknown('The catalog entry is unavailable, so this finding cannot be reassessed.')
  if (!asset.vendor || (!asset.model && !asset.operatingSystem))
    return unknown('Vendor and product metadata are needed to reassess this finding.')
  if (
    !distinctive(
      searchTokens(
        [text(asset.model), text(asset.operatingSystem), text(asset.catalogNumber)].join(' '),
      ),
    ).length
  )
    return unknown('More specific product metadata is needed to reassess this finding.')
  if (!candidate.affected?.length)
    return unknown('The catalog entry has no affected-version criteria to compare.')
  if (!candidate.affected.some(({ part }) => versionEvidence(asset, part).length))
    return unknown('A relevant version is not recorded for this asset.')
  if (matchAssetVulnerabilities(asset, [candidate]).length)
    return { assessment: 'matched' as const }
  return { assessment: 'no-longer-matches' as const }
}

export const loadAssetVulnerabilityReviews = async (
  payload: Payload,
  asset: Asset & AssetMatchInput,
  access: { req?: PayloadRequest; user?: PayloadRequest['user'] } = {},
) => {
  if (asset.lifecycle === 'merged') return { findings: [], resolved: [], reviews: [] as Review[] }
  const groups = await findAssemblyVulnerabilityGroups(payload, asset, access)
  const assetIDs = groups.flatMap(({ asset: target }) => (target.id ? [target.id] : []))
  const reviews = await allReviews(payload, assetIDs, access)
  const reviewByKey = new Map(
    reviews.map((review) => [`${idOf(review.asset)}:${review.cve}`, review]),
  )
  const groupByID = new Map(
    groups.flatMap((group) => (group.asset.id ? [[group.asset.id, group] as const] : [])),
  )
  const findings: Finding[] = []
  const resolved: {
    assetID: string
    assetName: string
    cve: string
    decidedAt: string
    evidence?: Review['evidence']
    reviewerName?: string | null
    revision: number
  }[] = []
  const matchedKeys = new Set<string>()

  for (const group of groups) {
    const assetID = group.asset.id
    if (!assetID) continue
    const assetName = group.asset.name || assetID
    for (const match of group.matches) {
      const key = `${assetID}:${match.cve}`
      matchedKeys.add(key)
      const review = reviewByKey.get(key)
      if (review?.status === 'dismissed') continue
      if (review?.status === 'resolved') {
        resolved.push({
          assetID,
          assetName,
          cve: review.cve,
          decidedAt: review.decidedAt,
          evidence: review.evidence,
          reviewerName: review.reviewerName,
          revision: review.revision,
        })
        continue
      }
      findings.push({
        assetID,
        assetName,
        assessment: 'matched',
        match,
        revision: review?.revision ?? 0,
        status: review?.status === 'confirmed' ? 'confirmed' : 'unconfirmed',
        ...(review?.status === 'confirmed'
          ? { reviewerName: review.reviewerName, decidedAt: review.decidedAt }
          : {}),
      })
    }
  }

  for (const review of reviews) {
    const assetID = idOf(review.asset)
    const group = groupByID.get(assetID)
    if (!group || matchedKeys.has(`${assetID}:${review.cve}`)) continue
    const assetName = group.asset.name || assetID
    if (review.status === 'dismissed') continue
    if (review.status === 'resolved') {
      resolved.push({
        assetID,
        assetName,
        cve: review.cve,
        decidedAt: review.decidedAt,
        evidence: review.evidence,
        reviewerName: review.reviewerName,
        revision: review.revision,
      })
      continue
    }
    const assessment = await reassessConfirmedReview(
      payload,
      group.asset,
      review.cve,
      access.req?.user ?? access.user ?? undefined,
      access.req,
    )
    const match = snapshotMatch(review)
    if (!match) continue
    findings.push({
      assetID,
      assetName,
      assessment: assessment.assessment,
      ...(assessment.assessment === 'unknown' ? { assessmentMessage: assessment.message } : {}),
      match,
      revision: review.revision,
      status: 'confirmed',
      reviewerName: review.reviewerName,
      decidedAt: review.decidedAt,
    })
  }

  return { findings, resolved, reviews }
}

const updateAssetCount = async (
  payload: Payload,
  asset: Asset,
  req: PayloadRequest,
  action: ReviewAction,
) => {
  if (await catalogIsLoaded(payload, req))
    return refreshAssetVulnerabilityCount(payload, asset, req)
  const delta = inputActionDelta(action)
  if (asset.vulnerabilityCount == null || delta === 0) return
  await payload.update({
    collection: 'assets',
    id: asset.id,
    data: { vulnerabilityCount: Math.max(0, asset.vulnerabilityCount + delta) },
    context: { vulnerabilityCountSync: true },
    overrideAccess: true,
    req,
  })
}

const inputActionDelta = (action: unknown) =>
  action === 'dismiss' || action === 'resolve' ? -1 : action === 'reopen' ? 1 : 0

const findReview = async (assetID: string, cve: string, req: PayloadRequest) => {
  const result = await req.payload.find({
    collection: 'asset-vulnerability-reviews',
    depth: 0,
    limit: 1,
    pagination: false,
    overrideAccess: false,
    req,
    where: { and: [{ asset: { equals: assetID } }, { cve: { equals: cve } }] },
  })
  return result.docs[0] as Review | undefined
}

export const performVulnerabilityReview = async (
  assetID: string,
  input: Record<string, unknown>,
  req: PayloadRequest,
) => {
  const principal = req.user
  if (!principal) throw new APIError('Authentication required.', 401)
  if (req.context.otterScannerID || 'otterScannerID' in principal)
    throw new APIError('Scanner credentials cannot review vulnerabilities.', 403)
  const action = input.action as ReviewAction
  const cve = input.cve
  const expectedRevision = input.revision
  if (!['confirm', 'dismiss', 'resolve', 'reopen'].includes(String(action)))
    throw new APIError('Unknown vulnerability review action.', 400)
  if (typeof cve !== 'string' || !CVE.test(cve))
    throw new APIError('Supply a canonical CVE identifier.', 400)
  if (!Number.isSafeInteger(expectedRevision) || Number(expectedRevision) < 0)
    throw new APIError('Supply the current review revision.', 400)

  try {
    return await inTransaction(req, async () => {
      const asset = await requireWritableAsset(assetID, req)
      if (asset.lifecycle === 'merged')
        throw new APIError('Merged assets no longer accept vulnerability reviews.', 409)
      const targetStatus: ReviewStatus =
        action === 'dismiss' ? 'dismissed' : action === 'resolve' ? 'resolved' : 'confirmed'
      const beforeLock = await findReview(asset.id, cve, req)
      if (beforeLock?.status === targetStatus) return beforeLock
      await lockIdentityAssets([asset.id], req)
      const current = await findReview(asset.id, cve, req)

      if (current?.status === targetStatus) return current
      if ((current?.revision ?? 0) !== Number(expectedRevision))
        throw new APIError('This vulnerability review changed. Refresh and try again.', 409)
      if (action === 'confirm' && current)
        throw new APIError('Only an unreviewed match can be confirmed.', 409)
      if (action === 'dismiss' && current)
        throw new APIError('Only an unreviewed match can be dismissed.', 409)
      if (action === 'resolve' && current?.status !== 'confirmed')
        throw new APIError('Only a confirmed vulnerability can be resolved.', 409)
      if (action === 'reopen' && current?.status !== 'resolved')
        throw new APIError('Only a resolved vulnerability can be reopened.', 409)

      const matches = await findAssetVulnerabilities(req.payload, asset, { req })
      const liveMatch = matches.find((match) => match.cve === cve)
      if (!current && !liveMatch)
        throw new APIError('This CVE is no longer a current match for the asset.', 409)

      const before = current ? { status: current.status, revision: current.revision } : undefined
      const at = new Date().toISOString()
      const reviewerName = typeof principal.name === 'string' ? principal.name : principal.email
      const evidence =
        current?.evidence ||
        (liveMatch
          ? {
              asset: Object.fromEntries(
                [
                  'vendor',
                  'model',
                  'catalogNumber',
                  'operatingSystem',
                  'firmwareVersion',
                  'hardwareVersion',
                ].map((field) => [field, asset[field as keyof AssetMatchInput]]),
              ),
              match: liveMatch,
            }
          : undefined)
      const data = {
        asset: asset.id,
        site: idOf(asset.site),
        cve,
        status: targetStatus,
        revision: (current?.revision ?? 0) + 1,
        decidedAt: at,
        reviewerID: String(principal.id),
        reviewerName,
        ...(evidence ? { evidence } : {}),
      }
      const saved = current
        ? await req.payload.update({
            collection: 'asset-vulnerability-reviews',
            id: current.id,
            data,
            overrideAccess: true,
            req,
          })
        : await req.payload.create({
            collection: 'asset-vulnerability-reviews',
            data,
            overrideAccess: true,
            req,
          })

      await writeAudit({
        action: 'custom',
        before: before ? { ...before, cve, action } : undefined,
        after: {
          id: saved.id,
          asset: asset.id,
          site: idOf(asset.site),
          cve,
          action,
          status: targetStatus,
          revision: data.revision,
        },
        assetID: asset.id,
        siteID: idOf(asset.site),
        req,
        targetCollection: 'asset-vulnerability-reviews',
      })
      await updateAssetCount(req.payload, asset, req, action)
      return saved
    })
  } catch (error) {
    const code = (error as { code?: number })?.code
    if (code === 11000 || code === 112)
      throw new APIError(
        'This vulnerability review changed concurrently. Refresh and try again.',
        409,
      )
    throw error
  }
}

const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

export const vulnerabilityReviewAction: PayloadHandler = async (req) => {
  if (!req.user) throw new APIError('Authentication required.', 401)
  let input: unknown
  try {
    input = await req.json?.()
  } catch {
    throw new APIError('Request body must be valid JSON.', 400)
  }
  const body = object(input)
  if (Object.keys(body).some((key) => !['action', 'cve', 'revision'].includes(key)))
    throw new APIError('Unexpected vulnerability review fields.', 400)
  return Response.json(
    await performVulnerabilityReview(String(req.routeParams?.id || ''), body, req),
  )
}
