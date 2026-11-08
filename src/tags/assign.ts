import {
  APIError,
  type CollectionBeforeChangeHook,
  type Payload,
  type PayloadRequest,
} from 'payload'
import { isDeepStrictEqual } from 'node:util'

import { relationshipID } from '../access/authorization'
import { activeCatalog } from '../metadata/runtime'
import type { CatalogProduct } from '../metadata/catalog'
import {
  matchesTagRules,
  tagRuleUsesVulnerabilities,
  validateTagRules,
  type TagRuleDefinition,
} from './rules'

type TagRuntime = {
  tags: TagRuleDefinition[]
  tagByID: Map<string, TagRuleDefinition>
  customFieldIDs: Set<string>
  catalog: Awaited<ReturnType<typeof activeCatalog>>
}

type ConfirmedMatch = {
  asset?: unknown
  status?: string
  evidence?: unknown
}

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const ids = (value: unknown): string[] =>
  (Array.isArray(value) ? value : [value])
    .map((item) => relationshipID(item))
    .filter((id): id is string => Boolean(id))

const loadTagRuntime = async (payload: Payload, req: PayloadRequest): Promise<TagRuntime> => {
  const cached = req.context.assetTagRuntime as TagRuntime | undefined
  if (cached) return cached
  const [tags, fields, catalog] = await Promise.all([
    payload.find({
      collection: 'tags',
      depth: 0,
      limit: 1000,
      pagination: false,
      overrideAccess: true,
      req,
      sort: 'name',
    }),
    payload.find({
      collection: 'asset-fields',
      depth: 0,
      limit: 1000,
      pagination: false,
      overrideAccess: true,
      req,
    }),
    activeCatalog(payload, req),
  ])
  const customFieldIDs = new Set(fields.docs.map(({ id }) => String(id)))
  const tagDocs = (tags.docs as unknown as TagRuleDefinition[]).map((tag) => ({
    ...tag,
    rules: tag.rules?.filter((rule) => validateTagRules([rule], false, customFieldIDs) === true),
  }))
  const runtime = {
    tags: tagDocs,
    tagByID: new Map(tagDocs.map((tag) => [String(tag.id), tag])),
    customFieldIDs,
    catalog,
  }
  req.context.assetTagRuntime = runtime
  return runtime
}

const connectedProducts = (asset: Record<string, unknown>, runtime: TagRuntime) => {
  const match = asRecord(asset.metadataMatch)
  if (
    match.catalogRevision !== runtime.catalog.revision ||
    match.status !== 'matched' ||
    !Array.isArray(match.products)
  )
    return []
  const ids = new Set(
    match.products.flatMap((product) => {
      const id = asRecord(product).id
      return typeof id === 'string' ? [id] : []
    }),
  )
  return runtime.catalog.catalog.devices.filter((product) =>
    ids.has(product.id),
  ) as CatalogProduct[]
}

const confirmedRecords = (reviews: ConfirmedMatch[]) =>
  reviews.flatMap((review) => {
    if (review.status !== 'confirmed') return []
    const match = asRecord(asRecord(review.evidence).match)
    return Object.keys(match).length ? [match] : []
  })

const calculateAssignments = (
  asset: Record<string, unknown>,
  runtime: TagRuntime,
  manualIDs: string[],
  confirmed: Record<string, unknown>[],
  now = Date.now(),
) => {
  const manualTags = [...new Set(manualIDs)].filter(
    (id) => runtime.tagByID.get(id)?.manual === true,
  )
  const connected = connectedProducts(asset, runtime)
  const automaticTags = runtime.tags
    .filter(
      (tag) =>
        tag.manual !== true &&
        matchesTagRules(
          tag.rules,
          asset,
          connected,
          tagRuleUsesVulnerabilities(tag.rules) ? confirmed : [],
          now,
        ),
    )
    .map(({ id }) => String(id))
  const assigned = [...new Set([...manualTags, ...automaticTags])]
  return {
    manualTags,
    automaticTags,
    tags: assigned,
    tagNames: assigned.flatMap((id) => {
      const name = runtime.tagByID.get(id)?.name
      return name ? [name] : []
    }),
  }
}

const loadConfirmedReviews = async (payload: Payload, assetIDs: string[], req: PayloadRequest) => {
  const reviews: ConfirmedMatch[] = []
  if (!assetIDs.length) return reviews
  for (let page = 1; ; page++) {
    const result = await payload.find({
      collection: 'asset-vulnerability-reviews',
      depth: 0,
      limit: 1000,
      page,
      req,
      overrideAccess: true,
      where: {
        and: [{ asset: { in: assetIDs } }, { status: { equals: 'confirmed' } }],
      },
      select: { asset: true, evidence: true, status: true },
    })
    reviews.push(...(result.docs as unknown as ConfirmedMatch[]))
    if (!result.hasNextPage) break
  }
  return reviews
}

const reviewMap = (reviews: ConfirmedMatch[]) => {
  const result = new Map<string, Record<string, unknown>[]>()
  for (const review of reviews) {
    if (review.status !== 'confirmed') continue
    const assetID = relationshipID(review.asset)
    if (!assetID) continue
    const key = String(assetID)
    const values = result.get(key) || []
    values.push(...confirmedRecords([review]))
    result.set(key, values)
  }
  return result
}

const manualAssignments = (
  requested: unknown,
  previous: unknown,
  runtime: TagRuntime,
  explicit: boolean,
) => {
  const requestedIDs = ids(explicit ? requested : previous)
  const unique = [...new Set(requestedIDs)]
  if (explicit && unique.some((id) => runtime.tagByID.get(id)?.manual !== true))
    throw new APIError('Only existing manual tags can be assigned to an asset.', 400)
  return unique.filter((id) => runtime.tagByID.get(id)?.manual === true)
}

export const assignAssetTagsBeforeChange: CollectionBeforeChangeHook = async ({
  context,
  data,
  originalDoc,
  req,
}) => {
  if (context.assetTagRefresh) return data
  const nextData = data || {}
  const runtime = await loadTagRuntime(req.payload, req)
  const merged = { ...originalDoc, ...nextData }
  const manual = manualAssignments(
    nextData.manualTags,
    originalDoc?.manualTags,
    runtime,
    Object.hasOwn(nextData, 'manualTags'),
  )
  const hasVulnerabilityRule = runtime.tags.some(
    (tag) => tag.manual !== true && tagRuleUsesVulnerabilities(tag.rules),
  )
  const reviews =
    hasVulnerabilityRule && merged.id
      ? await loadConfirmedReviews(req.payload, [String(merged.id)], req)
      : []
  return {
    ...nextData,
    ...calculateAssignments(merged, runtime, manual, confirmedRecords(reviews)),
  }
}

const changed = (asset: Record<string, unknown>, next: ReturnType<typeof calculateAssignments>) =>
  !isDeepStrictEqual(ids(asset.manualTags), next.manualTags) ||
  !isDeepStrictEqual(ids(asset.automaticTags), next.automaticTags) ||
  !isDeepStrictEqual(ids(asset.tags), next.tags) ||
  !isDeepStrictEqual(asset.tagNames || [], next.tagNames)

export const refreshAssetTagsForAsset = async (
  payload: Payload,
  assetID: string,
  req: PayloadRequest,
) => {
  const asset = (await payload.findByID({
    collection: 'assets',
    id: assetID,
    depth: 0,
    overrideAccess: true,
    req,
  })) as unknown as Record<string, unknown>
  const runtime = await loadTagRuntime(payload, req)
  const manual = manualAssignments(asset.manualTags, asset.manualTags, runtime, false)
  const reviews = runtime.tags.some(
    (tag) => tag.manual !== true && tagRuleUsesVulnerabilities(tag.rules),
  )
    ? await loadConfirmedReviews(payload, [assetID], req)
    : []
  const next = calculateAssignments(asset, runtime, manual, confirmedRecords(reviews))
  if (!changed(asset, next)) return false
  await payload.update({
    collection: 'assets',
    id: assetID,
    data: next,
    context: { assetTagRefresh: true, assetTagReclassification: true },
    overrideAccess: true,
    req,
  })
  return true
}

export const reapplyAssetTags = async (req: PayloadRequest) => {
  delete req.context.assetTagRuntime
  const runtime = await loadTagRuntime(req.payload, req)
  const usesVulnerabilities = runtime.tags.some(
    (tag) => tag.manual !== true && tagRuleUsesVulnerabilities(tag.rules),
  )
  let page = 1
  let scanned = 0
  let updated = 0
  for (;;) {
    const assets = await req.payload.find({
      collection: 'assets',
      depth: 0,
      limit: 100,
      overrideAccess: true,
      page,
      req,
      sort: 'id',
    })
    scanned += assets.docs.length
    const assetIDs = assets.docs.map(({ id }) => String(id))
    const reviews = usesVulnerabilities
      ? reviewMap(await loadConfirmedReviews(req.payload, assetIDs, req))
      : new Map<string, Record<string, unknown>[]>()
    for (const document of assets.docs) {
      const asset = document as unknown as Record<string, unknown>
      const manual = manualAssignments(asset.manualTags, asset.manualTags, runtime, false)
      const next = calculateAssignments(asset, runtime, manual, reviews.get(String(asset.id)) || [])
      if (!changed(asset, next)) continue
      await req.payload.update({
        collection: 'assets',
        id: String(asset.id),
        data: next,
        context: { assetTagRefresh: true, assetTagReclassification: true },
        overrideAccess: true,
        req,
      })
      updated++
    }
    if (!assets.hasNextPage) break
    page++
  }
  return { scanned, updated }
}

export const queueAssetTagReapply = async (req: PayloadRequest) =>
  req.payload.jobs.queue({
    task: 'reapply-asset-tags-v1',
    queue: 'maintenance',
    input: { version: 1 },
    req,
  })

export const scheduleAssetTagReapply = async (payload: Payload) => {
  const pending = await payload.find({
    collection: 'payload-jobs',
    limit: 10,
    pagination: false,
    sort: '-createdAt',
    where: {
      and: [{ taskSlug: { equals: 'reapply-asset-tags-v1' } }, { completedAt: { exists: false } }],
    },
  })
  if (pending.docs.length) return
  const completed = await payload.find({
    collection: 'payload-jobs',
    limit: 1,
    pagination: false,
    sort: '-createdAt',
    where: {
      and: [{ taskSlug: { equals: 'reapply-asset-tags-v1' } }, { completedAt: { exists: true } }],
    },
  })
  if (completed.docs[0] && Date.parse(completed.docs[0].createdAt) > Date.now() - 86_400_000) return
  const { systemRequest } = await import('../integrations/payload/requests')
  await payload.jobs.queue({
    task: 'reapply-asset-tags-v1',
    queue: 'maintenance',
    input: { version: 1 },
    req: await systemRequest(payload),
  })
}
