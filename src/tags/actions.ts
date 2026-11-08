import { APIError, type PayloadHandler } from 'payload'

import { relationshipID } from '../access/authorization'
import { inTransaction } from '../integrations/payload/transactions'

const parseBody = async (request: Request) => {
  const reader = request.body?.getReader()
  if (!reader) throw new APIError('A JSON request body is required.', 400)
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > 128 * 1024) {
      await reader.cancel()
      throw new APIError('Bulk tag requests are limited to 128 KiB.', 413)
    }
    chunks.push(value)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
  } catch {
    throw new APIError('Invalid JSON request.', 400)
  }
}

export const bulkManualAssetTags: PayloadHandler = async (req) => {
  if (!req.user || req.context.otterScannerID)
    throw new APIError('User authentication is required to assign tags.', 403)
  if (req.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json')
    throw new APIError('Send asset and tag selections as application/json.', 415)
  const body = await parseBody(req as Request)
  if (!body || typeof body !== 'object' || Array.isArray(body))
    throw new APIError('Invalid bulk tag request.', 400)
  const input = body as Record<string, unknown>
  const assetIDs = Array.isArray(input.assetIDs) ? input.assetIDs : []
  const tagIDs = Array.isArray(input.tagIDs) ? input.tagIDs : []
  if (
    !assetIDs.length ||
    assetIDs.length > 200 ||
    assetIDs.some((id) => (typeof id !== 'string' && typeof id !== 'number') || !String(id)) ||
    !tagIDs.length ||
    tagIDs.length > 100 ||
    tagIDs.some((id) => (typeof id !== 'string' && typeof id !== 'number') || !String(id)) ||
    !['add', 'remove'].includes(String(input.action))
  )
    throw new APIError('Select up to 200 assets, manual tags, and an add or remove action.', 400)
  const uniqueAssets = [...new Set(assetIDs.map(String))]
  const uniqueTags = [...new Set(tagIDs.map(String))]
  if (uniqueAssets.length !== assetIDs.length || uniqueTags.length !== tagIDs.length)
    throw new APIError('Duplicate assets or tags are not allowed.', 400)

  let updated = 0
  await inTransaction(req, async () => {
    for (const assetID of uniqueAssets) {
      const asset = await req.payload.findByID({
        collection: 'assets',
        id: assetID,
        depth: 0,
        overrideAccess: false,
        req,
      })
      const current = (Array.isArray(asset.manualTags) ? asset.manualTags : [])
        .map((tag) => relationshipID(tag))
        .filter((id): id is string => Boolean(id))
      const next =
        input.action === 'add'
          ? [...new Set([...current, ...uniqueTags])]
          : current.filter((id) => !uniqueTags.includes(id))
      if (next.length === current.length && next.every((id, index) => id === current[index]))
        continue
      await req.payload.update({
        collection: 'assets',
        id: assetID,
        data: { manualTags: next },
        overrideAccess: false,
        req,
      })
      updated++
    }
  })
  return Response.json({ updated })
}
