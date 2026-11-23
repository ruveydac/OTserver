import config from '@payload-config'
import { getPayload } from 'payload'

import { getApiDocument } from '@/apiDocs/openapi'

export async function GET(request: Request) {
  const payload = await getPayload({ config })
  const { user } = await payload.auth({ headers: request.headers, canSetHeaders: false })
  if (!user || 'otterScannerID' in user)
    return new Response(null, { status: 401, headers: { 'Cache-Control': 'private, no-store' } })

  return Response.json(await getApiDocument(payload), {
    headers: { 'Cache-Control': 'private, no-store' },
  })
}
