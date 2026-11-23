import { buildOpenApiDocument } from '@seshuk/payload-plugin-openapi'
import type { Payload } from 'payload'

export const getApiDocument = (payload: Payload) => {
  const options = payload.config.custom?.['@seshuk/payload-plugin-openapi']
  if (!options) throw new Error('The OpenAPI plugin is not configured.')
  return buildOpenApiDocument({ payload, options })
}
