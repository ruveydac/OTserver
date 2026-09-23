import { createLocalReq, type Payload, type RequestContext, type TypedUser } from 'payload'

export const systemRequest = (payload: Payload, context: RequestContext = {}) =>
  createLocalReq({ context }, payload)

export const principalRequest = (payload: Payload, user: TypedUser, context: RequestContext = {}) =>
  createLocalReq({ context, user }, payload)
