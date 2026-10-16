import { headers } from 'next/headers'
import type { Payload } from 'payload'

// List and dashboard slots receive a read-filtered user, which may omit the role.
export const authenticatedAdminUser = async (payload: Payload) =>
  (await payload.auth({ headers: await headers() })).user
