import type { MongooseAdapter } from '@payloadcms/db-mongodb'
import type { PayloadRequest } from 'payload'

export const mongoSession = async (req?: PayloadRequest) => {
  const id = await req?.transactionID
  return id ? (req!.payload.db as MongooseAdapter).sessions[id] : undefined
}
