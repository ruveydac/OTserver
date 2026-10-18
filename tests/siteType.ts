import type { Payload } from 'payload'

export const siteTypeID = async (payload: Payload, key = 'site') => {
  const result = await payload.find({
    collection: 'site-types',
    depth: 0,
    limit: 1,
    pagination: false,
    where: { key: { equals: key } },
  })
  if (!result.docs[0]) throw new Error(`Missing seeded site type: ${key}`)
  return result.docs[0].id
}
