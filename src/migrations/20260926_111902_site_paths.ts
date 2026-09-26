import type { MigrateDownArgs, MigrateUpArgs } from '@payloadcms/db-mongodb'

type SiteRecord = { _id: unknown; name: string; parent?: unknown }

export async function up({ payload, session }: MigrateUpArgs): Promise<void> {
  const sites = payload.db.collections.sites.collection
  const docs = (await sites
    .find({}, { projection: { _id: 1, name: 1, parent: 1 }, session })
    .toArray()) as SiteRecord[]
  const byID = new Map(docs.map((site) => [String(site._id), site]))
  const paths = new Map<string, string>()
  const visiting = new Set<string>()

  const pathFor = (site: SiteRecord): string => {
    const id = String(site._id)
    const existing = paths.get(id)
    if (existing) return existing
    if (visiting.has(id)) throw new Error('Cannot migrate cyclic site hierarchy.')

    visiting.add(id)
    const parent = site.parent ? byID.get(String(site.parent)) : undefined
    const path = parent ? `${pathFor(parent)} / ${site.name}` : site.name
    visiting.delete(id)
    paths.set(id, path)
    return path
  }

  if (docs.length) {
    await sites.bulkWrite(
      docs.map((site) => ({
        updateOne: { filter: { _id: site._id }, update: { $set: { path: pathFor(site) } } },
      })) as Parameters<typeof sites.bulkWrite>[0],
      { session },
    )
  }
}

export async function down({ payload, session }: MigrateDownArgs): Promise<void> {
  const sites = payload.db.collections.sites.collection
  await sites.updateMany({}, { $unset: { path: '' } }, { session })
}
