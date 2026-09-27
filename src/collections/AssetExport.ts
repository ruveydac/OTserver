import { ReadableStream, TextEncoderStream } from 'node:stream/web'
import { parseParams, type PayloadHandler } from 'payload'

const csvCell = (value: unknown): string => {
  if (value === null || value === undefined) return ''
  const text = Array.isArray(value)
    ? value
        .map((entry) =>
          entry !== null && typeof entry === 'object' ? JSON.stringify(entry) : String(entry),
        )
        .join(';')
    : typeof value === 'object'
      ? JSON.stringify(value)
      : String(value)
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text
}

export const exportAssetsCSV: PayloadHandler = async (req) => {
  const { where } = parseParams(req.query)
  const cutoff = new Date().toISOString()

  const rows = async function* (withRelations: boolean) {
    let after: string | undefined
    for (;;) {
      const assets = await req.payload.find({
        collection: 'assets',
        depth: 0,
        limit: 100,
        pagination: false,
        sort: 'id',
        overrideAccess: false,
        req,
        where: {
          and: [
            where || {},
            { createdAt: { less_than_equal: cutoff } },
            ...(after ? [{ id: { greater_than: after } }] : []),
          ],
        },
      })

      const siteNames = new Map<string, string>()
      if (withRelations && assets.docs.length) {
        const sites = await req.payload.find({
          collection: 'sites',
          depth: 0,
          pagination: false,
          overrideAccess: false,
          req,
          select: { name: true },
          where: {
            id: {
              in: assets.docs.map((asset) =>
                typeof asset.site === 'object' ? asset.site.id : asset.site,
              ),
            },
          },
        })
        for (const site of sites.docs) siteNames.set(site.id, site.name)
      }

      for (const asset of assets.docs) {
        const siteID = typeof asset.site === 'object' ? asset.site.id : asset.site
        const endpoints = []
        if (withRelations) {
          let endpointAfter: string | undefined
          for (;;) {
            const page = await req.payload.find({
              collection: 'network-endpoints',
              depth: 0,
              limit: 100,
              pagination: false,
              sort: 'id',
              overrideAccess: false,
              req,
              where: {
                and: [
                  { asset: { equals: asset.id } },
                  { endedAt: { exists: false } },
                  ...(endpointAfter ? [{ id: { greater_than: endpointAfter } }] : []),
                ],
              },
            })
            endpoints.push(...page.docs)
            if (page.docs.length < 100) break
            endpointAfter = page.docs.at(-1)!.id
          }
        }
        yield { ...asset, site: siteNames.get(siteID) ?? siteID, endpoints } as Record<
          string,
          unknown
        >
      }

      if (assets.docs.length < 100) break
      after = assets.docs.at(-1)!.id
    }
  }

  // The first pass retains only column names. The second emits one row per stream pull.
  const columns = new Set<string>()
  for await (const doc of rows(false)) for (const key of Object.keys(doc)) columns.add(key)
  if (!columns.size) columns.add('id')
  const keys = [...columns]
  const stream = ReadableStream.from(
    (async function* () {
      yield `\uFEFF${keys.map(csvCell).join(',')}\r\n`
      for await (const row of rows(true))
        yield `${keys.map((column) => csvCell(row[column])).join(',')}\r\n`
    })(),
  ).pipeThrough(new TextEncoderStream())

  return new Response(stream as unknown as BodyInit, {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Disposition': `attachment; filename="assets-${cutoff.slice(0, 10)}.csv"`,
      'Content-Type': 'text/csv; charset=utf-8',
    },
  })
}
