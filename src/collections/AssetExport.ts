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

  // The local API defaults to overrideAccess; opt into the collection read
  // access that limits results to readable sites. The applyAssetSearch hook
  // applies req.query.search.
  // ponytail: loads every match into memory; stream pages to disk if inventories outgrow it.
  const docs: Record<string, unknown>[] = []
  let page = 1
  for (;;) {
    const result = await req.payload.find({
      collection: 'assets',
      depth: 0,
      limit: 1000,
      overrideAccess: false,
      page,
      req,
      where,
    })
    docs.push(...(result.docs as unknown as Record<string, unknown>[]))
    if (!result.hasNextPage) break
    page += 1
  }

  const columns: string[] = []
  for (const doc of docs) {
    for (const key of Object.keys(doc)) if (!columns.includes(key)) columns.push(key)
  }
  if (!columns.length) columns.push('id')

  const rows = [columns.map(csvCell).join(',')]
  for (const doc of docs) rows.push(columns.map((column) => csvCell(doc[column])).join(','))

  return new Response(`\uFEFF${rows.join('\r\n')}\r\n`, {
    headers: {
      'Content-Disposition': `attachment; filename="assets-${new Date().toISOString().slice(0, 10)}.csv"`,
      'Content-Type': 'text/csv; charset=utf-8',
    },
  })
}
