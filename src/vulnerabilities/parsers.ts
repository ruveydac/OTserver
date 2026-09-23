import {
  type AffectedProduct,
  array,
  normalizeKey,
  productSearchKey,
  record,
  searchTokens,
  text,
} from './matching'

const MAX_AFFECTED = 200
export const MAX_DESCRIPTION = 4000
const MAX_REFERENCES = 25
const MAX_CSAF_PROVIDERS = 100
const MAX_ICS_VALUES = 25
const ICS_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
const CVE_PATTERN = /^CVE-\d{4}-\d{4,19}$/
const VERSION_BOUNDS = [
  'versionEndExcluding',
  'versionEndIncluding',
  'versionStartExcluding',
  'versionStartIncluding',
] as const

export type FeedDocument = {
  cve: string
  set: Record<string, unknown>
  setOnInsert?: Record<string, unknown>
}

export const parseNvdMeta = (
  meta: string,
): { lastModifiedDate?: string; sha256?: string; size?: number } => {
  const values: Record<string, string> = {}
  for (const line of meta.split(/\r?\n/)) {
    const separator = line.indexOf(':')
    if (separator < 0) continue
    values[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim()
  }
  const sha256 = values.sha256?.toLowerCase()
  return {
    ...(values.lastmodifieddate ? { lastModifiedDate: values.lastmodifieddate } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(Number(values.size) > 0 ? { size: Number(values.size) } : {}),
  }
}

export const parseCpe = (
  criteria: unknown,
): { part: string; product: string; vendor: string; version: string } | undefined => {
  const value = text(criteria)
  if (!value.startsWith('cpe:2.3:')) return undefined

  const parts = value.split(/(?<!\\):/).map((part) => part.replaceAll('\\:', ':'))
  const [part, vendor, product, version] = parts.slice(2, 6)
  if (!vendor || vendor === '*' || !product || product === '*') return undefined
  return { part: part || 'a', product, vendor, version: version || '*' }
}

export const affectedProducts = (configurations: unknown): AffectedProduct[] => {
  const entries: AffectedProduct[] = []
  const seen = new Set<string>()

  for (const configuration of array(configurations)) {
    for (const node of array(record(configuration).nodes)) {
      const nodeRecord = record(node)
      if (nodeRecord.negate === true) continue
      for (const candidate of array(nodeRecord.cpeMatch)) {
        const item = record(candidate)
        if (item.vulnerable !== true) continue
        const cpe = parseCpe(item.criteria)
        if (!cpe) continue

        const entry: AffectedProduct = { ...cpe, cpe: text(item.criteria) }
        for (const bound of VERSION_BOUNDS) {
          const value = text(item[bound])
          if (value) entry[bound] = value
        }

        const key = JSON.stringify(entry)
        if (seen.has(key)) continue
        seen.add(key)
        entries.push(entry)
        if (entries.length >= MAX_AFFECTED) return entries
      }
    }
  }

  return entries
}

/** Indexed lookup terms: an asset is matched through product tokens, never through vendor alone. */
export const searchKeys = (affected: AffectedProduct[]) => {
  const products = new Set<string>()
  const productTokens = new Set<string>()
  const vendors = new Set<string>()

  for (const entry of affected) {
    const vendorKey = normalizeKey(entry.vendor)
    if (vendorKey) vendors.add(vendorKey)
    for (const token of searchTokens(entry.vendor)) vendors.add(token)

    const productKey = productSearchKey(entry.product)
    if (productKey) products.add(productKey)
    for (const token of searchTokens(entry.product.replaceAll('_', ' '))) productTokens.add(token)
  }

  return { products: [...products], productTokens: [...productTokens], vendors: [...vendors] }
}

const dateValue = (value: unknown): Date | undefined => {
  const candidate = text(value)
  if (!candidate) return undefined
  const date = new Date(candidate)
  return Number.isNaN(date.getTime()) ? undefined : date
}

const cvss = (metrics: unknown) => {
  const values = record(metrics)
  for (const key of ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']) {
    const metric = record(array(values[key])[0])
    const data = record(metric.cvssData)
    const score = Number(data.baseScore)
    if (!Number.isFinite(score)) continue
    const severity = text(data.baseSeverity || metric.baseSeverity).toUpperCase()
    return { cvssScore: score, ...(severity ? { cvssSeverity: severity } : {}) }
  }
  return {}
}

export const parseNvdFeed = (feed: unknown): FeedDocument[] => {
  const vulnerabilities = record(feed).vulnerabilities
  if (!Array.isArray(vulnerabilities)) {
    throw new Error('The NVD feed does not contain a vulnerabilities array.')
  }
  const documents: FeedDocument[] = []

  for (const item of vulnerabilities) {
    const cve = record(record(item).cve)
    const id = text(cve.id)
    if (!CVE_PATTERN.test(id)) continue

    const descriptions = array(cve.descriptions).map(record)
    const description =
      descriptions.find((entry) => text(entry.lang).startsWith('en'))?.value ??
      descriptions[0]?.value
    const affected = affectedProducts(cve.configurations)

    documents.push({
      cve: id,
      set: {
        affected,
        ...cvss(cve.metrics),
        description: text(description).slice(0, MAX_DESCRIPTION),
        modified: dateValue(cve.lastModified),
        ...searchKeys(affected),
        published: dateValue(cve.published),
        references: array(cve.references)
          .map((reference) => text(record(reference).url))
          .filter(Boolean)
          .slice(0, MAX_REFERENCES),
        status: text(cve.vulnStatus),
        updatedAt: new Date(),
      },
    })
  }

  return documents
}

export const parseCisaCatalog = (
  catalog: unknown,
): { catalogVersion?: string; dateReleased?: Date; documents: FeedDocument[] } => {
  const source = record(catalog)
  const catalogVersion = text(source.catalogVersion)
  const dateReleased = dateValue(source.dateReleased)
  const vulnerabilities = source.vulnerabilities
  if (
    !catalogVersion ||
    !dateReleased ||
    !Number.isInteger(source.count) ||
    !Array.isArray(vulnerabilities)
  ) {
    throw new Error('The CISA KEV feed does not match the expected catalog schema.')
  }
  const documents: FeedDocument[] = []

  for (const item of vulnerabilities) {
    const entry = record(item)
    const id = text(entry.cveID)
    const product = text(entry.product)
    const vendor = text(entry.vendorProject)
    const dateAdded = dateValue(entry.dateAdded)
    const dueDate = dateValue(entry.dueDate)
    if (
      !CVE_PATTERN.test(id) ||
      !vendor ||
      !product ||
      !text(entry.vulnerabilityName) ||
      !dateAdded ||
      !text(entry.shortDescription) ||
      !text(entry.requiredAction) ||
      !dueDate
    ) {
      throw new Error(`The CISA KEV feed contains an invalid entry${id ? ` (${id})` : ''}.`)
    }
    documents.push({
      cve: id,
      set: {
        knownExploited: true,
        kevDateAdded: dateAdded,
        kevDueDate: dueDate,
        kevName: text(entry.vulnerabilityName),
        kevProduct: product,
        kevRequiredAction: text(entry.requiredAction),
        kevRansomwareUse: text(entry.knownRansomwareCampaignUse),
        kevVendor: vendor,
        updatedAt: new Date(),
      },
      // Only KEV-only records need these; NVD supplies richer CPE data when it exists.
      ...(vendor && product
        ? {
            setOnInsert: {
              createdAt: new Date(),
              description: text(entry.shortDescription).slice(0, MAX_DESCRIPTION),
              ...searchKeys([{ part: 'a', product, vendor, version: '*' }]),
            },
          }
        : {}),
    })
  }

  if (documents.length !== source.count) {
    throw new Error('The CISA KEV feed count does not match its vulnerability entries.')
  }

  return {
    catalogVersion,
    dateReleased,
    documents,
  }
}

const trustedCsafURL = (value: unknown): string | undefined => {
  const candidate = text(value)
  try {
    const url = new URL(candidate)
    if (
      url.protocol === 'https:' &&
      ['aggregator.certvde.com', 'raw.githubusercontent.com'].includes(url.hostname)
    )
      return url.href
  } catch {}
  return undefined
}

export const parseCsafAggregator = (input: unknown): string[] => {
  const source = record(input)
  if (text(source.aggregator_version) !== '2.0') {
    throw new Error('The CSAF aggregator does not match version 2.0.')
  }
  const providers = [...array(source.csaf_providers), ...array(source.csaf_publishers)]
  if (providers.length > MAX_CSAF_PROVIDERS)
    throw new Error('The CSAF provider limit was exceeded.')
  return [
    ...new Set(
      providers
        .flatMap((provider) => array(record(provider).mirrors))
        .map(trustedCsafURL)
        .filter((url): url is string => Boolean(url)),
    ),
  ]
}

export const parseCsafProviderMetadata = (input: unknown): string[] => {
  const source = record(input)
  if (text(source.metadata_version) !== '2.0' || !Array.isArray(source.distributions)) {
    throw new Error('The CSAF provider metadata does not match version 2.0.')
  }
  return [
    ...new Set(
      array(source.distributions)
        .flatMap((distribution) => array(record(record(distribution).rolie).feeds))
        .map((feed) => trustedCsafURL(record(feed).url))
        .filter((url): url is string => Boolean(url)),
    ),
  ]
}

export const parseRolieFeed = (
  input: unknown,
): { entries: { updated: string; url: string }[]; updated: string } => {
  const feed = record(record(input).feed)
  const updated = text(feed.updated)
  if (!updated || !dateValue(updated) || !Array.isArray(feed.entry)) {
    throw new Error('The CSAF ROLIE feed does not match the expected schema.')
  }
  const entries = array(feed.entry)
    .map(record)
    .map((entry) => ({
      updated: text(entry.updated),
      url: trustedCsafURL(record(entry.content).src),
    }))
    .filter((entry): entry is { updated: string; url: string } =>
      Boolean(entry.url && entry.updated && dateValue(entry.updated)),
    )
  if (entries.length !== feed.entry.length) {
    throw new Error('The CSAF ROLIE feed contains an invalid entry.')
  }
  return { entries, updated }
}

const versionRange = (value: string): Partial<AffectedProduct> => {
  const match = value.trim().match(/^(<=|>=|<|>)?\s*v?([0-9][a-z0-9._-]*)$/i)
  if (!match) return { version: value || '*' }
  const [, operator, version] = match
  if (operator === '<') return { version: '*', versionEndExcluding: version }
  if (operator === '<=') return { version: '*', versionEndIncluding: version }
  if (operator === '>') return { version: '*', versionStartExcluding: version }
  if (operator === '>=') return { version: '*', versionStartIncluding: version }
  return { version }
}

const csafProducts = (tree: unknown): Map<string, AffectedProduct> => {
  const products = new Map<string, AffectedProduct>()
  const walk = (
    branches: unknown,
    context: { product?: string; range?: string; vendor?: string } = {},
  ) => {
    for (const value of array(branches)) {
      const branch = record(value)
      const category = text(branch.category)
      const name = text(branch.name)
      const next = { ...context }
      if (category === 'vendor') next.vendor = name
      if (category === 'product_name') next.product = name
      if (category === 'product_version' || category === 'product_version_range') next.range = name

      const product = record(branch.product)
      const id = text(product.product_id)
      if (id) {
        const cpe = parseCpe(record(product.product_identification_helper).cpe)
        if (cpe) products.set(id, { ...cpe, ...(next.range ? versionRange(next.range) : {}) })
        else if (next.vendor && next.product) {
          products.set(id, {
            part: 'a',
            product: next.product,
            vendor: next.vendor,
            ...versionRange(next.range || '*'),
          } as AffectedProduct)
        }
      }
      walk(branch.branches, next)
    }
  }
  const source = record(tree)
  walk(source.branches)
  for (const value of array(source.full_product_names)) {
    const product = record(value)
    const cpe = parseCpe(record(product.product_identification_helper).cpe)
    const id = text(product.product_id)
    if (id && cpe) products.set(id, cpe)
  }
  return products
}

export const parseCsafDocument = (input: unknown): FeedDocument[] => {
  const source = record(input)
  const document = record(source.document)
  if (text(document.csaf_version) !== '2.0' || !Array.isArray(source.vulnerabilities)) {
    throw new Error('The CSAF document does not match version 2.0.')
  }
  const products = csafProducts(source.product_tree)
  const tracking = record(document.tracking)
  const documentReferences = array(document.references)
  const documents: FeedDocument[] = []

  for (const value of source.vulnerabilities) {
    const vulnerability = record(value)
    const cve = text(vulnerability.cve)
    if (!CVE_PATTERN.test(cve)) continue
    const affected = array(record(vulnerability.product_status).known_affected)
      .map((id) => products.get(text(id)))
      .filter((entry): entry is AffectedProduct => Boolean(entry))
      .slice(0, MAX_AFFECTED)
    const notes = array(vulnerability.notes).map(record)
    const description = text(
      notes.find((note) => ['summary', 'description'].includes(text(note.category)))?.text ??
        notes[0]?.text,
    )
    const score = record(array(vulnerability.scores)[0])
    const metric = record(score.cvss_v4 || score.cvss_v3 || score.cvss_v2)
    const cvssScore = Number(metric.baseScore)
    const references = [...documentReferences, ...array(vulnerability.references)]
      .map((reference) => text(record(reference).url))
      .filter(Boolean)
      .slice(0, MAX_REFERENCES)

    documents.push({
      cve,
      set: {
        affected,
        ...(Number.isFinite(cvssScore) ? { cvssScore } : {}),
        ...(text(metric.baseSeverity)
          ? { cvssSeverity: text(metric.baseSeverity).toUpperCase() }
          : {}),
        description: description.slice(0, MAX_DESCRIPTION),
        modified: dateValue(tracking.current_release_date),
        published: dateValue(tracking.initial_release_date),
        references,
        ...searchKeys(affected),
        status: 'CSAF',
        updatedAt: new Date(),
      },
    })
  }
  return documents
}

export const mergeCsafDocuments = (documents: FeedDocument[]): FeedDocument[] => {
  const merged = new Map<string, FeedDocument>()
  for (const document of documents) {
    const existing = merged.get(document.cve)
    if (!existing) {
      merged.set(document.cve, document)
      continue
    }
    const affected = [
      ...new Map(
        [...array(existing.set.affected), ...array(document.set.affected)].map((entry) => [
          JSON.stringify(entry),
          entry,
        ]),
      ).values(),
    ].slice(0, MAX_AFFECTED) as AffectedProduct[]
    existing.set = { ...existing.set, ...document.set, affected, ...searchKeys(affected) }
  }
  return [...merged.values()]
}

export const parseCsv = (input: string): string[][] => {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let quoted = false

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index] as string
    if (quoted) {
      if (character !== '"') field += character
      else if (input[index + 1] === '"') {
        field += '"'
        index += 1
      } else quoted = false
      continue
    }
    if (character === '"') quoted = true
    else if (character === ',') {
      row.push(field)
      field = ''
    } else if (character === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else if (character !== '\r') field += character
  }
  if (field || row.length) {
    row.push(field)
    rows.push(row)
  }
  return rows
}

/** The ICS Advisory Project publishes US-style month/day/year dates. */
const icsDate = (value: string): Date | undefined => {
  const match = value.trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/)
  if (!match) return undefined
  return new Date(Date.UTC(Number(match[3]), Number(match[1]) - 1, Number(match[2])))
}

type IcsEntry = {
  advisories: Set<string>
  distribution: string
  headquarters: string
  modified?: Date
  product: string
  published?: Date
  score?: number
  sectors: Set<string>
  severity?: string
  title: string
  vendor: string
}

/**
 * Reads the ICS Advisory Project master CSV, which flattens CISA ICS advisories into one row per
 * advisory. A CVE can appear in several advisories, so rows are merged per CVE. `Cumulative_CVSS`
 * describes the whole advisory rather than one CVE, so it is kept only as a fallback score for
 * records no authoritative source has scored yet.
 */
export const parseIcsAdvisories = (
  csv: string,
): { dateReleased?: Date; documents: FeedDocument[] } => {
  const rows = parseCsv(csv)
  const header = rows[0] ?? []
  const column = (name: string): number => header.indexOf(name)
  const required = [
    'CVE_Number',
    'Critical_Infrastructure_Sector',
    'Cumulative_CVSS',
    'CVSS_Severity',
    'ICS-CERT_Advisory_Title',
    'ICS-CERT_Number',
    'Last_Updated',
    'Original_Release_Date',
    'Product',
    'Product_Distribution',
    'Company_Headquarters',
    'Vendor',
  ]
  const missing = required.filter((name) => column(name) < 0)
  if (missing.length) {
    throw new Error(`The ICS Advisory Project file is missing columns: ${missing.join(', ')}.`)
  }

  const entries = new Map<string, IcsEntry>()
  let dateReleased: Date | undefined
  for (const row of rows.slice(1)) {
    if (row.length !== header.length) continue
    const advisory = text(row[column('ICS-CERT_Number')])
    const product = text(row[column('Product')])
    const vendor = text(row[column('Vendor')])
    const released = icsDate(row[column('Original_Release_Date')] ?? '')
    const updated = icsDate(row[column('Last_Updated')] ?? '')
    if (!advisory || !product || !vendor) continue
    if (updated && (!dateReleased || updated > dateReleased)) dateReleased = updated

    const score = Number(row[column('Cumulative_CVSS')])
    const level = text(row[column('CVSS_Severity')]).toUpperCase()
    for (const cve of (row[column('CVE_Number')] ?? '').split(/[\s,]+/)) {
      if (!CVE_PATTERN.test(cve)) continue
      const entry: IcsEntry = entries.get(cve) ?? {
        advisories: new Set(),
        distribution: '',
        headquarters: '',
        product,
        sectors: new Set(),
        title: text(row[column('ICS-CERT_Advisory_Title')]),
        vendor,
      }
      entry.advisories.add(advisory)
      entry.distribution ||= text(row[column('Product_Distribution')])
      entry.headquarters ||= text(row[column('Company_Headquarters')])
      for (const sector of (row[column('Critical_Infrastructure_Sector')] ?? '').split(';'))
        if (text(sector)) entry.sectors.add(text(sector))
      if (released && (!entry.published || released < entry.published)) entry.published = released
      if (updated && (!entry.modified || updated > entry.modified)) entry.modified = updated
      if (Number.isFinite(score) && score >= 0 && score <= 10 && score > (entry.score ?? -1)) {
        entry.score = score
        entry.severity = ICS_SEVERITIES.has(level) ? level : undefined
      }
      entries.set(cve, entry)
    }
  }

  const documents = [...entries].map(([cve, entry]): FeedDocument => {
    const advisories = [...entry.advisories].slice(0, MAX_ICS_VALUES)
    const set: Record<string, unknown> = {
      icsAdvisory: advisories,
      icsSectors: [...entry.sectors].slice(0, MAX_ICS_VALUES),
      updatedAt: new Date(),
    }
    if (entry.distribution) set.icsDistribution = entry.distribution
    if (entry.headquarters) set.icsHeadquarters = entry.headquarters

    return {
      cve,
      // Only the advisory context is authoritative here; NVD and CSAF keep their own fields.
      set,
      setOnInsert: {
        createdAt: new Date(),
        ...(entry.score === undefined ? {} : { cvssScore: entry.score }),
        ...(entry.severity ? { cvssSeverity: entry.severity } : {}),
        description: `CISA ICS advisory ${advisories[0]}: ${entry.title}`.slice(0, MAX_DESCRIPTION),
        ...(entry.modified ? { modified: entry.modified } : {}),
        ...(entry.published ? { published: entry.published } : {}),
        references: advisories
          .map((id) => `https://www.cisa.gov/news-events/ics-advisories/${id.toLowerCase()}`)
          .slice(0, MAX_REFERENCES),
        ...searchKeys([{ part: 'a', product: entry.product, vendor: entry.vendor, version: '*' }]),
      },
    }
  })

  return { dateReleased, documents }
}
