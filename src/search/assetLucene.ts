import lucene from 'lucene-query-parser'
import { APIError, type CollectionBeforeOperationHook, type Where } from 'payload'

type LuceneNode = {
  boost?: null | number
  field?: string
  inclusive_max?: boolean
  inclusive_min?: boolean
  left?: LuceneNode
  operator?: '<implicit>' | 'AND' | 'NOT' | 'OR'
  prefix?: null | '+' | '-'
  proximity?: null | number
  regexpr?: boolean
  right?: LuceneNode
  similarity?: null | number
  term?: string
  term_max?: string
  term_min?: string
}

type FieldKind = 'date' | 'keyword' | 'number' | 'text'

const fields: Record<string, { kind: FieldKind; path: string }> = {
  assetowner: { kind: 'text', path: 'assetOwner' },
  assetclass: { kind: 'text', path: 'assetClass.name' },
  assetclassid: { kind: 'keyword', path: 'assetClass' },
  class: { kind: 'text', path: 'assetClass.name' },
  classid: { kind: 'keyword', path: 'assetClass' },
  criticality: { kind: 'keyword', path: 'criticality' },
  createdat: { kind: 'date', path: 'createdAt' },
  description: { kind: 'text', path: 'description' },
  firmware: { kind: 'text', path: 'firmwareVersion' },
  firmwareversion: { kind: 'text', path: 'firmwareVersion' },
  gateway: { kind: 'text', path: 'gatewayAddress' },
  gatewayaddress: { kind: 'text', path: 'gatewayAddress' },
  importsource: { kind: 'text', path: 'importSource' },
  id: { kind: 'keyword', path: 'id' },
  ip: { kind: 'keyword', path: 'ipAddress' },
  ipaddress: { kind: 'keyword', path: 'ipAddress' },
  lastimportedat: { kind: 'date', path: 'lastImportedAt' },
  lastseen: { kind: 'date', path: 'lastSeen' },
  location: { kind: 'text', path: 'location' },
  mac: { kind: 'keyword', path: 'macAddress' },
  macaddress: { kind: 'keyword', path: 'macAddress' },
  model: { kind: 'text', path: 'model' },
  name: { kind: 'text', path: 'name' },
  networkmask: { kind: 'text', path: 'networkMask' },
  notes: { kind: 'text', path: 'notes' },
  operatingsystem: { kind: 'text', path: 'operatingSystem' },
  os: { kind: 'text', path: 'operatingSystem' },
  osaccuracy: { kind: 'number', path: 'osAccuracy' },
  owner: { kind: 'text', path: 'assetOwner' },
  protocol: { kind: 'keyword', path: 'protocols' },
  protocols: { kind: 'keyword', path: 'protocols' },
  serialnumber: { kind: 'text', path: 'serialNumber' },
  site: { kind: 'text', path: 'site.name' },
  siteid: { kind: 'keyword', path: 'site' },
  sourceversion: { kind: 'text', path: 'sourceVersion' },
  status: { kind: 'keyword', path: 'status' },
  type: { kind: 'text', path: 'assetClass.name' },
  updatedat: { kind: 'date', path: 'updatedAt' },
  vendor: { kind: 'text', path: 'vendor' },
}

const implicitFields = [
  'name',
  'description',
  'ipAddress',
  'macAddress',
  'vendor',
  'model',
  'operatingSystem',
  'serialNumber',
  'location',
  'assetOwner',
]

const fail = (message: string): never => {
  throw new APIError(`Invalid asset search: ${message}`, 400)
}

const fieldFor = (name: string) => fields[name.toLowerCase()] ?? fail(`unknown field "${name}".`)

const normalizeKeyword = (path: string, value: string) => {
  if (path === 'macAddress') return value.replaceAll('-', ':').toUpperCase()
  if (['criticality', 'protocols', 'status'].includes(path)) return value.toLowerCase()
  return value
}

const unescape = (value: string) => value.replaceAll(/\\(.)/g, '$1')

const leaf = (node: LuceneNode, inheritedField?: string): Where => {
  const fieldName = node.field === '<implicit>' ? inheritedField : node.field || inheritedField

  if (!fieldName) {
    if (node.term === '*') return {}
    const term = node.term?.replaceAll(/[?*]/g, '')
    if (!term) return fail('enter a search term.')
    return { or: implicitFields.map((path) => ({ [path]: { like: term } })) }
  }

  const field = fieldFor(fieldName)
  if (node.regexpr) return fail('regular expressions are not supported.')
  if (node.similarity != null || node.boost != null)
    return fail('fuzzy search and boosts are not supported.')

  if (node.term_min !== undefined || node.term_max !== undefined) {
    if (field.kind !== 'date' && field.kind !== 'number') {
      return fail(`ranges are not supported for ${fieldName}.`)
    }

    const convert = (value: string) => {
      if (field.kind === 'number') {
        const number = Number(unescape(value))
        if (!Number.isFinite(number)) return fail(`${value} is not a valid number.`)
        return number
      }
      const date = new Date(unescape(value))
      if (Number.isNaN(date.getTime())) return fail(`${value} is not a valid date.`)
      return date.toISOString()
    }

    const operators: Record<string, unknown> = {}
    if (node.term_min && node.term_min !== '*') {
      operators[node.inclusive_min ? 'greater_than_equal' : 'greater_than'] = convert(node.term_min)
    }
    if (node.term_max && node.term_max !== '*') {
      operators[node.inclusive_max ? 'less_than_equal' : 'less_than'] = convert(node.term_max)
    }
    if (!Object.keys(operators).length) return {}
    return { [field.path]: operators }
  }

  const rawTerm = node.term?.trim()
  if (!rawTerm) return fail('enter a search term.')
  if (rawTerm === '*') {
    const where: Where = { [field.path]: { exists: true } }
    return node.prefix === '-' ? negate(where) : where
  }

  const wildcard = /[?*]/.test(rawTerm)
  const term = unescape(rawTerm.replaceAll(/[?*]/g, ''))
  if (!term) return { [field.path]: { exists: true } }
  const operator =
    !wildcard && (field.kind !== 'text' || node.proximity !== undefined) ? 'equals' : 'like'
  const where: Where = {
    [field.path]: { [operator]: normalizeKeyword(field.path, term) },
  }
  return node.prefix === '-' ? negate(where) : where
}

const negate = (where: Where): Where => {
  if (where.and) return { or: where.and.map(negate) }
  if (where.or) return { and: where.or.map(negate) }

  const [path, condition] = Object.entries(where)[0] ?? []
  if (!path || !condition || Array.isArray(condition))
    return fail('this negation is not supported.')

  const inverse: Record<string, string> = {
    equals: 'not_equals',
    exists: 'exists',
    greater_than: 'less_than_equal',
    greater_than_equal: 'less_than',
    less_than: 'greater_than_equal',
    less_than_equal: 'greater_than',
    like: 'not_like',
    not_equals: 'equals',
    not_like: 'like',
  }
  const entries = Object.entries(condition)
  const negated = entries.map(([operator, value]) => ({
    [path]: {
      [inverse[operator] ?? fail(`cannot negate ${operator}.`)]:
        operator === 'exists' ? !value : value,
    },
  }))
  return negated.length === 1 ? negated[0] : { or: negated }
}

const translate = (node: LuceneNode, inheritedField?: string, depth = 0): Where => {
  if (depth > 20) return fail('query is too deeply nested.')
  const field = node.field && node.field !== '<implicit>' ? node.field : inheritedField

  if (node.left) {
    const left = translate(node.left, field, depth + 1)
    if (!node.right) return node.prefix === '-' ? negate(left) : left
    const right = translate(node.right, field, depth + 1)
    if (node.operator === 'AND') return { and: [left, right] }
    if (node.operator === 'NOT') return { and: [left, negate(right)] }
    return { or: [left, right] }
  }

  return leaf(node, field)
}

export const parseAssetSearch = (query: string): Where => {
  const trimmed = query.trim()
  if (!trimmed) return {}
  if (trimmed.length > 500) return fail('query is longer than 500 characters.')

  try {
    return translate(lucene.parse(trimmed) as LuceneNode)
  } catch (error) {
    if (error instanceof APIError) throw error
    return fail(error instanceof Error ? error.message : 'invalid syntax.')
  }
}

export const applyAssetSearch: CollectionBeforeOperationHook = ({ args, operation, req }) => {
  const search = req.query.search
  if (operation !== 'read' || typeof search !== 'string' || !('where' in args)) return args

  const parsed = parseAssetSearch(search)
  const graphicalWhere = req.query.where
  const serializedWhere = JSON.stringify(args.where)
  const graphicalOnly =
    graphicalWhere &&
    (serializedWhere === JSON.stringify(graphicalWhere) ||
      serializedWhere === JSON.stringify({ and: [graphicalWhere] }))
  args.where =
    !graphicalOnly && args.where && Object.keys(args.where).length
      ? { and: [args.where, parsed] }
      : parsed
  return args
}
