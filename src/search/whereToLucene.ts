import type { Where } from 'payload'

const fieldNames: Record<string, string> = {
  assetOwner: 'owner',
  assetClass: 'classid',
  gatewayAddress: 'gateway',
  ipAddress: 'ip',
  macAddress: 'mac',
  operatingSystem: 'os',
  site: 'siteid',
}

const fieldName = (path: string) => fieldNames[path] ?? path
const quote = (value: unknown) =>
  `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
const term = (value: unknown) => String(value).replaceAll(/([+\-!(){}[\]^"~*?:\\/\s])/g, '\\$1')
const values = (value: unknown) =>
  (Array.isArray(value) ? value : String(value).split(','))
    .map((item) => (typeof item === 'object' && item && 'value' in item ? item.value : item))
    .filter((item) => item !== '' && item != null)

const condition = (path: string, operator: string, value: unknown): string => {
  if (value == null || value === '') return ''
  const field = fieldName(path)

  if (operator === 'exists') {
    const exists = value === true || value === 'true'
    return `${field}:${exists ? '' : '-'}*`
  }
  if (operator === 'greater_than') return `${field}:{${term(value)} TO *}`
  if (operator === 'greater_than_equal') return `${field}:[${term(value)} TO *]`
  if (operator === 'less_than') return `${field}:{* TO ${term(value)}}`
  if (operator === 'less_than_equal') return `${field}:[* TO ${term(value)}]`

  if (['in', 'not_in', 'all'].includes(operator)) {
    const parts = values(value).map(
      (item) => `${field}:${operator === 'not_in' ? '-' : ''}${quote(item)}`,
    )
    const join = operator === 'in' ? ' OR ' : ' AND '
    return parts.length > 1 ? `(${parts.join(join)})` : (parts[0] ?? '')
  }

  const negative = ['not_equals', 'not_like'].includes(operator) ? '-' : ''
  const wildcard = ['contains', 'like', 'not_like'].includes(operator)
  return `${field}:${negative}${wildcard ? `*${term(value)}*` : quote(value)}`
}

export const whereToLucene = (where?: Where): string => {
  if (!where) return ''
  if (where.and) {
    const parts = where.and.map(whereToLucene).filter(Boolean)
    return parts.length > 1 ? `(${parts.join(' AND ')})` : (parts[0] ?? '')
  }
  if (where.or) {
    const parts = where.or.map(whereToLucene).filter(Boolean)
    return parts.length > 1 ? `(${parts.join(' OR ')})` : (parts[0] ?? '')
  }

  const parts = Object.entries(where)
    .flatMap(([path, operators]) =>
      Array.isArray(operators)
        ? []
        : Object.entries(operators).map(([operator, value]) => condition(path, operator, value)),
    )
    .filter(Boolean)
  return parts.length > 1 ? `(${parts.join(' AND ')})` : (parts[0] ?? '')
}
