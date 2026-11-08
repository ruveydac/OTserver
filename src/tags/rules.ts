import { validateAssignmentRegex } from '../domain/assignmentRegex'
import { assetTagRuleFieldLabels, vulnerabilityTagRuleFieldLabels } from './fields'

export type TagRuleCondition = {
  field: string
  operator: string
  value?: string
  compareField?: string
}

export type TagRule = { enabled?: boolean; conditions?: TagRuleCondition[] }

export type TagRuleDefinition = {
  id: string | number
  manual?: boolean
  name: string
  rules?: TagRule[]
  systemKey?: string
}

const assetFields = new Set(Object.keys(assetTagRuleFieldLabels))
const vulnerabilityFields = new Set(Object.keys(vulnerabilityTagRuleFieldLabels))

const operators = new Set([
  'contains',
  'equals',
  'exists',
  'greater_than',
  'less_than',
  'older_than_days',
  'regex',
  'version_greater_than_field',
  'version_less_than_field',
])

const safePath = (path: string) =>
  path.length <= 128 &&
  path.split('.').length <= 4 &&
  path.split('.').every((part) => /^[A-Za-z][A-Za-z0-9_]*$/.test(part)) &&
  !path.split('.').some((part) => ['__proto__', 'constructor', 'prototype'].includes(part))

export const validateTagRules = (
  rules: unknown,
  manual: boolean,
  customFieldIDs: ReadonlySet<string> = new Set(),
): string | true => {
  if (manual) return Array.isArray(rules) && rules.length ? 'Manual tags cannot have rules.' : true
  if (rules === undefined || rules === null) return true
  if (!Array.isArray(rules) || rules.length > 64) return 'A tag can contain at most 64 rules.'
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return 'Invalid tag rule.'
    const conditions = (rule as TagRule).conditions
    if (!Array.isArray(conditions) || conditions.length > 32)
      return 'Each rule needs up to 32 conditions.'
    for (const condition of conditions) {
      if (!condition || typeof condition !== 'object') return 'Invalid tag rule condition.'
      const { field, operator, value, compareField } = condition
      if (
        typeof field !== 'string' ||
        !operators.has(operator) ||
        (value !== undefined && (typeof value !== 'string' || value.length > 512))
      )
        return 'Invalid tag rule condition.'
      if (field.startsWith('asset.')) {
        if (!assetFields.has(field.slice(6))) return `Unsupported asset field: ${field}.`
      } else if (field.startsWith('customFields.')) {
        const id = field.slice('customFields.'.length)
        if (!id || !customFieldIDs.has(id)) return `Unknown custom asset field: ${field}.`
      } else if (field.startsWith('connected.')) {
        if (!safePath(field.slice('connected.'.length))) return `Invalid connected field: ${field}.`
      } else if (field.startsWith('vulnerability.')) {
        if (!vulnerabilityFields.has(field.slice('vulnerability.'.length)))
          return `Unsupported vulnerability field: ${field}.`
      } else return `Unsupported tag rule field: ${field}.`

      if (operator === 'regex') {
        const result = validateAssignmentRegex(value)
        if (result !== true) return result
      } else if (operator === 'older_than_days') {
        if (
          field !== 'asset.lastSeen' ||
          !value ||
          !Number.isFinite(Number(value)) ||
          Number(value) < 1
        )
          return 'Older-than rules need a positive day count and the asset.lastSeen field.'
      } else if (operator === 'greater_than' || operator === 'less_than') {
        if (value === undefined || !Number.isFinite(Number(value)))
          return 'Numeric comparisons need a number.'
      } else if (operator.startsWith('version_')) {
        if (
          !compareField ||
          typeof compareField !== 'string' ||
          (!compareField.startsWith('asset.') &&
            !compareField.startsWith('connected.') &&
            !compareField.startsWith('customFields.'))
        )
          return 'Version comparisons need an asset, custom, or connected comparison field.'
        if (compareField.startsWith('connected.') && !safePath(compareField.slice(10)))
          return `Invalid connected field: ${compareField}.`
        if (compareField.startsWith('asset.') && !assetFields.has(compareField.slice(6)))
          return `Unsupported asset field: ${compareField}.`
        if (compareField.startsWith('customFields.')) {
          const id = compareField.slice('customFields.'.length)
          if (!customFieldIDs.has(id)) return `Unknown custom asset field: ${compareField}.`
        }
      } else if (operator !== 'exists' && value === undefined) {
        return 'This tag rule condition needs a value.'
      }
    }
  }
  return true
}

const scalarValues = (value: unknown): Array<string | number | boolean | Date> => {
  if (Array.isArray(value)) return value.flatMap(scalarValues)
  if (value instanceof Date) return [value]
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')
    return [value]
  return []
}

const pathValues = (value: unknown, path: string): Array<string | number | boolean | Date> => {
  let values = [value]
  for (const key of path.split('.')) {
    values = values.flatMap((item) => {
      const entries = Array.isArray(item) ? item : [item]
      return entries.flatMap((entry) =>
        entry && typeof entry === 'object' && !Array.isArray(entry)
          ? [(entry as Record<string, unknown>)[key]]
          : [],
      )
    })
  }
  return values.flatMap(scalarValues)
}

export const compareNumericVersions = (left: unknown, right: unknown): -1 | 0 | 1 | undefined => {
  const parts = (value: unknown) => {
    if (typeof value !== 'string' || !/^v?\d+(?:\.\d+){0,7}$/i.test(value.trim())) return undefined
    return value.trim().replace(/^v/i, '').split('.').map(Number)
  }
  const a = parts(left)
  const b = parts(right)
  if (!a || !b) return undefined
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const delta = (a[index] || 0) - (b[index] || 0)
    if (delta) return delta < 0 ? -1 : 1
  }
  return 0
}

const connectedFirmwareVersions = (products: Array<{ data: Record<string, unknown> }>) => {
  return [
    ...new Set(
      products.flatMap(({ data }) => {
        const releases = Array.isArray(data.releases_json) ? data.releases_json : []
        const releaseVersions = releases.flatMap((release) => {
          if (!release || typeof release !== 'object' || Array.isArray(release)) return []
          const item = release as Record<string, unknown>
          return item.version_kind === 'firmware' &&
            (item.is_latest === true || item.is_recommended === true) &&
            typeof item.version === 'string'
            ? [item.version]
            : []
        })
        if (releaseVersions.length) return releaseVersions
        return data.version_kind === 'firmware' && typeof data.version === 'string'
          ? [data.version]
          : typeof data.firmware_version === 'string'
            ? [data.firmware_version]
            : []
      }),
    ),
  ]
}

const fieldValues = (
  field: string,
  asset: Record<string, unknown>,
  connected: Array<{ data: Record<string, unknown> }>,
  vulnerabilities: Record<string, unknown>[],
): Array<string | number | boolean | Date> => {
  if (field.startsWith('asset.')) return pathValues(asset, field.slice(6))
  if (field.startsWith('customFields.'))
    return pathValues(asset.customFields, field.slice('customFields.'.length))
  if (field === 'connected.firmwareVersion') return connectedFirmwareVersions(connected)
  if (field.startsWith('connected.'))
    return connected.flatMap(({ data }) => pathValues(data, field.slice(10)))
  if (field.startsWith('vulnerability.'))
    return vulnerabilities.flatMap((item) => pathValues(item, field.slice(14)))
  return []
}

const matchesCondition = (
  condition: TagRuleCondition,
  asset: Record<string, unknown>,
  connected: Array<{ data: Record<string, unknown> }>,
  vulnerabilities: Record<string, unknown>[],
  now: number,
) => {
  const values = fieldValues(condition.field, asset, connected, vulnerabilities)
  const target = condition.value ?? ''
  switch (condition.operator) {
    case 'exists':
      return values.some((value) => value !== '')
    case 'regex': {
      const regex = new RegExp(target, 'i')
      return values.some(
        (value) =>
          (typeof value === 'string' || typeof value === 'number') &&
          regex.test(String(value).slice(0, 512)),
      )
    }
    case 'contains':
      return values.some(
        (value) => typeof value === 'string' && value.toLowerCase().includes(target.toLowerCase()),
      )
    case 'equals':
      return values.some((value) => String(value).toLowerCase() === target.toLowerCase())
    case 'greater_than':
      return values.some((value) => Number(value) > Number(target))
    case 'less_than':
      return values.some((value) => Number(value) < Number(target))
    case 'older_than_days':
      return values.some((value) => {
        const timestamp = value instanceof Date ? value.getTime() : Date.parse(String(value))
        return Number.isFinite(timestamp) && timestamp < now - Number(target) * 86_400_000
      })
    case 'version_less_than_field':
    case 'version_greater_than_field': {
      const compare = condition.compareField
        ? fieldValues(condition.compareField, asset, connected, vulnerabilities)
        : []
      const left = [...new Set(values.map(String))]
      const right = [...new Set(compare.map(String))]
      if (left.length !== 1 || right.length !== 1) return false
      const order = compareNumericVersions(left[0], right[0])
      return (
        order !== undefined &&
        (condition.operator === 'version_less_than_field' ? order < 0 : order > 0)
      )
    }
    default:
      return false
  }
}

export const matchesTagRules = (
  rules: TagRule[] | undefined,
  asset: Record<string, unknown>,
  connected: Array<{ data: Record<string, unknown> }>,
  vulnerabilities: Record<string, unknown>[],
  now = Date.now(),
) =>
  Boolean(
    rules?.some(
      (rule) =>
        rule.enabled !== false &&
        Boolean(rule.conditions?.length) &&
        rule.conditions!.every((condition) =>
          matchesCondition(condition, asset, connected, vulnerabilities, now),
        ),
    ),
  )

export const tagRuleUsesVulnerabilities = (rules: TagRule[] | undefined) =>
  Boolean(
    rules?.some((rule) => rule.conditions?.some(({ field }) => field.startsWith('vulnerability.'))),
  )
