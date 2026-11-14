import assert from 'node:assert/strict'
import groupSchema from '../data/device-metadata/schema/ot-device-types.schema.json'
import { validateAssignmentRegex } from '../domain/assignmentRegex'

type Condition = { field: string; operator: string; value: string; caseSensitive?: boolean }
type Rule = Condition | { all: Rule[] } | { any: Rule[] }
export type CatalogProduct = {
  id: string
  manufacturer_id: string
  device_type_id: string
  data: Record<string, unknown>
  rules: Rule
}
type Manufacturer = {
  id: string
  data: Record<string, unknown> & {
    name: string
    aliases?: string[]
    website?: string
    description?: string
  }
  rules: Rule
}
export type Catalog = {
  manufacturers: Manufacturer[]
  devices: CatalogProduct[]
  groups: { id: string; key: string; name: string; description: string }[]
}
export type MatchEvidence = Condition & { actual: string }
export type MetadataMatch = {
  catalogRevision: string
  status: 'matched' | 'unmatched' | 'ambiguous'
  manufacturerIDs: string[]
  manufacturerEvidence: MatchEvidence[]
  groupIDs: string[]
  products: {
    id: string
    manufacturerID: string
    groupID: string
    evidence: MatchEvidence[]
  }[]
}

export const metadataGroups = groupSchema.$defs.deviceType.oneOf.map((item) => item.const)
export const emptyCatalog: Catalog = { manufacturers: [], devices: [], groups: metadataGroups }
export const metadataLicense = {
  attribution: 'OTserver Asset Metadata, https://otserver.org',
  license: 'CC-BY-NC-4.0',
  licenseURL: 'https://creativecommons.org/licenses/by-nc/4.0/',
}
const fields = new Set([
  'manufacturer',
  'vendor',
  'product',
  'product_family',
  'model',
  'model_name',
  'device_name',
  'part_number',
  'order_number',
  'hardware_revision',
  'device_type',
  'serial_number',
  'firmware_version',
  'software_version',
  'version',
  'version_component',
  'version_kind',
  'protocol',
])

const compile = (
  rule: Rule,
  depth = 0,
): ((record: Record<string, unknown>) => MatchEvidence[] | undefined) => {
  assert(depth <= 16, 'Catalog rule nesting exceeds 16 levels')
  if ('all' in rule || 'any' in rule) {
    const nodes = 'all' in rule ? rule.all : rule.any
    assert(nodes.length > 0 && nodes.length <= 128, 'Invalid catalog rule group')
    const children = nodes.map((child) => compile(child, depth + 1))
    return (record) => {
      const matched = children.map((match) => match(record))
      return 'all' in rule
        ? matched.every((item) => item !== undefined)
          ? matched.flatMap((item) => item!)
          : undefined
        : matched.some((item) => item !== undefined)
          ? matched.flatMap((item) => item ?? [])
          : undefined
    }
  }
  assert(
    fields.has(rule.field) && typeof rule.value === 'string' && rule.value.length <= 512,
    'Invalid catalog condition',
  )
  assert(
    ['equals', 'contains', 'starts_with', 'ends_with', 'regex'].includes(rule.operator),
    'Invalid catalog operator',
  )
  const regex =
    rule.operator === 'regex'
      ? (() => {
          assert.equal(
            validateAssignmentRegex(rule.value),
            true,
            'Unsafe catalog regular expression',
          )
          return new RegExp(rule.value, rule.caseSensitive ? '' : 'i')
        })()
      : undefined
  const expected = rule.caseSensitive ? rule.value : rule.value.toLowerCase()
  return (record) => {
    const values = Array.isArray(record[rule.field])
      ? (record[rule.field] as unknown[])
      : [record[rule.field]]
    for (const value of values) {
      if (typeof value !== 'string' || value.length > 512) continue
      const actual = rule.caseSensitive ? value : value.toLowerCase()
      const matched = regex
        ? regex.test(value)
        : rule.operator === 'equals'
          ? actual === expected
          : rule.operator === 'contains'
            ? actual.includes(expected)
            : rule.operator === 'starts_with'
              ? actual.startsWith(expected)
              : actual.endsWith(expected)
      if (matched) return [{ ...rule, actual: value }]
    }
    return undefined
  }
}

export const observedMetadata = (asset: Record<string, unknown>): Record<string, unknown> => ({
  manufacturer: asset.vendor,
  vendor: asset.vendor,
  model: asset.model,
  model_name: asset.model,
  device_name: asset.model,
  product_family: asset.productFamily,
  part_number: asset.partNumber ?? asset.catalogNumber,
  order_number: asset.orderNumber ?? asset.catalogNumber,
  hardware_revision: asset.hardwareVersion,
  serial_number: asset.serialNumber,
  firmware_version: asset.firmwareVersion,
  software_version: asset.softwareVersion,
  version_component: asset.versionComponent,
  protocol: asset.protocols,
})

export const createCatalogMatcher = (source: Catalog, revision: string) => {
  const groups = new Map(source.groups.map((group) => [group.id, group]))
  const manufacturers = source.manufacturers.map((manufacturer) => ({
    ...manufacturer,
    match: compile(manufacturer.rules),
  }))
  assert.equal(
    new Set(manufacturers.map(({ id }) => id)).size,
    manufacturers.length,
    'Duplicate manufacturer ID',
  )
  assert.equal(groups.size, source.groups.length, 'Duplicate group ID')
  for (const manufacturer of manufacturers) {
    for (const name of [manufacturer.data.name, ...(manufacturer.data.aliases ?? [])]) {
      assert.deepEqual(
        manufacturers
          .filter(({ match }) => match({ manufacturer: name }) !== undefined)
          .map(({ id }) => id),
        [manufacturer.id],
        'Ambiguous manufacturer alias',
      )
    }
  }
  for (const name of ['', ' ', 'unknown', 'not a manufacturer'])
    assert(
      !manufacturers.some(({ match }) => match({ manufacturer: name }) !== undefined),
      'Manufacturer rules accept a placeholder',
    )
  assert.equal(
    new Set(source.devices.map(({ id }) => id)).size,
    source.devices.length,
    'Duplicate product ID',
  )
  const identityFields = [
    'product_family',
    'model',
    'part_number',
    'order_number',
    'hardware_revision',
    'version_component',
    'version_kind',
    'version',
  ]
  const identities = source.devices.map((product) =>
    JSON.stringify([
      product.manufacturer_id.toLowerCase(),
      ...identityFields.map((field) =>
        typeof product.data[field] === 'string' ? product.data[field].trim().toLowerCase() : '',
      ),
    ]),
  )
  assert.equal(new Set(identities).size, identities.length, 'Duplicate catalog product identity')
  const products = source.devices.map((product) => {
    assert(
      manufacturers.some(({ id }) => id === product.manufacturer_id),
      'Unknown catalog manufacturer',
    )
    assert.equal(
      groups.get(product.device_type_id)?.name,
      product.data.device_type,
      'Unknown or inconsistent catalog group',
    )
    const match = compile(product.rules)
    const manufacturer = manufacturers.find(({ id }) => id === product.manufacturer_id)!
    if (typeof product.data.manufacturer === 'string')
      assert(
        manufacturer.match({ manufacturer: product.data.manufacturer }) !== undefined,
        'Product manufacturer name disagrees with its reference',
      )
    const identity = observedMetadata({
      vendor: manufacturer.data.name,
      model: product.data.model,
      productFamily: product.data.product_family,
      partNumber: product.data.part_number,
      orderNumber: product.data.order_number,
      hardwareVersion: product.data.hardware_revision,
      firmwareVersion: product.data.version_kind === 'firmware' ? product.data.version : undefined,
      softwareVersion: product.data.version_kind === 'software' ? product.data.version : undefined,
      versionComponent: product.data.version_component,
    })
    identity.version = product.data.version
    identity.version_kind = product.data.version_kind
    const names = [
      product.data.model,
      product.data.product_family,
      product.data.part_number,
      product.data.order_number,
    ].filter((value): value is string => typeof value === 'string')
    assert(
      names.some(
        (name) =>
          match({ ...identity, model: name, model_name: name, device_name: name }) !== undefined,
      ),
      'Product rules reject their own identity',
    )
    assert(
      match({ manufacturer: manufacturer.data.name }) === undefined,
      'Product rules require product identity',
    )
    return { ...product, match }
  })
  return (asset: Record<string, unknown>): MetadataMatch => {
    const record = observedMetadata(asset)
    const makers = manufacturers.filter(({ match }) => match(record) !== undefined)
    const result: MetadataMatch = {
      catalogRevision: revision,
      status: 'unmatched',
      manufacturerIDs: makers.map(({ id }) => id),
      manufacturerEvidence: makers.flatMap(({ match }) => match(record) ?? []),
      groupIDs: [],
      products: [],
    }
    if (makers.length !== 1)
      return { ...result, status: makers.length > 1 ? 'ambiguous' : 'unmatched' }
    const versions = [
      { version: asset.firmwareVersion, version_kind: 'firmware' },
      { version: asset.softwareVersion, version_kind: 'software' },
    ].filter(({ version }) => typeof version === 'string' && version.length > 0)
    const records = versions.length
      ? versions.map((version) => ({
          ...record,
          ...version,
          firmware_version: version.version_kind === 'firmware' ? version.version : undefined,
          software_version: version.version_kind === 'software' ? version.version : undefined,
        }))
      : [record]
    for (const product of products) {
      if (product.manufacturer_id !== makers[0].id) continue
      const evidence = records
        .map((input) => product.match(input))
        .find((item) => item !== undefined)
      if (evidence)
        result.products.push({
          id: product.id,
          manufacturerID: product.manufacturer_id,
          groupID: product.device_type_id,
          evidence,
        })
    }
    result.groupIDs = [...new Set(result.products.map(({ groupID }) => groupID))].sort()
    result.status =
      result.groupIDs.length > 1 ? 'ambiguous' : result.products.length ? 'matched' : 'unmatched'
    return result
  }
}
