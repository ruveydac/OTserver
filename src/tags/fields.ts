import deviceSchema from '../data/device-metadata/schema/ot-devices.schema.json'

export const assetTagRuleFieldLabels = {
  assetOwner: 'Asset owner',
  baselined: 'Baselined',
  catalogNumber: 'Catalog / part number',
  description: 'Description',
  firmwareVersion: 'Firmware version',
  gatewayAddress: 'Gateway address',
  hardwareVersion: 'Hardware version',
  id: 'ID',
  importSource: 'Import source',
  ipAddress: 'IP address',
  lastImportedAt: 'Last imported at',
  lastSeen: 'Last seen',
  lifecycle: 'Lifecycle',
  location: 'Physical location',
  macAddress: 'MAC address',
  model: 'Model',
  name: 'Name',
  networkMask: 'Network mask',
  notes: 'Notes',
  operatingSystem: 'Operating system',
  orderNumber: 'Order number',
  osAccuracy: 'OS accuracy',
  partNumber: 'Part number',
  physicalKind: 'Physical kind',
  productFamily: 'Product family',
  protocols: 'Protocols',
  purdueLevels: 'Purdue levels',
  serialNumber: 'Serial number',
  site: 'Site',
  slotCapacity: 'Slot capacity',
  softwareVersion: 'Software version',
  sourceVersion: 'Source version',
  status: 'Status',
  updatedAt: 'Last updated',
  uuid: 'Asset UUID',
  vendor: 'Vendor / manufacturer',
  versionComponent: 'Version component',
  vulnerabilityCount: 'Vulnerability count',
} as const

export const vulnerabilityTagRuleFieldLabels = {
  'components.id': 'Component ID',
  'components.name': 'Component name',
  'components.version': 'Component version',
  constraint: 'Affected-version constraint',
  cpe: 'CPE',
  cve: 'CVE',
  cvssScore: 'CVSS score',
  cvssSeverity: 'CVSS severity',
  knownExploited: 'Known exploited',
  matchedProduct: 'Matched product',
  matchedVendor: 'Matched vendor',
  version: 'Version',
  versionEvidence: 'Version evidence',
} as const

type MetadataSchemaNode = {
  $ref?: string
  additionalProperties?: boolean | MetadataSchemaNode
  allOf?: MetadataSchemaNode[]
  anyOf?: MetadataSchemaNode[]
  items?: MetadataSchemaNode
  oneOf?: MetadataSchemaNode[]
  properties?: Record<string, MetadataSchemaNode>
  type?: string
}

const metadataSchema = deviceSchema as unknown as { $defs: Record<string, MetadataSchemaNode> }

const resolveSchema = (input: MetadataSchemaNode): MetadataSchemaNode => {
  let schema = input
  const seen = new Set<string>()
  while (schema.$ref?.startsWith('#/$defs/') && !seen.has(schema.$ref)) {
    seen.add(schema.$ref)
    const referenced = metadataSchema.$defs[schema.$ref.slice('#/$defs/'.length)]
    if (!referenced) break
    schema = referenced
  }
  return schema
}

const scalarPaths = (input: MetadataSchemaNode, prefix = ''): string[] => {
  const schema = resolveSchema(input)
  if (schema.properties)
    return Object.entries(schema.properties).flatMap(([key, value]) =>
      scalarPaths(value, prefix ? `${prefix}.${key}` : key),
    )
  if (schema.items) return scalarPaths(schema.items, prefix)
  const variants = schema.oneOf || schema.anyOf || schema.allOf
  if (variants?.length) return variants.flatMap((variant) => scalarPaths(variant, prefix))
  if (schema.type === 'object' || schema.additionalProperties !== undefined) return []
  return prefix ? [prefix] : []
}

const deviceData = resolveSchema(metadataSchema.$defs.deviceData)
const deviceDataProperties = deviceData.properties || {}
const connectedPaths = [
  'firmwareVersion',
  ...Object.entries(deviceDataProperties).flatMap(([key, value]) => scalarPaths(value, key)),
  ...Object.keys(deviceDataProperties)
    .filter((key) => key !== 'evidence_json')
    .flatMap((key) => scalarPaths(metadataSchema.$defs.evidence!, `evidence_json.${key}`)),
]

export type CustomTagRuleField = { id: number | string; label: string }
export type TagRuleFieldOption = { label: string; value: string }

export const tagRuleFieldOptions = (
  customFields: CustomTagRuleField[],
  includeVulnerabilityFields = true,
): TagRuleFieldOption[] => [
  ...Object.entries(assetTagRuleFieldLabels).map(([name, label]) => ({
    label: `Asset · ${label} (asset.${name})`,
    value: `asset.${name}`,
  })),
  ...customFields.map(({ id, label }) => ({
    label: `Custom asset field · ${label} (customFields.${id})`,
    value: `customFields.${id}`,
  })),
  ...connectedPaths.map((path) => ({
    label: `Connected catalog · connected.${path}`,
    value: `connected.${path}`,
  })),
  ...(includeVulnerabilityFields
    ? Object.entries(vulnerabilityTagRuleFieldLabels).map(([name, label]) => ({
        label: `Confirmed vulnerability · ${label} (vulnerability.${name})`,
        value: `vulnerability.${name}`,
      }))
    : []),
]
