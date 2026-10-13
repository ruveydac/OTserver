export type AssetSearchFieldKind = 'date' | 'keyword' | 'number' | 'text'

type AssetSearchField = {
  kind: AssetSearchFieldKind
  path: string
  wherePath?: string
  whereField?: string
}

// This browser-safe manifest drives both Lucene parsing and Payload filter serialization.
export const assetSearchFields: Record<string, AssetSearchField> = {
  assetowner: { kind: 'text', path: 'assetOwner' },
  uuid: { kind: 'keyword', path: 'uuid' },
  lifecycle: { kind: 'keyword', path: 'lifecycle' },
  physicalkind: { kind: 'keyword', path: 'physicalKind' },
  catalog: { kind: 'text', path: 'catalogNumber' },
  catalognumber: { kind: 'text', path: 'catalogNumber' },
  assetclass: { kind: 'text', path: 'assetClass.name' },
  assetclassid: { kind: 'keyword', path: 'assetClass' },
  class: { kind: 'text', path: 'assetClass.name' },
  classid: { kind: 'keyword', path: 'assetClass', wherePath: 'assetClass' },
  criticality: { kind: 'keyword', path: 'criticality' },
  createdat: { kind: 'date', path: 'createdAt' },
  deletedat: { kind: 'date', path: 'deletedAt' },
  description: { kind: 'text', path: 'description' },
  firmware: { kind: 'text', path: 'firmwareVersion' },
  firmwareversion: { kind: 'text', path: 'firmwareVersion' },
  gateway: { kind: 'text', path: 'gatewayAddress', wherePath: 'gatewayAddress' },
  gatewayaddress: { kind: 'text', path: 'gatewayAddress' },
  hardware: { kind: 'text', path: 'hardwareVersion' },
  hardwareversion: { kind: 'text', path: 'hardwareVersion' },
  importsource: { kind: 'text', path: 'importSource' },
  id: { kind: 'keyword', path: 'id' },
  ip: { kind: 'keyword', path: 'ipAddress', wherePath: 'ipAddress' },
  ipaddress: { kind: 'keyword', path: 'ipAddress' },
  lastimportedat: { kind: 'date', path: 'lastImportedAt' },
  lastseen: { kind: 'date', path: 'lastSeen' },
  location: { kind: 'text', path: 'location' },
  mac: { kind: 'keyword', path: 'macAddress', wherePath: 'macAddress' },
  macaddress: { kind: 'keyword', path: 'macAddress' },
  model: { kind: 'text', path: 'model' },
  name: { kind: 'text', path: 'name' },
  networkmask: { kind: 'text', path: 'networkMask' },
  notes: { kind: 'text', path: 'notes' },
  operatingsystem: { kind: 'text', path: 'operatingSystem' },
  os: { kind: 'text', path: 'operatingSystem', wherePath: 'operatingSystem' },
  osaccuracy: { kind: 'number', path: 'osAccuracy' },
  owner: { kind: 'text', path: 'assetOwner', wherePath: 'assetOwner' },
  protocol: { kind: 'keyword', path: 'protocols' },
  protocols: { kind: 'keyword', path: 'protocols' },
  serialnumber: { kind: 'text', path: 'serialNumber' },
  site: { kind: 'text', path: 'site.name' },
  siteid: { kind: 'keyword', path: 'site', wherePath: 'site' },
  sourceversion: { kind: 'text', path: 'sourceVersion' },
  status: { kind: 'keyword', path: 'status' },
  type: { kind: 'text', path: 'assetClass.name' },
  updatedat: { kind: 'date', path: 'updatedAt' },
  vendor: { kind: 'text', path: 'vendor' },
  vulnerabilitycount: {
    kind: 'number',
    path: 'vulnerabilityCount',
    wherePath: 'vulnerabilityCount',
    whereField: 'vulnerabilityCount',
  },
}

export const graphicalAssetFieldNames = Object.fromEntries(
  Object.entries(assetSearchFields).flatMap(([name, field]) =>
    field.wherePath ? [[field.wherePath, field.whereField || name]] : [],
  ),
)
