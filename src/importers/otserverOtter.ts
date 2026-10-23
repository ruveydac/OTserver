import { isIP } from 'node:net'

import type { DataQuality } from './assetQuality'
import {
  importedProtocols,
  type ImportedAsset,
  type ImportedObservation,
  type ImportedTopologyLink,
  type ImportResult,
} from './types'
import { normalizeMAC } from '../domain/network'
import { endpointEvidence, expandPhysicalEvidence, serviceEvidence } from '../identity/evidence'
import { text } from '../identity/keys'

const macPattern = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/
const uuidPattern = /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i
const dateTimePattern =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/
const sources: Record<string, DataQuality> = {
  arp: 'medium',
  bacnet: 'medium',
  'beckhoff-ads': 'high',
  dnp3: 'medium',
  'ethernet-ip': 'high',
  iec61850: 'medium',
  lldp: 'high',
  netbios: 'medium',
  'niagara-fox': 'medium',
  'omron-fins': 'medium',
  'opc-ua': 'medium',
  'os-fingerprint': 'medium',
  'profinet-dcp': 'high',
  s7: 'medium',
  snmp: 'high',
  unknown: 'low',
}
const allowedFields = new Set([
  'catalogNumber',
  'description',
  'firmwareVersion',
  'gatewayAddress',
  'hardwareVersion',
  'ipAddress',
  'lastSeen',
  'location',
  'macAddress',
  'model',
  'name',
  'networkMask',
  'operatingSystem',
  'osAccuracy',
  'protocols',
  'serialNumber',
  'status',
  'vendor',
])
const allowedProtocols = new Set<string>(importedProtocols)
const textFields = new Set(
  [...allowedFields].filter((field) => !['osAccuracy', 'protocols'].includes(field)),
)
const secretKey = /community|password|secret/i

export const MAX_OTTER_IMPORT_FILE_SIZE = 500 * 1024 * 1024

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const array = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])
const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === 'object' && !Array.isArray(value))
const isDateTime = (value: unknown): value is string =>
  typeof value === 'string' && dateTimePattern.test(value) && !Number.isNaN(Date.parse(value))
const isStringList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string')

const rejectSecrets = (value: unknown) => {
  const pending: { path: string; value: unknown }[] = [{ path: '$', value }]
  while (pending.length) {
    const current = pending.pop()!
    if (!current.value || typeof current.value !== 'object') continue
    for (const [key, item] of Object.entries(current.value)) {
      if (secretKey.test(key))
        throw new Error(`Otter export contains a secret-like field at ${current.path}.${key}.`)
      pending.push({ path: `${current.path}.${key}`, value: item })
    }
  }
}

const mac = (value: unknown, label: string) => {
  if (typeof value !== 'string' || !macPattern.test(normalizeMAC(value))) {
    throw new Error(`${label} must contain a normalized MAC address.`)
  }
  return normalizeMAC(value)
}

const safeFields = (value: unknown, identity: string) => {
  const fields = Object.fromEntries(
    Object.entries(record(value)).filter(([key]) => allowedFields.has(key)),
  )
  if (identity) fields.macAddress = identity
  else delete fields.macAddress
  for (const field of textFields) {
    if (fields[field] !== undefined && typeof fields[field] !== 'string') delete fields[field]
  }
  if (typeof fields.ipAddress === 'string' && isIP(fields.ipAddress) === 0) delete fields.ipAddress
  if (typeof fields.gatewayAddress === 'string' && isIP(fields.gatewayAddress) === 0)
    delete fields.gatewayAddress
  if (typeof fields.networkMask === 'string' && isIP(fields.networkMask) === 0)
    delete fields.networkMask
  if (
    fields.osAccuracy !== undefined &&
    (typeof fields.osAccuracy !== 'number' || fields.osAccuracy < 0 || fields.osAccuracy > 100)
  )
    delete fields.osAccuracy
  if (
    fields.status !== undefined &&
    !['maintenance', 'offline', 'online', 'unknown'].includes(String(fields.status))
  )
    delete fields.status
  if (fields.lastSeen !== undefined && Number.isNaN(Date.parse(String(fields.lastSeen))))
    delete fields.lastSeen
  if (Array.isArray(fields.protocols))
    fields.protocols = [
      ...new Set(
        fields.protocols.filter(
          (protocol) => typeof protocol === 'string' && allowedProtocols.has(protocol),
        ),
      ),
    ]
  else delete fields.protocols
  return fields
}

const addTextField = (
  fields: Record<string, unknown>,
  mergeFields: Record<string, unknown>,
  field: string,
  ...values: unknown[]
) => {
  const value = values.find((item) => typeof item === 'string' && item.trim())
  if (typeof value !== 'string') return
  if (fields[field] === undefined) fields[field] = value
  if (typeof mergeFields[field] !== 'string' || !mergeFields[field].trim())
    mergeFields[field] = value
}

export const parseOTserverOtter = (input: string): ImportResult => {
  if (Buffer.byteLength(input, 'utf8') > MAX_OTTER_IMPORT_FILE_SIZE)
    throw new Error('Otter JSON exceeds the 500 MB import limit.')
  let parsed: unknown
  try {
    parsed = JSON.parse(input)
  } catch {
    throw new Error('The uploaded file is not valid JSON.')
  }
  rejectSecrets(parsed)
  const root = record(parsed)
  if (root.format !== 'otserver-scan' || root.schemaVersion !== 2) {
    throw new Error(
      'Unsupported Otter file. Expected otserver-scan schemaVersion 2. Run a new scan with OTserver Otter.',
    )
  }
  const scanner = record(root.scanner)
  const scan = record(root.scan)
  if (
    typeof scanner.name !== 'string' ||
    !scanner.name.trim() ||
    typeof scanner.version !== 'string' ||
    !scanner.version.trim() ||
    typeof scan.id !== 'string' ||
    !uuidPattern.test(scan.id)
  ) {
    throw new Error('Otter and scan metadata are required.')
  }
  const selectedInterface = record(scan.interface)
  if (
    !isDateTime(scan.startedAt) ||
    !isDateTime(scan.finishedAt) ||
    !Array.isArray(scan.targets) ||
    !scan.targets.length ||
    scan.targets.some((target) => typeof target !== 'string' || !target.trim()) ||
    typeof selectedInterface.id !== 'string' ||
    !selectedInterface.id.trim() ||
    typeof selectedInterface.name !== 'string' ||
    !selectedInterface.name.trim() ||
    (selectedInterface.addresses !== undefined && !isStringList(selectedInterface.addresses))
  )
    throw new Error('Otter scan metadata is invalid.')
  if (
    !Array.isArray(root.devices) ||
    !Array.isArray(root.links) ||
    !Array.isArray(root.unresolved) ||
    !isStringList(root.warnings) ||
    !isStringList(root.errors)
  )
    throw new Error(
      'Otter devices, links, unresolved observations, warnings, and errors are invalid.',
    )

  const identities = new Set<string>()
  const assets = array(root.devices).flatMap((entry, index): ImportedAsset[] => {
    const device = record(entry)
    const identity = mac(device.macAddress, `devices[${index}].macAddress`)
    if (
      !isStringList(device.macAddresses) ||
      !isStringList(device.ipAddresses) ||
      !Array.isArray(device.observations) ||
      !Array.isArray(device.interfaces) ||
      !Array.isArray(device.ports)
    )
      throw new Error(`devices[${index}] is missing required arrays.`)
    for (const [macIndex, value] of device.macAddresses.entries())
      mac(value, `devices[${index}].macAddresses[${macIndex}]`)
    for (const [field, values] of [
      ['interfaces', device.interfaces],
      ['ports', device.ports],
    ] as const)
      values.forEach((item, itemIndex) => {
        const value = record(item)
        if (
          !isRecord(item) ||
          typeof value.key !== 'string' ||
          !value.key.trim() ||
          typeof value.source !== 'string' ||
          !value.source.trim()
        )
          throw new Error(`devices[${index}].${field}[${itemIndex}] is invalid.`)
      })
    if (identities.has(identity)) throw new Error(`Duplicate device MAC address: ${identity}.`)
    identities.add(identity)
    const observations = array(device.observations).map(
      (entry, observationIndex): ImportedObservation => {
        const observation = record(entry)
        if (
          !isRecord(entry) ||
          typeof observation.source !== 'string' ||
          !isRecord(observation.fields) ||
          !Object.hasOwn(observation, 'raw') ||
          !isStringList(observation.warnings)
        )
          throw new Error(`devices[${index}].observations[${observationIndex}] is invalid.`)
        if (!isDateTime(observation.observedAt))
          throw new Error(
            `devices[${index}].observations[${observationIndex}].observedAt is invalid.`,
          )
        const source =
          typeof observation.source === 'string' && observation.source in sources
            ? observation.source
            : 'unknown'
        const originalFields = record(observation.fields)
        const fields = { ...originalFields }
        const mergeFields = safeFields(originalFields, identity)
        if (fields.ipAddress === undefined && typeof observation.ipAddress === 'string')
          fields.ipAddress = observation.ipAddress
        if (fields.macAddress === undefined && typeof observation.macAddress === 'string')
          fields.macAddress = observation.macAddress
        if (fields.macAddress === undefined) fields.macAddress = identity

        const raw = record(observation.raw)
        const serialClaim = source === 'profinet-dcp' ? {} : record(raw.serialClaim)
        const physicalEntities = array(raw.physicalEntities).map(record)
        const snmpRoots = physicalEntities.filter(
          (entity) => !text(entity.parentRef) && ['chassis', 'stack'].includes(text(entity.class)),
        )
        const legacySnmpRoots = physicalEntities.filter(
          (entity) => !text(entity.parentRef) && entity.class === undefined,
        )
        const primaryEntity =
          source === 'snmp'
            ? snmpRoots.length === 1
              ? snmpRoots[0]
              : snmpRoots.length === 0 && legacySnmpRoots.length === 1
                ? legacySnmpRoots[0]
                : undefined
            : undefined
        const primarySerialClaim = record(primaryEntity?.serialClaim)
        if (source === 'profinet-dcp' || source === 'snmp') {
          delete fields.serialNumber
          delete mergeFields.serialNumber
        }
        addTextField(
          fields,
          mergeFields,
          'vendor',
          serialClaim.issuer,
          primarySerialClaim.issuer,
          primaryEntity?.manufacturer,
        )
        addTextField(
          fields,
          mergeFields,
          'serialNumber',
          source === 'snmp' ? undefined : serialClaim.original,
          primarySerialClaim.original,
        )
        addTextField(fields, mergeFields, 'name', primaryEntity?.name)
        addTextField(fields, mergeFields, 'description', primaryEntity?.description)
        addTextField(fields, mergeFields, 'model', primaryEntity?.name)
        addTextField(
          fields,
          mergeFields,
          'catalogNumber',
          source === 's7' ? raw.module : undefined,
          source === 's7' ? raw.basicHardware : undefined,
          serialClaim.catalogNumber,
          primaryEntity?.catalogNumber,
          source === 'snmp' && primaryEntity ? raw['1.3.6.1.4.1.4329.6.3.2.1.1.2.0'] : undefined,
        )
        addTextField(
          fields,
          mergeFields,
          'hardwareVersion',
          primaryEntity?.hardwareRevision,
          source === 'snmp' && primaryEntity ? raw['1.3.6.1.4.1.4329.6.3.2.1.1.4.0'] : undefined,
        )
        addTextField(fields, mergeFields, 'firmwareVersion', primaryEntity?.firmwareRevision)
        if (source === 'arp') addTextField(fields, mergeFields, 'vendor', raw.ouiVendor)
        if (source === 'profinet-dcp') {
          const primary = array(raw.pnioRecords)
            .map(record)
            .find(
              (item) =>
                Number(item.api) === 0 &&
                Number(item.slot) === 0 &&
                Number(item.subslot) === 1 &&
                text(item.index).toUpperCase() === '0xAFF0',
            )
          const parsed = record(primary?.parsed)
          addTextField(
            fields,
            mergeFields,
            'vendor',
            originalFields.manufacturer,
            parsed.manufacturerName,
          )
          addTextField(
            fields,
            mergeFields,
            'firmwareVersion',
            originalFields.softwareRevision,
            parsed.softwareRevision,
          )
        }
        return {
          fields,
          mergeFields,
          interfaces: array(device.interfaces),
          observedAt: observation.observedAt,
          ports: array(device.ports),
          quality: sources[source],
          raw: observation.raw,
          source,
          warnings: observation.warnings as string[],
        }
      },
    )
    if (!observations.length) throw new Error(`Device ${identity} has no observations.`)
    const preferred = observations.reduce(
      (result, observation) => ({ ...result, ...(observation.mergeFields || observation.fields) }),
      {} as Record<string, unknown>,
    )
    return expandPhysicalEvidence({
      ...preferred,
      macAddress: identity,
      name: typeof preferred.name === 'string' && preferred.name ? preferred.name : identity,
      observations,
      endpoints: endpointEvidence(device),
      services: serviceEvidence(device),
    } as ImportedAsset)
  })

  const unresolved: unknown[] = []
  for (const [index, entry] of array(root.unresolved).entries()) {
    const value = record(entry)
    if (
      !isRecord(entry) ||
      typeof value.source !== 'string' ||
      !isRecord(value.fields) ||
      !Object.hasOwn(value, 'raw') ||
      !isStringList(value.warnings)
    )
      throw new Error(`unresolved[${index}] is invalid.`)
    if (!isDateTime(value.observedAt))
      throw new Error(`unresolved[${index}].observedAt is invalid.`)
    const source =
      typeof value.source === 'string' && value.source in sources ? value.source : 'unknown'
    const evidence = expandPhysicalEvidence({
      name: 'Unresolved protocol target',
      observations: [
        {
          fields: safeFields(value.fields, ''),
          observedAt: value.observedAt,
          quality: sources[source],
          source,
          raw: value.raw,
          warnings: value.warnings as string[],
        },
      ],
    }).filter((asset) => asset.identity)
    if (evidence.length) assets.push(...evidence)
    else unresolved.push(entry)
  }

  const links = array(root.links).map((entry, index): ImportedTopologyLink => {
    const link = record(entry)
    const local = record(link.local)
    const remote = record(link.remote)
    local.macAddress = mac(local.macAddress, `links[${index}].local.macAddress`)
    remote.macAddress = mac(remote.macAddress, `links[${index}].remote.macAddress`)
    if (
      !isRecord(entry) ||
      typeof link.source !== 'string' ||
      !isRecord(link.local) ||
      !isRecord(link.remote) ||
      !Object.hasOwn(link, 'raw')
    )
      throw new Error(`links[${index}] is invalid.`)
    if (!isDateTime(link.observedAt)) throw new Error(`links[${index}].observedAt is invalid.`)
    return {
      local,
      observedAt: link.observedAt,
      raw: link.raw,
      remote,
      source: ['lldp', 'profinet-dcp', 'snmp'].includes(link.source) ? link.source : 'unknown',
    }
  })
  return {
    assets,
    links,
    scanMetadata: { scan, scanner },
    sourceVersion: scanner.version,
    unresolved,
    warnings: [...(root.warnings as string[]), ...(root.errors as string[])],
  }
}
