import { isIP } from 'node:net'

import type { DataQuality } from './assetQuality'
import type {
  ImportedAsset,
  ImportedObservation,
  ImportedTopologyLink,
  ImportResult,
} from './types'
import { normalizeMAC } from '../collections/Assets'
import { endpointEvidence, expandPhysicalEvidence, serviceEvidence } from '../identity/evidence'

const macPattern = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/
const sources: Record<string, DataQuality> = {
  arp: 'medium',
  bacnet: 'medium',
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
const allowedProtocols = new Set([
  'bacnet',
  'dnp3',
  'ethernet-ip',
  'iec61850',
  'modbus-tcp',
  'netbios',
  'niagara-fox',
  'omron-fins',
  'opc-ua',
  'other',
  'profinet',
  's7',
])
const textFields = new Set(
  [...allowedFields].filter((field) => !['osAccuracy', 'protocols'].includes(field)),
)
const secretKey = /community|password|secret/i

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const array = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

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

export const parseOTserverOtter = (input: string): ImportResult => {
  if (Buffer.byteLength(input, 'utf8') > 50 * 1024 * 1024)
    throw new Error('Otter JSON exceeds the 50 MB import limit.')
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
  if (typeof scanner.version !== 'string' || typeof scan.id !== 'string') {
    throw new Error('Otter and scan metadata are required.')
  }
  if (
    !Array.isArray(root.devices) ||
    (root.links !== undefined && !Array.isArray(root.links)) ||
    (root.unresolved !== undefined && !Array.isArray(root.unresolved))
  )
    throw new Error('Otter devices, links, and unresolved observations must be arrays.')

  const identities = new Set<string>()
  const assets = array(root.devices).flatMap((entry, index): ImportedAsset[] => {
    const device = record(entry)
    const identity = mac(device.macAddress, `devices[${index}].macAddress`)
    if (identities.has(identity)) throw new Error(`Duplicate device MAC address: ${identity}.`)
    identities.add(identity)
    const observations = array(device.observations).map(
      (entry, observationIndex): ImportedObservation => {
        const observation = record(entry)
        const source =
          typeof observation.source === 'string' && observation.source in sources
            ? observation.source
            : 'unknown'
        if (
          typeof observation.observedAt !== 'string' ||
          Number.isNaN(Date.parse(observation.observedAt))
        ) {
          throw new Error(
            `devices[${index}].observations[${observationIndex}].observedAt is invalid.`,
          )
        }
        const fields = safeFields(observation.fields, identity)
        const ouiVendor = record(observation.raw).ouiVendor
        if (source === 'arp' && !fields.vendor && typeof ouiVendor === 'string')
          fields.vendor = ouiVendor
        return {
          fields,
          interfaces: array(device.interfaces),
          observedAt: observation.observedAt,
          ports: array(device.ports),
          quality: sources[source],
          raw: observation.raw,
          source,
          warnings: array(observation.warnings).filter(
            (item): item is string => typeof item === 'string',
          ),
        }
      },
    )
    if (!observations.length) throw new Error(`Device ${identity} has no observations.`)
    const preferred = observations.reduce(
      (result, observation) => ({ ...result, ...observation.fields }),
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
  for (const entry of array(root.unresolved)) {
    const value = record(entry)
    if (typeof value.observedAt !== 'string' || Number.isNaN(Date.parse(value.observedAt))) {
      unresolved.push(entry)
      continue
    }
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
          warnings: array(value.warnings).filter(
            (item): item is string => typeof item === 'string',
          ),
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
    if (typeof link.observedAt !== 'string' || Number.isNaN(Date.parse(link.observedAt)))
      throw new Error(`links[${index}].observedAt is invalid.`)
    return {
      local,
      observedAt: link.observedAt,
      raw: link.raw,
      remote,
      source: typeof link.source === 'string' ? link.source : 'unknown',
    }
  })
  return {
    assets,
    links,
    scanMetadata: { scan, scanner },
    sourceVersion: scanner.version,
    unresolved,
    warnings: [...array(root.warnings), ...array(root.errors)].filter(
      (item): item is string => typeof item === 'string',
    ),
  }
}
