import { isIP } from 'node:net'
import { normalizeMAC, validateMACAddress } from '../domain/network'
import type { ImportedAsset, ImportedObservation } from '../importers/types'
import { hardwareKey, normalizeIdentity, record, text, type HardwareIdentity } from './keys'

export type EndpointEvidence = {
  macAddress?: string
  interfaceKey?: string
  name?: string
  addresses: { address: string; networkMask?: string | null; gatewayAddress?: string | null }[]
  source: string
}
export type ServiceEvidence = {
  address?: string
  transport: 'tcp' | 'udp'
  port: number
  protocol: string
  route?: string
  source: string
}

/** Only source-specific identity layouts that the pinned v2 scanner actually emits. */
export const observationIdentity = (
  observation: ImportedObservation,
): HardwareIdentity | undefined => {
  const raw = record(observation.raw)
  const fields = observation.mergeFields || observation.fields
  const serial = text(fields.serialNumber)
  let identity: HardwareIdentity | undefined
  if (
    observation.source === 'ethernet-ip' &&
    Number.isInteger(raw.vendorId) &&
    Number.isInteger(raw.deviceType) &&
    serial === text(raw.serialNumber)
  ) {
    identity = {
      authority: 'cip',
      manufacturer: String(raw.vendorId),
      scope: raw.deviceType === 12 ? 'adapter' : raw.deviceType === 14 ? 'cpu' : 'device',
      serial,
    }
  } else if (observation.source === 's7' && text(raw.module) && serial) {
    identity = { authority: 'siemens', manufacturer: 'siemens', scope: 'cpu', serial }
  }
  if (!identity) return undefined
  try {
    return normalizeIdentity(identity)
  } catch {
    return undefined
  }
}

export const endpointEvidence = (device: Record<string, unknown>): EndpointEvidence[] => {
  const endpoints: EndpointEvidence[] = []
  const interfaces = Array.isArray(device.interfaces) ? device.interfaces : []
  for (const item of interfaces) {
    const value = record(item)
    const macAddress = text(value.macAddress)
    const addresses = (Array.isArray(value.ipAddresses) ? value.ipAddresses : []).filter(
      (address): address is string => typeof address === 'string' && isIP(address) !== 0,
    )
    if (!macAddress && !text(value.key)) continue
    if (macAddress && validateMACAddress(macAddress) !== true) continue
    endpoints.push({
      macAddress: macAddress ? normalizeMAC(macAddress) : undefined,
      interfaceKey: text(value.key) || undefined,
      name: text(value.name) || undefined,
      addresses: addresses.map((address) => ({ address })),
      source: text(value.source) || 'unknown',
    })
  }
  const primaryMAC = normalizeMAC(text(device.macAddress))
  if (!endpoints.some(({ macAddress }) => macAddress === primaryMAC)) {
    // Device-level IPs have a known MAC only when the v2 device has a single interface.
    const ips = !interfaces.length && Array.isArray(device.ipAddresses) ? device.ipAddresses : []
    endpoints.unshift({
      macAddress: primaryMAC,
      addresses: ips
        .filter((ip): ip is string => typeof ip === 'string' && isIP(ip) !== 0)
        .map((address) => ({ address })),
      source: 'otserver-otter',
    })
  }
  for (const value of Array.isArray(device.macAddresses) ? device.macAddresses : []) {
    const macAddress = text(value)
    if (
      macAddress &&
      validateMACAddress(macAddress) === true &&
      !endpoints.some((endpoint) => endpoint.macAddress === normalizeMAC(macAddress))
    )
      endpoints.push({
        macAddress: normalizeMAC(macAddress),
        addresses: [],
        source: 'otserver-otter',
      })
  }
  return endpoints
}

export const serviceEvidence = (device: Record<string, unknown>): ServiceEvidence[] => {
  const observations = (Array.isArray(device.observations) ? device.observations : []).map(record)
  const ports = (Array.isArray(device.ports) ? device.ports : []).map(record)
  const explicit = observations.flatMap((observation): ServiceEvidence[] => {
    const source = text(observation.source) || 'unknown'
    return (
      Array.isArray(record(observation.raw).listeners)
        ? (record(observation.raw).listeners as unknown[])
        : []
    ).flatMap((entry): ServiceEvidence[] => {
      const listener = record(entry)
      const address = text(listener.address)
      const transport = text(listener.transport)
      const port = listener.port
      if (
        !isIP(address) ||
        !['tcp', 'udp'].includes(transport) ||
        typeof port !== 'number' ||
        !Number.isInteger(port) ||
        port < 0 ||
        port > 65535
      )
        return []
      const route = Array.isArray(listener.route)
        ? listener.route.length
          ? JSON.stringify(listener.route)
          : undefined
        : text(listener.route) || undefined
      return [
        {
          address,
          transport: transport as 'tcp' | 'udp',
          port,
          protocol: source,
          ...(route ? { route } : {}),
          source,
        },
      ]
    })
  })
  const inferred = ports.flatMap((port): ServiceEvidence[] => {
    const match = /^(tcp|udp):(\d+)$/.exec(text(port.key))
    if (!match || Number(match[2]) > 65535) return []
    const addresses = [
      ...new Set(
        observations
          .filter((observation) => observation.source === port.source)
          .map(
            (observation) =>
              text(observation.ipAddress) || text(record(observation.fields).ipAddress),
          )
          .filter((address) => isIP(address) !== 0),
      ),
    ]
    // v2 aggregates ports at device level: never invent a port/address cross product.
    if (addresses.length !== 1) return []
    return [
      {
        address: addresses[0],
        transport: match[1] as 'tcp' | 'udp',
        port: Number(match[2]),
        protocol: text(port.source),
        source: text(port.source),
      },
    ]
  })
  return [
    ...new Map(
      [...inferred, ...explicit].map((item) => [
        JSON.stringify([item.address, item.transport, item.port, item.protocol]),
        item,
      ]),
    ).values(),
  ]
}

export const expandPhysicalEvidence = (asset: ImportedAsset): ImportedAsset[] => {
  const observations = asset.observations || []
  const claims = observations.flatMap((observation) => {
    const identity = observationIdentity(observation)
    return identity ? [{ identity, observation }] : []
  })
  const root = claims.find(({ observation }) => observation.source === 'ethernet-ip') || claims[0]
  const result: ImportedAsset[] = [{ ...asset, ...(root ? { identity: root.identity } : {}) }]
  if (root) {
    const rootKey = hardwareKey(root.identity)
    const other = claims.filter(({ identity }) => hardwareKey(identity) !== rootKey)
    result[0].observations = observations.filter(
      (observation) => !other.some((item) => item.observation === observation),
    )
    for (const { identity, observation } of other)
      result.push({
        ...(observation.mergeFields || observation.fields),
        name: text((observation.mergeFields || observation.fields).name) || identity.serial,
        identity,
        observations: [observation],
        componentRef: hardwareKey(identity),
        observedViaMAC: asset.macAddress,
      })
  }

  const entityRoot = '1.3.6.1.2.1.47.1.1.1.1.'
  for (const observation of observations.filter(({ source }) => source === 'snmp')) {
    const raw = record(observation.raw)
    const indexes = [
      ...new Set(
        Object.keys(raw).flatMap((key) =>
          key.startsWith(entityRoot) ? [key.slice(entityRoot.length).split('.')[1]] : [],
        ),
      ),
    ]
    const entities = indexes.flatMap((index) => {
      const value = (column: number) => raw[`${entityRoot}${column}.${index}`]
      if (![3, 9].includes(Number(value(5)))) return []
      const identity: HardwareIdentity = {
        authority: 'entity-mib',
        manufacturer: text(value(12)),
        scope: Number(value(5)) === 3 ? 'chassis' : 'module',
        serial: text(value(11)),
      }
      try {
        normalizeIdentity(identity)
      } catch {
        return []
      }
      return [
        {
          index,
          parent: String(value(4)),
          position: value(6),
          identity,
          fields: {
            vendor: text(value(12)),
            serialNumber: text(value(11)),
            model: text(value(13)),
            catalogNumber: text(value(13)),
            hardwareVersion: text(value(8)),
            firmwareVersion: text(value(9)),
          },
        },
      ]
    })
    if (root && entities.length) {
      result[0].observations = result[0].observations?.map((item) =>
        item === observation
          ? {
              ...item,
              mergeFields: networkFields(item.fields),
            }
          : item,
      )
    }
    for (const entity of entities) {
      const componentRef = `${asset.macAddress}:entity:${entity.index}`
      const parent = entities.find(({ index }) => index === entity.parent)
      // Preserve the root chassis as its own record too when another protocol identified an adapter.
      if (
        !root &&
        entity.identity.scope === 'chassis' &&
        entity.parent === '0' &&
        entities.filter((item) => item.parent === '0').length === 1
      ) {
        result[0].identity = entity.identity
        result[0].componentRef = componentRef
        result[0].observations = observations.map((item) =>
          item === observation
            ? {
                ...item,
                fields: { ...item.fields, ...entity.fields },
                mergeFields: { ...(item.mergeFields || item.fields), ...entity.fields },
              }
            : item,
        )
      } else {
        result.push({
          ...entity.fields,
          name: entity.fields.model || entity.identity.serial,
          identity: entity.identity,
          componentRef,
          ...(parent ? { parentComponentRef: `${asset.macAddress}:entity:${parent.index}` } : {}),
          ...(Number.isInteger(entity.position) && Number(entity.position) >= 0
            ? { slotPath: String(entity.position) }
            : {}),
          observations: [{ ...observation, fields: entity.fields, mergeFields: entity.fields }],
          observedViaMAC: asset.macAddress,
        })
      }
    }
  }
  const primary = result[0]
  if (primary.identity && primary.identity.scope !== 'cpu') {
    primary.observations = primary.observations?.map((observation) =>
      observation.source === 's7'
        ? {
            ...observation,
            mergeFields: networkFields(observation.mergeFields || observation.fields),
          }
        : observation,
    )
  }
  return result
}

// Preserve the observation's original fields while restricting what a different physical subject can inherit.
const networkFields = (fields: Record<string, unknown>) =>
  Object.fromEntries(
    Object.entries(fields).filter(([field]) =>
      [
        'macAddress',
        'ipAddress',
        'networkMask',
        'gatewayAddress',
        'protocols',
        'status',
        'lastSeen',
      ].includes(field),
    ),
  )
