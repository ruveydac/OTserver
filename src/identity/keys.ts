import { createHash } from 'node:crypto'

// Published with the manager's identity scheme. Never change an existing namespace.
export const OT_NAMESPACE = 'a346ed7e-daca-4e40-8bb1-72f0a9119943'
export const IDENTITY_SCHEME = 'ot-hardware-v1'
export const identityScopes = ['device', 'chassis', 'cpu', 'adapter', 'module'] as const
export type IdentityScope = (typeof identityScopes)[number]
export type HardwareIdentity = {
  authority: string
  manufacturer: string
  scope: IdentityScope
  serial: string
  productScope?: string
}

export const uuidV5 = (namespace: string, name: string): string => {
  if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(namespace))
    throw new Error('Invalid UUID namespace.')
  const bytes = createHash('sha1')
    .update(Buffer.from(namespace.replaceAll('-', ''), 'hex'))
    .update(name, 'utf8')
    .digest()
    .subarray(0, 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x50
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : '')
export const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

export const normalizeIdentity = (input: HardwareIdentity): HardwareIdentity => {
  const authority = text(input.authority).toLowerCase()
  let manufacturer = text(input.manufacturer).toLowerCase()
  let serial = text(input.serial)
  if (
    !authority ||
    !manufacturer ||
    !identityScopes.includes(input.scope) ||
    !serial ||
    /^(?:0+|f{8}|unknown|n\/?a|none|not specified|default)$/i.test(serial) ||
    [authority, manufacturer, serial, input.productScope || ''].some(
      (value) => value.length > 200 || /[\x00-\x1f\x7f]/.test(value),
    )
  )
    throw new Error('Supply a non-placeholder manufacturer, component scope, and hardware serial.')
  // CIP serials are unsigned 32-bit numbers exported by Otter as eight hexadecimal digits.
  if (authority === 'cip') {
    if (
      !/^\d+$/.test(manufacturer) ||
      Number(manufacturer) < 1 ||
      Number(manufacturer) > 65535 ||
      !/^[\da-f]{8}$/i.test(serial)
    )
      throw new Error('Invalid CIP manufacturer or serial.')
    serial = serial.toUpperCase()
    manufacturer = String(Number(manufacturer))
  }
  return {
    authority,
    manufacturer,
    scope: input.scope,
    serial,
    ...(text(input.productScope) ? { productScope: text(input.productScope) } : {}),
  }
}

export const hardwareKey = (input: HardwareIdentity): string => {
  const value = normalizeIdentity(input)
  return uuidV5(
    OT_NAMESPACE,
    JSON.stringify([
      IDENTITY_SCHEME,
      value.authority,
      value.manufacturer,
      value.scope,
      value.productScope || '',
      value.serial,
    ]),
  )
}

export const slotUUID = (parentUUID: string, slotPath: string): string => {
  if (!text(slotPath) || slotPath.length > 100) throw new Error('Supply a slot or subslot path.')
  return uuidV5(parentUUID, JSON.stringify(['slot-v1', slotPath.trim()]))
}

export const scopedKey = (...parts: unknown[]): string =>
  uuidV5(OT_NAMESPACE, JSON.stringify(parts))

export const endpointBindingKey = (
  site: string,
  mac: string | undefined,
  asset: string,
  interfaceKey: string,
) => scopedKey('endpoint', site, mac || ['interface', asset, interfaceKey])
