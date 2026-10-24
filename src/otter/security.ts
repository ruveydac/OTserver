import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { APIError, type AuthStrategy, type PayloadRequest, type TypedUser } from 'payload'
import { getAuthorization, relationshipID } from '../access/authorization'

const credentialPrefix = 'Otter '

export const tokenDigest = (token: string) => createHash('sha256').update(token).digest('hex')

export const newToken = () => randomBytes(32).toString('base64url')

const pathOf = (req?: PayloadRequest) => {
  if (!req?.url) return ''
  try {
    return new URL(req.url, 'http://otserver.invalid').pathname
  } catch {
    return ''
  }
}

const acceptsScannerCredentials = (req?: PayloadRequest) => {
  const path = pathOf(req)
  return (
    path.startsWith('/api/otter/v1/') ||
    path === '/api/asset-imports' ||
    path.startsWith('/api/asset-imports/')
  )
}

export const otterMachineStrategy: AuthStrategy = {
  name: 'otter-machine',
  authenticate: async ({ headers, payload, req }) => {
    const authorization = headers.get('authorization')
    if (!req || !authorization?.startsWith(credentialPrefix) || !acceptsScannerCredentials(req))
      return { user: null }

    const token = authorization.slice(credentialPrefix.length)
    if (!/^[A-Za-z0-9_-]{40,}$/.test(token)) return { user: null }
    const now = new Date().toISOString()
    const result = await payload.find({
      collection: 'otter-scanners',
      depth: 0,
      limit: 1,
      overrideAccess: true,
      where: {
        and: [
          { credentialHash: { equals: tokenDigest(token) } },
          { enabled: { equals: true } },
          { credentialExpiresAt: { greater_than: now } },
        ],
      },
    })
    const scanner = result.docs[0]
    const siteID = relationshipID(scanner?.site)
    if (!scanner || !siteID) return { user: null }

    req.context.otterScannerID = String(scanner.id)
    req.context.otterScannerSiteID = String(siteID)

    return {
      user: {
        collection: 'users',
        email: `otter-${scanner.id}@otter.invalid`,
        id: `otter:${scanner.id}`,
        otterScannerID: String(scanner.id),
        role: null,
      } as unknown as TypedUser,
    }
  },
}

const encryptionKey = () => {
  const value = process.env.OTSERVER_OTTER_ENCRYPTION_KEY
  if (!value || !/^[\da-f]{64}$/i.test(value))
    throw new APIError('Otter credential encryption is not configured.', 503)
  return Buffer.from(value, 'hex')
}

export const encryptOtterCredentials = (value: unknown) => {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv)
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()])
  return [
    'v1',
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.')
}

export const decryptOtterCredentials = (value?: string | null) => {
  if (!value) return {}
  const [version, iv, tag, encrypted] = value.split('.')
  if (version !== 'v1' || !iv || !tag || !encrypted)
    throw new APIError('Stored Otter credentials have an unsupported format.', 500)
  const key = encryptionKey()
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'))
    decipher.setAuthTag(Buffer.from(tag, 'base64url'))
    return JSON.parse(
      Buffer.concat([
        decipher.update(Buffer.from(encrypted, 'base64url')),
        decipher.final(),
      ]).toString('utf8'),
    ) as Record<string, unknown>
  } catch {
    throw new APIError('Stored Otter credentials could not be decrypted.', 500)
  }
}

const configKeys = new Set([
  'targets',
  'interface',
  'sourceMac',
  'noProtocols',
  'noArp',
  'noProfinet',
  'allowDcpSource',
  'noS7',
  'noEnip',
  'noBacnet',
  'noFins',
  'noFox',
  'noDnp3',
  'noIec61850',
  'noNetbios',
  'noSmb',
  'noRpc',
  'noHttp',
  'noAds',
  'noOpcua',
  'noSnmp',
  'noLldp',
  'adsSourceNetId',
  'adsTargetNetIds',
  'adsPorts',
  'opcuaPorts',
])

const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:[0-9]|[12][0-9]|3[0-2]))?$/
const isIPv4Address = (value: string) =>
  value.split('.').length === 4 &&
  value.split('.').every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
const isAdsNetId = (value: unknown): value is string => {
  if (typeof value !== 'string') return false
  const octets = value.split('.')
  return (
    octets.length === 6 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255) &&
    octets.some((octet) => Number(octet) > 0)
  )
}

export const validateOtterConfiguration = (input: unknown) => {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new APIError('Otter configuration must be an object.', 400)
  const config = input as Record<string, unknown>
  const unknown = Object.keys(config).find((key) => !configKeys.has(key))
  if (unknown) throw new APIError(`Unsupported Otter configuration option: ${unknown}.`, 400)

  if (!Array.isArray(config.targets) || !config.targets.length || config.targets.length > 1024)
    throw new APIError('Enter one or more valid IPv4 addresses or CIDR ranges.', 400)
  let targetCount = 0
  for (const target of config.targets) {
    if (
      typeof target !== 'string' ||
      target.length > 64 ||
      !ipv4.test(target) ||
      target
        .split('/')[0]
        .split('.')
        .some((part) => Number(part) > 255)
    )
      throw new APIError('Enter one or more valid IPv4 addresses or CIDR ranges.', 400)
    const prefix = Number(target.split('/')[1] || 32)
    targetCount += 2 ** (32 - prefix)
    if (targetCount > 65_536)
      throw new APIError('The configured targets exceed Otter’s 65,536-address scan limit.', 400)
  }

  if (
    config.interface !== undefined &&
    (typeof config.interface !== 'string' ||
      !config.interface.trim() ||
      config.interface.length > 256)
  )
    throw new APIError('The interface must be a non-empty name of at most 256 characters.', 400)
  if (
    config.sourceMac !== undefined &&
    (typeof config.sourceMac !== 'string' ||
      !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(config.sourceMac))
  )
    throw new APIError('The source MAC address is invalid.', 400)

  for (const [key, value] of Object.entries(config)) {
    if (key.startsWith('no') || key === 'allowDcpSource') {
      if (typeof value !== 'boolean') throw new APIError(`${key} must be a boolean.`, 400)
    }
  }
  if (
    config.opcuaPorts !== undefined &&
    (!Array.isArray(config.opcuaPorts) ||
      config.opcuaPorts.length > 64 ||
      config.opcuaPorts.some(
        (port) => !Number.isInteger(port) || Number(port) < 1 || Number(port) > 65535,
      ))
  )
    throw new APIError('OPC UA ports must be integers from 1 to 65535.', 400)

  if (config.adsSourceNetId !== undefined && !isAdsNetId(config.adsSourceNetId))
    throw new APIError('ADS source NetID must contain six decimal octets from 0 to 255.', 400)
  if (
    config.adsTargetNetIds !== undefined &&
    (!config.adsTargetNetIds ||
      typeof config.adsTargetNetIds !== 'object' ||
      Array.isArray(config.adsTargetNetIds) ||
      Object.keys(config.adsTargetNetIds).length > 1024 ||
      Object.entries(config.adsTargetNetIds).some(
        ([target, netID]) => !isIPv4Address(target) || !isAdsNetId(netID),
      ))
  )
    throw new APIError('ADS target NetIDs must map IPv4 addresses to valid AMS NetIDs.', 400)
  if (
    config.adsPorts !== undefined &&
    (!Array.isArray(config.adsPorts) ||
      config.adsPorts.length > 8 ||
      config.adsPorts.some(
        (port) => !Number.isInteger(port) || Number(port) < 1 || Number(port) > 65535,
      ) ||
      new Set(config.adsPorts).size !== config.adsPorts.length)
  )
    throw new APIError('ADS AMS ports must be unique integers from 1 to 65535 (at most 8).', 400)

  return structuredClone(config)
}

export const validateOtterCredentials = (input: unknown) => {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new APIError('Otter credentials must be an object.', 400)
  const value = input as Record<string, unknown>
  const allowed = new Set(['snmp', 'opcuaCredentials', 'opcuaUsername', 'opcuaPassword'])
  const unknown = Object.keys(value).find((key) => !allowed.has(key))
  if (unknown) throw new APIError(`Unsupported credential option: ${unknown}.`, 400)
  if (value.snmp !== undefined) {
    const entries = Array.isArray(value.snmp) ? value.snmp : [value.snmp]
    if (
      entries.length > 32 ||
      entries.some((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return true
        const credential = item as Record<string, unknown>
        const keys = new Set([
          'version',
          'community',
          'username',
          'contextName',
          'authProtocol',
          'authPassword',
          'privacyProtocol',
          'privacyPassword',
        ])
        if (Object.keys(credential).some((key) => !keys.has(key))) return true
        for (const [key, field] of Object.entries(credential)) {
          if (
            typeof field !== 'string' ||
            field.length > (key.toLowerCase().includes('password') ? 4096 : 512)
          )
            return true
        }
        if (
          credential.authProtocol !== undefined &&
          !['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].includes(
            String(credential.authProtocol).toLowerCase(),
          )
        )
          return true
        if (
          credential.privacyProtocol !== undefined &&
          !['des', 'aes128', 'aes192', 'aes256'].includes(
            String(credential.privacyProtocol).toLowerCase(),
          )
        )
          return true
        if (
          (credential.authProtocol !== undefined &&
            (typeof credential.authPassword !== 'string' || credential.authPassword.length < 8)) ||
          (credential.privacyProtocol !== undefined &&
            (typeof credential.privacyPassword !== 'string' ||
              credential.privacyPassword.length < 8))
        )
          return true
        return Boolean(
          credential.version !== undefined &&
          !['1', '2c', '3', 'auto'].includes(String(credential.version).toLowerCase()),
        )
      })
    )
      throw new APIError('SNMP credentials contain invalid entries.', 400)
  }
  const opcua = value.opcuaCredentials
  if (
    opcua !== undefined &&
    (Array.isArray(opcua)
      ? opcua.length > 32 || opcua.some((entry) => !isOpcuaCredential(entry))
      : !isOpcuaCredential(opcua))
  )
    throw new APIError('OPC UA credentials contain invalid entries.', 400)
  for (const key of ['opcuaUsername', 'opcuaPassword'])
    if (
      value[key] !== undefined &&
      (typeof value[key] !== 'string' || value[key].length > (key === 'opcuaPassword' ? 4096 : 512))
    )
      throw new APIError(`${key} must be text.`, 400)
  return structuredClone(value)
}

const isOpcuaCredential = (value: unknown) =>
  Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => ['username', 'password'].includes(key)) &&
    typeof (value as Record<string, unknown>).username === 'string' &&
    (value as Record<string, string>).username.length <= 512 &&
    ((value as Record<string, unknown>).password === undefined ||
      (typeof (value as Record<string, unknown>).password === 'string' &&
        (value as Record<string, string>).password.length <= 4096)),
  )

export const scannerIDFromRequest = (req: PayloadRequest) => {
  const value = req.context.otterScannerID
  return typeof value === 'string' ? value : undefined
}

export const requireOtterScanner = (req: PayloadRequest) => {
  const id = scannerIDFromRequest(req)
  if (!id) throw new APIError('Otter scanner authentication is required.', 401)
  return id
}

export const requireOtterConfigAccess = async (
  req: PayloadRequest,
  site: unknown,
  write = false,
) => {
  const authorization = await getAuthorization(req)
  const siteID = String(relationshipID(site) ?? '')
  if (
    !authorization.canConfigureOtter ||
    !(
      authorization.isAdmin ||
      (write
        ? authorization.writableSiteIDs.includes(siteID)
        : authorization.readableSiteIDs.includes(siteID))
    )
  )
    throw new APIError('Otter Config permission for this site is required.', 403)
}
