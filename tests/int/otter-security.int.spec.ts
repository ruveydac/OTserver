import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFile } from 'node:fs/promises'
import type { Field } from 'payload'
import {
  canCreateSiteDocument,
  canCreateOtterImport,
  canReadOtterImports,
  canReadSites,
  canReadSiteDocuments,
  canWriteSiteDocuments,
  enforceWritableSite,
  filterWritableSites,
} from '../../src/access/authorization'
import { getAuditChanges } from '../../src/collections/AuditLogs'
import { createOtterScanner, pollOtter } from '../../src/otter/controller'
import {
  otterCreateAccess,
  OtterProfiles,
  OtterSchedules,
  otterReadAccess,
  otterWriteAccess,
} from '../../src/collections/Otter'
import {
  decryptOtterCredentials,
  encryptOtterCredentials,
  newToken,
  otterMachineStrategy,
  requireOtterConfigAccess,
  requireOtterScanner,
  scannerIDFromRequest,
  tokenDigest,
  validateOtterConfiguration,
  validateOtterCredentials,
} from '../../src/otter/security'
import { cronForSchedule, dueOccurrence, validateScheduleInput } from '../../src/otter/scheduling'

const encryptionKey = 'a'.repeat(64)

beforeEach(() => {
  process.env.OTSERVER_OTTER_ENCRYPTION_KEY = encryptionKey
})

describe.each(['development', 'production'])('Otter browser requests in %s', (environment) => {
  beforeEach(() => {
    vi.stubEnv('NODE_ENV', environment)
    vi.stubEnv('OTSERVER_PUBLIC_URL', 'https://otserver.example')
  })
  afterEach(() => vi.unstubAllEnvs())

  const create = (url: string, origin: string, headers: Record<string, string> = {}) =>
    createOtterScanner(
      Object.assign(
        new Request(`${url}/api/otter/v1/scanners`, {
          method: 'POST',
          headers: { ...headers, ...(origin ? { Origin: origin } : {}) },
          body: JSON.stringify({ name: 'Local Otter', site: 'site-1' }),
        }),
        { context: {}, payload: { findGlobal: vi.fn(async () => ({})) } },
      ) as never,
    )

  it.each(['localhost', '127.0.0.1', '[::1]'])(
    'allows HTTP controller URLs on %s',
    async (host) => {
      const url = `http://${host}:3000`
      vi.stubEnv('OTSERVER_PUBLIC_URL', url)
      // Passing the URL checks must still reach authentication, never bypass it.
      await expect(create(url, url)).rejects.toMatchObject({ status: 401 })
    },
  )

  it.each(['localhost', '127.0.0.1', '[::1]'])(
    'accepts the local browser origin %s despite a public URL',
    async (host) => {
      await expect(create('http://127.0.0.1:3000', `http://${host}:3000`)).rejects.toMatchObject({
        status: 401,
      })
    },
  )

  it('accepts loopback Host and forwarded headers when the server URL is internal', async () => {
    await expect(
      create('http://0.0.0.0:3000', 'http://localhost:3000', {
        host: 'localhost:3000',
      }),
    ).rejects.toMatchObject({ status: 401 })
    await expect(
      create('http://internal:3000', 'http://[::1]:3000', {
        'x-forwarded-host': '[::1]:3000, internal:3000',
        'x-forwarded-proto': 'http, http',
      }),
    ).rejects.toMatchObject({ status: 401 })
  })

  it.each([
    '',
    'null',
    'not a URL',
    'https://attacker.example',
    'http://localhost.attacker.example:3000',
    'http://192.168.50.10:3000',
    'http://localhost:4000',
    'https://localhost:3000',
  ])('rejects unrelated or malformed browser origins: %s', async (origin) => {
    await expect(create('http://localhost:3000', origin)).rejects.toMatchObject({ status: 403 })
  })

  it.each([
    'http://scanner-host.example',
    'http://192.168.50.10:3000',
    'http://localhost.attacker.example:3000',
    'ftp://localhost:3000',
    'https://user:password@localhost:3000',
    'http://localhost:3000?query=1',
    'http://localhost:3000#fragment',
  ])('rejects insecure or invalid controller URLs: %s', async (url) => {
    vi.stubEnv('OTSERVER_PUBLIC_URL', url)
    const origin = new URL(url).origin
    await expect(create(origin, origin)).rejects.toMatchObject({ status: 503 })
  })

  it('accepts the configured HTTPS origin behind a proxy', async () => {
    await expect(create('http://internal:3000', 'https://otserver.example')).rejects.toMatchObject({
      status: 401,
    })
  })

  it('keeps production pinned to the configured non-loopback origin', async () => {
    vi.stubEnv('NODE_ENV', 'production')
    await expect(
      create('https://other.example', 'https://other.example', {
        'x-forwarded-host': 'other.example',
        'x-forwarded-proto': 'https',
      }),
    ).rejects.toMatchObject({ status: 403 })
    await expect(create('https://other.example', 'http://localhost:3000')).rejects.toMatchObject({
      status: 403,
    })
  })
})

describe('Otter security and scheduling boundaries', () => {
  it('covers every local Otter configuration option with managed fields or encrypted credentials', async () => {
    const source = await readFile('otserver-otter/src/main.rs', 'utf8')
    const config = source.match(/pub struct ScannerConfig \{([\s\S]*?)\n\}/)![1]!
    const options = [...config.matchAll(/pub (\w+):/g)].map(([, name]) =>
      name!.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase()),
    )
    const fieldNames = (fields: Field[]): string[] =>
      fields.flatMap((field) => [
        ...('name' in field ? [field.name] : []),
        ...('fields' in field ? fieldNames(field.fields) : []),
      ])
    const managed = ['output', 'serverUrl', 'apiKey']
    const encrypted = ['snmp', 'opcuaCredentials', 'opcuaUsername', 'opcuaPassword']
    expect(
      options.filter(
        (option) =>
          ![...fieldNames(OtterProfiles.fields), ...managed, ...encrypted].includes(option),
      ),
    ).toEqual([])
  })

  it('encrypts credentials with authenticated encryption and never stores plaintext', () => {
    const credentials = {
      snmp: [{ version: '3', username: 'inventory', authPassword: 'do-not-log-this' }],
    }
    const encrypted = encryptOtterCredentials(credentials)
    expect(encrypted).not.toContain('do-not-log-this')
    expect(decryptOtterCredentials(encrypted)).toEqual(credentials)
    const [version, iv, tag, ciphertext] = encrypted.split('.')
    const alteredTag = (tag!.startsWith('A') ? 'B' : 'A') + tag!.slice(1)
    expect(() => decryptOtterCredentials(`${version}.${iv}.${alteredTag}.${ciphertext}`)).toThrow()
  })

  it('requires a deployment encryption key before storing secrets', () => {
    delete process.env.OTSERVER_OTTER_ENCRYPTION_KEY
    expect(() => encryptOtterCredentials({ snmp: [] })).toThrow(/not configured/i)
  })

  it('rejects malformed keys and encrypted credential envelopes', () => {
    process.env.OTSERVER_OTTER_ENCRYPTION_KEY = 'z'.repeat(64)
    expect(() => encryptOtterCredentials({ snmp: [] })).toThrow(/not configured/i)
    expect(() => decryptOtterCredentials('v2.iv.tag.data')).toThrow(/unsupported format/i)
    process.env.OTSERVER_OTTER_ENCRYPTION_KEY = encryptionKey
    expect(decryptOtterCredentials(null)).toEqual({})
    const encrypted = encryptOtterCredentials({ opcuaCredentials: [] })
    process.env.OTSERVER_OTTER_ENCRYPTION_KEY = 'c'.repeat(64)
    expect(() => decryptOtterCredentials(encrypted)).toThrow(/could not be decrypted/i)
  })

  it('validates scanner input and rejects management-controlled or unsupported settings', () => {
    expect(() => validateOtterConfiguration(null)).toThrow(/object/i)
    expect(() => validateOtterConfiguration({})).toThrow(/IPv4/i)
    expect(
      validateOtterConfiguration({
        targets: ['192.0.2.1', '192.0.2.0/24'],
        interface: 'eth0',
        noSnmp: true,
        noSmb: true,
        noRpc: true,
        noHttp: true,
        noAds: true,
        adsSourceNetId: '192.0.2.1.1.1',
        adsTargetNetIds: { '192.0.2.10': '10.0.0.10.1.1' },
        adsPorts: [851, 801],
        opcuaPorts: [4840],
      }),
    ).toMatchObject({
      targets: ['192.0.2.1', '192.0.2.0/24'],
      noSmb: true,
      noRpc: true,
      noHttp: true,
      noAds: true,
      adsSourceNetId: '192.0.2.1.1.1',
      adsTargetNetIds: { '192.0.2.10': '10.0.0.10.1.1' },
      adsPorts: [851, 801],
    })
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], apiKey: 'secret' })).toThrow(
      /unsupported/i,
    )
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.999'] })).toThrow(/IPv4/i)
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], noArp: 'false' })).toThrow(
      /boolean/i,
    )
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.0/15'] })).toThrow(/65,536/i)
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], interface: '  ' })).toThrow(
      /interface/i,
    )
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], sourceMac: 'bad' })).toThrow(
      /MAC/i,
    )
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], opcuaPorts: [0] })).toThrow(
      /ports/i,
    )
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], adsSourceNetId: 7 })).toThrow(
      /NetID/i,
    )
    expect(() =>
      validateOtterConfiguration({ targets: ['192.0.2.1'], adsSourceNetId: '0.0.0.0.0.0' }),
    ).toThrow(/NetID/i)
    expect(() =>
      validateOtterConfiguration({
        targets: ['192.0.2.1'],
        adsTargetNetIds: { '192.0.2.999': '10.0.0.10.1.1' },
      }),
    ).toThrow(/NetID/i)
    expect(() =>
      validateOtterConfiguration({
        targets: ['192.0.2.1'],
        adsTargetNetIds: { '192.0.2.10': '10.0.0.10.1.256' },
      }),
    ).toThrow(/NetID/i)
    expect(() =>
      validateOtterConfiguration({ targets: ['192.0.2.1'], adsTargetNetIds: [] }),
    ).toThrow(/NetID/i)
    expect(() =>
      validateOtterConfiguration({ targets: ['192.0.2.1'], adsPorts: [851, 851] }),
    ).toThrow(/ADS AMS ports/i)
    expect(() => validateOtterConfiguration({ targets: ['192.0.2.1'], adsPorts: [65536] })).toThrow(
      /ADS AMS ports/i,
    )
  })

  it('accepts only the supported bounded credential shapes', () => {
    expect(
      validateOtterCredentials({
        snmp: [{ version: '3', username: 'inventory', authPassword: 'secret' }],
        opcuaCredentials: [{ username: 'operator', password: 'secret' }],
      }),
    ).toHaveProperty('snmp')
    expect(
      validateOtterCredentials({ snmp: { version: '2c', community: 'public' } }),
    ).toHaveProperty('snmp')
    expect(() => validateOtterCredentials({ apiKey: 'secret' })).toThrow(/unsupported/i)
    expect(() => validateOtterCredentials({ snmp: [{ community: 7 }] })).toThrow(/invalid/i)
    expect(() => validateOtterCredentials({ snmp: [null] })).toThrow(/invalid/i)
    expect(() => validateOtterCredentials({ snmp: [{ unexpected: 'field' }] })).toThrow(/invalid/i)
    expect(() => validateOtterCredentials('invalid')).toThrow(/object/i)
    expect(() => validateOtterCredentials({ snmp: [{ version: 'v99' }] })).toThrow(/invalid/i)
    expect(() => validateOtterCredentials({ snmp: [{ authProtocol: 'bad' }] })).toThrow(/invalid/i)
    expect(() => validateOtterCredentials({ snmp: [{ authProtocol: 'sha256' }] })).toThrow(
      /invalid/i,
    )
    expect(() => validateOtterCredentials({ snmp: [{ privacyProtocol: 'bad' }] })).toThrow(
      /invalid/i,
    )
    expect(() => validateOtterCredentials({ snmp: [{ privacyProtocol: 'aes128' }] })).toThrow(
      /invalid/i,
    )
    expect(
      validateOtterCredentials({
        snmp: [
          {
            version: '3',
            username: 'operator',
            authProtocol: 'sha256',
            authPassword: 'auth-password',
            privacyProtocol: 'aes128',
            privacyPassword: 'privacy-password',
          },
        ],
      }),
    ).toHaveProperty('snmp')
    expect(() => validateOtterCredentials({ opcuaCredentials: [{ username: 7 }] })).toThrow(
      /OPC UA/i,
    )
    expect(validateOtterCredentials({ opcuaCredentials: { username: 'operator' } })).toHaveProperty(
      'opcuaCredentials',
    )
    expect(() => validateOtterCredentials({ opcuaUsername: 7 })).toThrow(/text/i)
    expect(() => validateOtterCredentials({ opcuaPassword: 4 })).toThrow(/text/i)
  })

  it('redacts scanner and protocol credentials from audit changes', () => {
    expect(
      getAuditChanges(
        {},
        {
          community: 'private-community',
          encryptedCredentials: 'ciphertext',
          snmpAuthPassword: 'secret-password',
        },
      ),
    ).toEqual({
      community: { after: '[REDACTED]' },
      encryptedCredentials: { after: '[REDACTED]' },
      snmpAuthPassword: { after: '[REDACTED]' },
    })
  })

  it('issues opaque enrollment credentials and restricts their authentication routes', async () => {
    const credential = newToken()
    expect(credential).toHaveLength(43)
    expect(tokenDigest(credential)).toMatch(/^[a-f\d]{64}$/)
    const scanner = { id: 'scanner-1', site: 'site-1' }
    const payload = { find: async () => ({ docs: [scanner] }) }
    const req = { context: {}, url: 'https://otserver.example/api/otter/v1/poll' }
    const result = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: payload as never,
      req: req as never,
    })
    expect(result.user).toMatchObject({ id: 'otter:scanner-1', collection: 'users' })
    expect(req.context).toMatchObject({ otterScannerID: 'scanner-1', otterScannerSiteID: 'site-1' })
    expect(scannerIDFromRequest(req as never)).toBe('scanner-1')
    expect(requireOtterScanner(req as never)).toBe('scanner-1')

    const noScanner = { context: {} }
    expect(scannerIDFromRequest(noScanner as never)).toBeUndefined()
    expect(() => requireOtterScanner(noScanner as never)).toThrow(/authentication/i)

    const forbidden = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: payload as never,
      req: { ...req, url: 'https://otserver.example/api/assets' } as never,
    })
    expect(forbidden.user).toBeNull()
    const missingScanner = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: { find: async () => ({ docs: [] }) } as never,
      req: { context: {}, url: 'https://otserver.example/api/otter/v1/poll' } as never,
    })
    expect(missingScanner.user).toBeNull()
    const scannerWithoutSite = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: { find: async () => ({ docs: [{ id: 'scanner-without-site' }] }) } as never,
      req: { context: {}, url: 'https://otserver.example/api/otter/v1/poll' } as never,
    })
    expect(scannerWithoutSite.user).toBeNull()
    const invalidToken = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: 'Otter bad-token' }),
      payload: payload as never,
      req: { context: {}, url: 'https://otserver.example/api/otter/v1/poll' } as never,
    })
    expect(invalidToken.user).toBeNull()
    const invalidRequestURL = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: payload as never,
      req: { context: {}, url: 'http://[' } as never,
    })
    expect(invalidRequestURL.user).toBeNull()
    const noHeader = await otterMachineStrategy.authenticate({
      headers: new Headers(),
      payload: payload as never,
      req: { context: {}, url: 'https://otserver.example/api/otter/v1/poll' } as never,
    })
    expect(noHeader.user).toBeNull()
    const noRequest = await otterMachineStrategy.authenticate({
      headers: new Headers({ authorization: `Otter ${credential}` }),
      payload: payload as never,
    })
    expect(noRequest.user).toBeNull()
  })

  it('rejects controller polling for a disabled scanner principal', async () => {
    await expect(
      pollOtter({
        context: { otterScannerID: 'disabled-scanner' },
        payload: {
          findByID: async () => ({ id: 'disabled-scanner', enabled: false }),
        },
      } as never),
    ).rejects.toMatchObject({ status: 403 })
  })

  it('limits scanner API access to its own exact-site imports', async () => {
    const req: { context: Record<string, unknown>; user: { id: string } } = {
      context: { otterScannerID: 'scanner-1', otterScannerSiteID: 'site-1' },
      user: { id: 'otter:scanner-1' },
    }
    expect(
      await canCreateOtterImport({
        data: { site: 'site-1', source: 'otserver-otter' },
        req: req as never,
      }),
    ).toBe(true)
    expect(
      await canCreateOtterImport({
        data: { site: 'site-2', source: 'otserver-otter' },
        req: req as never,
      }),
    ).toBe(false)
    expect(
      await canCreateOtterImport({
        data: { site: 'site-1', source: 'nmap' },
        req: req as never,
      }),
    ).toBe(false)
    expect(await canReadOtterImports({ req: req as never })).toEqual({
      scanner: { equals: 'scanner-1' },
    })
    expect(await canWriteSiteDocuments({ req: req as never })).toBe(false)
    expect(await canReadSiteDocuments({ req: req as never })).toBe(false)
    expect(await canCreateSiteDocument({ data: { site: 'site-1' }, req: req as never })).toBe(false)
    req.context.assetImport = true
    expect(await canWriteSiteDocuments({ req: req as never })).toEqual({
      site: { equals: 'site-1' },
    })
    expect(await canReadSiteDocuments({ req: req as never })).toEqual({
      site: { equals: 'site-1' },
    })
    expect(await canReadSites({ req: req as never })).toEqual({ id: { equals: 'site-1' } })
    expect(await filterWritableSites({ req: req as never })).toEqual({
      id: { equals: 'site-1' },
    })
    expect(
      await canCreateSiteDocument({
        data: { site: 'site-1' },
        req: req as never,
      }),
    ).toBe(true)
    expect(
      await canCreateSiteDocument({
        data: { site: 'site-2' },
        req: req as never,
      }),
    ).toBe(false)
    const data = { site: 'site-1' }
    await expect(enforceWritableSite({ data, req: req as never } as never)).resolves.toBe(data)
    await expect(
      enforceWritableSite({
        data: { site: 'site-2' },
        req: { context: req.context, user: req.user } as never,
      } as never),
    ).rejects.toMatchObject({ status: 403 })
  })

  it('requires Otter Config and a writable assigned site for human management', async () => {
    const req = {
      context: {},
      user: { id: 'user-1', role: 'role-1' },
      payload: {
        find: async ({
          collection,
          where,
        }: {
          collection: string
          where?: Record<string, unknown>
        }) => {
          if (collection === 'user-roles')
            return {
              docs: [
                {
                  isAdmin: false,
                  otterConfig: true,
                  permissions: [{ site: 'site-1', access: 'read-write' }],
                },
              ],
            }
          if (collection === 'sites') {
            const parents = (where?.parent as { in?: string[] } | undefined)?.in || []
            return { docs: parents.includes('site-1') ? [{ id: 'child-1' }] : [] }
          }
          return { docs: [] }
        },
      },
    }
    await expect(requireOtterConfigAccess(req as never, 'site-1', true)).resolves.toBeUndefined()
    await expect(requireOtterConfigAccess(req as never, 'site-1', false)).resolves.toBeUndefined()
    await expect(requireOtterConfigAccess(req as never, 'child-1', true)).resolves.toBeUndefined()
    await expect(requireOtterConfigAccess(req as never, 'other-site', true)).rejects.toMatchObject({
      status: 403,
    })
    await expect(requireOtterConfigAccess(req as never, undefined, false)).rejects.toMatchObject({
      status: 403,
    })
    const noOtterRole = {
      ...req,
      context: {},
      payload: {
        find: async ({ collection }: { collection: string }) =>
          collection === 'user-roles'
            ? {
                docs: [
                  {
                    isAdmin: false,
                    otterConfig: false,
                    permissions: [{ site: 'site-1', access: 'read-write' }],
                  },
                ],
              }
            : { docs: [] },
      },
    }
    await expect(
      requireOtterConfigAccess(noOtterRole as never, 'site-1', true),
    ).rejects.toMatchObject({
      status: 403,
    })
    const readOnlyOtter = {
      ...req,
      context: {},
      payload: {
        find: async ({ collection }: { collection: string }) =>
          collection === 'user-roles'
            ? {
                docs: [
                  {
                    isAdmin: false,
                    otterConfig: true,
                    permissions: [{ site: 'site-1', access: 'read' }],
                  },
                ],
              }
            : { docs: [] },
      },
    }
    await expect(
      requireOtterConfigAccess(readOnlyOtter as never, 'site-1', false),
    ).resolves.toBeUndefined()
    await expect(
      requireOtterConfigAccess(readOnlyOtter as never, 'site-1', true),
    ).rejects.toMatchObject({
      status: 403,
    })
  })

  it('applies the Otter Config role and site scope to management collections', async () => {
    const makeRequest = (otterConfig: boolean, isAdmin = false) => ({
      context: {},
      user: { id: 'user-1', role: 'role-1' },
      payload: {
        find: async ({
          collection,
          where,
        }: {
          collection: string
          where?: Record<string, unknown>
        }) => {
          if (collection === 'user-roles')
            return {
              docs: [
                {
                  isAdmin,
                  otterConfig,
                  permissions: [{ site: 'site-1', access: 'read-write' }],
                },
              ],
            }
          if (collection === 'sites') {
            const parents = (where?.parent as { in?: string[] } | undefined)?.in || []
            return { docs: parents.includes('site-1') ? [{ id: 'child-1' }] : [] }
          }
          return { docs: [] }
        },
      },
    })
    const manager = makeRequest(true)
    expect(await otterReadAccess({ req: manager as never })).toMatchObject({
      site: { in: ['site-1', 'child-1'] },
    })
    expect(await otterWriteAccess({ req: manager as never })).toMatchObject({
      site: { in: ['site-1', 'child-1'] },
    })
    expect(await otterCreateAccess({ data: { site: 'site-1' }, req: manager as never })).toBe(true)
    expect(await otterCreateAccess({ data: { site: 'outside' }, req: manager as never })).toBe(
      false,
    )
    expect(await otterCreateAccess({ req: manager as never })).toBe(true)

    const reader = makeRequest(false)
    expect(await otterReadAccess({ req: reader as never })).toBe(false)
    expect(await otterWriteAccess({ req: reader as never })).toBe(false)
    expect(await otterCreateAccess({ req: reader as never })).toBe(false)

    const admin = makeRequest(false, true)
    expect(await otterReadAccess({ req: admin as never })).toBe(true)
    expect(await otterWriteAccess({ req: admin as never })).toBe(true)
    expect(await otterCreateAccess({ data: { site: 'outside' }, req: admin as never })).toBe(true)
    expect(await otterCreateAccess({ data: {}, req: admin as never })).toBe(true)
    await expect(requireOtterConfigAccess(admin as never, 'outside', true)).resolves.toBeUndefined()

    const scanner = {
      ...manager,
      context: { otterScannerID: 'scanner-1' },
    }
    expect(await otterReadAccess({ req: scanner as never })).toBe(false)
    expect(await otterWriteAccess({ req: scanner as never })).toBe(false)
    expect(await otterCreateAccess({ req: scanner as never })).toBe(false)
  })

  it('validates scanner/profile pairing, schedule caps, and admin schedule controls', async () => {
    let scannerSite = 'site-1'
    let profileSite = 'site-1'
    let profileScanner = 'scanner-1'
    let scheduledCount = 50
    const req = {
      context: {},
      user: { id: 'admin-1', role: 'admin-role' },
      payload: {
        find: async ({ collection }: { collection: string }) =>
          collection === 'user-roles' ? { docs: [{ isAdmin: true }] } : { docs: [] },
        findByID: async ({ collection, id }: { collection: string; id: string }) =>
          collection === 'sites'
            ? { id, type: 'type-1' }
            : collection === 'site-types'
              ? { id, blockImports: false }
              : collection === 'otter-scanners'
                ? { id, site: scannerSite }
                : {
                    id,
                    site: profileSite,
                    scanner: profileScanner,
                    encryptedCredentials: 'ciphertext',
                  },
        count: async () => ({ totalDocs: scheduledCount }),
      },
    }
    const scheduleHook = OtterSchedules.hooks!.beforeChange![0]!
    const scheduleCreateAccess = OtterSchedules.access!.create!
    const profileHook = OtterProfiles.hooks!.beforeChange![0]!
    const schedule = {
      cron: '0 2 * * *',
      enabled: true,
      intervalMinutes: 5,
      name: 'Test schedule',
      profile: 'profile-1',
      scanner: 'scanner-1',
      scheduleType: 'interval',
      site: 'site-1',
      timezone: 'UTC',
    }
    await expect(scheduleCreateAccess({ req } as never)).resolves.toBe(true)
    await expect(scheduleCreateAccess({ data: {}, req } as never)).resolves.toBe(true)
    await expect(
      scheduleHook({ data: schedule, operation: 'create', req } as never),
    ).rejects.toMatchObject({ status: 400 })

    await expect(
      scheduleHook({ data: { enabled: true }, operation: 'create', req } as never),
    ).rejects.toMatchObject({ status: 400 })

    scheduledCount = 0
    scannerSite = 'outside-site'
    await expect(
      scheduleHook({ data: schedule, operation: 'create', req } as never),
    ).rejects.toMatchObject({ status: 400 })

    scannerSite = 'site-1'
    profileSite = 'outside-site'
    await expect(
      scheduleHook({ data: schedule, operation: 'create', req } as never),
    ).rejects.toMatchObject({ status: 400 })
    profileSite = 'site-1'
    profileScanner = 'another-scanner'
    await expect(
      scheduleHook({ data: { ...schedule }, operation: 'create', req } as never),
    ).resolves.toMatchObject({ scanner: 'another-scanner', site: 'site-1' })
    profileScanner = 'scanner-1'

    await expect(
      profileHook({
        data: { name: 'Missing scanner', configuration: { targets: ['192.0.2.1'] } },
        operation: 'create',
        req,
      } as never),
    ).rejects.toMatchObject({ status: 400 })
    scannerSite = 'outside-site'
    await expect(
      profileHook({
        data: {
          name: 'Wrong site',
          site: 'site-1',
          scanner: 'scanner-1',
          configuration: { targets: ['192.0.2.1'] },
        },
        operation: 'create',
        req,
      } as never),
    ).rejects.toMatchObject({ status: 400 })
    scannerSite = 'site-1'
    const profileUpdate = await profileHook({
      data: { name: 'Updated' },
      operation: 'update',
      originalDoc: {
        id: 'profile-1',
        site: 'site-1',
        scanner: 'scanner-1',
        configuration: { targets: ['192.0.2.1'] },
      },
      req,
    } as never)
    expect(profileUpdate).toMatchObject({
      encryptedCredentials: 'ciphertext',
      credentialsConfigured: true,
    })

    scheduledCount = 0
    const disabled = { ...schedule, enabled: false }
    expect(await scheduleHook({ data: disabled, operation: 'create', req } as never)).toMatchObject(
      {
        enabled: false,
        nextRunAt: null,
      },
    )
    await expect(
      scheduleHook({
        data: { enabled: false },
        operation: 'update',
        originalDoc: {
          site: 'site-1',
          scanner: 'scanner-1',
          scheduleType: 'interval',
          intervalMinutes: 5,
          timezone: 'UTC',
          enabled: true,
        },
        req,
      } as never),
    ).rejects.toMatchObject({ status: 400 })

    const scannerFilter = OtterProfiles.fields.find(
      (field) => 'name' in field && field.name === 'scanner',
    )
    const filter =
      scannerFilter && 'filterOptions' in scannerFilter ? scannerFilter.filterOptions : undefined
    expect(typeof filter === 'function' ? await filter({ req } as never) : null).toBe(true)
    const siteManager = {
      context: {},
      user: { id: 'operator-1', role: 'operator-role' },
      payload: {
        find: async ({ collection }: { collection: string }) =>
          collection === 'user-roles'
            ? {
                docs: [
                  {
                    isAdmin: false,
                    otterConfig: true,
                    permissions: [{ site: 'site-1', access: 'read-write' }],
                  },
                ],
              }
            : { docs: [] },
      },
    }
    expect(
      typeof filter === 'function' ? await filter({ req: siteManager } as never) : null,
    ).toEqual({ site: { in: ['site-1'] } })

    const scheduleFields = OtterSchedules.fields.filter((field) => 'name' in field)
    for (const [name, type] of [
      ['runAt', 'once'],
      ['intervalMinutes', 'interval'],
      ['cron', 'cron'],
    ]) {
      const field = scheduleFields.find((candidate) => candidate.name === name)
      const condition = field && 'admin' in field ? field.admin?.condition : undefined
      expect(
        typeof condition === 'function'
          ? condition({}, { scheduleType: type }, {} as never)
          : false,
      ).toBe(true)
      expect(
        typeof condition === 'function'
          ? condition({}, { scheduleType: 'other' }, {} as never)
          : false,
      ).toBe(false)
    }
  })

  it('validates calendar time zones and coalesces interval catch-up to the latest occurrence', () => {
    expect(
      validateScheduleInput(
        { scheduleType: 'interval', intervalMinutes: 5 },
        new Date('2026-01-01T00:00:00.000Z'),
      ),
    ).toBe('2026-01-01T00:05:00.000Z')
    expect(
      dueOccurrence(
        {
          scheduleType: 'interval',
          intervalMinutes: 5,
          nextRunAt: '2026-01-01T00:00:00.000Z',
        },
        new Date('2026-01-01T00:17:00.000Z'),
      ),
    ).toEqual({
      occurrence: new Date('2026-01-01T00:15:00.000Z'),
      nextRunAt: '2026-01-01T00:20:00.000Z',
    })
    expect(() => validateScheduleInput({ scheduleType: 'interval', intervalMinutes: 1 })).toThrow()
    expect(() =>
      validateScheduleInput({ scheduleType: 'interval', intervalMinutes: 10_081 }),
    ).toThrow()
    expect(() => validateScheduleInput({ scheduleType: 'once', runAt: 'not a date' })).toThrow()
    expect(() => validateScheduleInput({ scheduleType: 'once' })).toThrow()
    expect(validateScheduleInput({ scheduleType: 'once', runAt: '2026-01-01T00:00:00Z' })).toBe(
      '2026-01-01T00:00:00.000Z',
    )
    expect(() => validateScheduleInput({ scheduleType: 'unknown' as never })).toThrow()
    expect(() => validateScheduleInput({ scheduleType: 'cron' })).toThrow()
    expect(() =>
      validateScheduleInput({ scheduleType: 'interval', intervalMinutes: 5, timezone: 'Bad/Zone' }),
    ).toThrow()
    expect(() =>
      validateScheduleInput({ scheduleType: 'cron', cron: '0 0 * * *', timezone: 'x'.repeat(129) }),
    ).toThrow()
    expect(() => cronForSchedule('too many fields in this schedule', 'UTC')).toThrow()
    expect(() => cronForSchedule('x x x x x', 'UTC')).toThrow()
    expect(
      validateScheduleInput(
        { scheduleType: 'cron', cron: '0 2 * * *', timezone: 'UTC' },
        new Date('2026-01-01T00:00:00.000Z'),
      ),
    ).toBe('2026-01-01T02:00:00.000Z')
    expect(() => validateScheduleInput({ scheduleType: 'cron', cron: '99 99 * * *' })).toThrow()
    expect(() => validateScheduleInput({ scheduleType: 'cron', cron: '0 0 31 2 *' })).toThrow(
      /upcoming/i,
    )
    expect(
      dueOccurrence(
        { scheduleType: 'once', nextRunAt: '2026-01-01T00:00:00.000Z' },
        new Date('2026-01-02T00:00:00.000Z'),
      ),
    ).toEqual({ occurrence: new Date('2026-01-01T00:00:00.000Z'), nextRunAt: undefined })
    expect(
      dueOccurrence(
        {
          scheduleType: 'cron',
          cron: '0 2 * * *',
          timezone: 'UTC',
          nextRunAt: '2030-01-01T00:00:00Z',
        },
        new Date('2026-01-01T00:00:00Z'),
      ),
    ).toBeUndefined()
    expect(
      dueOccurrence(
        { scheduleType: 'unsupported' as never, nextRunAt: '2026-01-01T00:00:00Z' },
        new Date('2026-01-02T00:00:00Z'),
      ),
    ).toBeUndefined()
    expect(
      dueOccurrence(
        { scheduleType: 'interval', intervalMinutes: 0, nextRunAt: '2026-01-01T00:00:00Z' },
        new Date('2026-01-02T00:00:00Z'),
      ),
    ).toBeUndefined()
    expect(dueOccurrence({ scheduleType: 'once' })).toBeUndefined()
    expect(
      dueOccurrence(
        { scheduleType: 'cron', cron: '0 2 * * *', nextRunAt: '2026-01-01T00:00:00Z' },
        new Date('2026-01-02T04:00:00Z'),
      ),
    ).toBeDefined()
    expect(
      dueOccurrence(
        { scheduleType: 'cron', cron: '0 0 31 2 *', nextRunAt: '2026-01-01T00:00:00Z' },
        new Date('2026-01-02T00:00:00Z'),
      ),
    ).toBeUndefined()
  })

  it('coalesces missed cron occurrences to the most recent run', () => {
    expect(
      dueOccurrence(
        {
          cron: '0 2 * * *',
          scheduleType: 'cron',
          timezone: 'UTC',
          nextRunAt: '2026-01-01T02:00:00.000Z',
        },
        new Date('2026-01-02T04:00:00.000Z'),
      ),
    ).toEqual({
      occurrence: new Date('2026-01-02T02:00:00.000Z'),
      nextRunAt: '2026-01-03T02:00:00.000Z',
    })
  })
})
