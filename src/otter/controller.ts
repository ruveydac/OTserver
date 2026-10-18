import { APIError, type Endpoint, type Payload, type PayloadRequest } from 'payload'
import { isIP } from 'node:net'
import { getAuthorization, relationshipID } from '../access/authorization'
import { inTransaction } from '../integrations/payload/transactions'
import type { OtterRun, OtterScanner, OtterSchedule } from '../payload-types'
import {
  decryptOtterCredentials,
  encryptOtterCredentials,
  newToken,
  requireOtterConfigAccess,
  requireOtterScanner,
  scannerIDFromRequest,
  tokenDigest,
  validateOtterCredentials,
  validateOtterConfiguration,
} from './security'
import { dueOccurrence } from './scheduling'
import { getAssetOverrides } from '../application/processImport'
import { systemRequest } from '../integrations/payload/requests'
import {
  assertSiteAllowsImports,
  IMPORTS_BLOCKED_MESSAGE,
  importableSitesWhere,
  siteBlocksImports,
} from '../application/importSites'
import {
  activeRunStatuses,
  assertCurrentOtterRunLease,
  assertOtterRunOwner,
  isRunLeaseExpired,
} from './runLease'

const json = (data: unknown, status = 200) =>
  Response.json(data, { headers: { 'Cache-Control': 'no-store' }, status })

const scannerReport = (input: Record<string, unknown>) => {
  if (
    input.version !== undefined &&
    (typeof input.version !== 'string' || input.version.length > 64)
  )
    throw new APIError('Scanner version is invalid.', 400)
  for (const key of ['capabilities', 'interfaces']) {
    const value = input[key]
    if (
      value !== undefined &&
      (!Array.isArray(value) ||
        value.length > 128 ||
        value.some((entry) => typeof entry !== 'string' || entry.length > 256))
    )
      throw new APIError(`Scanner ${key} must be a bounded list of text values.`, 400)
  }
  if (
    input.computerName !== undefined &&
    (typeof input.computerName !== 'string' ||
      !input.computerName.trim() ||
      input.computerName.length > 256 ||
      /[\u0000-\u001f]/.test(input.computerName))
  )
    throw new APIError('Scanner computer name is invalid.', 400)

  let networkAdapters:
    | Array<{
        name: string
        friendlyName: string
        description: string
        macAddress?: string
        ipAddresses: string[]
      }>
    | undefined
  if (input.networkAdapters !== undefined) {
    if (!Array.isArray(input.networkAdapters) || input.networkAdapters.length > 32)
      throw new APIError('Scanner network adapters must be a bounded list.', 400)
    networkAdapters = input.networkAdapters.map((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new APIError('Scanner network adapter is invalid.', 400)
      const adapter = value as Record<string, unknown>
      if (
        Object.keys(adapter).some(
          (key) =>
            !['name', 'friendlyName', 'description', 'macAddress', 'ipAddresses'].includes(key),
        ) ||
        ['name', 'friendlyName', 'description'].some(
          (key) =>
            typeof adapter[key] !== 'string' ||
            !String(adapter[key]).trim() ||
            String(adapter[key]).length > 256 ||
            /[\u0000-\u001f]/.test(String(adapter[key])),
        ) ||
        (adapter.macAddress !== undefined &&
          (typeof adapter.macAddress !== 'string' ||
            !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(adapter.macAddress))) ||
        !Array.isArray(adapter.ipAddresses) ||
        adapter.ipAddresses.length > 16 ||
        adapter.ipAddresses.some(
          (address) => typeof address !== 'string' || isIP(address) === 0 || address.length > 64,
        )
      )
        throw new APIError('Scanner network adapter is invalid.', 400)
      return {
        name: adapter.name as string,
        friendlyName: adapter.friendlyName as string,
        description: adapter.description as string,
        ...(typeof adapter.macAddress === 'string'
          ? { macAddress: adapter.macAddress.toUpperCase() }
          : {}),
        ipAddresses: [...new Set(adapter.ipAddresses as string[])],
      }
    })
  }
  return {
    ...(typeof input.version === 'string' ? { version: input.version } : {}),
    ...(Array.isArray(input.capabilities) ? { capabilities: input.capabilities as string[] } : {}),
    ...(Array.isArray(input.interfaces) ? { interfaces: input.interfaces as string[] } : {}),
    ...(typeof input.computerName === 'string' ? { computerName: input.computerName.trim() } : {}),
    ...(networkAdapters ? { networkAdapters } : {}),
  }
}

const body = async (req: PayloadRequest, maxBytes = 32_000) => {
  const length = Number(req.headers.get('content-length') || 0)
  if (length > maxBytes) throw new APIError('Request body is too large.', 413)
  const stream = (req as Request).body
  if (!stream) throw new APIError('A JSON request body is required.', 400)
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let bytes = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    bytes += value.byteLength
    if (bytes > maxBytes) {
      await reader.cancel()
      throw new APIError('Request body is too large.', 413)
    }
    chunks.push(value)
  }
  const text = Buffer.concat(chunks).toString('utf8')
  try {
    const result: unknown = JSON.parse(text)
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error()
    return result as Record<string, unknown>
  } catch {
    throw new APIError('A JSON object is required.', 400)
  }
}

const isLoopbackURL = (url: URL) =>
  ['http:', 'https:'].includes(url.protocol) &&
  ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)

const humanOrigin = (req: PayloadRequest) => {
  const origin = req.headers.get('origin')
  const configured = process.env.OTSERVER_PUBLIC_URL
  if (!origin || !req.url) throw new APIError('A same-origin browser request is required.', 403)

  const allowedURLs: URL[] = []
  let hasConfiguredOrigin = false
  if (configured) {
    try {
      allowedURLs.push(new URL(configured))
      hasConfiguredOrigin = true
    } catch {
      // A malformed public URL does not invalidate the request's actual same origin.
    }
  }

  const allowRequestOrigin = !hasConfiguredOrigin || process.env.NODE_ENV !== 'production'
  let requestURL: URL
  try {
    requestURL = new URL(req.url, 'http://otserver.invalid')
  } catch {
    throw new APIError('A same-origin browser request is required.', 403)
  }
  if (allowRequestOrigin || isLoopbackURL(requestURL)) allowedURLs.push(requestURL)

  const firstHeader = (name: string) => req.headers.get(name)?.split(',')[0]?.trim()
  const host = firstHeader('x-forwarded-host') || req.headers.get('host')
  const protocol = firstHeader('x-forwarded-proto') || requestURL.protocol.slice(0, -1)
  if (host && ['http', 'https'].includes(protocol)) {
    try {
      const forwardedURL = new URL(`${protocol}://${host}`)
      if (allowRequestOrigin || isLoopbackURL(forwardedURL)) allowedURLs.push(forwardedURL)
    } catch {
      // Ignore malformed proxy headers and fail closed below.
    }
  }

  try {
    const browserURL = new URL(origin)
    if (
      allowedURLs.some(
        (url) =>
          url.origin === browserURL.origin ||
          // Loopback aliases can differ from Next's internal host, including in standalone builds.
          (isLoopbackURL(url) &&
            isLoopbackURL(browserURL) &&
            url.protocol === browserURL.protocol &&
            url.port === browserURL.port),
      )
    )
      return
  } catch {
    // An invalid Origin is rejected with the same response as a foreign origin.
  }
  throw new APIError('Cross-origin Otter management requests are not allowed.', 403)
}

const requireHuman = async (req: PayloadRequest, site?: unknown, write = false) => {
  if (scannerIDFromRequest(req)) throw new APIError('This action requires a management user.', 403)
  if (!req.user) throw new APIError('Authentication is required.', 401)
  const auth = await getAuthorization(req)
  if (!auth.canConfigureOtter) throw new APIError('The Otter Config role is required.', 403)
  if (site !== undefined) await requireOtterConfigAccess(req, site, write)
  return auth
}

const scannerDocument = async (req: PayloadRequest): Promise<OtterScanner> => {
  const id = requireOtterScanner(req)
  const scanner = await req.payload.findByID({
    collection: 'otter-scanners',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
  if (!scanner.enabled) throw new APIError('Otter scanner is disabled.', 403)
  return scanner
}

const profileFor = async (req: PayloadRequest, id: unknown, scannerID: string) => {
  if (typeof id !== 'string') throw new APIError('A scan profile is required.', 400)
  const profile = await req.payload.findByID({
    collection: 'otter-profiles',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
  if (String(relationshipID(profile.scanner)) !== scannerID)
    throw new APIError('The profile does not belong to this scanner.', 403)
  const configuration = validateOtterConfiguration(profile.configuration)
  return { configuration, encryptedCredentials: profile.encryptedCredentials, profile }
}

const publicControllerURL = () => {
  const value = process.env.OTSERVER_PUBLIC_URL
  if (!value)
    throw new APIError('OTSERVER_PUBLIC_URL must be configured before Otter jobs can run.', 503)
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new APIError('OTSERVER_PUBLIC_URL is invalid.', 503)
  }
  if (url.username || url.password || url.search || url.hash)
    throw new APIError(
      'OTSERVER_PUBLIC_URL must not contain credentials, a query, or a fragment.',
      503,
    )
  if (url.protocol !== 'https:' && !isLoopbackURL(url))
    throw new APIError('OTSERVER_PUBLIC_URL must use HTTPS, or HTTP on localhost/loopback.', 503)
  return url.toString().replace(/\/$/, '')
}

const runInput = async (
  req: PayloadRequest,
  scanner: OtterScanner,
  profileID: unknown,
  schedule?: OtterSchedule,
  scheduledFor?: Date,
) => {
  const { configuration, encryptedCredentials, profile } = await profileFor(
    req,
    profileID,
    String(scanner.id),
  )
  const siteID = String(relationshipID(scanner.site))
  if (String(relationshipID(profile.site)) !== siteID)
    throw new APIError('The profile and scanner must belong to the same site.', 400)
  await assertSiteAllowsImports(siteID, req)
  return {
    configSnapshot: {
      ...configuration,
      name: profile.name,
    },
    importOverridesSnapshot: {
      assetOverrides: getAssetOverrides(profile.assetOverrides),
      customFieldOverrides: profile.customFieldOverrides || {},
    },
    encryptedCredentialsSnapshot: encryptedCredentials || null,
    name: schedule?.name ? `${profile.name} — ${schedule.name}` : profile.name,
    profile: profile.id,
    ...(schedule ? { schedule: schedule.id } : {}),
    ...(scheduledFor ? { scheduledFor: scheduledFor.toISOString() } : {}),
    site: siteID,
    scanner: String(scanner.id),
    status: 'queued' as const,
  }
}

const isActiveRun = (run: OtterRun) => activeRunStatuses.includes(run.status)
const leaseExpiredMessage =
  'Scanner lease expired because no heartbeat was received before the deadline. The scanner may have stopped or lost its controller connection.'

const expireRun = async (req: PayloadRequest, run: OtterRun, scanner: OtterScanner, now: Date) => {
  await req.payload.update({
    collection: 'otter-runs',
    id: run.id,
    overrideAccess: true,
    req,
    data: {
      status: 'expired',
      completedAt: now.toISOString(),
      message: leaseExpiredMessage,
    },
  })
  if (String(relationshipID(scanner.currentRun)) !== String(run.id)) return
  await req.payload.update({
    collection: 'otter-scanners',
    context: { otterScannerUpdate: true },
    id: scanner.id,
    overrideAccess: true,
    req,
    data: { currentRun: null },
  })
  scanner.currentRun = null
}

/** Expire abandoned assignments without relying on another scanner poll. */
export const expireOtterLeases = async (payload: Payload, now = new Date()) => {
  const req = await systemRequest(payload)
  const stale = await payload.find({
    collection: 'otter-runs',
    depth: 0,
    limit: 100,
    overrideAccess: true,
    req,
    where: {
      and: [
        { status: { in: activeRunStatuses } },
        {
          or: [
            { leaseExpiresAt: { less_than_equal: now.toISOString() } },
            { leaseExpiresAt: { exists: false } },
          ],
        },
      ],
    },
  })
  for (const candidate of stale.docs) {
    await inTransaction(req, async () => {
      const run = await payload.findByID({
        collection: 'otter-runs',
        depth: 0,
        id: candidate.id,
        overrideAccess: true,
        req,
      })
      if (!isActiveRun(run) || !isRunLeaseExpired(run, now)) return
      const scannerID = relationshipID(run.scanner)
      if (!scannerID) {
        await payload.update({
          collection: 'otter-runs',
          id: run.id,
          overrideAccess: true,
          req,
          data: {
            status: 'expired',
            completedAt: now.toISOString(),
            message: leaseExpiredMessage,
          },
        })
        return
      }
      const scanner = await payload.findByID({
        collection: 'otter-scanners',
        depth: 0,
        id: String(scannerID),
        overrideAccess: true,
        req,
      })
      await expireRun(req, run, scanner, now)
    })
  }
}

const cancelBlockedRun = async (req: PayloadRequest, run: OtterRun): Promise<OtterRun> =>
  run.status === 'cancel-requested'
    ? run
    : req.payload.update({
        collection: 'otter-runs',
        id: run.id,
        overrideAccess: true,
        req,
        data: { status: 'cancel-requested', message: IMPORTS_BLOCKED_MESSAGE },
      })

const assignJob = async (req: PayloadRequest, scanner: OtterScanner, now: Date) => {
  const blocked = await siteBlocksImports(scanner.site, req)
  const activeID = relationshipID(scanner.currentRun)
  if (activeID) {
    const active = await req.payload.findByID({
      collection: 'otter-runs',
      depth: 0,
      id: String(activeID),
      overrideAccess: true,
      req,
    })
    if (isActiveRun(active)) {
      if (!isRunLeaseExpired(active, now)) return blocked ? cancelBlockedRun(req, active) : active
      await expireRun(req, active, scanner, now)
    } else {
      await req.payload.update({
        collection: 'otter-scanners',
        context: { otterScannerUpdate: true },
        id: scanner.id,
        overrideAccess: true,
        req,
        data: { currentRun: null },
      })
      scanner.currentRun = null
    }
  }

  if (blocked) return undefined
  const schedules = await req.payload.find({
    collection: 'otter-schedules',
    depth: 0,
    limit: 100,
    overrideAccess: true,
    req,
    sort: 'nextRunAt',
    where: {
      and: [
        { scanner: { equals: scanner.id } },
        { enabled: { equals: true } },
        { nextRunAt: { less_than_equal: now.toISOString() } },
      ],
    },
  })
  for (const schedule of schedules.docs) {
    const due = dueOccurrence(
      schedule as unknown as import('./scheduling').ScheduleInput & { nextRunAt?: string },
      now,
    )
    if (!due) continue
    const profileID = relationshipID(schedule.profile)
    const input = await runInput(req, scanner, String(profileID), schedule, due.occurrence)
    const occurrenceKey = `${schedule.id}:${due.occurrence.toISOString()}`
    const existing = await req.payload.find({
      collection: 'otter-runs',
      depth: 0,
      limit: 1,
      overrideAccess: true,
      req,
      where: { scheduleOccurrenceKey: { equals: occurrenceKey } },
    })
    if (!existing.docs.length)
      await req.payload.create({
        collection: 'otter-runs',
        data: { ...input, scheduleOccurrenceKey: occurrenceKey },
        overrideAccess: true,
        req,
      })
    await req.payload.update({
      collection: 'otter-schedules',
      id: schedule.id,
      overrideAccess: true,
      req,
      context: { otterSchedulerUpdate: true },
      data: {
        enabled: schedule.scheduleType === 'once' ? false : schedule.enabled,
        nextRunAt: due.nextRunAt || null,
      },
    })
  }

  const pending = await req.payload.find({
    collection: 'otter-runs',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    sort: 'createdAt',
    where: { and: [{ scanner: { equals: scanner.id } }, { status: { equals: 'queued' } }] },
  })
  const run = pending.docs[0]
  if (!run) return undefined
  const leaseExpiresAt = new Date(now.getTime() + 120_000).toISOString()
  const assigned = await req.payload.update({
    collection: 'otter-runs',
    id: run.id,
    overrideAccess: true,
    req,
    data: { assignedAt: now.toISOString(), leaseExpiresAt, status: 'assigned' },
  })
  await req.payload.update({
    collection: 'otter-scanners',
    context: { otterScannerUpdate: true },
    id: scanner.id,
    overrideAccess: true,
    req,
    data: { currentRun: String(run.id) },
  })
  scanner.currentRun = String(run.id)
  return assigned
}

const jobResponse = (run: OtterRun, scanner: OtterScanner) => {
  if (run.status === 'cancel-requested') return { action: 'cancel', runID: String(run.id) }
  if (
    !run.configSnapshot ||
    typeof run.configSnapshot !== 'object' ||
    Array.isArray(run.configSnapshot)
  )
    throw new APIError('Stored Otter run configuration is invalid.', 500)
  const configuration = run.configSnapshot as Record<string, unknown>
  return {
    action: 'run',
    run: {
      configuration: {
        ...configuration,
        serverUrl: publicControllerURL(),
        site: String(relationshipID(scanner.site)),
      },
      credentials: decryptOtterCredentials(run.encryptedCredentialsSnapshot),
      id: String(run.id),
      leaseExpiresAt: run.leaseExpiresAt,
      uploadPath: '/api/asset-imports',
    },
  }
}

export const otterOverview: Endpoint['handler'] = async (req) => {
  const authorization = await requireHuman(req)
  const scanners = await req.payload.find({
    collection: 'otter-scanners',
    depth: 1,
    limit: 200,
    overrideAccess: false,
    req,
    sort: 'name',
  })
  const scannerIDs = scanners.docs.map((scanner) => String(scanner.id))
  const [schedules, runs] = await Promise.all([
    req.payload.find({
      collection: 'otter-schedules',
      depth: 0,
      limit: 500,
      overrideAccess: false,
      req,
      sort: 'nextRunAt',
      where: authorization.isAdmin
        ? { scanner: { in: scannerIDs } }
        : {
            and: [{ scanner: { in: scannerIDs } }, { site: { in: authorization.readableSiteIDs } }],
          },
    }),
    req.payload.find({
      collection: 'otter-runs',
      depth: 0,
      limit: 100,
      overrideAccess: false,
      req,
      sort: '-createdAt',
      where: { scanner: { in: scannerIDs } },
    }),
  ])
  const profiles = await req.payload.find({
    collection: 'otter-profiles',
    depth: 0,
    limit: 500,
    overrideAccess: false,
    req,
    sort: 'name',
    where: { scanner: { in: scannerIDs } },
  })
  const sites = await req.payload.find({
    collection: 'sites',
    depth: 0,
    limit: 1000,
    overrideAccess: false,
    req,
    sort: 'path',
    where: authorization.isAdmin ? {} : { id: { in: authorization.readableSiteIDs } },
  })
  const writableSites = await req.payload.find({
    collection: 'sites',
    depth: 0,
    limit: 1000,
    overrideAccess: false,
    req,
    sort: 'path',
    where: {
      and: [
        importableSitesWhere,
        ...(authorization.isAdmin ? [] : [{ id: { in: authorization.writableSiteIDs } }]),
      ],
    },
  })
  return json({
    controllerUrl: process.env.OTSERVER_PUBLIC_URL ? publicControllerURL() : '',
    runs: runs.docs.map(
      ({
        id,
        name,
        scanner,
        status,
        scheduledFor,
        completedAt,
        progress,
        message,
        import: imported,
      }) => ({
        id,
        name,
        scanner: String(relationshipID(scanner)),
        status,
        scheduledFor,
        completedAt,
        progress,
        message,
        import: relationshipID(imported),
      }),
    ),
    scanners: scanners.docs.map(
      ({
        id,
        name,
        site,
        enabled,
        enrolledAt,
        interfaces,
        networkAdapters,
        computerName,
        inventoryReportedAt,
        lastSeenAt,
        version,
        currentRun,
      }) => ({
        id,
        name,
        site: String(relationshipID(site) ?? ''),
        enabled,
        enrolled: Boolean(enrolledAt),
        enrolledAt,
        lastSeenAt,
        version,
        interfaces: Array.isArray(interfaces)
          ? interfaces.filter((entry): entry is string => typeof entry === 'string')
          : [],
        computerName,
        networkAdapters: Array.isArray(networkAdapters) ? networkAdapters : [],
        inventoryReportedAt,
        currentRun: relationshipID(currentRun),
        nextRunAt: schedules.docs
          .filter(
            (schedule) =>
              String(relationshipID(schedule.scanner)) === String(id) && schedule.enabled,
          )
          .map((schedule) => schedule.nextRunAt)
          .filter(Boolean)
          .sort()[0],
        lastRun: runs.docs.find((run) => String(relationshipID(run.scanner)) === String(id)),
      }),
    ),
    profiles: profiles.docs.map(({ id, name, scanner, site, credentialsConfigured }) => ({
      id,
      name,
      scanner: String(relationshipID(scanner)),
      site: String(relationshipID(site)),
      credentialsConfigured,
    })),
    sites: sites.docs.map(({ id, name, path }) => ({ id, name: path || name })),
    writableSites: writableSites.docs.map(({ id, name, path }) => ({ id, name: path || name })),
  })
}

export const getOtterScanner: Endpoint['handler'] = async (req) => {
  const id = String(req.routeParams?.id || '')
  const scanner = await req.payload.findByID({
    collection: 'otter-scanners',
    depth: 0,
    id,
    overrideAccess: false,
    req,
  })
  await requireHuman(req, scanner.site)
  return json({
    id: String(scanner.id),
    computerName: scanner.computerName,
    networkAdapters: Array.isArray(scanner.networkAdapters) ? scanner.networkAdapters : [],
    version: scanner.version,
  })
}

export const createOtterScanner: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const controllerUrl = publicControllerURL()
  const data = await body(req)
  const name = typeof data.name === 'string' ? data.name.trim() : ''
  if (!name || name.length > 120 || /[\u0000-\u001f]/.test(name))
    throw new APIError('Enter a scanner name of 1 to 120 characters.', 400)
  const site = String(data.site || '')
  await requireHuman(req, site, true)
  const siteDoc = await req.payload.findByID({
    collection: 'sites',
    depth: 0,
    id: site,
    overrideAccess: false,
    req,
  })
  const token = newToken()
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString()
  const scanner = await req.payload.create({
    collection: 'otter-scanners',
    data: {
      name,
      site,
      enabled: true,
      enrollmentTokenHash: tokenDigest(token),
      enrollmentExpiresAt: expiresAt,
    },
    overrideAccess: true,
    req,
  })
  return json(
    {
      controllerUrl,
      enrollmentToken: token,
      expiresAt,
      scanner: { id: scanner.id, name, site: siteDoc.name },
    },
    201,
  )
}

export const enrollOtter: Endpoint['handler'] = async (req) => {
  const data = await body(req, 64_000)
  const report = scannerReport(data)
  const token = typeof data.token === 'string' ? data.token : ''
  if (!/^[A-Za-z0-9_-]{40,}$/.test(token))
    throw new APIError('Enrollment token is invalid or expired.', 401)
  const now = new Date().toISOString()
  const scanners = await req.payload.find({
    collection: 'otter-scanners',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    where: {
      and: [
        { enrollmentTokenHash: { equals: tokenDigest(token) } },
        { enrollmentExpiresAt: { greater_than: now } },
        { credentialHash: { equals: null } },
        { enabled: { equals: true } },
      ],
    },
  })
  const scanner = scanners.docs[0]
  if (!scanner) throw new APIError('Enrollment token is invalid, expired, or already used.', 401)

  const credential = newToken()
  const credentialExpiresAt = new Date(Date.now() + 365 * 86_400_000).toISOString()
  const updated = await inTransaction(req, async () => {
    await assertSiteAllowsImports(scanner.site, req)
    const claimed = await req.payload.update({
      collection: 'otter-scanners',
      context: { otterScannerUpdate: true },
      where: {
        and: [
          { id: { equals: scanner.id } },
          { enrollmentTokenHash: { equals: tokenDigest(token) } },
          { enrollmentExpiresAt: { greater_than: now } },
          { credentialHash: { equals: null } },
        ],
      },
      data: {
        enrollmentTokenHash: null,
        enrollmentExpiresAt: null,
        credentialHash: tokenDigest(credential),
        credentialExpiresAt,
        enrolledAt: now,
        ...report,
        ...(report.computerName !== undefined || report.networkAdapters !== undefined
          ? { inventoryReportedAt: now }
          : {}),
      },
      overrideAccess: true,
      req,
    })
    if (!claimed.docs.length) throw new APIError('Enrollment token was already consumed.', 409)
    return claimed.docs[0]
  })
  return json(
    {
      credential,
      credentialExpiresAt,
      scanner: { id: updated.id, name: updated.name, site: String(relationshipID(updated.site)) },
    },
    201,
  )
}

export const pollOtter: Endpoint['handler'] = async (req) => {
  const scanner = await scannerDocument(req)
  const report = await body(req, 64_000)
  const validated = scannerReport(report)

  const now = new Date()
  const lastSeen = Date.parse(scanner.lastSeenAt || '')
  const heartbeatDue = !Number.isFinite(lastSeen) || now.getTime() - lastSeen >= 60_000
  const changed = Object.entries(validated).some(([key, value]) => {
    const current = scanner[key as keyof OtterScanner]
    const comparable =
      key === 'networkAdapters' && Array.isArray(current)
        ? current.map((adapter) => {
            const item = adapter as Record<string, unknown>
            return {
              name: item.name,
              friendlyName: item.friendlyName,
              description: item.description,
              ...(typeof item.macAddress === 'string' ? { macAddress: item.macAddress } : {}),
              ipAddresses: item.ipAddresses,
            }
          })
        : current
    return JSON.stringify(value) !== JSON.stringify(comparable)
  })

  const response = await inTransaction(req, async () => {
    if (heartbeatDue || changed)
      await req.payload.update({
        collection: 'otter-scanners',
        context: { otterScannerUpdate: true },
        id: scanner.id,
        overrideAccess: true,
        req,
        data: {
          lastSeenAt: now.toISOString(),
          ...validated,
          ...(validated.computerName !== undefined || validated.networkAdapters !== undefined
            ? { inventoryReportedAt: now.toISOString() }
            : {}),
        },
      })
    const refreshed = {
      ...scanner,
      ...(heartbeatDue || changed ? { lastSeenAt: now.toISOString() } : {}),
    }
    const run = await assignJob(req, refreshed, now)
    if (!run) return { action: 'idle', retryAfterSeconds: 30 }
    if (run.status === 'cancel-requested') return jobResponse(run, refreshed)
    return jobResponse(run, refreshed)
  })
  return json(response)
}

const activeRunForScanner = async (req: PayloadRequest, runID: string) => {
  const scanner = await scannerDocument(req)
  const run = await req.payload.findByID({
    collection: 'otter-runs',
    depth: 0,
    id: runID,
    overrideAccess: true,
    req,
  })
  assertOtterRunOwner(run, scanner)
  return { run, scanner }
}

export const startOtterRun: Endpoint['handler'] = async (req) => {
  const runID = String(req.routeParams?.id || '')
  const result = await inTransaction(req, async () => {
    const { run, scanner } = await activeRunForScanner(req, runID)
    const now = new Date()
    assertCurrentOtterRunLease(run, scanner, now)
    await assertSiteAllowsImports(scanner.site, req)
    if (run.status === 'running') return { status: run.status }
    if (run.status !== 'assigned') throw new APIError('This scan run cannot be started.', 409)
    await req.payload.update({
      collection: 'otter-runs',
      id: run.id,
      overrideAccess: true,
      req,
      data: {
        startedAt: now.toISOString(),
        leaseExpiresAt: new Date(now.getTime() + 120_000).toISOString(),
        status: 'running',
      },
    })
    return { status: 'running', scanner: scanner.id }
  })
  return json(result)
}

export const heartbeatOtterRun: Endpoint['handler'] = async (req) => {
  const runID = String(req.routeParams?.id || '')
  const data = await body(req, 4_000)
  if (
    data.progress !== undefined &&
    (!Number.isInteger(data.progress) || Number(data.progress) < 0 || Number(data.progress) > 100)
  )
    throw new APIError('Progress must be an integer from 0 to 100.', 400)
  const progress = typeof data.progress === 'number' ? data.progress : undefined
  const result = await inTransaction(req, async () => {
    const active = await activeRunForScanner(req, runID)
    const scanner = active.scanner
    let run = active.run
    const now = new Date()
    assertCurrentOtterRunLease(run, scanner, now)
    if (!['running', 'cancel-requested'].includes(run.status))
      throw new APIError('This scan run is no longer active.', 409)
    if (await siteBlocksImports(scanner.site, req)) run = await cancelBlockedRun(req, run)
    let leaseExpiresAt = run.leaseExpiresAt
    if (run.status !== 'cancel-requested') {
      leaseExpiresAt = new Date(now.getTime() + 120_000).toISOString()
      await req.payload.update({
        collection: 'otter-runs',
        id: run.id,
        overrideAccess: true,
        req,
        data: {
          leaseExpiresAt,
          ...(progress !== undefined ? { progress } : {}),
        },
      })
    }
    return { cancelRequested: run.status === 'cancel-requested', leaseExpiresAt }
  })
  return json(result)
}

export const finishOtterRun: Endpoint['handler'] = async (req) => {
  const runID = String(req.routeParams?.id || '')
  const data = await body(req, 8_000)
  const status = data.status
  if (!['completed', 'partial', 'failed', 'cancelled'].includes(String(status)))
    throw new APIError('Choose a valid terminal run status.', 400)
  const message =
    (typeof data.message === 'string' ? data.message.trim().slice(0, 4000) : '') ||
    (status === 'failed' ? 'Scanner reported a failure without diagnostic details.' : undefined)
  const importID = typeof data.importID === 'string' ? data.importID : undefined
  const result = await inTransaction(req, async () => {
    const { run, scanner } = await activeRunForScanner(req, runID)
    if (['completed', 'partial', 'failed', 'cancelled'].includes(run.status))
      return { status: run.status }
    assertCurrentOtterRunLease(run, scanner, new Date())
    const now = new Date().toISOString()
    if (importID) {
      const imported = await req.payload.find({
        collection: 'asset-imports',
        depth: 0,
        limit: 1,
        overrideAccess: true,
        req,
        where: {
          and: [
            { id: { equals: importID } },
            { scanner: { equals: scanner.id } },
            { otterRun: { equals: run.id } },
          ],
        },
      })
      if (!imported.docs.length)
        throw new APIError('Import does not belong to this scanner run.', 400)
    }
    await req.payload.update({
      collection: 'otter-runs',
      id: run.id,
      overrideAccess: true,
      req,
      data: {
        status: status as 'completed' | 'partial' | 'failed' | 'cancelled',
        completedAt: now,
        progress: status === 'completed' ? 100 : run.progress,
        ...(message ? { message } : {}),
        ...(importID ? { import: importID } : {}),
      },
    })
    await req.payload.update({
      collection: 'otter-scanners',
      context: { otterScannerUpdate: true },
      id: scanner.id,
      overrideAccess: true,
      req,
      data: { currentRun: null },
    })
    const scheduleID = relationshipID(run.schedule)
    if (scheduleID)
      await req.payload.update({
        collection: 'otter-schedules',
        id: String(scheduleID),
        overrideAccess: true,
        req,
        context: { otterSchedulerUpdate: true },
        data: { lastRunAt: now },
      })
    return { status }
  })
  return json(result)
}

export const rotateOtterCredential: Endpoint['handler'] = async (req) => {
  const scanner = await scannerDocument(req)
  const credential = newToken()
  const expiresAt = new Date(Date.now() + 365 * 86_400_000).toISOString()
  await req.payload.update({
    collection: 'otter-scanners',
    context: { otterScannerUpdate: true },
    id: scanner.id,
    overrideAccess: true,
    req,
    data: { credentialHash: tokenDigest(credential), credentialExpiresAt: expiresAt },
  })
  return json({ credential, credentialExpiresAt: expiresAt })
}

export const saveOtterCredentials: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const id = String(req.routeParams?.id || '')
  const profile = await req.payload.findByID({
    collection: 'otter-profiles',
    depth: 0,
    id,
    overrideAccess: false,
    req,
  })
  await requireHuman(req, profile.site, true)
  const data = await body(req, 32_000)
  const credentials = data.clear === true ? undefined : validateOtterCredentials(data.credentials)
  const encryptedCredentials = credentials ? encryptOtterCredentials(credentials) : null
  await req.payload.update({
    collection: 'otter-profiles',
    id,
    overrideAccess: true,
    context: { otterCredentialWrite: true },
    req,
    data: {
      encryptedCredentials,
      credentialsConfigured: Boolean(encryptedCredentials),
    },
  })
  return json({ credentialsConfigured: Boolean(encryptedCredentials) })
}

export const runOtterNow: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const data = await body(req)
  const run = await inTransaction(req, async () => {
    const scanner = await req.payload.findByID({
      collection: 'otter-scanners',
      depth: 0,
      id: String(data.scannerID || ''),
      overrideAccess: false,
      req,
    })
    await requireHuman(req, scanner.site, true)
    if (!scanner.enabled) throw new APIError('Enable the scanner before scheduling a run.', 409)
    const pending = await req.payload.count({
      collection: 'otter-runs',
      overrideAccess: true,
      req,
      where: { and: [{ scanner: { equals: scanner.id } }, { status: { equals: 'queued' } }] },
    })
    if (pending.totalDocs >= 20) throw new APIError('This scanner already has 20 queued runs.', 429)
    const input = await runInput(req, scanner, data.profileID)
    return req.payload.create({
      collection: 'otter-runs',
      data: input,
      overrideAccess: true,
      req,
    })
  })
  return json({ id: run.id, status: run.status }, 201)
}

export const cancelOtterRun: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const id = String(req.routeParams?.id || '')
  const result = await inTransaction(req, async () => {
    const run = await req.payload.findByID({
      collection: 'otter-runs',
      depth: 0,
      id,
      overrideAccess: false,
      req,
    })
    await requireHuman(req, run.site, true)
    if (run.status === 'queued') {
      await req.payload.update({
        collection: 'otter-runs',
        id,
        overrideAccess: true,
        req,
        data: { status: 'cancelled', completedAt: new Date().toISOString() },
      })
      return { status: 'cancelled' }
    }
    if (['assigned', 'running'].includes(run.status)) {
      await req.payload.update({
        collection: 'otter-runs',
        id,
        overrideAccess: true,
        req,
        data: { status: 'cancel-requested' },
      })
      return { status: 'cancel-requested' }
    }
    return { status: run.status }
  })
  return json(result)
}

export const revokeOtterScanner: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const id = String(req.routeParams?.id || '')
  await inTransaction(req, async () => {
    const scanner = await req.payload.findByID({
      collection: 'otter-scanners',
      depth: 0,
      id,
      overrideAccess: false,
      req,
    })
    await requireHuman(req, scanner.site, true)
    const activeID = relationshipID(scanner.currentRun)
    if (activeID)
      await req.payload.update({
        collection: 'otter-runs',
        id: String(activeID),
        overrideAccess: true,
        req,
        data: {
          status: 'cancelled',
          completedAt: new Date().toISOString(),
          message: 'Scanner credential revoked.',
        },
      })
    await req.payload.update({
      collection: 'otter-scanners',
      context: { otterScannerUpdate: true },
      id,
      overrideAccess: true,
      req,
      data: {
        enabled: false,
        enrollmentTokenHash: null,
        enrollmentExpiresAt: null,
        credentialHash: null,
        credentialExpiresAt: null,
        currentRun: null,
      },
    })
  })
  return json({ revoked: true })
}

export const reenrollOtterScanner: Endpoint['handler'] = async (req) => {
  humanOrigin(req)
  const controllerUrl = publicControllerURL()
  const id = String(req.routeParams?.id || '')
  const token = newToken()
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString()
  await inTransaction(req, async () => {
    const scanner = await req.payload.findByID({
      collection: 'otter-scanners',
      depth: 0,
      id,
      overrideAccess: false,
      req,
    })
    await requireHuman(req, scanner.site, true)
    await assertSiteAllowsImports(scanner.site, req)
    const activeID = relationshipID(scanner.currentRun)
    if (activeID)
      await req.payload.update({
        collection: 'otter-runs',
        id: String(activeID),
        overrideAccess: true,
        req,
        data: {
          status: 'cancelled',
          completedAt: new Date().toISOString(),
          message: 'Scanner re-enrolled.',
        },
      })
    await req.payload.update({
      collection: 'otter-scanners',
      context: { otterScannerUpdate: true },
      id,
      overrideAccess: true,
      req,
      data: {
        enabled: true,
        currentRun: null,
        enrollmentTokenHash: tokenDigest(token),
        enrollmentExpiresAt: expiresAt,
        enrolledAt: null,
        lastSeenAt: null,
        credentialHash: null,
        credentialExpiresAt: null,
      },
    })
  })
  return json({ controllerUrl, enrollmentToken: token, expiresAt })
}

export const otterEndpoints: Endpoint[] = [
  { path: '/otter/v1/overview', method: 'get', handler: otterOverview },
  { path: '/otter/v1/scanners/:id', method: 'get', handler: getOtterScanner },
  { path: '/otter/v1/scanners', method: 'post', handler: createOtterScanner },
  { path: '/otter/v1/scanners/:id/revoke', method: 'post', handler: revokeOtterScanner },
  { path: '/otter/v1/scanners/:id/reenroll', method: 'post', handler: reenrollOtterScanner },
  { path: '/otter/v1/enroll', method: 'post', handler: enrollOtter },
  { path: '/otter/v1/poll', method: 'post', handler: pollOtter },
  { path: '/otter/v1/credentials/rotate', method: 'post', handler: rotateOtterCredential },
  { path: '/otter/v1/profiles/:id/credentials', method: 'post', handler: saveOtterCredentials },
  { path: '/otter/v1/runs', method: 'post', handler: runOtterNow },
  { path: '/otter/v1/runs/:id/cancel', method: 'post', handler: cancelOtterRun },
  { path: '/otter/v1/runs/:id/start', method: 'post', handler: startOtterRun },
  { path: '/otter/v1/runs/:id/heartbeat', method: 'post', handler: heartbeatOtterRun },
  { path: '/otter/v1/runs/:id/finish', method: 'post', handler: finishOtterRun },
]
