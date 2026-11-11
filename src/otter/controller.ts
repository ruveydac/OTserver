import { APIError, type Endpoint, type Payload, type PayloadRequest } from 'payload'
import { isIP } from 'node:net'
import { createHash } from 'node:crypto'
import { open } from 'node:fs/promises'
import path from 'node:path'
import { Readable } from 'node:stream'
import { getAuthorization, relationshipID } from '../access/authorization'
import { inTransaction } from '../integrations/payload/transactions'
import { compareOtterVersions, MAX_OTTER_RELEASE_SIZE, OTTER_UPDATE_TARGETS } from './releases'
import type {
  OtterRelease,
  OtterRun,
  OtterScanner,
  OtterSchedule,
  OtterUpdate,
} from '../payload-types'
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
import {
  configuredControllerURL,
  isLoopbackControllerURL,
  validateControllerURL,
} from '../application/settings'
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
  OTTER_RUN_LEASE_MS,
} from './runLease'

const json = (data: unknown, status = 200) =>
  Response.json(data, { headers: { 'Cache-Control': 'no-store' }, status })

const scannerReport = (input: Record<string, unknown>) => {
  if (
    input.version !== undefined &&
    (typeof input.version !== 'string' || input.version.length > 64)
  )
    throw new APIError('Scanner version is invalid.', 400)
  if (
    input.buildTarget !== undefined &&
    (typeof input.buildTarget !== 'string' ||
      !OTTER_UPDATE_TARGETS.includes(input.buildTarget as (typeof OTTER_UPDATE_TARGETS)[number]))
  )
    throw new APIError('Scanner build target is invalid.', 400)
  if (
    input.osVersion !== undefined &&
    (typeof input.osVersion !== 'string' ||
      !input.osVersion.trim() ||
      input.osVersion.length > 256 ||
      /[\u0000-\u001f]/.test(input.osVersion))
  )
    throw new APIError('Scanner OS version is invalid.', 400)
  if (
    input.binaryDigest !== undefined &&
    (typeof input.binaryDigest !== 'string' || !/^[a-f\d]{64}$/i.test(input.binaryDigest))
  )
    throw new APIError('Scanner executable digest is invalid.', 400)
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
    ...(typeof input.buildTarget === 'string' ? { buildTarget: input.buildTarget } : {}),
    ...(typeof input.osVersion === 'string' ? { osVersion: input.osVersion.trim() } : {}),
    ...(typeof input.binaryDigest === 'string'
      ? { binaryDigest: input.binaryDigest.toLowerCase() }
      : {}),
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
  ['http:', 'https:'].includes(url.protocol) && isLoopbackControllerURL(url)

const humanOrigin = async (req: PayloadRequest) => {
  const origin = req.headers.get('origin')
  const configured = await configuredControllerURL(req.payload, req)
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

const publicControllerURL = async (req: PayloadRequest, configuredValue?: string) => {
  const value = configuredValue ?? (await configuredControllerURL(req.payload, req))
  if (!value)
    throw new APIError('Configure the public controller URL before Otter jobs can run.', 503)
  const validation = validateControllerURL(value)
  if (validation !== true)
    throw new APIError(`The public controller URL is invalid. ${validation}`, 503)
  const url = new URL(value)
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
const activeUpdateStatuses = ['queued', 'downloading', 'verified', 'installing'] as const
const terminalUpdateStatuses = ['completed', 'failed', 'rolled-back'] as const
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
  const updates = await req.payload.find({
    collection: 'otter-updates',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    where: {
      and: [{ scanner: { equals: scanner.id } }, { status: { in: [...activeUpdateStatuses] } }],
    },
  })
  if (updates.docs.length) return undefined
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
  const leaseExpiresAt = new Date(now.getTime() + OTTER_RUN_LEASE_MS).toISOString()
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

const jobResponse = async (run: OtterRun, scanner: OtterScanner, req: PayloadRequest) => {
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
        serverUrl: await publicControllerURL(req),
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
  const controllerURL = await configuredControllerURL(req.payload, req)
  return json({
    controllerUrl: controllerURL ? await publicControllerURL(req, controllerURL) : '',
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
        osVersion,
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
        osVersion,
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
    buildTarget: scanner.buildTarget,
    osVersion: scanner.osVersion,
    currentUpdate: relationshipID(scanner.currentUpdate),
  })
}

const releaseSummary = (release: OtterRelease) => ({
  id: String(release.id),
  version: String(release.version),
  target: String(release.target),
  filesize: Number(release.filesize),
})

export const listOtterReleases: Endpoint['handler'] = async (req) => {
  await requireHuman(req)
  const releases = await req.payload.find({
    collection: 'otter-releases',
    depth: 0,
    limit: 500,
    pagination: false,
    overrideAccess: true,
    req,
    sort: '-createdAt',
  })
  return json({ releases: releases.docs.map((release) => releaseSummary(release)) })
}

export const queueOtterUpdates: Endpoint['handler'] = async (req) => {
  await humanOrigin(req)
  const data = await body(req)
  if (
    typeof data.version !== 'string' ||
    !data.version.trim() ||
    data.version.length > 64 ||
    !Array.isArray(data.scannerIDs) ||
    data.scannerIDs.length < 1 ||
    data.scannerIDs.length > 100 ||
    data.scannerIDs.some((id) => typeof id !== 'string' || !id) ||
    new Set(data.scannerIDs).size !== data.scannerIDs.length
  )
    throw new APIError('Select one to 100 unique scanners and an Otter release version.', 400)

  const version = data.version.trim()
  const results = await inTransaction(req, async () => {
    const queued: Array<{ id: string; scannerID: string; name: string }> = []
    for (const id of data.scannerIDs as string[]) {
      const scanner = await req.payload.findByID({
        collection: 'otter-scanners',
        depth: 0,
        id,
        overrideAccess: false,
        req,
      })
      await requireHuman(req, scanner.site, true)
      const releases = await req.payload.find({
        collection: 'otter-releases',
        depth: 0,
        limit: 1,
        overrideAccess: true,
        req,
        where: {
          and: [
            { version: { equals: version } },
            { target: { equals: scanner.buildTarget || '' } },
          ],
        },
      })
      const release = releases.docs[0]
      if (!release)
        throw new APIError(
          `${scanner.name} has no signed executable for version ${version} and its platform.`,
          409,
        )
      if (
        !scanner.enabled ||
        !scanner.enrolledAt ||
        !Array.isArray(scanner.capabilities) ||
        !scanner.capabilities.includes('update-v1')
      )
        throw new APIError(
          `${scanner.name} is not enrolled with a compatible update-capable Otter.`,
          409,
        )
      if (
        typeof scanner.version !== 'string' ||
        compareOtterVersions(version, scanner.version) <= 0
      )
        throw new APIError(`${scanner.name} is already running this version or a newer one.`, 409)

      const existing = await req.payload.find({
        collection: 'otter-updates',
        depth: 0,
        limit: 1,
        overrideAccess: true,
        req,
        where: {
          and: [{ scanner: { equals: scanner.id } }, { status: { in: [...activeUpdateStatuses] } }],
        },
      })
      if (existing.docs.length)
        throw new APIError(`${scanner.name} already has an update queued or in progress.`, 409)

      const update = await req.payload.create({
        collection: 'otter-updates',
        context: { otterUpdateWrite: true },
        data: {
          name: `${scanner.name} to ${version}`,
          site: String(relationshipID(scanner.site)),
          scanner: String(scanner.id),
          release: String(release.id),
          target: String(release.target),
          targetVersion: version,
          binaryDigest: String(release.binaryDigest),
          binarySize: Number(release.filesize),
          previousVersion: scanner.version,
          status: 'queued',
        },
        overrideAccess: true,
        req,
      })
      await req.payload.update({
        collection: 'otter-scanners',
        context: { otterScannerUpdate: true },
        data: { currentUpdate: String(update.id) },
        id: scanner.id,
        overrideAccess: true,
        req,
      })
      queued.push({ id: String(update.id), scannerID: String(scanner.id), name: scanner.name })
    }
    return queued
  })
  return json({ queued: results }, 202)
}

const setUpdateStatus = async (
  req: PayloadRequest,
  update: OtterUpdate,
  status: OtterUpdate['status'],
  message?: string,
) => {
  const now = new Date().toISOString()
  const terminal = terminalUpdateStatuses.includes(
    status as (typeof terminalUpdateStatuses)[number],
  )
  await req.payload.update({
    collection: 'otter-updates',
    context: { otterUpdateWrite: true },
    data: {
      status,
      ...(message ? { message } : { message: null }),
      ...(status === 'downloading' && !update.startedAt ? { startedAt: now } : {}),
      ...(terminal ? { completedAt: now } : {}),
    },
    id: String(update.id),
    overrideAccess: true,
    req,
  })
  if (terminal) {
    const scanner = await req.payload.findByID({
      collection: 'otter-scanners',
      depth: 0,
      id: String(relationshipID(update.scanner)),
      overrideAccess: true,
      req,
    })
    if (String(relationshipID(scanner.currentUpdate)) === String(update.id))
      await req.payload.update({
        collection: 'otter-scanners',
        context: { otterScannerUpdate: true },
        data: { currentUpdate: null },
        id: scanner.id,
        overrideAccess: true,
        req,
      })
  }
  return status
}

const activeUpdateFor = async (req: PayloadRequest, scannerID: string) => {
  const found = await req.payload.find({
    collection: 'otter-updates',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    where: {
      and: [{ scanner: { equals: scannerID } }, { status: { in: [...activeUpdateStatuses] } }],
    },
  })
  return found.docs[0]
}

const pollOtterUpdate = async (req: PayloadRequest, scanner: OtterScanner) => {
  const update = await activeUpdateFor(req, String(scanner.id))
  if (!update) return undefined
  if (
    scanner.version === update.targetVersion &&
    scanner.buildTarget === update.target &&
    scanner.binaryDigest === update.binaryDigest
  ) {
    await setUpdateStatus(req, update, 'completed')
    return {
      action: 'idle',
      retryAfterSeconds: 30,
    }
  }
  if (scanner.buildTarget !== update.target) {
    await setUpdateStatus(
      req,
      update,
      'failed',
      'Scanner platform no longer matches the selected release.',
    )
    return { action: 'idle', retryAfterSeconds: 30 }
  }
  if (
    typeof scanner.version !== 'string' ||
    compareOtterVersions(String(update.targetVersion), scanner.version) <= 0
  ) {
    await setUpdateStatus(
      req,
      update,
      'failed',
      'The selected release is not newer than the scanner.',
    )
    return { action: 'idle', retryAfterSeconds: 30 }
  }
  return {
    action: 'update',
    update: {
      id: String(update.id),
      version: String(update.targetVersion),
      target: String(update.target),
      binaryDigest: String(update.binaryDigest),
      binarySize: Number(update.binarySize),
    },
  }
}

export const downloadOtterUpdate: Endpoint['handler'] = async (req) => {
  const scanner = await scannerDocument(req)
  const id = String(req.routeParams?.id || '')
  const update = await req.payload.findByID({
    collection: 'otter-updates',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
  if (
    String(relationshipID(update.scanner)) !== String(scanner.id) ||
    !activeUpdateStatuses.includes(update.status as (typeof activeUpdateStatuses)[number])
  )
    throw new APIError('The update is no longer available to this scanner.', 404)
  const release = await req.payload.findByID({
    collection: 'otter-releases',
    depth: 0,
    id: String(relationshipID(update.release)),
    overrideAccess: true,
    req,
  })
  const filename = typeof release.filename === 'string' ? release.filename : ''
  if (!filename || path.basename(filename) !== filename)
    throw new APIError('The stored Otter release is unavailable.', 500)
  const filepath = path.resolve(
    process.env.OTSERVER_TEST_UPLOAD_DIR || 'import-files',
    'otter-releases',
    filename,
  )
  const root = path.resolve(
    process.env.OTSERVER_TEST_UPLOAD_DIR || 'import-files',
    'otter-releases',
  )
  if (!filepath.startsWith(`${root}${path.sep}`))
    throw new APIError('The stored Otter release path is invalid.', 500)
  const file = await open(filepath, 'r').catch(() => undefined)
  if (!file) throw new APIError('The stored Otter release is unavailable.', 404)
  try {
    const metadata = await file.stat()
    if (
      !metadata.isFile() ||
      metadata.size !== release.filesize ||
      metadata.size > MAX_OTTER_RELEASE_SIZE
    )
      throw new APIError('The stored Otter release size does not match its verified record.', 500)
    const digest = createHash('sha256')
    for await (const chunk of file.createReadStream({ autoClose: false })) digest.update(chunk)
    if (digest.digest('hex') !== release.binaryDigest)
      throw new APIError('The stored Otter release failed its integrity check.', 500)
    if (update.status === 'queued') await setUpdateStatus(req, update, 'downloading')
    const stream = file.createReadStream({ start: 0, end: metadata.size - 1, autoClose: true })
    return new Response(Readable.toWeb(stream) as ReadableStream, {
      headers: {
        'Cache-Control': 'no-store',
        'Content-Length': String(metadata.size),
        'Content-Type': 'application/octet-stream',
        'X-Content-Type-Options': 'nosniff',
      },
    })
  } catch (error) {
    await file.close().catch(() => undefined)
    await setUpdateStatus(
      req,
      update,
      'failed',
      'The stored release failed server-side integrity checks.',
    )
    throw error
  }
}

export const reportOtterUpdate: Endpoint['handler'] = async (req) => {
  const scanner = await scannerDocument(req)
  const id = String(req.routeParams?.id || '')
  const update = await req.payload.findByID({
    collection: 'otter-updates',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
  if (String(relationshipID(update.scanner)) !== String(scanner.id))
    throw new APIError('The update is not assigned to this scanner.', 404)
  const data = await body(req)
  if (!['verified', 'installing', 'failed', 'rolled-back'].includes(String(data.status)))
    throw new APIError('The update status is invalid.', 400)
  const status = String(data.status) as OtterUpdate['status']
  if (
    (status === 'verified' && ['verified', 'installing'].includes(update.status)) ||
    (status === 'installing' && update.status === 'installing')
  )
    return json({ id: String(update.id), status: update.status })
  const allowed =
    (status === 'verified' && update.status === 'downloading') ||
    (status === 'installing' && update.status === 'verified') ||
    (status === 'failed' &&
      activeUpdateStatuses.includes(update.status as (typeof activeUpdateStatuses)[number])) ||
    (status === 'rolled-back' && update.status === 'installing')
  if (!allowed) throw new APIError('The update status transition is not allowed.', 409)
  const reasons: Record<string, string> = {
    downloadFailed: 'Otter could not download the selected release.',
    signatureRejected: 'Otter rejected the downloaded executable signature or platform.',
    installationFailed: 'Otter could not safely install the selected release.',
    startupFailed: 'Otter could not start the updated executable.',
  }
  const message = status === 'failed' ? reasons[String(data.reason)] : undefined
  if (status === 'failed' && !message)
    throw new APIError('The update failure reason is invalid.', 400)
  await setUpdateStatus(req, update, status, message)
  return json({ id: String(update.id), status })
}

export const createOtterScanner: Endpoint['handler'] = async (req) => {
  await humanOrigin(req)
  const controllerUrl = await publicControllerURL(req)
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
      ...validated,
      ...(heartbeatDue || changed ? { lastSeenAt: now.toISOString() } : {}),
    }
    const run = await assignJob(req, refreshed, now)
    if (!run)
      return (await pollOtterUpdate(req, refreshed)) || { action: 'idle', retryAfterSeconds: 30 }
    return jobResponse(run, refreshed, req)
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
        leaseExpiresAt: new Date(now.getTime() + OTTER_RUN_LEASE_MS).toISOString(),
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
      leaseExpiresAt = new Date(now.getTime() + OTTER_RUN_LEASE_MS).toISOString()
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
    const lastSeen = Date.parse(scanner.lastSeenAt || '')
    if (!Number.isFinite(lastSeen) || now.getTime() - lastSeen >= 60_000)
      await req.payload.update({
        collection: 'otter-scanners',
        context: { otterScannerUpdate: true },
        id: scanner.id,
        overrideAccess: true,
        req,
        data: { lastSeenAt: now.toISOString() },
      })
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
  await humanOrigin(req)
  const id = String(req.routeParams?.id || '')
  const data = await body(req, 32_000)
  const result = await inTransaction(req, async () => {
    const profile = await humanOtterProfile(req, id, true)
    const revision = otterCredentialRevision(profile.encryptedCredentials)
    if (data.revision !== revision)
      throw new APIError('Credentials changed in another session. Refresh and try again.', 409)

    const current = decryptOtterCredentials(profile.encryptedCredentials)
    const credentials = editOtterCredentials(current, data)
    const encryptedCredentials =
      Object.keys(credentials).length > 0 ? encryptOtterCredentials(credentials) : null
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
    return otterCredentialState(encryptedCredentials)
  })
  return json(result)
}

const humanOtterProfile = async (req: PayloadRequest, id: string, write: boolean) => {
  const readableProfile = await req.payload.findByID({
    collection: 'otter-profiles',
    depth: 0,
    id,
    overrideAccess: false,
    user: req.user || undefined,
    req,
  })
  await requireHuman(req, readableProfile.site, write)
  return req.payload.findByID({
    collection: 'otter-profiles',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
}

const otterCredentialRevision = (encrypted?: string | null) =>
  encrypted ? createHash('sha256').update(encrypted).digest('hex') : null

const asCredentialList = (value: unknown) =>
  Array.isArray(value) ? value : value === undefined ? [] : [value]

const hasCredentialSecret = (value: unknown, fields: string[]) =>
  Boolean(
    value &&
    typeof value === 'object' &&
    fields.some((field) => {
      const secret = (value as Record<string, unknown>)[field]
      return typeof secret === 'string' && secret.length > 0
    }),
  )

const otterCredentialState = (encrypted?: string | null) => {
  const credentials = decryptOtterCredentials(encrypted)
  const entries: Array<Record<string, string>> = []
  for (const [index, value] of asCredentialList(credentials.snmp).entries()) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    const entry = value as Record<string, unknown>
    entries.push({
      id: `snmp:${index}`,
      type: 'snmp',
      ...(typeof entry.version === 'string' ? { version: entry.version } : {}),
      ...(typeof entry.username === 'string' ? { username: entry.username } : {}),
      ...(typeof entry.contextName === 'string' ? { contextName: entry.contextName } : {}),
      ...(typeof entry.authProtocol === 'string' ? { authProtocol: entry.authProtocol } : {}),
      ...(typeof entry.privacyProtocol === 'string'
        ? { privacyProtocol: entry.privacyProtocol }
        : {}),
    })
  }
  for (const [index, value] of asCredentialList(credentials.opcuaCredentials).entries()) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    const username = (value as Record<string, unknown>).username
    entries.push({
      id: `opcua:${index}`,
      type: 'opcua',
      ...(typeof username === 'string' ? { username } : {}),
    })
  }
  if ('opcuaUsername' in credentials || 'opcuaPassword' in credentials)
    entries.push({
      id: 'opcuaFallback',
      type: 'opcua-fallback',
      ...(typeof credentials.opcuaUsername === 'string'
        ? { username: credentials.opcuaUsername }
        : {}),
    })
  return {
    credentialsConfigured: entries.length > 0,
    revision: otterCredentialRevision(encrypted),
    entries,
  }
}

const editOtterCredentials = (current: Record<string, unknown>, data: Record<string, unknown>) => {
  if (data.action === 'clear') return {}

  const credentials = structuredClone(current)
  if (data.action === 'add') {
    const added = validateOtterCredentials(data.credentials)
    if (!Object.keys(added).length)
      throw new APIError('Add at least one SNMP or OPC UA credential.', 400)
    for (const key of ['snmp', 'opcuaCredentials'] as const) {
      const items = [...asCredentialList(credentials[key]), ...asCredentialList(added[key])]
      if (items.length) credentials[key] = items
    }
    if ('opcuaUsername' in added || 'opcuaPassword' in added) {
      if ('opcuaUsername' in credentials || 'opcuaPassword' in credentials)
        throw new APIError('The OPC UA fallback already exists. Replace it instead.', 409)
      for (const key of ['opcuaUsername', 'opcuaPassword'] as const)
        if (key in added) credentials[key] = added[key]
    }
  } else if (data.action === 'remove' || data.action === 'replace') {
    if (typeof data.id !== 'string') throw new APIError('Select a credential entry.', 400)
    const fallback = data.id === 'opcuaFallback'
    const match = /^(snmp|opcua):(\d+)$/.exec(data.id)
    if (!fallback && !match) throw new APIError('The credential entry is invalid.', 400)

    if (fallback) {
      if (!('opcuaUsername' in credentials || 'opcuaPassword' in credentials))
        throw new APIError('The credential entry no longer exists.', 409)
      const hadSecret = hasCredentialSecret({ password: credentials.opcuaPassword }, ['password'])
      delete credentials.opcuaUsername
      delete credentials.opcuaPassword
      if (data.action === 'replace') {
        const replacement = validateOtterCredentials(data.credentials)
        if (!('opcuaUsername' in replacement || 'opcuaPassword' in replacement))
          throw new APIError('Enter the replacement OPC UA credential.', 400)
        if (
          hadSecret &&
          !hasCredentialSecret({ password: replacement.opcuaPassword }, ['password'])
        )
          throw new APIError('Enter a new password to replace this credential.', 400)
        for (const key of ['opcuaUsername', 'opcuaPassword'] as const)
          if (key in replacement) credentials[key] = replacement[key]
      }
    } else {
      const key = match![1] === 'snmp' ? 'snmp' : 'opcuaCredentials'
      const index = Number(match![2])
      const existing = asCredentialList(credentials[key])
      if (!Number.isSafeInteger(index) || index >= existing.length)
        throw new APIError('The credential entry no longer exists.', 409)
      if (data.action === 'remove') existing.splice(index, 1)
      else {
        const replacement = validateOtterCredentials(
          key === 'snmp' ? { snmp: [data.credentials] } : { opcuaCredentials: [data.credentials] },
        )
        const next = asCredentialList(replacement[key])[0]
        const secretFields =
          key === 'snmp' ? ['community', 'authPassword', 'privacyPassword'] : ['password']
        if (
          hasCredentialSecret(existing[index], secretFields) &&
          !hasCredentialSecret(next, secretFields)
        )
          throw new APIError('Enter a new secret to replace this credential.', 400)
        existing[index] = next
      }
      if (existing.length) credentials[key] = existing
      else delete credentials[key]
    }
  } else {
    throw new APIError('Choose whether to add, replace, remove, or clear credentials.', 400)
  }

  return validateOtterCredentials(credentials)
}

export const getOtterCredentials: Endpoint['handler'] = async (req) => {
  const profile = await humanOtterProfile(req, String(req.routeParams?.id || ''), false)
  return json(otterCredentialState(profile.encryptedCredentials))
}

export const runOtterNow: Endpoint['handler'] = async (req) => {
  await humanOrigin(req)
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
  await humanOrigin(req)
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
  await humanOrigin(req)
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
    const update = await activeUpdateFor(req, String(scanner.id))
    if (update)
      await setUpdateStatus(
        req,
        update,
        'failed',
        'Scanner credentials were revoked before the update completed.',
      )
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
        currentUpdate: null,
      },
    })
  })
  return json({ revoked: true })
}

export const reenrollOtterScanner: Endpoint['handler'] = async (req) => {
  await humanOrigin(req)
  const controllerUrl = await publicControllerURL(req)
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
    const update = await activeUpdateFor(req, String(scanner.id))
    if (update)
      await setUpdateStatus(
        req,
        update,
        'failed',
        'Scanner was re-enrolled before the update completed.',
      )
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
        currentUpdate: null,
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
  { path: '/otter/v1/updates/releases', method: 'get', handler: listOtterReleases },
  { path: '/otter/v1/updates', method: 'post', handler: queueOtterUpdates },
  { path: '/otter/v1/updates/:id/binary', method: 'get', handler: downloadOtterUpdate },
  { path: '/otter/v1/updates/:id/status', method: 'post', handler: reportOtterUpdate },
  { path: '/otter/v1/scanners/:id', method: 'get', handler: getOtterScanner },
  { path: '/otter/v1/scanners', method: 'post', handler: createOtterScanner },
  { path: '/otter/v1/scanners/:id/revoke', method: 'post', handler: revokeOtterScanner },
  { path: '/otter/v1/scanners/:id/reenroll', method: 'post', handler: reenrollOtterScanner },
  { path: '/otter/v1/enroll', method: 'post', handler: enrollOtter },
  { path: '/otter/v1/poll', method: 'post', handler: pollOtter },
  { path: '/otter/v1/credentials/rotate', method: 'post', handler: rotateOtterCredential },
  { path: '/otter/v1/profiles/:id/credentials', method: 'get', handler: getOtterCredentials },
  { path: '/otter/v1/profiles/:id/credentials', method: 'post', handler: saveOtterCredentials },
  { path: '/otter/v1/runs', method: 'post', handler: runOtterNow },
  { path: '/otter/v1/runs/:id/cancel', method: 'post', handler: cancelOtterRun },
  { path: '/otter/v1/runs/:id/start', method: 'post', handler: startOtterRun },
  { path: '/otter/v1/runs/:id/heartbeat', method: 'post', handler: heartbeatOtterRun },
  { path: '/otter/v1/runs/:id/finish', method: 'post', handler: finishOtterRun },
]
