import type { Payload, PayloadRequest } from 'payload'
import { normalizeCustomCsafFeeds, type CustomCsafFeed } from '../vulnerabilities/sources'

export type ApplicationSettings = {
  vulnerabilityFeeds?: {
    automaticUpdates?: boolean | null
    pullIntervalDays?: number | null
    customCsafFeeds?: CustomCsafFeed[] | null
  } | null
  metadataImports?: boolean | null
  metadataSync?: {
    requestedAt?: string | null
    lastCheckedAt?: string | null
    lastSyncedAt?: string | null
    commitSHA?: string | null
    error?: string | null
    jobID?: string | null
  } | null
  otterReleaseImports?: boolean | null
  otterReleaseSync?: {
    requestedAt?: string | null
    lastCheckedAt?: string | null
    lastSyncedAt?: string | null
    version?: string | null
    error?: string | null
    jobID?: string | null
  } | null
  controllerURL?: string | null
  queuedImports?: 'deployment' | 'enabled' | 'disabled' | null
}

export const DEFAULT_VULNERABILITY_FEED_INTERVAL_DAYS = 7

export const readVulnerabilityFeedSettings = async (payload: Payload, req?: PayloadRequest) => {
  const settings = (await readApplicationSettings(payload, req)).vulnerabilityFeeds
  const pullIntervalDays = settings?.pullIntervalDays ?? DEFAULT_VULNERABILITY_FEED_INTERVAL_DAYS
  if (!Number.isInteger(pullIntervalDays) || pullIntervalDays < 1 || pullIntervalDays > 365)
    throw new Error('The vulnerability feed interval must be a whole number from 1 to 365 days.')
  return {
    automaticUpdates: settings?.automaticUpdates !== false,
    pullIntervalDays,
    customCsafFeeds: normalizeCustomCsafFeeds(settings?.customCsafFeeds),
  }
}

export const readApplicationSettings = async (
  payload: Payload,
  req?: PayloadRequest,
): Promise<ApplicationSettings> =>
  (await payload.findGlobal({
    slug: 'application-settings',
    depth: 0,
    overrideAccess: true,
    ...(req ? { req } : {}),
  })) as ApplicationSettings

export const configuredControllerURL = async (payload: Payload, req?: PayloadRequest) => {
  const saved = (await readApplicationSettings(payload, req)).controllerURL?.trim()
  return saved || process.env.OTSERVER_PUBLIC_URL?.trim() || ''
}

export const queuedImportsEnabled = async (payload: Payload, req?: PayloadRequest) => {
  const setting = (await readApplicationSettings(payload, req)).queuedImports
  return (
    setting === 'enabled' ||
    (setting !== 'disabled' && process.env.OTSERVER_QUEUED_IMPORTS === 'on')
  )
}

export const isLoopbackControllerURL = (url: URL) =>
  ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)

export const validateControllerURL = (value: unknown): true | string => {
  if (value == null || (typeof value === 'string' && !value.trim())) return true
  if (typeof value !== 'string' || value.length > 2048)
    return 'Enter a valid controller URL of at most 2,048 characters.'

  let url: URL
  try {
    url = new URL(value.trim())
  } catch {
    return 'Enter a valid controller URL.'
  }
  if (url.username || url.password || url.search || url.hash)
    return 'The controller URL cannot contain credentials, a query, or a fragment.'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackControllerURL(url)))
    return 'Use HTTPS for remote controller URLs. HTTP is allowed only on localhost or loopback.'
  return true
}
