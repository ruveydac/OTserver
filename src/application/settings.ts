import type { Payload, PayloadRequest } from 'payload'
import { normalizeCustomCsafFeeds, type CustomCsafFeed } from '../vulnerabilities/sources'

export type ApplicationSettings = {
  vulnerabilityFeeds?: {
    automaticUpdates?: boolean | null
    pullIntervalDays?: number | null
    customCsafFeeds?: CustomCsafFeed[] | null
  } | null
  assetImportCleanup?: {
    enabled?: boolean | null
    maxFiles?: number | null
    maxAgeDays?: number | null
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
export const DEFAULT_ASSET_IMPORT_CLEANUP_MAX_FILES = 1000
export const DEFAULT_ASSET_IMPORT_CLEANUP_MAX_AGE_DAYS = 90
export const MAX_ASSET_IMPORT_CLEANUP_FILES = 100_000
export const MAX_ASSET_IMPORT_CLEANUP_AGE_DAYS = 3650

export const readAssetImportCleanupSettings = async (payload: Payload, req?: PayloadRequest) => {
  const settings = (await readApplicationSettings(payload, req)).assetImportCleanup
  const enabled = settings?.enabled ?? false
  const maxFiles = settings?.maxFiles ?? DEFAULT_ASSET_IMPORT_CLEANUP_MAX_FILES
  const maxAgeDays = settings?.maxAgeDays ?? DEFAULT_ASSET_IMPORT_CLEANUP_MAX_AGE_DAYS

  if (typeof enabled !== 'boolean')
    throw new Error('Asset import cleanup enabled must be a boolean.')
  if (!Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > MAX_ASSET_IMPORT_CLEANUP_FILES)
    throw new Error(
      `Asset import cleanup file limit must be from 1 to ${MAX_ASSET_IMPORT_CLEANUP_FILES}.`,
    )
  if (
    !Number.isInteger(maxAgeDays) ||
    maxAgeDays < 1 ||
    maxAgeDays > MAX_ASSET_IMPORT_CLEANUP_AGE_DAYS
  )
    throw new Error(
      `Asset import cleanup age must be from 1 to ${MAX_ASSET_IMPORT_CLEANUP_AGE_DAYS} days.`,
    )

  return { enabled, maxFiles, maxAgeDays }
}

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
