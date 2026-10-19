import type { Payload, PayloadRequest } from 'payload'

export type ApplicationSettings = {
  controllerURL?: string | null
  queuedImports?: 'deployment' | 'enabled' | 'disabled' | null
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
