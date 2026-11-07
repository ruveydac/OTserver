import { APIError, type Payload, type PayloadHandler, type PayloadRequest } from 'payload'
import { getAuthorization } from '../access/authorization'
import { readApplicationSettings, type ApplicationSettings } from '../application/settings'
import { writeAudit } from '../collections/AuditLogs'
import { principalRequest, systemRequest } from '../integrations/payload/requests'
import { inTransaction } from '../integrations/payload/transactions'
import {
  MAX_OTTER_RELEASE_SIZE,
  parseOtterVersion,
  unpackOtterRelease,
  verifyOtterRelease,
} from './releases'

export const OTTER_RELEASE_SYNC_TASK = 'otter-release-sync-v1'
export const OTTER_RELEASE_SYNC_INTERVAL_MS = 86_400_000
const repository = 'https://github.com/ruveydac/otserver-otter'
const assets = [
  { name: 'otserver-otter-linux-x86_64.tar.gz', target: 'x86_64-unknown-linux-gnu' },
  { name: 'otserver-otter-linux-aarch64.tar.gz', target: 'aarch64-unknown-linux-gnu' },
  { name: 'otserver-otter.exe', target: 'x86_64-pc-windows-msvc' },
] as const

const requireAdmin = async (req: PayloadRequest) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
}

const saveState = async (
  req: PayloadRequest,
  state: NonNullable<ApplicationSettings['otterReleaseSync']>,
) => {
  const settings = await readApplicationSettings(req.payload, req)
  await req.payload.updateGlobal({
    slug: 'application-settings',
    data: { otterReleaseSync: { ...settings.otterReleaseSync, ...state } },
    overrideAccess: true,
    req,
  })
}

export const queueOtterReleaseSync = async (req: PayloadRequest, scheduled = false) => {
  if (!scheduled) await requireAdmin(req)
  try {
    return await inTransaction(req, async () => {
      const settings = await readApplicationSettings(req.payload, req)
      if (
        scheduled &&
        (!settings.otterReleaseImports ||
          Date.parse(settings.otterReleaseSync?.requestedAt || '') >
            Date.now() - OTTER_RELEASE_SYNC_INTERVAL_MS)
      )
        return
      const pending = await req.payload.find({
        collection: 'payload-jobs',
        depth: 0,
        limit: 1,
        req,
        where: {
          and: [
            { taskSlug: { equals: OTTER_RELEASE_SYNC_TASK } },
            { completedAt: { exists: false } },
            { hasError: { not_equals: true } },
          ],
        },
      })
      if (pending.docs[0]) return pending.docs[0]
      // The shared settings write makes concurrent manual and scheduled requests contend.
      await saveState(req, { requestedAt: new Date().toISOString(), error: null })
      const job = await req.payload.jobs.queue({
        task: OTTER_RELEASE_SYNC_TASK,
        queue: 'maintenance',
        input: { version: 1, ...(scheduled ? {} : { submittedBy: String(req.user!.id) }) },
        req,
      })
      await saveState(req, { jobID: String(job.id) })
      await writeAudit({
        action: 'custom',
        req,
        targetCollection: 'otter-releases',
        after: {
          id: 'github-import',
          name: 'Otter release import requested',
          jobID: String(job.id),
          scheduled,
        },
      })
      return job
    })
  } catch (error) {
    if ([11000, 112].includes((error as { code?: number }).code || 0))
      throw new APIError(
        'Another release import was requested at the same time. Refresh the status and try again.',
        409,
      )
    throw error
  }
}

export const scheduleOtterReleaseSync = async (payload: Payload) => {
  await queueOtterReleaseSync(await systemRequest(payload), true)
}

export const otterReleaseControl: PayloadHandler = async (req) => {
  await requireAdmin(req)
  const settings = await readApplicationSettings(req.payload, req)
  const job = settings.otterReleaseSync?.jobID
    ? await req.payload.findByID({
        collection: 'payload-jobs',
        id: settings.otterReleaseSync.jobID,
        depth: 0,
        overrideAccess: false,
        disableErrors: true,
        req,
      })
    : undefined
  return Response.json(
    {
      enabled: settings.otterReleaseImports === true,
      ...settings.otterReleaseSync,
      active: Boolean(job && !job.completedAt && !job.hasError),
      processing: Boolean(job?.processing),
    },
    { headers: { 'Cache-Control': 'no-store' } },
  )
}

export const refreshOtterReleases: PayloadHandler = async (req) => {
  const job = await queueOtterReleaseSync(req)
  return Response.json({ jobID: String(job!.id) }, { status: 202 })
}

const download = async (url: string, limit: number): Promise<Buffer> => {
  const signal = AbortSignal.timeout(5 * 60_000)
  for (let redirects = 0; redirects <= 3; redirects++) {
    const destination = new URL(url)
    if (
      destination.protocol !== 'https:' ||
      (destination.port !== '' && destination.port !== '443') ||
      destination.username ||
      destination.password ||
      ![
        'api.github.com',
        'github.com',
        'release-assets.githubusercontent.com',
        'objects.githubusercontent.com',
      ].includes(destination.hostname)
    )
      throw new APIError('GitHub returned an unsupported release download location.', 400)
    let response: Response
    try {
      response = await fetch(url, {
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'OTserver Otter release import',
        },
        redirect: 'manual',
        signal,
      })
    } catch {
      throw new APIError('GitHub could not be reached. The release import will be retried.', 503)
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      await response.body?.cancel()
      const location = response.headers.get('location')
      if (!location) break
      url = new URL(location, url).href
      continue
    }
    if (!response.ok || !response.body) {
      await response.body?.cancel()
      const retryable =
        response.status === 429 ||
        response.status >= 500 ||
        (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0')
      throw new APIError(
        `GitHub release download failed (HTTP ${response.status}).`,
        retryable ? 503 : 400,
      )
    }
    if (Number(response.headers.get('content-length')) > limit) {
      await response.body.cancel()
      throw new APIError('The GitHub release download exceeds its size limit.', 400)
    }
    const chunks: Buffer[] = []
    let size = 0
    try {
      for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
        size += chunk.length
        if (size > limit)
          throw new APIError('The GitHub release download exceeds its size limit.', 400)
        chunks.push(Buffer.from(chunk))
      }
    } catch (error) {
      if (error instanceof APIError) throw error
      throw new APIError(
        'The GitHub release download was interrupted. The import will be retried.',
        503,
      )
    }
    return Buffer.concat(chunks)
  }
  throw new APIError('GitHub returned too many release download redirects.', 400)
}

const latestRelease = async () => {
  const metadata = await download(
    'https://api.github.com/repos/ruveydac/otserver-otter/releases/latest',
    1024 * 1024,
  )
  let release: {
    tag_name: string
    draft: boolean
    prerelease: boolean
    assets: { name: string; size: number; browser_download_url: string }[]
  }
  try {
    release = JSON.parse(metadata.toString('utf8'))
  } catch {
    throw new APIError('GitHub returned invalid release metadata.', 400)
  }
  if (
    !release ||
    typeof release.tag_name !== 'string' ||
    release.tag_name.length > 128 ||
    release.draft !== false ||
    release.prerelease !== false ||
    !Array.isArray(release.assets) ||
    parseOtterVersion(release.tag_name).prerelease.length
  )
    throw new APIError('GitHub did not return a stable Otter release.', 400)
  const selected = assets.map((expected) => {
    const matches = release.assets.filter((asset) => asset && asset.name === expected.name)
    const asset = matches[0]
    const url = `${repository}/releases/download/${encodeURIComponent(release.tag_name)}/${expected.name}`
    if (
      matches.length !== 1 ||
      asset.browser_download_url !== url ||
      !Number.isSafeInteger(asset.size) ||
      asset.size <= 0 ||
      asset.size > MAX_OTTER_RELEASE_SIZE
    )
      throw new APIError(`The GitHub release is missing a usable ${expected.name} asset.`, 400)
    return { ...expected, url, size: asset.size }
  })
  return { version: release.tag_name, assets: selected }
}

export const executeOtterReleaseSync = async (
  payload: Payload,
  input: { submittedBy?: string | null },
) => {
  let req = await systemRequest(payload)
  try {
    if (input.submittedBy) {
      const user = await payload.findByID({
        collection: 'users',
        id: input.submittedBy,
        depth: 0,
        disableErrors: true,
      })
      if (!user)
        throw new APIError('The administrator who requested this import no longer exists.', 403)
      req = await principalRequest(payload, { ...user, collection: 'users' })
      await requireAdmin(req)
    } else if (!(await readApplicationSettings(payload, req)).otterReleaseImports) {
      return { imported: 0, skipped: 0 }
    }
    await saveState(req, { lastCheckedAt: new Date().toISOString(), error: null })
    const release = await latestRelease()
    let imported = 0
    let skipped = 0
    for (const asset of release.assets) {
      const existing = await payload.find({
        collection: 'otter-releases',
        limit: 1,
        depth: 0,
        req,
        where: {
          and: [
            { target: { equals: asset.target } },
            {
              version: {
                in: [
                  release.version,
                  release.version.replace(/^v/, ''),
                  `v${release.version.replace(/^v/, '')}`,
                ],
              },
            },
          ],
        },
      })
      if (existing.docs.length) {
        skipped++
        continue
      }
      const downloaded = await download(asset.url, MAX_OTTER_RELEASE_SIZE)
      if (downloaded.length !== asset.size)
        throw new APIError('The GitHub release asset size does not match its metadata.', 400)
      const binary = await unpackOtterRelease(downloaded)
      const verified = await verifyOtterRelease(binary)
      if (
        verified.target !== asset.target ||
        verified.version.replace(/^v/, '') !== release.version.replace(/^v/, '')
      )
        throw new APIError(
          'The signed executable does not match the GitHub release version and platform.',
          400,
        )
      try {
        await payload.create({
          collection: 'otter-releases',
          data: verified,
          req,
          overrideAccess: !input.submittedBy,
          file: {
            data: binary,
            name: asset.name.endsWith('.exe') ? asset.name : 'otserver-otter',
            size: binary.length,
            mimetype: 'application/octet-stream',
          },
        })
        imported++
      } catch (error) {
        const concurrent = await payload.find({
          collection: 'otter-releases',
          limit: 1,
          depth: 0,
          req,
          where: {
            and: [
              { target: { equals: verified.target } },
              { version: { equals: verified.version } },
            ],
          },
        })
        if (concurrent.docs[0]?.binaryDigest !== verified.binaryDigest) throw error
        skipped++
      }
    }
    await saveState(req, {
      version: release.version,
      lastSyncedAt: new Date().toISOString(),
      error: null,
    })
    await writeAudit({
      action: 'custom',
      req,
      targetCollection: 'otter-releases',
      after: {
        id: 'github-import',
        name: 'Otter release import completed',
        version: release.version,
        imported,
        skipped,
      },
    })
    return { imported, skipped }
  } catch (error) {
    await saveState(req, {
      error:
        error instanceof APIError
          ? error.message.slice(0, 1000)
          : 'Otter release import failed. Check the worker logs and retry.',
    })
    throw error
  }
}
