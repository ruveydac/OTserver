import { createHash } from 'node:crypto'
import { APIError, type Payload, type PayloadRequest } from 'payload'
import { readApplicationSettings, type ApplicationSettings } from '../application/settings'
import { writeAudit } from '../collections/AuditLogs'
import { systemRequest } from '../integrations/payload/requests'
import { inTransaction } from '../integrations/payload/transactions'
import { safeFailure } from '../jobs/errors'
import { MAX_METADATA_BYTES, applyMetadataFilesInTransaction } from './import'

export const METADATA_SYNC_TASK = 'device-metadata-sync-v1'
export const METADATA_SYNC_INTERVAL_MS = 86_400_000
const repository = 'https://api.github.com/repos/ruveydac/OTserver-metadata'
const rawRepository = 'https://raw.githubusercontent.com/ruveydac/OTserver-metadata'
const maxGitHubResponse = 1024 * 1024
const metadataPath = /^data\/ot-(?:manufacturers|devices)(?:-[a-z0-9-]+)?\.json$/

const saveState = async (
  req: PayloadRequest,
  state: NonNullable<ApplicationSettings['metadataSync']>,
) => {
  const settings = await readApplicationSettings(req.payload, req)
  await req.payload.updateGlobal({
    slug: 'application-settings',
    data: { metadataSync: { ...settings.metadataSync, ...state } },
    overrideAccess: true,
    req,
  })
}

const limitedResponse = async (
  url: string,
  limit: number,
  logger: Payload['logger'],
): Promise<Buffer> => {
  let response: Response
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'OTserver metadata updater' },
      redirect: 'error',
      signal: AbortSignal.timeout(120_000),
    })
  } catch (error) {
    logger.warn({ event: 'metadata-sync.request-failed', error: safeFailure(error) })
    throw new APIError('GitHub could not be reached. The metadata update will be retried.', 503)
  }
  if (!response.ok || !response.body) {
    await response.body?.cancel()
    const retryable =
      response.status === 429 ||
      response.status >= 500 ||
      (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0')
    throw new APIError(
      `GitHub metadata request failed (HTTP ${response.status}).`,
      retryable ? 503 : 400,
    )
  }
  if (Number(response.headers.get('content-length')) > limit) {
    await response.body.cancel()
    throw new APIError('A GitHub metadata response exceeds its size limit.', 413)
  }
  const chunks: Buffer[] = []
  let size = 0
  try {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.length
      if (size > limit)
        throw new APIError('A GitHub metadata response exceeds its size limit.', 413)
      chunks.push(Buffer.from(chunk))
    }
  } catch (error) {
    if (error instanceof APIError) throw error
    logger.warn({ event: 'metadata-sync.download-interrupted', error: safeFailure(error) })
    throw new APIError(
      'The GitHub metadata download was interrupted. The update will be retried.',
      503,
    )
  }
  return Buffer.concat(chunks)
}

const parseJSON = <T>(data: Buffer, message: string): T => {
  try {
    return JSON.parse(data.toString('utf8')) as T
  } catch {
    throw new APIError(message, 400)
  }
}

const latestCommit = async (logger: Payload['logger']) => {
  const data = await limitedResponse(`${repository}/commits/main`, maxGitHubResponse, logger)
  const commit = parseJSON<{
    sha?: unknown
    commit?: { tree?: { sha?: unknown } }
  }>(data, 'GitHub returned invalid metadata commit information.')
  if (
    !commit ||
    typeof commit !== 'object' ||
    typeof commit.sha !== 'string' ||
    !/^[0-9a-f]{40}$/i.test(commit.sha) ||
    typeof commit.commit?.tree?.sha !== 'string' ||
    !/^[0-9a-f]{40}$/i.test(commit.commit.tree.sha)
  )
    throw new APIError('GitHub returned invalid metadata commit information.', 400)
  return { commitSHA: commit.sha.toLowerCase(), treeSHA: commit.commit.tree.sha.toLowerCase() }
}

const filesAtCommit = async (commitSHA: string, treeSHA: string, logger: Payload['logger']) => {
  const response = await limitedResponse(
    `${repository}/git/trees/${treeSHA}?recursive=1`,
    maxGitHubResponse,
    logger,
  )
  const tree = parseJSON<{
    truncated?: unknown
    tree?: { path?: unknown; type?: unknown; sha?: unknown; size?: unknown }[]
  }>(response, 'GitHub returned an invalid metadata file list.')
  if (!tree || typeof tree !== 'object' || tree.truncated !== false || !Array.isArray(tree.tree))
    throw new APIError('GitHub returned an incomplete metadata file list.', 400)
  const entries = tree.tree.filter(
    (entry) =>
      Boolean(entry && typeof entry === 'object') &&
      typeof entry.path === 'string' &&
      metadataPath.test(entry.path),
  )
  if (
    entries.length < 2 ||
    entries.length > 50 ||
    !entries.some(({ path }) => path === 'data/ot-manufacturers.json') ||
    !entries.some(({ path }) => typeof path === 'string' && path.startsWith('data/ot-devices'))
  )
    throw new APIError('GitHub metadata is missing required manufacturer or device files.', 400)
  let totalSize = 0
  const files = []
  for (const entry of entries) {
    if (
      entry.type !== 'blob' ||
      typeof entry.path !== 'string' ||
      typeof entry.sha !== 'string' ||
      !/^[0-9a-f]{40}$/i.test(entry.sha) ||
      !Number.isSafeInteger(entry.size) ||
      (entry.size as number) <= 0
    )
      throw new APIError('GitHub returned invalid metadata file information.', 400)
    totalSize += entry.size as number
    if (totalSize > MAX_METADATA_BYTES)
      throw new APIError('The GitHub metadata snapshot exceeds 8 MiB.', 413)
    const path = entry.path
    const content = await limitedResponse(
      `${rawRepository}/${commitSHA}/${path}`,
      entry.size as number,
      logger,
    )
    if (
      content.length !== entry.size ||
      createHash('sha1').update(`blob ${content.length}\0`).update(content).digest('hex') !==
        entry.sha.toLowerCase()
    )
      throw new APIError(`GitHub metadata file ${path} failed its commit integrity check.`, 400)
    files.push({ name: path, content: parseJSON(content, `${path} is not valid JSON.`) })
  }
  return files
}

export const queueMetadataSync = async (req: PayloadRequest) => {
  try {
    return await inTransaction(req, async () => {
      const settings = await readApplicationSettings(req.payload, req)
      if (
        settings.metadataImports !== true ||
        Date.parse(settings.metadataSync?.requestedAt || '') >
          Date.now() - METADATA_SYNC_INTERVAL_MS
      )
        return
      const pending = await req.payload.find({
        collection: 'payload-jobs',
        depth: 0,
        limit: 1,
        req,
        where: {
          and: [
            { taskSlug: { equals: METADATA_SYNC_TASK } },
            { completedAt: { exists: false } },
            { hasError: { not_equals: true } },
          ],
        },
      })
      if (pending.docs[0]) return pending.docs[0]
      await saveState(req, { requestedAt: new Date().toISOString(), error: null })
      const job = await req.payload.jobs.queue({
        task: METADATA_SYNC_TASK,
        queue: 'maintenance',
        input: { version: 1 },
        req,
      })
      await saveState(req, { jobID: String(job.id) })
      await writeAudit({
        action: 'custom',
        req,
        targetCollection: 'device-catalog',
        after: {
          id: 'github-import',
          name: 'Device metadata update requested',
          jobID: String(job.id),
          scheduled: true,
        },
      })
      return job
    })
  } catch (error) {
    if ([11000, 112].includes((error as { code?: number }).code || 0))
      throw new APIError('Another metadata update was queued at the same time.', 409)
    throw error
  }
}

export const scheduleMetadataSync = async (payload: Payload) =>
  queueMetadataSync(await systemRequest(payload))

export const executeMetadataSync = async (payload: Payload) => {
  const req = await systemRequest(payload)
  const initial = await readApplicationSettings(payload, req)
  if (initial.metadataImports !== true) return { updated: false }
  const checkedAt = new Date().toISOString()
  try {
    const { commitSHA, treeSHA } = await latestCommit(payload.logger)
    if (commitSHA === initial.metadataSync?.commitSHA) {
      await inTransaction(req, async () => {
        const settings = await readApplicationSettings(payload, req)
        if (settings.metadataImports !== true) return
        await saveState(req, { lastCheckedAt: checkedAt, error: null })
      })
      return { updated: false }
    }
    const files = await filesAtCommit(commitSHA, treeSHA, payload.logger)
    const result = await inTransaction(req, async () => {
      const settings = await readApplicationSettings(payload, req)
      if (settings.metadataImports !== true) return { updated: false }
      const imported = await applyMetadataFilesInTransaction(req, files)
      await saveState(req, {
        lastCheckedAt: checkedAt,
        lastSyncedAt: checkedAt,
        commitSHA,
        error: null,
      })
      await writeAudit({
        action: 'custom',
        req,
        targetCollection: 'device-catalog',
        after: {
          id: 'github-import',
          name: 'Device metadata update completed',
          commitSHA,
          changed: imported.changed,
        },
      })
      return { updated: imported.changed }
    })
    return result
  } catch (error) {
    const failure = [11000, 112].includes((error as { code?: number }).code || 0)
      ? new APIError(
          'The catalog changed during the metadata update. The update will be retried.',
          503,
        )
      : error
    const message =
      failure instanceof APIError
        ? failure.message
        : 'Metadata update failed. Check application logs.'
    await inTransaction(req, async () => {
      const settings = await readApplicationSettings(payload, req)
      if (settings.metadataImports === true)
        await saveState(req, { lastCheckedAt: checkedAt, error: message })
    }).catch((stateError) =>
      payload.logger.warn({
        event: 'metadata-sync.status-write-failed',
        error: safeFailure(stateError),
      }),
    )
    payload.logger.warn({ event: 'metadata-sync.failed', error: safeFailure(failure) })
    throw failure
  }
}
