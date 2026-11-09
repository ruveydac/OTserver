import { unlink } from 'node:fs/promises'
import path from 'node:path'
import type { Payload, PayloadRequest, Where } from 'payload'
import { withRequestContext } from '../integrations/payload/context'
import { readAssetImportCleanupSettings } from './settings'

const PAGE_SIZE = 100

export const cleanupAssetImportFiles = async (payload: Payload, req: PayloadRequest) => {
  const { enabled, maxAgeDays, maxFiles } = await readAssetImportCleanupSettings(payload, req)
  if (!enabled) return

  const directory = payload.collections['asset-imports'].config.upload?.staticDir
  if (typeof directory !== 'string')
    throw new Error('Asset import upload directory is not configured.')

  const startedAt = new Date()
  const snapshot = startedAt.toISOString()
  const cutoff = startedAt.getTime() - maxAgeDays * 86_400_000
  const fileClauses: Where[] = [
    { filename: { exists: true } },
    { filename: { not_equals: null } },
    { or: [{ fileRemovedAt: { exists: false } }, { fileRemovedAt: { equals: null } }] },
    { updatedAt: { less_than_equal: snapshot } },
  ]
  const completedFiles = await payload.count({
    collection: 'asset-imports',
    overrideAccess: true,
    req,
    where: { and: [...fileClauses, { status: { equals: 'completed' } }] },
  })
  const otherFiles = await payload.count({
    collection: 'asset-imports',
    overrideAccess: true,
    req,
    where: { and: [...fileClauses, { status: { not_equals: 'completed' } }] },
  })
  const completedLimit = Math.max(0, maxFiles - otherFiles.totalDocs)
  const absoluteDirectory = path.resolve(directory)
  let remainingCompleted = completedFiles.totalDocs
  let filesMarkedRemoved = 0

  cleanup: for (;;) {
    const imports = await payload.find({
      collection: 'asset-imports',
      depth: 0,
      limit: PAGE_SIZE,
      overrideAccess: true,
      page: 1,
      req,
      select: { createdAt: true, filename: true },
      sort: 'createdAt',
      where: { and: [...fileClauses, { status: { equals: 'completed' } }] },
    })
    if (!imports.docs.length) break

    for (const imported of imports.docs) {
      const createdAt = Date.parse(imported.createdAt || '')
      const expired = Number.isFinite(createdAt) && createdAt <= cutoff
      if (!expired && remainingCompleted <= completedLimit) break cleanup

      const filename = imported.filename
      if (!filename || path.basename(filename) !== filename) {
        payload.logger.warn({
          event: 'asset-import.file-cleanup.invalid-filename',
          importID: String(imported.id),
        })
        break cleanup
      }

      try {
        await unlink(path.join(absoluteDirectory, filename))
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          payload.logger.error({
            event: 'asset-import.file-cleanup.failed',
            importID: String(imported.id),
            fileName: filename,
            err: error,
          })
          break cleanup
        }
      }

      const fileRemovedAt = new Date().toISOString()
      await withRequestContext(req, { importWrite: true, skipAssetImport: true }, () =>
        payload.update({
          collection: 'asset-imports',
          id: imported.id,
          context: { importWrite: true, skipAssetImport: true },
          data: { fileRemovedAt },
          overrideAccess: true,
          req,
        }),
      )
      remainingCompleted--
      filesMarkedRemoved++
    }
  }

  if (filesMarkedRemoved)
    payload.logger.info({
      event: 'asset-import.files-cleaned',
      filesMarkedRemoved,
      maxAgeDays,
      maxFiles,
    })
}
