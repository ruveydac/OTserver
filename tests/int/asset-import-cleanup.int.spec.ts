import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { FileUploadError } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { AssetImports } from '../../src/collections/AssetImports'
import { cleanupAssetImportFiles } from '../../src/application/assetImportCleanup'

describe('asset import file cleanup', () => {
  it('applies age and count limits while preserving active and retryable files', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'otserver-import-cleanup-'))
    const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString()
    type ImportDoc = {
      id: string
      filename: string
      executionMode: 'sync' | 'queued'
      status: 'completed' | 'pending' | 'running' | 'failed'
      updatedAt: string
      createdAt: string
      site: string
      fileRemovedAt?: string
    }
    const docs: ImportDoc[] = [
      {
        id: 'newest',
        filename: 'newest.json',
        executionMode: 'sync',
        status: 'completed',
        updatedAt: daysAgo(1),
        createdAt: daysAgo(1),
        site: 'site-1',
      },
      {
        id: 'over-count',
        filename: 'over-count.json',
        executionMode: 'sync',
        status: 'completed',
        updatedAt: daysAgo(3),
        createdAt: daysAgo(3),
        site: 'site-1',
      },
      {
        id: 'second-newest',
        filename: 'second-newest.json',
        executionMode: 'sync',
        status: 'completed',
        updatedAt: daysAgo(2),
        createdAt: daysAgo(2),
        site: 'site-1',
      },
      {
        id: 'over-age',
        filename: 'over-age.json',
        executionMode: 'sync',
        status: 'completed',
        updatedAt: daysAgo(40),
        createdAt: daysAgo(40),
        site: 'site-1',
      },
      {
        id: 'active',
        filename: 'active.json',
        executionMode: 'queued',
        status: 'running',
        updatedAt: daysAgo(150),
        createdAt: daysAgo(150),
        site: 'site-1',
      },
      {
        id: 'retryable',
        filename: 'retryable.json',
        executionMode: 'queued',
        status: 'failed',
        updatedAt: daysAgo(180),
        createdAt: daysAgo(180),
        site: 'site-1',
      },
      {
        id: 'pending-sync',
        filename: 'pending-sync.json',
        executionMode: 'sync',
        status: 'pending',
        updatedAt: daysAgo(200),
        createdAt: daysAgo(200),
        site: 'site-1',
      },
      {
        id: 'failed-sync',
        filename: 'failed-sync.json',
        executionMode: 'sync',
        status: 'failed',
        updatedAt: daysAgo(220),
        createdAt: daysAgo(220),
        site: 'site-1',
      },
    ]
    const logger = { error: vi.fn(), info: vi.fn(), warn: vi.fn() }
    const update = vi.fn(async (args: { id: string; data: { fileRemovedAt: string } }) => {
      const doc = docs.find(({ id }) => id === args.id)
      if (doc) doc.fileRemovedAt = args.data.fileRemovedAt
      return { id: args.id, ...args.data }
    })
    const payload = {
      collections: { 'asset-imports': { config: { upload: { staticDir: directory } } } },
      count: vi
        .fn()
        .mockResolvedValueOnce({ totalDocs: 4 })
        .mockResolvedValueOnce({ totalDocs: 4 }),
      find: vi.fn(async () => {
        return {
          docs: docs
            .filter((doc) => doc.status === 'completed' && !doc.fileRemovedAt)
            .sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt))
            .slice(0, 100),
        }
      }),
      findGlobal: vi.fn(async () => ({
        assetImportCleanup: { enabled: true, maxFiles: 6, maxAgeDays: 30 },
      })),
      logger,
      delete: vi.fn(),
      update,
    }
    const req = { context: {}, payload }

    try {
      await mkdir(path.join(directory, 'vulnerability-feeds'))
      await Promise.all([
        ...docs.map(({ filename }) => writeFile(path.join(directory, filename), filename)),
        writeFile(path.join(directory, 'vulnerability-feeds', 'feed.json'), 'leave untouched'),
      ])

      await cleanupAssetImportFiles(payload as never, req as never)

      await expect(readFile(path.join(directory, 'newest.json'), 'utf8')).resolves.toBe(
        'newest.json',
      )
      await expect(readFile(path.join(directory, 'second-newest.json'), 'utf8')).resolves.toBe(
        'second-newest.json',
      )
      for (const filename of ['over-count.json', 'over-age.json'])
        await expect(readFile(path.join(directory, filename))).rejects.toMatchObject({
          code: 'ENOENT',
        })
      for (const filename of [
        'active.json',
        'retryable.json',
        'pending-sync.json',
        'failed-sync.json',
      ])
        await expect(readFile(path.join(directory, filename), 'utf8')).resolves.toBe(filename)
      await expect(
        readFile(path.join(directory, 'vulnerability-feeds', 'feed.json'), 'utf8'),
      ).resolves.toBe('leave untouched')
      expect(update).toHaveBeenCalledTimes(2)
      expect(update.mock.calls.map(([args]) => args)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'over-count',
            data: { fileRemovedAt: expect.any(String) },
          }),
          expect.objectContaining({ id: 'over-age', data: { fileRemovedAt: expect.any(String) } }),
        ]),
      )
      expect(payload.delete).not.toHaveBeenCalled()
      expect(payload.count).toHaveBeenCalledTimes(2)
      expect(payload.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            and: expect.arrayContaining([{ status: { equals: 'completed' } }]),
          },
        }),
      )
      expect(req.context).toEqual({})
    } finally {
      await rm(directory, { force: true, recursive: true })
    }
  })

  it('does not query or remove files when cleanup is disabled', async () => {
    const count = vi.fn()
    const find = vi.fn()
    const payload = {
      count,
      find,
      findGlobal: vi.fn(async () => ({ assetImportCleanup: { enabled: false } })),
    }

    await cleanupAssetImportFiles(payload as never, { context: {}, payload } as never)

    expect(count).not.toHaveBeenCalled()
    expect(find).not.toHaveBeenCalled()
  })

  it('clears the cleanup marker when a synchronous import file is replaced', async () => {
    const beforeChange = AssetImports.hooks?.beforeChange?.[1]
    const req = { context: { assetImportFileReplacement: true }, file: { name: 'new.xml' } }
    const data: Record<string, unknown> = {}

    await (beforeChange as (args: never) => unknown)({
      data,
      context: req.context,
      operation: 'update',
      originalDoc: { executionMode: 'sync', fileRemovedAt: '2026-01-01T00:00:00.000Z' },
      req,
    } as never)

    expect(data.fileRemovedAt).toBeNull()
  })

  it('logs upload errors with the asset import request and file metadata', async () => {
    const loggerError = vi.fn()
    const req = {
      context: {},
      file: { name: 'plant-scan.xml', size: 1234 },
      method: 'POST',
      pathname: '/api/asset-imports',
      payload: { logger: { error: loggerError } },
    }
    const afterError = AssetImports.hooks?.afterError?.[0]

    await (afterError as (args: never) => unknown)({
      error: new FileUploadError(),
      req,
      collection: { slug: 'asset-imports' },
      context: {},
    } as never)
    const diskFull = Object.assign(new Error('disk is full'), { code: 'ENOSPC' })
    await (afterError as (args: never) => unknown)({
      error: diskFull,
      req,
      collection: { slug: 'asset-imports' },
      context: {},
    } as never)

    expect(loggerError).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'asset-import.upload.failed',
        fileName: 'plant-scan.xml',
        fileSize: 1234,
        method: 'POST',
        requestPath: '/api/asset-imports',
        err: expect.any(FileUploadError),
      }),
    )
    expect(loggerError).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'asset-import.upload.failed', err: diskFull }),
    )
  })
})
