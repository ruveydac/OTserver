import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  bindImportedIdentity: vi.fn().mockResolvedValue([]),
  parseNmap: vi.fn(),
  parseOTserverOtter: vi.fn(),
  parseProneta: vi.fn(),
  requireTransaction: vi.fn().mockResolvedValue(undefined),
  resolveImportedIdentity: vi.fn(),
  suggestAdjacentInterfaces: vi.fn().mockResolvedValue(undefined),
  suggestAttachmentChange: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../src/importers/nmap', () => ({ parseNmap: mocks.parseNmap }))
vi.mock('../../src/importers/otserverOtter', () => ({
  parseOTserverOtter: mocks.parseOTserverOtter,
}))
vi.mock('../../src/importers/proneta', () => ({ parseProneta: mocks.parseProneta }))
vi.mock('../../src/identity/access', () => ({
  idOf: (value: unknown) =>
    value && typeof value === 'object'
      ? String((value as { id?: unknown }).id ?? '')
      : String(value ?? ''),
  requireTransaction: mocks.requireTransaction,
}))
vi.mock('../../src/identity/reconcile', () => ({
  bindImportedIdentity: mocks.bindImportedIdentity,
  descriptiveFields: (value: Record<string, unknown>) => value,
  importObservedAt: () => '2026-09-01T08:00:00.000Z',
  recordContainment: vi.fn(),
  resolveImportedIdentity: mocks.resolveImportedIdentity,
  suggestAdjacentInterfaces: mocks.suggestAdjacentInterfaces,
  suggestAttachmentChange: mocks.suggestAttachmentChange,
}))

import { processImport } from '../../src/application/processImport'

const doc = { id: 'import-1', site: 'site-1', source: 'nmap' }

beforeEach(() => {
  vi.clearAllMocks()
  mocks.requireTransaction.mockResolvedValue(undefined)
  mocks.bindImportedIdentity.mockResolvedValue([])
  mocks.suggestAdjacentInterfaces.mockResolvedValue(undefined)
  mocks.suggestAttachmentChange.mockResolvedValue(undefined)
  mocks.resolveImportedIdentity.mockReset()
  mocks.parseNmap.mockReset()
})

describe('processImport runtime boundaries', () => {
  it('resolves existing endpoint owners and preserves topology links', async () => {
    const endpointAssets: Record<string, string> = {
      'AA:BB:CC:DD:EE:01': 'asset-local',
      'AA:BB:CC:DD:EE:02': 'asset-remote',
    }
    const find = vi.fn(async ({ collection, where }: { collection: string; where?: unknown }) => {
      if (collection === 'asset-imports') return { docs: [] }
      if (collection !== 'network-endpoints') return { docs: [] }
      const clauses = (where as { and?: Array<Record<string, unknown>> })?.and || []
      const mac = clauses.find((clause) => 'macAddress' in clause) as
        { macAddress?: { equals?: string } } | undefined
      const asset = mac?.macAddress?.equals ? endpointAssets[mac.macAddress.equals] : undefined
      return { docs: asset ? [{ asset }] : [] }
    })
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'topology-link-1',
      ...data,
    }))
    const update = vi.fn(async ({ id, data }: { id: string; data: Record<string, unknown> }) => ({
      id,
      ...data,
    }))
    const originalContext = {
      assetImport: false,
      importWrite: 'outer-operation',
      identityImportSource: 'previous-source',
    }
    const req = {
      context: { ...originalContext },
      payload: {
        create,
        find,
        update,
        findByID: vi.fn(async ({ collection }: { collection: string }) =>
          collection === 'sites' ? { type: 'type-1' } : { blockImports: false },
        ),
      },
    }
    mocks.parseNmap.mockReturnValue({
      assets: [],
      links: [
        {
          local: { macAddress: 'AA:BB:CC:DD:EE:01', portId: 'port-1' },
          observedAt: '2026-09-01T08:00:00.000Z',
          raw: { protocol: 'lldp' },
          remote: { macAddress: 'AA:BB:CC:DD:EE:02' },
          source: 'lldp',
        },
        {
          local: {},
          observedAt: '2026-09-01T08:01:00.000Z',
          remote: { macAddress: 'AA:BB:CC:DD:EE:03' },
          source: 'arp',
        },
      ],
      warnings: ['one warning'],
    })

    const result = await processImport({
      data: Buffer.from('<nmaprun />'),
      doc: doc as never,
      req: req as never,
    })

    expect(mocks.suggestAttachmentChange).toHaveBeenCalledWith(
      'site-1',
      'asset-local',
      'asset-remote',
      'port-1',
      '2026-09-01T08:00:00.000Z',
      req,
    )
    expect(create).toHaveBeenCalledTimes(2)
    expect(create.mock.calls[0]?.[0]).toMatchObject({
      collection: 'topology-links',
      data: {
        localAsset: 'asset-local',
        remoteAsset: 'asset-remote',
        raw: { protocol: 'lldp' },
      },
    })
    expect(create.mock.calls[1]?.[0]).toMatchObject({
      collection: 'topology-links',
      data: { localAsset: undefined, remoteAsset: undefined },
    })
    expect(result).toMatchObject({
      id: 'import-1',
      status: 'completed',
      topologyName: undefined,
      warnings: 'one warning',
    })
    expect(req.context).toEqual(originalContext)
  })

  it('rejects an oversized identity import before opening a transaction', async () => {
    mocks.parseNmap.mockReturnValue({
      assets: Array.from({ length: 2001 }, () => ({ name: 'device' })),
      links: [],
      warnings: [],
    })

    const req = {
      context: { assetImport: false, importWrite: 'outer-operation' },
      payload: {},
    }
    await expect(
      processImport({
        data: Buffer.from('<nmaprun />'),
        doc: doc as never,
        req: req as never,
        throwValidationErrors: true,
      }),
    ).rejects.toThrow('limited to 2000')
    expect(mocks.requireTransaction).not.toHaveBeenCalled()
    expect(req.context).toEqual({ assetImport: false, importWrite: 'outer-operation' })
  })

  it('logs the failing import phase and can process the next import after a write error', async () => {
    mocks.parseNmap.mockReturnValue({
      assets: [{ name: 'device', macAddress: '02:00:00:00:00:01' }],
      links: [],
      warnings: [],
    })
    mocks.resolveImportedIdentity.mockResolvedValue({
      current: undefined,
      blocked: false,
      unresolved: false,
    })
    const failure = new Error('injected asset write failure')
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'asset-1',
      ...data,
    }))
    create.mockRejectedValueOnce(failure)
    const loggerError = vi.fn()
    const req = {
      context: {},
      payload: {
        create,
        find: vi.fn(async () => ({ docs: [] })),
        findByID: vi.fn(async ({ collection }: { collection: string }) =>
          collection === 'sites' ? { type: 'type-1' } : { blockImports: false },
        ),
        logger: { error: loggerError },
        update: vi.fn(async ({ id, data }: { id: string; data: Record<string, unknown> }) => ({
          id,
          ...data,
        })),
      },
    }

    await expect(
      processImport({ data: Buffer.from('<nmaprun />'), doc: doc as never, req: req as never }),
    ).rejects.toBe(failure)
    expect(loggerError).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'asset-import.failed',
        importID: 'import-1',
        source: 'nmap',
        siteID: 'site-1',
        phase: 'write-asset',
        assetCount: 1,
        assetsProcessed: 0,
        assetsCreatedBeforeFailure: 0,
        err: failure,
      }),
    )

    await expect(
      processImport({ data: Buffer.from('<nmaprun />'), doc: doc as never, req: req as never }),
    ).resolves.toMatchObject({ status: 'completed' })
    expect(create).toHaveBeenCalledTimes(2)
    expect(req.context).toEqual({})
  })
})
