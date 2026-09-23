import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  recount: vi.fn(),
  sync: vi.fn(),
  systemRequest: vi.fn(async () => ({ context: {} })),
}))

vi.mock('../../src/vulnerabilities/feeds', () => ({
  SYNC_INTERVAL_MS: 604_800_000,
  syncVulnerabilityFeeds: mocks.sync,
}))

vi.mock('../../src/vulnerabilities/match', () => ({
  recountAssetVulnerabilities: mocks.recount,
}))

vi.mock('../../src/integrations/payload/requests', () => ({
  systemRequest: mocks.systemRequest,
}))

import { runMaintenance, TRASH_RETENTION_DAYS } from '../../src/jobs/maintenance'

describe('maintenance task', () => {
  const makePayload = (batches: unknown[][]) => ({
    delete: vi.fn(async () => undefined),
    find: vi.fn(async () => ({ docs: batches.shift() || [] })),
    update: vi.fn(async () => ({ docs: [] })),
  })

  beforeEach(() => {
    vi.clearAllMocks()
    process.env.OTSERVER_VULNERABILITY_FEEDS = 'off'
  })

  afterEach(() => {
    process.env.OTSERVER_VULNERABILITY_FEEDS = 'off'
  })

  it('deletes expired trash in bounded batches and records completion', async () => {
    const payload = makePayload([[{ id: 'asset-a' }, { id: 'asset-b' }], []])
    await runMaintenance(payload as never)

    expect(TRASH_RETENTION_DAYS).toBe(90)
    expect(payload.find).toHaveBeenCalledTimes(2)
    expect(payload.find).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'assets',
        limit: 100,
        trash: true,
        where: { deletedAt: { less_than_equal: expect.any(String) } },
      }),
    )
    expect(payload.delete).toHaveBeenCalledTimes(2)
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'worker-leases',
        data: { lastSuccessAt: expect.any(String) },
      }),
    )
    expect(mocks.sync).not.toHaveBeenCalled()
  })

  it('refreshes the catalog and recounts assets when feeds are enabled', async () => {
    process.env.OTSERVER_VULNERABILITY_FEEDS = 'on'
    const payload = makePayload([[]])
    await runMaintenance(payload as never)

    expect(mocks.sync).toHaveBeenCalledWith(payload, {
      failOnSourceError: true,
      force: true,
    })
    expect(mocks.recount).toHaveBeenCalledWith(payload)
  })
})
