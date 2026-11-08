import type { PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'

import { bulkManualAssetTags } from '../../src/tags/actions'

const makePayload = () => ({
  find: vi.fn(async () => ({ docs: [] })),
  findByID: vi.fn(async ({ id }: { id: string }) => ({
    manualTags: id === 'same' ? ['tag-a'] : id === 'remove' ? ['tag-a', 'tag-b'] : [],
  })),
  update: vi.fn(async () => ({})),
})

const makeRequest = (
  body: string | undefined,
  {
    contentType = 'application/json',
    user = { id: 'operator' },
    otterScannerID,
    payload = makePayload(),
  }: {
    contentType?: string
    user?: { id: string } | null
    otterScannerID?: string
    payload?: ReturnType<typeof makePayload>
  } = {},
) => {
  const request = new Request('http://localhost/api/assets/bulk-tags', {
    method: 'POST',
    headers: contentType ? { 'content-type': contentType } : undefined,
    body,
  })
  const req = Object.assign(request, {
    context: otterScannerID ? { otterScannerID } : {},
    payload,
    transactionID: Promise.resolve('existing-transaction'),
    user,
  }) as unknown as PayloadRequest
  return { payload, req }
}

describe('bulk manual asset tag action', () => {
  it('rejects unauthenticated and scanner principals and unsupported content types', async () => {
    await expect(bulkManualAssetTags(makeRequest('{}', { user: null }).req)).rejects.toThrow(
      'User authentication is required to assign tags.',
    )
    await expect(
      bulkManualAssetTags(makeRequest('{}', { otterScannerID: 'scanner' }).req),
    ).rejects.toThrow('User authentication is required to assign tags.')
    await expect(
      bulkManualAssetTags(makeRequest('{}', { contentType: 'text/plain' }).req),
    ).rejects.toThrow('Send asset and tag selections as application/json.')
  })

  it('rejects missing, oversized, malformed, and invalid JSON request bodies', async () => {
    await expect(bulkManualAssetTags(makeRequest(undefined).req)).rejects.toThrow(
      'A JSON request body is required.',
    )
    await expect(bulkManualAssetTags(makeRequest('x'.repeat(128 * 1024 + 1)).req)).rejects.toThrow(
      'Bulk tag requests are limited to 128 KiB.',
    )
    await expect(bulkManualAssetTags(makeRequest('{').req)).rejects.toThrow('Invalid JSON request.')
    for (const body of ['null', '[]', '"text"'])
      await expect(bulkManualAssetTags(makeRequest(body).req)).rejects.toThrow(
        'Invalid bulk tag request.',
      )
  })

  it('rejects empty, oversized, invalid, and duplicate selections', async () => {
    const invalidBodies: Array<[Record<string, unknown>, string]> = [
      [{ assetIDs: [], tagIDs: ['tag'], action: 'add' }, 'Select up to 200 assets'],
      [
        { assetIDs: Array(201).fill('asset'), tagIDs: ['tag'], action: 'add' },
        'Select up to 200 assets',
      ],
      [{ assetIDs: [''], tagIDs: ['tag'], action: 'add' }, 'Select up to 200 assets'],
      [{ assetIDs: [{}], tagIDs: ['tag'], action: 'add' }, 'Select up to 200 assets'],
      [{ assetIDs: ['asset'], tagIDs: [], action: 'add' }, 'Select up to 200 assets'],
      [
        { assetIDs: ['asset'], tagIDs: Array(101).fill('tag'), action: 'add' },
        'Select up to 200 assets',
      ],
      [{ assetIDs: ['asset'], tagIDs: [''], action: 'add' }, 'Select up to 200 assets'],
      [{ assetIDs: ['asset'], tagIDs: [{}], action: 'add' }, 'Select up to 200 assets'],
      [{ assetIDs: ['asset'], tagIDs: ['tag'], action: 'replace' }, 'Select up to 200 assets'],
      [
        { assetIDs: ['asset', 'asset'], tagIDs: ['tag'], action: 'add' },
        'Duplicate assets or tags',
      ],
      [
        { assetIDs: ['asset'], tagIDs: ['tag', 'tag'], action: 'remove' },
        'Duplicate assets or tags',
      ],
    ]

    for (const [body, message] of invalidBodies)
      await expect(bulkManualAssetTags(makeRequest(JSON.stringify(body)).req)).rejects.toThrow(
        message,
      )
  })

  it('adds missing tags, skips unchanged assets, and removes selected tags', async () => {
    const add = makeRequest(
      JSON.stringify({ assetIDs: ['same', 'new'], tagIDs: ['tag-a'], action: 'add' }),
    )
    const added = await bulkManualAssetTags(add.req)
    expect(await added.json()).toEqual({ updated: 1 })
    expect(add.payload.update).toHaveBeenCalledTimes(1)
    expect(add.payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'new', data: { manualTags: ['tag-a'] }, req: add.req }),
    )

    const remove = makeRequest(
      JSON.stringify({ assetIDs: ['remove'], tagIDs: ['tag-a'], action: 'remove' }),
    )
    const removed = await bulkManualAssetTags(remove.req)
    expect(await removed.json()).toEqual({ updated: 1 })
    expect(remove.payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'remove', data: { manualTags: ['tag-b'] }, req: remove.req }),
    )
  })
})
