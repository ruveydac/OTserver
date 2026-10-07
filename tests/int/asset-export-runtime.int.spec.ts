import { describe, expect, it, vi } from 'vitest'

import { exportAssetsCSV } from '../../src/collections/AssetExport'

describe('asset export runtime boundaries', () => {
  it('paginates assets and active endpoints while streaming related data', async () => {
    const assets = Array.from({ length: 100 }, (_, index) => ({
      id: `asset-${String(index).padStart(3, '0')}`,
      name: `Asset ${index}`,
      site: 'site-1',
    }))
    let assetPages = 0
    let endpointPages = 0
    const find = vi.fn(async ({ collection }: { collection: string }) => {
      if (collection === 'assets') {
        assetPages++
        return { docs: assetPages % 2 ? assets : [] }
      }
      if (collection === 'sites') return { docs: [{ id: 'site-1', name: 'Plant' }] }
      endpointPages++
      return {
        docs:
          endpointPages === 1
            ? Array.from({ length: 100 }, (_, index) => ({
                address: `192.0.2.${index + 1}`,
                id: `endpoint-${index}`,
              }))
            : [],
      }
    })

    const response = await exportAssetsCSV({ query: {}, payload: { find } } as never)
    const csv = await response.text()

    expect(csv.split('\r\n')).toHaveLength(102)
    expect(csv).toContain('Plant')
    expect(csv).toContain('endpoint-0')
    expect(assetPages).toBe(4)
    expect(endpointPages).toBe(101)
    expect(find).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'network-endpoints',
        where: expect.objectContaining({ and: expect.any(Array) }),
      }),
    )
  })
})
