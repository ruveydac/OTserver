import { describe, expect, it } from 'vitest'

import { AssetImports, getAssetOverrides } from '../../src/collections/AssetImports'
import { Sites } from '../../src/collections/Sites'
import { importSources } from '../../src/importers/sources'

describe('import source guidance', () => {
  it('documents how to create a usable file for every importer', () => {
    expect(importSources.map(({ value }) => value)).toEqual(['otserver-scanner', 'proneta', 'nmap'])
    expect(Object.fromEntries(importSources.map(({ quality, value }) => [value, quality]))).toEqual(
      {
        nmap: 'medium',
        'otserver-scanner': 'low',
        proneta: 'high',
      },
    )

    for (const source of importSources) {
      expect(source.steps.length).toBeGreaterThan(0)
      expect(source.required).toBeTruthy()
      expect(source.note).toBeTruthy()
    }

    const nmap = importSources.find(({ value }) => value === 'nmap')
    const command = nmap && 'command' in nmap ? nmap.command : ''
    for (const script of ['bacnet-info', 'enip-info', 'fox-info', 'omron-info', 's7-info']) {
      expect(command).toContain(script)
    }
    expect(command).toContain('T:102,1911,4911,9600,44818')
    expect(command).toContain('U:9600,44818,47808')
    expect(command).not.toContain('modbus-discover')
    expect(command).not.toContain('502')

    const sourceField = AssetImports.fields.find(
      (field) => field.type === 'select' && field.name === 'source',
    )
    expect(sourceField).toMatchObject({ defaultValue: 'otserver-scanner' })

    const siteIDField = Sites.fields.find(
      (field) => field.type === 'ui' && field.name === 'siteIDDisplay',
    )
    expect(siteIDField).toMatchObject({
      admin: { components: { Field: '@/components/SiteIDField' } },
    })
  })

  it('keeps only configured, non-empty asset overrides', () => {
    expect(
      getAssetOverrides({
        assetOwner: '  Operations  ',
        location: ' Cabinet A ',
        macAddress: '00:00:00:00:00:00',
      }),
    ).toEqual({ assetOwner: 'Operations', location: 'Cabinet A' })
    expect(getAssetOverrides(undefined)).toEqual({})
  })
})
