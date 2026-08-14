import { describe, expect, it } from 'vitest'

import { mergeAssetData, trackHumanAssetChanges } from '../../src/importers/assetQuality'

describe('asset data quality', () => {
  it('fills empty fields and only lets equal or higher quality replace populated fields', () => {
    const merged = mergeAssetData(
      {
        description: '',
        ipAddress: '192.0.2.10',
        model: 'Old medium model',
        name: 'Human name',
        fieldProvenance: {
          ipAddress: { quality: 'high', source: 'proneta' },
          model: { quality: 'medium', source: 'nmap' },
          name: { quality: 'human', source: 'human' },
        },
      },
      [
        {
          data: {
            description: 'Discovered description',
            ipAddress: '192.0.2.20',
            model: 'New medium model',
            name: 'Discovered name',
          },
          quality: 'medium',
          source: 'nmap',
        },
      ],
    )

    expect(merged.data).toEqual({
      description: 'Discovered description',
      model: 'New medium model',
    })
    expect(merged.fieldProvenance).toMatchObject({
      description: { quality: 'medium', source: 'nmap' },
      ipAddress: { quality: 'high', source: 'proneta' },
      model: { quality: 'medium', source: 'nmap' },
      name: { quality: 'human', source: 'human' },
    })
  })

  it('records higher-quality confirmation without rewriting an equal value', () => {
    const merged = mergeAssetData(
      {
        operatingSystem: 'Linux',
        fieldProvenance: {
          operatingSystem: { quality: 'medium', source: 'nmap' },
        },
      },
      [
        {
          data: { operatingSystem: 'Linux' },
          quality: 'high',
          source: 'proneta',
        },
      ],
    )

    expect(merged.changed).toBe(true)
    expect(merged.data).toEqual({})
    expect(merged.fieldProvenance.operatingSystem).toEqual({
      quality: 'high',
      source: 'proneta',
    })
  })

  it('protects only the fields a human changed', () => {
    const data = trackHumanAssetChanges(
      {
        fieldProvenance: { name: { quality: 'low', source: 'spoofed' } },
        ipAddress: '192.0.2.10',
        name: 'Human correction',
      },
      {
        ipAddress: '192.0.2.10',
        name: 'Discovered name',
        fieldProvenance: {
          ipAddress: { quality: 'medium', source: 'nmap' },
          name: { quality: 'medium', source: 'nmap' },
        },
      },
    )

    expect(data.fieldProvenance).toEqual({
      ipAddress: { quality: 'medium', source: 'nmap' },
      name: { quality: 'human', source: 'human' },
    })
  })

  it('combines protocol evidence without downgrading its provenance', () => {
    const merged = mergeAssetData(
      {
        protocols: ['profinet'],
        fieldProvenance: { protocols: { quality: 'high', source: 'profinet-dcp' } },
      },
      [{ data: { protocols: ['niagara-fox'] }, quality: 'medium', source: 'niagara-fox' }],
    )

    expect(merged.data.protocols).toEqual(['profinet', 'niagara-fox'])
    expect(merged.fieldProvenance.protocols).toEqual({ quality: 'high', source: 'profinet-dcp' })
  })
})
