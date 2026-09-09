import type { Where } from 'payload'
import { describe, expect, it } from 'vitest'

import { applyAssetSearch, parseAssetSearch } from '../../src/search/assetLucene'
import { whereToLucene } from '../../src/search/whereToLucene'

describe('asset Lucene search', () => {
  it('translates search, boolean filters, aliases, and ranges', () => {
    expect(parseAssetSearch('plc').or).toContainEqual({ name: { like: 'plc' } })
    expect(parseAssetSearch('status:online AND vendor:Siemens')).toEqual({
      and: [{ status: { equals: 'online' } }, { vendor: { like: 'Siemens' } }],
    })
    expect(parseAssetSearch('mac:00-11-22-33-44-55')).toEqual({
      macAddress: { equals: '00:11:22:33:44:55' },
    })
    expect(parseAssetSearch('osAccuracy:[80 TO 100]')).toEqual({
      osAccuracy: { greater_than_equal: 80, less_than_equal: 100 },
    })
    expect(parseAssetSearch('status:(online OR maintenance)')).toEqual({
      or: [{ status: { equals: 'online' } }, { status: { equals: 'maintenance' } }],
    })
    expect(parseAssetSearch('class:PLC')).toEqual({ 'assetClass.name': { like: 'PLC' } })
    expect(parseAssetSearch(whereToLucene({ assetClass: { equals: 'class-1' } }))).toEqual({
      assetClass: { equals: 'class-1' },
    })
  })

  it('covers remaining whereToLucene branches', () => {
    expect(whereToLucene({ status: { exists: true } })).toBe('status:*')
    expect(whereToLucene({ status: { in: ['online', 'offline'] } })).toBe(
      '(status:"online" OR status:"offline")',
    )
    expect(whereToLucene({ status: { in: 'online,offline' } })).toBe(
      '(status:"online" OR status:"offline")',
    )
    expect(whereToLucene({ status: { not_in: ['offline'] } })).toBe('status:-"offline"')
    expect(whereToLucene({ and: [{ status: { equals: 'online' } }] })).toBe('status:"online"')
    expect(
      whereToLucene({ or: [{ status: { equals: 'online' } }, { status: { equals: 'offline' } }] }),
    ).toBe('(status:"online" OR status:"offline")')
    expect(whereToLucene({ status: { equals: '' } })).toBe('')
    expect(whereToLucene({ status: { equals: null } })).toBe('')
    expect(whereToLucene({ vendor: { not_equals: 'Siemens' } })).toBe('vendor:-"Siemens"')
    expect(whereToLucene({ vendor: { not_like: 'Siemens' } })).toBe('vendor:-*Siemens*')
    expect(whereToLucene({ osAccuracy: { greater_than: 80 } })).toBe('osAccuracy:{80 TO *}')
    expect(whereToLucene({ osAccuracy: { less_than: 100 } })).toBe('osAccuracy:{* TO 100}')
    expect(whereToLucene({ osAccuracy: { less_than_equal: 100 } })).toBe('osAccuracy:[* TO 100]')
    expect(whereToLucene({ status: { in: [] } })).toBe('')
    expect(whereToLucene({ and: [{ status: { equals: '' } }] })).toBe('')
    expect(whereToLucene({ or: [{ status: { equals: '' } }] })).toBe('')
    expect(whereToLucene(undefined)).toBe('')
  })

  it('supports exclusion and rejects unknown fields', () => {
    expect(parseAssetSearch('vendor:Siemens NOT status:offline')).toEqual({
      and: [{ vendor: { like: 'Siemens' } }, { status: { not_equals: 'offline' } }],
    })
    expect(() => parseAssetSearch('password:secret')).toThrow('unknown field')
  })

  it('rejects a NOT without a left operand instead of inverting the filter', () => {
    for (const query of [
      'NOT status:offline',
      'status:online AND NOT vendor:Siemens',
      'status:online OR NOT vendor:Siemens',
      'NOT (status:online OR status:offline)',
      'status:online NOT NOT vendor:Siemens',
    ]) {
      expect(() => parseAssetSearch(query)).toThrow('NOT needs a term on both sides')
    }

    expect(parseAssetSearch('name:"NOT a term"')).toEqual({ name: { equals: 'NOT a term' } })
    expect(parseAssetSearch('vendor:Siemens NOT status:offline')).toEqual({
      and: [{ vendor: { like: 'Siemens' } }, { status: { not_equals: 'offline' } }],
    })
  })

  it('rejects unsupported syntax with a clear error', () => {
    expect(() => parseAssetSearch('name:/plc.*/')).toThrow('regular expressions are not supported')
    expect(() => parseAssetSearch('name:plc~2')).toThrow(
      'fuzzy search and boosts are not supported',
    )
    expect(() => parseAssetSearch('name:plc^2')).toThrow(
      'fuzzy search and boosts are not supported',
    )
    expect(() => parseAssetSearch('name:[a TO z]')).toThrow('ranges are not supported for name')
    expect(() => parseAssetSearch('osAccuracy:[abc TO 100]')).toThrow('abc is not a valid number')
    expect(() => parseAssetSearch('lastseen:[abc TO *]')).toThrow('abc is not a valid date')
    expect(() => parseAssetSearch('**')).toThrow('enter a search term')
    expect(() => parseAssetSearch('x'.repeat(501))).toThrow('longer than 500 characters')
    expect(() => parseAssetSearch(`${'('.repeat(25)}name:x${')'.repeat(25)}`)).toThrow(
      'too deeply nested',
    )
  })

  it('translates ranges, wildcards, and negated ranges', () => {
    expect(parseAssetSearch('osAccuracy:{80 TO 100}')).toEqual({
      osAccuracy: { greater_than: 80, less_than: 100 },
    })
    expect(parseAssetSearch('osAccuracy:[* TO *]')).toEqual({})
    expect(parseAssetSearch('*')).toEqual({})
    expect(parseAssetSearch('name:*')).toEqual({ name: { exists: true } })
    expect(parseAssetSearch('name:**')).toEqual({ name: { exists: true } })
    expect(parseAssetSearch('status:-*')).toEqual({ status: { exists: false } })
    expect(parseAssetSearch('name:"foo bar"~3')).toEqual({ name: { equals: 'foo bar' } })
    expect(parseAssetSearch('criticality:HIGH')).toEqual({ criticality: { equals: 'high' } })
    expect(parseAssetSearch('vendor:a NOT osAccuracy:[80 TO 100]')).toEqual({
      and: [
        { vendor: { like: 'a' } },
        { or: [{ osAccuracy: { less_than: 80 } }, { osAccuracy: { greater_than: 100 } }] },
      ],
    })
  })

  it('turns Payload graphical filters into equivalent Lucene', () => {
    const graphicalWhere: Where = {
      or: [
        { and: [{ status: { equals: 'online' } }, { vendor: { like: 'Siemens AG' } }] },
        { and: [{ osAccuracy: { greater_than_equal: 80 } }] },
      ],
    }
    const lucene = whereToLucene(graphicalWhere)

    expect(whereToLucene({ vendor: { equals: 'Siemens' } })).toBe('vendor:"Siemens"')
    expect(whereToLucene({ vendor: { contains: 'Siemens' } })).toBe('vendor:*Siemens*')
    expect(lucene).toBe('((status:"online" AND vendor:*Siemens\\ AG*) OR osAccuracy:[80 TO *])')
    expect(parseAssetSearch(lucene)).toEqual({
      or: [
        { and: [{ status: { equals: 'online' } }, { vendor: { like: 'Siemens AG' } }] },
        { osAccuracy: { greater_than_equal: 80 } },
      ],
    })
    expect(parseAssetSearch(whereToLucene({ status: { exists: false } }))).toEqual({
      status: { exists: false },
    })
    expect(
      parseAssetSearch(
        whereToLucene({ lastSeen: { greater_than_equal: '2026-08-09T12:30:00.000Z' } }),
      ),
    ).toEqual({
      lastSeen: { greater_than_equal: '2026-08-09T12:30:00.000Z' },
    })

    const result = applyAssetSearch({
      args: { where: { and: [graphicalWhere] } },
      operation: 'read',
      req: { query: { search: lucene, where: graphicalWhere } },
    } as never) as { where: unknown }
    expect(result.where).toEqual(parseAssetSearch(lucene))
  })
})
