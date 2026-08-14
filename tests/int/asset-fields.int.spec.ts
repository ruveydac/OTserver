import { describe, expect, it } from 'vitest'

import { cleanCustomFieldValues } from '../../src/collections/AssetFields'

const definitions = [
  { id: 'text', type: 'text' },
  { id: 'notes', type: 'textarea' },
  { id: 'number', type: 'number' },
  { id: 'flag', type: 'checkbox' },
  { id: 'date', type: 'date' },
] as const

describe('custom asset fields', () => {
  it('validates configured values and discards unknown fields', () => {
    expect(
      cleanCustomFieldValues(
        {
          date: '2026-08-09',
          flag: false,
          notes: 'Line one\nLine two',
          number: 0,
          text: 'Value',
          unknown: 'discarded',
        },
        [...definitions],
      ),
    ).toEqual({
      date: '2026-08-09',
      flag: false,
      notes: 'Line one\nLine two',
      number: 0,
      text: 'Value',
    })

    expect(() => cleanCustomFieldValues({ date: '2026-02-30' }, [...definitions])).toThrow(
      'Invalid value for custom field date',
    )
    expect(() => cleanCustomFieldValues({ number: '12' }, [...definitions])).toThrow(
      'Invalid value for custom field number',
    )
  })
})
