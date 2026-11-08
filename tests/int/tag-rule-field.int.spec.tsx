// @vitest-environment jsdom

import { act, createElement, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ setValue: vi.fn(), value: '' as string }))

vi.mock('@payloadcms/ui', () => ({
  SelectInput: ({
    label,
    name,
    onChange,
    options,
    readOnly,
    required,
    value,
  }: {
    label: ReactNode
    name: string
    onChange: (value: { label: string; value: string }) => void
    options: Array<{ label: string; value: string }>
    readOnly?: boolean
    required?: boolean
    value?: string | string[]
  }) => (
    <label>
      {label}
      <select
        aria-label={String(label)}
        disabled={readOnly}
        name={name}
        onChange={(event) => {
          const option = options.find(({ value }) => value === event.currentTarget.value)
          if (option) onChange(option)
        }}
        required={required}
        value={typeof value === 'string' ? value : ''}
      >
        <option value="">Select a field</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  ),
  useConfig: () => ({ config: { routes: { api: '/api' } } }),
  useField: () => ({ setValue: mocks.setValue, showError: false, value: mocks.value }),
}))

import TagRuleField from '@/components/TagRuleField'

let container: HTMLDivElement
let root: Root

const render = async (name: string) =>
  act(async () => {
    root.render(
      createElement(TagRuleField, {
        field: { label: name === 'field' ? 'Field' : 'Compare field', name },
        path: `rules.0.conditions.0.${name}`,
      } as never),
    )
    for (let index = 0; index < 5; index++) await Promise.resolve()
  })

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  mocks.value = ''
  mocks.setValue.mockClear()
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  container.remove()
  vi.unstubAllGlobals()
})

describe('automatic tag rule field selector', () => {
  it('offers all field types and stores a selected custom field path', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ docs: [{ id: 42, label: 'Control area' }] }),
      })),
    )
    await render('field')

    const select = container.querySelector<HTMLSelectElement>('select')!
    const values = [...select.options].map(({ value }) => value)
    expect(values).toEqual(
      expect.arrayContaining([
        'asset.vendor',
        'customFields.42',
        'connected.firmwareVersion',
        'connected.device_type',
        'connected.releases_json.version',
        'vulnerability.cve',
      ]),
    )

    await act(async () => {
      select.value = 'customFields.42'
      select.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith('customFields.42')
  })

  it('limits version comparison fields to asset, custom, and connected values', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ docs: [{ id: 'text-field', label: 'Firmware baseline' }] }),
      })),
    )
    mocks.value = 'connected.firmwareVersion'
    await render('compareField')

    const values = [...container.querySelectorAll('option')].map(({ value }) => value)
    expect(values).toContain('asset.firmwareVersion')
    expect(values).toContain('customFields.text-field')
    expect(values).toContain('connected.firmwareVersion')
    expect(values).not.toContain('vulnerability.cve')
  })

  it('shows loading and custom-field fetch error states', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise(() => {})),
    )
    await act(async () =>
      root.render(
        createElement(TagRuleField, {
          field: { label: 'Field', name: 'field' },
          path: 'rules.0.conditions.0.field',
        } as never),
      ),
    )
    expect(container.querySelector('[role="status"]')?.textContent).toContain('Loading')

    await act(async () => root.unmount())
    root = createRoot(container)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('Offline')
      }),
    )
    await render('field')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Other field choices remain available.',
    )
  })
})
