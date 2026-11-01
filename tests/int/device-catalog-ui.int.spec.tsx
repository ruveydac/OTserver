// @vitest-environment jsdom

import { act, createElement, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  catalog: undefined as unknown,
  refresh: vi.fn(),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: mocks.refresh }) }))
vi.mock('@payloadcms/ui', () => ({
  Button: ({
    children,
    ...props
  }: {
    children: ReactNode
    buttonStyle?: string
    extraButtonProps?: Record<string, unknown>
  }) => {
    delete props.buttonStyle
    const extra = props.extraButtonProps
    delete props.extraButtonProps
    return (
      <button {...props} {...extra}>
        {children}
      </button>
    )
  },
  Gutter: ({ children, ...props }: { children: ReactNode }) => <div {...props}>{children}</div>,
  useConfig: () => ({ config: { routes: { api: '/api' } } }),
  useField: () => ({ value: mocks.catalog }),
}))

import DeviceCatalogImporter from '../../src/components/DeviceCatalogImporter'
import DeviceCatalogTables from '../../src/components/DeviceCatalogTables'

let container: HTMLDivElement
let root: Root
const response = (data: unknown, ok = true) => ({ ok, json: async () => data })
const render = (component: ReactNode) =>
  act(async () => {
    root.render(component)
  })
const button = (label: string) =>
  [...container.querySelectorAll('button')].find((item) => item.textContent === label)
const click = (label: string) =>
  act(async () => {
    button(label)!.click()
  })

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.clearAllMocks()
  mocks.catalog = undefined
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})
afterEach(async () => {
  await act(async () => root.unmount())
  document.body.replaceChildren()
  vi.unstubAllGlobals()
})

describe('device catalog import action', () => {
  const open = () => click('Import JSON files')

  it('opens the import form from one action and focuses the file input', async () => {
    await render(<DeviceCatalogImporter />)
    expect(container.querySelector('form')).toBeNull()
    expect(button('Import JSON files')!.getAttribute('aria-expanded')).toBe('false')

    await open()
    expect(button('Import JSON files')!.getAttribute('aria-expanded')).toBe('true')
    expect(container.querySelector('form')).not.toBeNull()
    expect(document.activeElement).toBe(container.querySelector('input[type=file]'))
  })

  it('rejects an empty selection before contacting the API', async () => {
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    await render(<DeviceCatalogImporter />)
    await open()

    await act(async () => {
      container.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true }))
    })
    expect(container.querySelector('[role=alert]')!.textContent).toContain(
      'Select 1 to 50 JSON files',
    )
    expect(fetch).not.toHaveBeenCalled()
  })

  it('reports invalid JSON and API failures', async () => {
    const fetch = vi.fn(async () => response({ errors: [{ message: 'Invalid catalog.' }] }, false))
    vi.stubGlobal('fetch', fetch)
    await render(<DeviceCatalogImporter />)
    await open()

    const chooseFile = (text: string) =>
      act(async () => {
        const file = new File([text], 'catalog.json', { type: 'application/json' })
        Object.defineProperty(file, 'text', { value: async () => text })
        const input = container.querySelector<HTMLInputElement>('input[type=file]')!
        Object.defineProperty(input, 'files', { configurable: true, value: [file] })
        input.dispatchEvent(new Event('change', { bubbles: true }))
      })

    await chooseFile('{')
    await click('Import selected files')
    expect(container.querySelector('[role=alert]')!.textContent).toContain(
      'catalog.json: invalid JSON.',
    )
    expect(fetch).not.toHaveBeenCalled()

    await chooseFile('[]')
    await click('Import selected files')
    expect(container.querySelector('[role=alert]')!.textContent).toBe('Invalid catalog.')
  })

  it('imports the selected files and reports the result', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        response({
          manufacturers: { added: 1, updated: 0, unchanged: 0 },
          devices: { added: 2, updated: 0, unchanged: 0 },
          changed: true,
        }),
      ),
    )
    await render(<DeviceCatalogImporter />)
    await open()

    const file = new File(['[]'], 'catalog.json', { type: 'application/json' })
    Object.defineProperty(file, 'text', { value: async () => '[]' })
    const input = container.querySelector<HTMLInputElement>('input[type=file]')!
    await act(async () => {
      Object.defineProperty(input, 'files', { configurable: true, value: [file] })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })
    await click('Import selected files')

    expect(container.textContent).toContain(
      'Manufacturers: 1 added, 0 updated, 0 unchanged. Devices: 2 added, 0 updated, 0 unchanged.',
    )
    expect(container.textContent).toContain('Background reclassification queued.')
    expect(mocks.refresh).toHaveBeenCalled()
  })
})

describe('device catalog tables', () => {
  it('shows an empty state when no catalog has been imported', async () => {
    await render(createElement(DeviceCatalogTables, { field: {}, path: 'catalogTables' } as never))
    expect(container.textContent).toContain('No manufacturer or device data imported.')
  })

  it('lists every manufacturer and device field, including nested details', async () => {
    mocks.catalog = {
      manufacturers: [
        {
          id: 'm1',
          data: { aliases: ['Z'], name: 'Zeta', website: 'https://example.test/maker' },
          rules: { any: [] },
        },
        {
          id: 'm2',
          data: {
            aliases: [],
            name: 'Alpha',
            rankingScore: 7,
            website: 'https://user:pass@example.test',
          },
          rules: { any: [] },
        },
        {
          id: 'm3',
          data: { confidence: true, name: 'Beta', website: 'javascript:alert(1)' },
          rules: {},
        },
        { id: 'm4', data: [], rules: {} },
        { id: 'm5', rules: {} },
      ],
      devices: [
        {
          id: 'd1',
          manufacturer_id: 'm1',
          device_type_id: 'g1',
          data: {
            description: '',
            model: 'M1',
            protocols_json: ['snmp', 'opcua'],
            releases_json: [{ version: '1' }],
            source_url: 'https://example.test/device',
          },
          rules: { all: [] },
        },
        {
          id: 'd2',
          manufacturer_id: 'm2',
          device_type_id: 'g1',
          data: { model: 'M0', protocols_json: [] },
          rules: {},
        },
      ],
    }
    await render(createElement(DeviceCatalogTables, { field: {}, path: 'catalogTables' } as never))

    const headings = [...container.querySelectorAll('h2')].map((heading) => heading.textContent)
    expect(headings[0]).toContain('Manufacturers')
    expect(headings[0]).toContain('5')
    expect(headings[1]).toContain('Devices')
    expect(headings[1]).toContain('2')

    const headers = [...container.querySelectorAll('thead th')].map((cell) => cell.textContent)
    const nameColumn = headers.indexOf('Name')
    const names = [...container.querySelectorAll('tbody tr')]
      .slice(0, 5)
      .map((row) => row.children[nameColumn]?.textContent)
    expect(names).toEqual(['Alpha', 'Beta', '—', '—', 'Zeta'])

    expect(container.querySelectorAll('a[href="https://example.test/maker"]')).toHaveLength(1)
    expect(container.querySelectorAll('a')).toHaveLength(2)
    expect(container.textContent).toContain('javascript:alert(1)')
    expect(container.textContent).toContain('https://user:pass@example.test')

    expect(container.textContent).toContain('snmp, opcua')
    expect(container.textContent).toContain('1 entry')
    expect(container.textContent).toContain('Manufacturer ID')
    expect(container.querySelectorAll('details')).toHaveLength(8)
  })

  it('renders each table with its own empty message', async () => {
    mocks.catalog = {
      devices: [{ id: 'd1', data: { model: 'M1' }, rules: {} }],
    }
    await render(createElement(DeviceCatalogTables, { field: {}, path: 'catalogTables' } as never))
    expect(container.textContent).toContain('No manufacturers imported.')
    expect(container.textContent).not.toContain('No devices imported.')

    mocks.catalog = {
      manufacturers: [{ id: 'm1', data: { name: 'Zeta' }, rules: {} }],
    }
    await render(createElement(DeviceCatalogTables, { field: {}, path: 'catalogTables' } as never))
    expect(container.textContent).toContain('No devices imported.')
    expect(container.textContent).not.toContain('No manufacturers imported.')
  })
})
