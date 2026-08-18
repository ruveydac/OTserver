// @vitest-environment jsdom

import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  documentID: undefined as string | undefined,
  fieldValue: {} as Record<string, boolean | number | string> | string,
  openModal: vi.fn(),
  push: vi.fn(),
  query: {} as { search?: string; where?: Record<string, unknown> },
  refineListData: vi.fn(),
  selection: { count: 0, getQueryParams: vi.fn(() => ''), selectAll: 'none' } as {
    count: number
    getQueryParams: () => string
    selectAll: string
  },
  setValue: vi.fn(),
}))

vi.mock('@payloadcms/ui', async () => {
  const { createElement } = await import('react')
  return {
    Button: ({ children, ...props }: Record<string, unknown>) => {
      delete props.buttonStyle
      return createElement('button', props, children as never)
    },
    ConfirmationModal: ({ body, onConfirm }: { body: unknown; onConfirm: () => void }) =>
      createElement(
        'div',
        null,
        body as never,
        createElement('button', { onClick: onConfirm }, 'Confirm'),
      ),
    CopyToClipboard: ({ defaultMessage }: { defaultMessage: string }) =>
      createElement('span', null, defaultMessage),
    useDocumentInfo: () => ({ id: mocks.documentID }),
    useField: () => ({ setValue: mocks.setValue, value: mocks.fieldValue }),
    useListQuery: () => ({ query: mocks.query, refineListData: mocks.refineListData }),
    useModal: () => ({ openModal: mocks.openModal }),
    useSelection: () => mocks.selection,
  }
})

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: mocks.push }) }))

import AssetListInteractions from '../../src/components/AssetListInteractions'
import CustomAssetFields from '../../src/components/CustomAssetFields'
import ImportInstructions from '../../src/components/ImportInstructions'
import SiteIDField from '../../src/components/SiteIDField'

let container: HTMLDivElement
let root: Root

const render = async (component: React.ReactNode) => {
  await act(async () => {
    root.render(component)
    await new Promise((resolve) => setTimeout(resolve, 0))
  })
}

beforeEach(() => {
  ;(
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true
  vi.clearAllMocks()
  mocks.documentID = undefined
  mocks.fieldValue = {}
  mocks.query = {}
  mocks.selection = { count: 0, getQueryParams: vi.fn(() => ''), selectAll: 'none' }
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  document.body.replaceChildren()
  vi.unstubAllGlobals()
})

describe('custom asset fields', () => {
  it('loads every input type and sends normalized edits', async () => {
    mocks.fieldValue = { checkbox: true, number: 3, text: 'old', textarea: 'notes' }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            docs: [
              { description: 'Enabled state', id: 'checkbox', label: 'Enabled', type: 'checkbox' },
              { id: 'number', label: 'Level', type: 'number' },
              { id: 'text', label: 'Owner', type: 'text' },
              { id: 'textarea', label: 'Notes', type: 'textarea' },
              { id: 'date', label: 'Installed', type: 'date' },
            ],
          }),
        ok: true,
      }),
    )

    await render(
      createElement(CustomAssetFields, {
        field: { label: 'Details' },
        path: 'customFields',
      } as never),
    )
    expect(container.textContent).toContain('Enabled state')
    expect(container.querySelector('legend')?.textContent).toBe('Details')

    const checkbox = container.querySelector<HTMLInputElement>('#customFields-checkbox')!
    await act(async () => checkbox.click())
    expect(mocks.setValue).toHaveBeenCalledWith(expect.objectContaining({ checkbox: false }))

    const number = container.querySelector<HTMLInputElement>('#customFields-number')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(number, '12')
      number.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith(expect.objectContaining({ number: 12 }))

    const text = container.querySelector<HTMLInputElement>('#customFields-text')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(text, '')
      text.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith(
      expect.not.objectContaining({ text: expect.anything() }),
    )

    const textarea = container.querySelector<HTMLTextAreaElement>('#customFields-textarea')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set?.call(
        textarea,
        'new notes',
      )
      textarea.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith(expect.objectContaining({ textarea: 'new notes' }))
  })

  it('shows empty and failed loading states', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ json: () => Promise.resolve({ docs: [] }), ok: true }),
    )
    await render(createElement(CustomAssetFields, { field: {}, path: 'customFields' } as never))
    expect(container.textContent).toContain('No custom fields have been configured')

    await act(async () => root.unmount())
    root = createRoot(container)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
    await render(createElement(CustomAssetFields, { field: {}, path: 'customFields' } as never))
    expect(container.textContent).toContain('Could not load custom asset fields')
  })

  it('aborts loading when unmounted', async () => {
    let signal: AbortSignal | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn((_url, options) => {
        signal = options.signal
        return new Promise(() => undefined)
      }),
    )
    await render(createElement(CustomAssetFields, { field: {}, path: 'customFields' } as never))
    await act(async () => root.unmount())
    root = createRoot(container)
    expect(signal?.aborted).toBe(true)
  })
})

describe('asset list interactions', () => {
  it('synchronizes filters, labels search, and opens a double-clicked row', async () => {
    document.body.insertAdjacentHTML(
      'afterbegin',
      '<div class="collection-list--assets"><input id="search-filter-input"><table><tbody><tr data-id="asset/a"><td>PLC</td><td><a href="#">Link</a></td></tr></tbody></table></div>',
    )
    mocks.query = { search: '', where: { status: { equals: 'online' } } }
    await render(createElement(AssetListInteractions))

    expect(mocks.refineListData).toHaveBeenCalledWith({ page: 1, search: 'status:"online"' })
    const search = document.querySelector<HTMLInputElement>('#search-filter-input')!
    expect(search.ariaLabel).toBe('Lucene asset search and filter')
    expect(search.placeholder).toContain('Lucene:')

    document.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))
    document.querySelector('a')!.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))
    document.querySelector('td')!.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))
    expect(mocks.push).toHaveBeenCalledWith('/admin/collections/assets/asset%2Fa')
  })

  it('does not resubmit missing or already synchronized filters', async () => {
    await render(createElement(AssetListInteractions))
    expect(mocks.refineListData).not.toHaveBeenCalled()
    mocks.query = { search: 'status:"online"', where: { status: { equals: 'online' } } }
    await render(createElement(AssetListInteractions))
    expect(mocks.refineListData).not.toHaveBeenCalled()
  })

  it('downloads the selected or filtered assets as CSV from the selection bar', async () => {
    document.body.insertAdjacentHTML(
      'afterbegin',
      '<div class="collection-list--assets"><div class="list-selection"><div class="list-selection__actions"></div></div></div>',
    )
    vi.stubGlobal('URL', { createObjectURL: vi.fn(() => 'blob:csv'), revokeObjectURL: vi.fn() })
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ blob: () => Promise.resolve(new Blob()), ok: true }),
    )

    mocks.query = { search: 'vendor:Siemens' }
    mocks.selection = {
      count: 1,
      getQueryParams: () => '?where%5Bid%5D%5Bin%5D=abc',
      selectAll: 'some',
    }
    await render(createElement(AssetListInteractions))
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50))
    })
    const bar = document.querySelector<HTMLElement>('.list-selection__actions')!
    const button = bar.querySelector<HTMLButtonElement>('.asset-export-csv')!
    expect(button.textContent).toContain('Download CSV')
    await act(async () => button.click())
    expect(fetch).toHaveBeenCalledWith('/api/assets/export-csv?where%5Bid%5D%5Bin%5D=abc')

    mocks.selection = { count: 5, getQueryParams: vi.fn(() => ''), selectAll: 'allAvailable' }
    await render(createElement(AssetListInteractions))
    await act(async () => bar.querySelector<HTMLButtonElement>('.asset-export-csv')!.click())
    expect(fetch).toHaveBeenCalledWith('/api/assets/export-csv?search=vendor%3ASiemens')
  })
})

describe('import instructions', () => {
  it('opens automatically and responds to controls', async () => {
    mocks.fieldValue = 'nmap'
    await render(createElement(ImportInstructions))
    expect(mocks.openModal).toHaveBeenCalledWith('asset-import-instructions')

    const buttons = [...container.querySelectorAll('button')]
    await act(async () => buttons[0].click())
    await act(async () => buttons.at(-1)!.click())
    await act(async () =>
      container.querySelector<HTMLInputElement>('input[value="proneta"]')!.click(),
    )
    expect(mocks.openModal).toHaveBeenCalledTimes(2)
    expect(mocks.setValue).toHaveBeenCalledWith('proneta')
  })
})

describe('site ID field', () => {
  it('shows a copyable ID on existing site documents', async () => {
    mocks.documentID = 'site-automatic-import'
    await render(createElement(SiteIDField))

    expect(container.textContent).toContain('Site ID')
    expect(container.textContent).toContain('site-automatic-import')
    expect(container.textContent).toContain('Copy Site ID')
    expect(container.textContent).toContain('automatic imports')
  })

  it('stays hidden until a site has been created', async () => {
    await render(createElement(SiteIDField))
    expect(container.textContent).toBe('')
  })
})
