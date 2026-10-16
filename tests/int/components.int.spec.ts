// @vitest-environment jsdom

import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  documentID: undefined as string | undefined,
  documentCanUpdate: true,
  authPermissions: undefined as
    { collections?: Record<string, { read?: boolean; create?: boolean }> } | undefined,
  fieldValue: {} as Record<string, boolean | number | string> | boolean | string | null,
  openModal: vi.fn(),
  push: vi.fn(),
  refresh: vi.fn(),
  redirect: vi.fn(() => {
    throw new Error('redirect')
  }),
  collectionSlug: undefined as string | undefined,
  modalOpen: true,
  pathname: '/admin/otters',
  query: {} as { search?: string; where?: Record<string, unknown> },
  refineListData: vi.fn(),
  formFields: {} as {
    name?: { value: unknown }
    site?: { value: unknown }
    scanner?: { value: unknown }
  },
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
    Gutter: ({ children }: { children: React.ReactNode }) => createElement('div', null, children),
    Pill: ({ children }: { children: React.ReactNode }) => createElement('span', null, children),
    FieldLabel: ({ label }: { label: string }) => createElement('label', null, label),
    FieldError: () => null,
    ReactSelect: ({
      options,
      onChange,
      value,
      disabled,
    }: {
      options: Array<{ label: string; value: string }>
      onChange: (value: { label: string; value: string } | null) => void
      value?: { label: string; value: string }
      disabled?: boolean
    }) =>
      createElement(
        'select',
        {
          disabled,
          value: value?.value || '',
          onChange: (event: React.ChangeEvent<HTMLSelectElement>) =>
            onChange(
              options.find(({ value: optionValue }) => optionValue === event.target.value) || null,
            ),
        },
        options.map(({ label, value }) => createElement('option', { key: value, value }, label)),
      ),
    TextInput: ({
      value,
      onChange,
      path,
      readOnly,
    }: {
      value?: string
      onChange: React.ChangeEventHandler<HTMLInputElement>
      path: string
      readOnly?: boolean
    }) => createElement('input', { value, onChange, disabled: readOnly, 'data-path': path }),
    ConfirmationModal: ({
      body,
      onConfirm,
      onCancel,
      confirmLabel = 'Confirm',
      cancelLabel = 'Cancel',
    }: {
      body: unknown
      onConfirm: () => void
      onCancel?: () => void
      confirmLabel?: string
      cancelLabel?: string
    }) =>
      createElement(
        'div',
        null,
        body as never,
        createElement('button', { onClick: onConfirm }, confirmLabel),
        createElement('button', { onClick: onCancel }, cancelLabel),
      ),
    CopyToClipboard: ({ defaultMessage }: { defaultMessage: string }) =>
      createElement('span', null, defaultMessage),
    Banner: ({ children }: { children: React.ReactNode }) => createElement('div', null, children),
    useDocumentInfo: () => ({
      id: mocks.documentID,
      collectionSlug: mocks.collectionSlug,
      docPermissions: { update: mocks.documentCanUpdate },
    }),
    useField: () => ({ setValue: mocks.setValue, value: mocks.fieldValue }),
    useFormFields: (
      selector: (
        state: [
          {
            name?: { value: unknown }
            site?: { value: unknown }
            scanner?: { value: unknown }
          },
        ],
      ) => unknown,
    ) => selector([mocks.formFields]),
    useListQuery: () => ({ query: mocks.query, refineListData: mocks.refineListData }),
    useModal: () => ({
      openModal: mocks.openModal,
      closeModal: vi.fn(),
      isModalOpen: () => mocks.modalOpen,
    }),
    useSelection: () => mocks.selection,
    useAuth: () => ({ permissions: mocks.authPermissions }),
    useConfig: () => ({ config: { routes: { admin: '/admin', api: '/api' } } }),
  }
})

vi.mock('next/navigation', () => ({
  redirect: mocks.redirect,
  usePathname: () => mocks.pathname,
  useRouter: () => ({ push: mocks.push, refresh: mocks.refresh }),
}))
vi.mock('next/link', async () => {
  const { createElement } = await import('react')
  return {
    default: ({ href, children, ...props }: Record<string, unknown>) =>
      createElement('a', { href, ...props }, children as never),
  }
})
vi.mock('@payloadcms/next/templates', async () => {
  const { createElement } = await import('react')
  return {
    DefaultTemplate: ({ children }: { children: React.ReactNode }) =>
      createElement('div', null, children),
  }
})

import AssetListInteractions from '../../src/components/AssetListInteractions'
import CopyButton from '../../src/components/AssetView/CopyButton'
import DensityToggle from '../../src/components/AssetView/DensityToggle'
import CustomAssetFields from '../../src/components/CustomAssetFields'
import ImportInstructions from '../../src/components/ImportInstructions'
import SiteIDField from '../../src/components/SiteIDField'
import OtterCredentialsField from '../../src/components/OtterCredentialsField'
import OtterInterfaceField from '../../src/components/OtterInterfaceField'
import OtterManagementView from '../../src/components/OtterManagementView'
import OtterEnrollment, { otterAction } from '../../src/components/OtterEnrollment'
import OtterScannerActions from '../../src/components/OtterScannerActions'
import OtterManagedSettingsField from '../../src/components/OtterManagedSettingsField'
import TopologyNavLink from '../../src/components/TopologyNavLink'

let container: HTMLDivElement
let root: Root

const render = async (component: React.ReactNode) => {
  await act(async () => {
    root.render(component)
    await new Promise((resolve) => setTimeout(resolve, 0))
  })
}

const renderFresh = async (component: React.ReactNode) => {
  await act(async () => root.unmount())
  root = createRoot(container)
  await render(component)
}

beforeEach(() => {
  ;(
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true
  vi.clearAllMocks()
  mocks.documentID = undefined
  mocks.documentCanUpdate = true
  mocks.collectionSlug = undefined
  mocks.authPermissions = undefined
  mocks.fieldValue = {}
  mocks.query = {}
  mocks.formFields = { scanner: { value: 'scanner-1' } }
  mocks.modalOpen = true
  mocks.pathname = '/admin/otters'
  mocks.selection = { count: 0, getQueryParams: vi.fn(() => ''), selectAll: 'none' }
  window.localStorage.clear()
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
  it('prevents edits in read-only mode and accepts cleared JSON values', async () => {
    mocks.fieldValue = null
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ docs: [{ id: 'text', label: 'Owner', type: 'text' }] }),
      }),
    )
    await render(
      createElement(CustomAssetFields, {
        field: {},
        path: 'customFields',
        readOnly: true,
      } as never),
    )
    expect(container.querySelector('fieldset')?.disabled).toBe(true)
    const input = container.querySelector('input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        input,
        'changed',
      )
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(mocks.setValue).not.toHaveBeenCalled()
  })
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

describe('asset view controls', () => {
  it('uses the native clipboard control', async () => {
    await render(createElement(CopyButton, { value: '192.0.2.1' }))
    expect(container.textContent).toContain('Copy value')
  })

  it('restores saved density, persists changes, and tolerates a missing view root', async () => {
    window.localStorage.setItem('otserver-asset-density', 'compact')
    const view = document.createElement('div')
    view.className = 'asset-view'
    document.body.append(view)
    await render(createElement(DensityToggle))

    const button = container.querySelector<HTMLButtonElement>('button')!
    expect(button.textContent).toBe('Compact')
    expect(button.ariaPressed).toBe('true')
    expect(view.dataset.density).toBe('compact')
    expect(window.localStorage.getItem('otserver-asset-density')).toBe('compact')

    view.remove()
    await act(async () => button.click())
    expect(button.textContent).toBe('Comfortable')
    expect(button.ariaPressed).toBe('false')
    expect(window.localStorage.getItem('otserver-asset-density')).toBe('comfortable')
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
    expect(button.textContent).toContain('Export diagnostic CSV')
    await act(async () => button.click())
    expect(fetch).toHaveBeenCalledWith('/api/assets/export-csv?where%5Bid%5D%5Bin%5D=abc')

    mocks.selection = { count: 5, getQueryParams: vi.fn(() => ''), selectAll: 'allAvailable' }
    await render(createElement(AssetListInteractions))
    await act(async () => bar.querySelector<HTMLButtonElement>('.asset-export-csv')!.click())
    expect(fetch).toHaveBeenCalledWith('/api/assets/export-csv?search=vendor%3ASiemens')
    vi.mocked(fetch).mockResolvedValueOnce({ ok: false } as Response)
    await act(async () => bar.querySelector<HTMLButtonElement>('.asset-export-csv')!.click())
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not export assets',
    )
    expect(button.disabled).toBe(false)
    vi.mocked(fetch).mockRejectedValueOnce(new Error('offline'))
    await act(async () => bar.querySelector<HTMLButtonElement>('.asset-export-csv')!.click())
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('try again')
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
    expect(container.textContent).toContain('Copy site ID')
    expect(container.textContent).toContain('automatic imports')
  })

  it('stays hidden until a site has been created', async () => {
    await render(createElement(SiteIDField))
    expect(container.textContent).toBe('')
  })
})

describe('Otter profile credentials field', () => {
  const click = async (label: string) => {
    const button = [...container.querySelectorAll('button')].find((entry) =>
      entry.textContent?.includes(label),
    )!
    await act(async () => button.click())
  }

  const setInput = async (label: string, value: string) => {
    const field = [...container.querySelectorAll('label')].find((entry) =>
      entry.textContent?.trim().startsWith(label),
    )!
    const element = field.querySelector<HTMLInputElement>('input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        element,
        value,
      )
      element.dispatchEvent(new Event('input', { bubbles: true }))
    })
  }

  it('saves write-only credentials and clears them without reloading the document', async () => {
    mocks.documentID = 'profile-1'
    mocks.fieldValue = true
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ credentialsConfigured: true }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ credentialsConfigured: false }) })
    vi.stubGlobal('fetch', fetchMock)
    await render(createElement(OtterCredentialsField))
    expect(container.textContent).toContain('encrypted at rest')
    await click('Add SNMP credential')
    await setInput('Community', 'secret')
    await click('Encrypt and save credentials')
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/api/otter/v1/profiles/profile-1/credentials',
      expect.objectContaining({ method: 'POST' }),
    )
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      credentials: { snmp: [{ version: '2c', community: 'secret' }] },
    })
    expect(container.textContent).toContain('Credentials encrypted and saved')

    await click('Clear stored credentials')
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/otter/v1/profiles/profile-1/credentials',
      expect.objectContaining({ body: JSON.stringify({ clear: true }) }),
    )
    expect(container.textContent).toContain('No credentials are stored')
  })

  it('requires a saved profile for credentials and hides controls in read-only mode', async () => {
    mocks.documentID = 'profile-1'
    mocks.fieldValue = false
    vi.stubGlobal('fetch', vi.fn())
    await render(createElement(OtterCredentialsField))
    await click('Encrypt and save credentials')
    expect(container.textContent).toContain('Add at least one')
    expect(fetch).not.toHaveBeenCalled()

    await click('Add OPC UA credential')
    await setInput('Username', 'operator')
    mocks.documentID = undefined
    await render(createElement(OtterCredentialsField))
    expect(container.textContent).toContain('SNMP v2c community public')
    await click('Encrypt and save credentials')
    expect(container.textContent).toContain('Save the configuration before adding credentials')

    await act(async () => root.unmount())
    root = createRoot(container)
    await render(createElement(OtterCredentialsField, { readOnly: true } as never))
    expect(container.querySelector('input')).toBeNull()
    expect(container.querySelector('button')).toBeNull()
  })

  it('shows credential API failures without returning stored values', async () => {
    mocks.documentID = 'profile-1'
    mocks.fieldValue = false
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => ({ errors: [{ message: 'Otter Config permission is required.' }] }),
      }),
    )
    await render(createElement(OtterCredentialsField))
    await click('Add OPC UA credential')
    await setInput('Username', 'operator')
    await click('Encrypt and save credentials')
    expect(container.textContent).toContain('Otter Config permission is required')
  })
})

describe('Otter profile interface field', () => {
  it('disables both manual and reported adapter controls in read-only mode', async () => {
    mocks.fieldValue = 'eth0'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({ networkAdapters: [] }) }),
    )
    await render(
      createElement(OtterInterfaceField, {
        field: {},
        path: 'configuration.interface',
        readOnly: true,
      } as never),
    )
    expect(container.querySelector('input')?.disabled).toBe(true)
    expect(container.querySelector('select')?.disabled).toBe(true)
  })
  it('offers the selected scanner adapters and displays their addresses', async () => {
    mocks.fieldValue = 'eth0'
    mocks.formFields = { scanner: { value: 'scanner-201' } }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'scanner-201',
          networkAdapters: [
            {
              name: 'eth0',
              friendlyName: 'Industrial Ethernet',
              description: 'Primary adapter',
              macAddress: '00:11:22:33:44:55',
              ipAddresses: ['192.0.2.10'],
            },
            {
              name: 'eth1',
              friendlyName: 'Service Ethernet',
              description: 'Maintenance adapter',
              macAddress: '00:11:22:33:44:66',
              ipAddresses: ['192.0.2.20'],
            },
          ],
        }),
      }),
    )
    await render(
      createElement(OtterInterfaceField, {
        field: { label: 'Network interface', type: 'text' },
        path: 'configuration.interface',
      } as never),
    )
    expect(container.textContent).toContain('Primary adapter')
    expect(container.textContent).toContain('00:11:22:33:44:55')
    expect(container.textContent).toContain('operating system route table')
    expect(fetch).toHaveBeenCalledWith(
      '/api/otter/v1/scanners/scanner-201',
      expect.objectContaining({ cache: 'no-store' }),
    )
    const select = container.querySelector('select')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(
        select,
        'eth1',
      )
      select.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith('eth1')
  })
})

describe('Otter management overview', () => {
  it('creates an enrollment token in the scanner list popup and opens native settings', async () => {
    mocks.authPermissions = { collections: { 'otter-profiles': { create: true } } }
    const fetch = vi.fn().mockImplementation(async (_url: string, options?: RequestInit) => ({
      ok: true,
      json: async () =>
        options?.method === 'POST'
          ? {
              scanner: { id: 'new-scanner' },
              enrollmentToken: 'single-use-token',
              controllerUrl: 'https://otserver.example',
              expiresAt: new Date().toISOString(),
            }
          : { writableSites: [{ id: 'site-1', name: 'Plant' }] },
    }))
    vi.stubGlobal('fetch', fetch)
    await render(createElement(OtterEnrollment))
    expect(container.textContent).toContain('Enroll scanner')
    const input = container.querySelector('input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        input,
        'Line scanner',
      )
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await act(async () =>
      container
        .querySelector('form')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })),
    )
    expect(fetch).toHaveBeenCalledWith(
      '/api/otter/v1/scanners',
      expect.objectContaining({ body: JSON.stringify({ name: 'Line scanner', site: 'site-1' }) }),
    )
    expect(container.textContent).toContain('single-use-token')
    expect(container.textContent).toContain('--enroll --ack-authorized')
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Configure scanner')!
        .click(),
    )
    expect(mocks.push).toHaveBeenCalledWith('/admin/collections/otter-scanners/new-scanner')
    expect(container.textContent).not.toContain('single-use-token')
  })

  it('runs the saved configuration only after confirming authorization with Yes', async () => {
    mocks.documentID = 'profile-1'
    mocks.collectionSlug = 'otter-profiles'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'queued' }) }),
    )
    await render(createElement(OtterScannerActions))
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Run now')!
        .click(),
    )
    expect(mocks.openModal).toHaveBeenCalledWith('otter-run-confirm')
    expect(fetch).not.toHaveBeenCalled()
    expect(container.textContent).toContain('permission to run this configuration')
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'No')!
        .click(),
    )
    expect(fetch).not.toHaveBeenCalled()
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Run now')!
        .click(),
    )
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Yes')!
        .click(),
    )
    expect(fetch).toHaveBeenCalledWith(
      '/api/otter/v1/runs',
      expect.objectContaining({
        body: JSON.stringify({ scannerID: 'scanner-1', profileID: 'profile-1' }),
      }),
    )
    expect(container.textContent).toContain('Scan queued')
  })

  it('directs scanner settings to configurations instead of running an implicit profile', async () => {
    mocks.documentID = 'scanner-1'
    mocks.collectionSlug = 'otter-scanners'
    await render(createElement(OtterScannerActions))
    expect(container.querySelector('a')?.getAttribute('href')).toBe(
      '/admin/collections/otter-profiles',
    )
    expect(container.textContent).not.toContain('Run now')
  })

  it('redirects the old management URL to the scanner collection', async () => {
    await expect(
      OtterManagementView({
        payload: { config: { routes: { admin: '/admin' } } },
        viewType: 'custom',
      } as never),
    ).rejects.toThrow('redirect')
    expect(mocks.redirect).toHaveBeenCalledWith('/admin/collections/otter-scanners')
  })
})

describe('remaining Otter component states', () => {
  it('renders controller-owned settings for selected and unresolved values', async () => {
    let overview: {
      controllerUrl?: string
      sites?: Array<{ id: string; name: string }>
      scanners?: Array<{ id: string; enabled: boolean; enrolled: boolean }>
    } = {
      controllerUrl: 'https://otserver.example',
      sites: [{ id: 'site-1', name: 'Plant' }],
      scanners: [{ id: 'scanner-1', enabled: true, enrolled: true }],
    }
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => overview }))
    vi.stubGlobal('fetch', fetchMock)
    const field = createElement(OtterManagedSettingsField)

    mocks.formFields = {
      name: { value: 'Production' },
      site: { value: { value: 'site-1' } },
      scanner: { value: { value: 'scanner-1' } },
    }
    await render(field)
    expect(container.textContent).toContain('Production')
    expect(container.textContent).toContain('Plant')
    expect(container.textContent).toContain('https://otserver.example')
    expect(container.textContent).toContain('Enrolled machine credential')

    overview = {
      sites: [],
      scanners: [{ id: 'scanner-1', enabled: false, enrolled: true }],
    }
    mocks.formFields = {
      name: { value: 3 },
      site: { value: 'deleted-site' },
      scanner: { value: 'scanner-1' },
    }
    await renderFresh(field)
    expect(container.textContent).toContain('Enter a configuration name')
    expect(container.textContent).toContain('deleted-site')
    expect(container.textContent).toContain('Scanner is disabled')
    expect(container.textContent).toContain('Set OTSERVER_PUBLIC_URL')

    overview = { scanners: [{ id: 'scanner-1', enabled: true, enrolled: false }] }
    mocks.formFields = { site: { value: '' }, scanner: { value: 'scanner-1' } }
    await renderFresh(field)
    expect(container.textContent).toContain('Select a site')
    expect(container.textContent).toContain('Awaiting enrollment')

    mocks.formFields = {}
    fetchMock.mockResolvedValueOnce({ ok: false, json: async () => ({}) })
    await renderFresh(field)
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load managed settings',
    )
    expect(container.textContent).toContain('Select a site')

    fetchMock.mockRejectedValueOnce('offline')
    await renderFresh(field)
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load managed settings',
    )
  })

  it('shows adapter fallbacks and keeps manual interface names usable', async () => {
    mocks.collectionSlug = 'otter-scanners'
    mocks.documentID = 'scanner-2'
    mocks.fieldValue = 'eth9'
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
    const field = createElement(OtterInterfaceField, { field: {}, path: 'interface' } as never)
    await render(field)
    expect(fetch).toHaveBeenCalledWith('/api/otter/v1/scanners/scanner-2', expect.anything())
    expect(container.textContent).toContain('eth9 · not currently reported')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load scanner adapters',
    )

    const input = container.querySelector<HTMLInputElement>('input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, 'eth8')
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith('eth8')

    const select = container.querySelector('select')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(select, '')
      select.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(mocks.setValue).toHaveBeenCalledWith('')

    mocks.collectionSlug = undefined
    mocks.documentID = undefined
    mocks.formFields = { scanner: { value: { value: 'scanner-3' } } }
    mocks.fieldValue = 'eth0'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'scanner-3',
          networkAdapters: [
            { name: 'eth0', friendlyName: 'LAN', description: 'Local', ipAddresses: [] },
          ],
        }),
      }),
    )
    await renderFresh(field)
    expect(container.textContent).toContain('LAN · no IP · no MAC')
    expect(container.textContent).toContain('MAC not reported · No IP addresses')
  })

  it('shows the topology nav indicator only on its route', async () => {
    const link = createElement(TopologyNavLink)
    await render(link)
    expect(container.querySelector('.nav__link-indicator')).toBeNull()

    mocks.pathname = '/admin/topology'
    await renderFresh(link)
    expect(container.querySelector('.nav__link-indicator')).not.toBeNull()
  })

  it('keeps remaining SNMP and OPC UA credential rows after removing the first row', async () => {
    mocks.documentID = 'profile-1'
    mocks.fieldValue = false
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ credentialsConfigured: true }),
    })
    vi.stubGlobal('fetch', fetchMock)
    await render(createElement(OtterCredentialsField))

    const click = async (label: string) => {
      const button = [...container.querySelectorAll('button')].find((entry) =>
        entry.textContent?.includes(label),
      )!
      await act(async () => button.click())
    }
    const setEntryInput = async (entry: ParentNode, name: string, value: string) => {
      const label = [...entry.querySelectorAll('label')].find((item) =>
        item.textContent?.trim().startsWith(name),
      )!
      const input = label.querySelector<HTMLInputElement>('input')!
      await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
          input,
          value,
        )
        input.dispatchEvent(new Event('input', { bubbles: true }))
      })
    }
    const setSelect = async (select: HTMLSelectElement, value: string) => {
      await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(
          select,
          value,
        )
        select.dispatchEvent(new Event('change', { bubbles: true }))
      })
    }

    await click('Add SNMP credential')
    await click('Add SNMP credential')
    const snmpEntries = container.querySelectorAll<HTMLElement>(
      '.otter-credentials__section:first-of-type .otter-credentials__entry',
    )
    const snmpSelects = container.querySelectorAll<HTMLSelectElement>(
      '.otter-credentials__section select',
    )
    await setSelect(snmpSelects[0]!, '1')
    await setSelect(snmpSelects[1]!, 'sha1')
    await setSelect(snmpSelects[2]!, 'des')
    await setSelect(snmpSelects[3]!, 'auto')
    await setSelect(snmpSelects[4]!, 'sha256')
    await setSelect(snmpSelects[5]!, 'aes128')
    for (const [entry, values] of [
      [
        snmpEntries[0]!,
        [
          ['Community', 'discard-community'],
          ['Username', 'discard-user'],
          ['Context name', 'discard-context'],
          ['Authentication password', 'discard-auth'],
          ['Privacy password', 'discard-privacy'],
        ],
      ],
      [
        snmpEntries[1]!,
        [
          ['Community', 'private'],
          ['Username', 'snmp-user'],
          ['Context name', 'engineering'],
          ['Authentication password', 'auth-secret'],
          ['Privacy password', 'privacy-secret'],
        ],
      ],
    ] as const) {
      for (const [name, value] of values) await setEntryInput(entry, name, value)
    }

    await click('Add OPC UA credential')
    await click('Add OPC UA credential')
    const opcuaSection = container.querySelectorAll('.otter-credentials__section')[1]!
    const opcuaEntries = opcuaSection.querySelectorAll<HTMLElement>('.otter-credentials__entry')
    await setEntryInput(opcuaEntries[0]!, 'Username', 'discard-opcua-user')
    await setEntryInput(opcuaEntries[0]!, 'Password', 'discard-opcua-password')
    await setEntryInput(opcuaEntries[1]!, 'Username', 'operator')
    await setEntryInput(opcuaEntries[1]!, 'Password', 'opcua-secret')

    await act(async () => snmpEntries[0]!.querySelector('button')!.click())
    await act(async () => opcuaEntries[0]!.querySelector('button')!.click())
    await click('Encrypt and save credentials')

    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      credentials: {
        snmp: [
          {
            version: 'auto',
            community: 'private',
            username: 'snmp-user',
            contextName: 'engineering',
            authProtocol: 'sha256',
            authPassword: 'auth-secret',
            privacyProtocol: 'aes128',
            privacyPassword: 'privacy-secret',
          },
        ],
        opcuaCredentials: [{ username: 'operator', password: 'opcua-secret' }],
      },
    })
    expect(container.textContent).toContain('Credentials encrypted and saved')
  })

  it('handles enrollment permission, loading, and response error paths', async () => {
    const enrollment = createElement(OtterEnrollment)
    const fetchMock = vi.fn().mockRejectedValue('offline')
    vi.stubGlobal('fetch', fetchMock)
    mocks.modalOpen = false
    await render(enrollment)
    expect(container.textContent).toBe('')
    expect(fetchMock).not.toHaveBeenCalled()

    mocks.authPermissions = { collections: { 'otter-profiles': { create: true } } }
    mocks.modalOpen = false
    await renderFresh(enrollment)
    expect(fetchMock).not.toHaveBeenCalled()
    await act(async () =>
      [...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Enroll scanner')!
        .click(),
    )
    expect(mocks.openModal).toHaveBeenCalledWith('otter-scanner-enrollment')
    mocks.modalOpen = true
    await renderFresh(enrollment)
    expect(container.textContent).toContain('Could not load sites.')

    const actions = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ accepted: true }) })
      .mockResolvedValueOnce({ ok: false, json: async () => ({ message: 'Enrollment rejected.' }) })
      .mockResolvedValueOnce({ ok: false, json: async () => ({}) })
    vi.stubGlobal('fetch', actions)
    await expect(otterAction('/api/ok')).resolves.toEqual({ accepted: true })
    await expect(otterAction('/api/denied')).rejects.toThrow('Enrollment rejected.')
    await expect(otterAction('/api/unknown')).rejects.toThrow('The Otter action failed.')
    expect(actions.mock.calls[0]?.[1]).toMatchObject({ method: 'POST' })
    expect(actions.mock.calls[0]?.[1]).not.toHaveProperty('body')
  })

  it('handles scanner re-enrollment, revocation, and non-Error failures', async () => {
    const actions = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          enrollmentToken: 'new-token',
          expiresAt: new Date().toISOString(),
          controllerUrl: 'https://otserver.example',
        }),
      })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'revoked' }) })
      .mockRejectedValueOnce('offline')
    vi.stubGlobal('fetch', actions)
    const component = createElement(OtterScannerActions)

    await render(component)
    expect(container.textContent).toBe('')
    mocks.documentID = 'scanner-1'
    mocks.documentCanUpdate = false
    await renderFresh(component)
    expect(container.textContent).toBe('')

    mocks.documentCanUpdate = true
    mocks.collectionSlug = 'otter-scanners'
    await renderFresh(component)
    const click = async (label: string) => {
      const button = [...container.querySelectorAll('button')].find((entry) =>
        entry.textContent?.includes(label),
      )!
      await act(async () => button.click())
    }
    await click('Re-enroll')
    const confirmation = [...container.querySelectorAll('button')].filter(
      (entry) => entry.textContent === 'Confirm',
    )[0]!
    await act(async () => confirmation.click())
    expect(container.textContent).toContain('new-token')

    await click('Revoke')
    const confirmations = [...container.querySelectorAll('button')].filter(
      (entry) => entry.textContent === 'Confirm',
    )
    await act(async () => confirmations[1]!.click())
    expect(container.textContent).toContain('Scanner credential revoked.')

    await click('Revoke')
    const retryConfirmations = [...container.querySelectorAll('button')].filter(
      (entry) => entry.textContent === 'Confirm',
    )
    await act(async () => retryConfirmations[1]!.click())
    expect(container.textContent).toContain('The action failed.')
    expect(mocks.refresh).toHaveBeenCalled()
  })
})
