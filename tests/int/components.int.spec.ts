// @vitest-environment jsdom

import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  documentID: undefined as string | undefined,
  authPermissions: undefined as
    { collections?: Record<string, { read?: boolean; create?: boolean }> } | undefined,
  fieldValue: {} as Record<string, boolean | number | string> | boolean | string,
  openModal: vi.fn(),
  push: vi.fn(),
  refresh: vi.fn(),
  redirect: vi.fn(() => {
    throw new Error('redirect')
  }),
  collectionSlug: undefined as string | undefined,
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
    Gutter: ({ children }: { children: React.ReactNode }) => createElement('div', null, children),
    Pill: ({ children }: { children: React.ReactNode }) => createElement('span', null, children),
    FieldLabel: ({ label }: { label: string }) => createElement('label', null, label),
    FieldError: () => null,
    ReactSelect: ({
      options,
      onChange,
      value,
    }: {
      options: Array<{ label: string; value: string }>
      onChange: (value: { label: string; value: string } | null) => void
      value?: { label: string; value: string }
    }) =>
      createElement(
        'select',
        {
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
    }: {
      value?: string
      onChange: React.ChangeEventHandler<HTMLInputElement>
      path: string
    }) => createElement('input', { value, onChange, 'data-path': path }),
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
    useDocumentInfo: () => ({
      id: mocks.documentID,
      collectionSlug: mocks.collectionSlug,
      docPermissions: { update: true },
    }),
    useField: () => ({ setValue: mocks.setValue, value: mocks.fieldValue }),
    useFormFields: (selector: (state: [{ scanner?: { value: string } }]) => unknown) =>
      selector([{ scanner: { value: 'scanner-1' } }]),
    useListQuery: () => ({ query: mocks.query, refineListData: mocks.refineListData }),
    useModal: () => ({ openModal: mocks.openModal, closeModal: vi.fn(), isModalOpen: () => true }),
    useSelection: () => mocks.selection,
    useAuth: () => ({ permissions: mocks.authPermissions }),
    useConfig: () => ({ config: { routes: { admin: '/admin' } } }),
  }
})

vi.mock('next/navigation', () => ({
  redirect: mocks.redirect,
  usePathname: () => '/admin/otters',
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
import OtterManagement from '../../src/components/OtterManagementView/view'
import OtterNavLink from '../../src/components/OtterNavLink'
import OtterEnrollment from '../../src/components/OtterEnrollment'
import OtterScannerActions from '../../src/components/OtterScannerActions'

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
  mocks.collectionSlug = undefined
  mocks.authPermissions = undefined
  mocks.fieldValue = {}
  mocks.query = {}
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
  it('reports successful and failed clipboard writes', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    await render(createElement(CopyButton, { value: '192.0.2.1' }))

    const button = container.querySelector<HTMLButtonElement>('button')!
    vi.useFakeTimers()
    await act(async () => button.click())
    expect(writeText).toHaveBeenCalledWith('192.0.2.1')
    expect(button.textContent).toBe('Copied')
    expect(button.ariaLabel).toBe('Copied 192.0.2.1')

    await act(async () => vi.advanceTimersByTimeAsync(1400))
    expect(button.textContent).toBe('Copy')

    writeText.mockRejectedValueOnce(new Error('clipboard unavailable'))
    await act(async () => button.click())
    expect(button.textContent).toBe('Copy')
    expect(button.ariaLabel).toBe('Copy 192.0.2.1')
    vi.useRealTimers()
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
    expect(container.textContent).toContain('Save the profile before configuring credentials')

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
  it('offers the selected scanner adapters and displays their addresses', async () => {
    mocks.fieldValue = 'eth0'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          scanners: [
            {
              id: 'scanner-1',
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
    expect(container.textContent).toContain('Create New')
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

  it('shows the Otter navigation link only to users with scanner read access', async () => {
    await render(createElement(OtterNavLink))
    expect(container.querySelector('a')).toBeNull()

    mocks.authPermissions = { collections: { 'otter-scanners': { read: true } } }
    await render(createElement(OtterNavLink))
    expect(container.querySelector('a')?.getAttribute('href')).toBe('/admin/otters')
    expect(container.textContent).toContain('Manage Otters')
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

  it('loads site-scoped scanners and performs run, cancel, enroll, and revoke actions', async () => {
    const overview = {
      scanners: [
        {
          id: 'scanner-1',
          name: 'Line A',
          site: { id: 'site-1', name: 'Plant / Line A' },
          enabled: true,
          enrolled: true,
          lastSeenAt: new Date().toISOString(),
          version: '0.9.0',
          nextRunAt: new Date().toISOString(),
          currentRun: 'run-1',
        },
        { id: 'scanner-2', name: 'Offline Otter', site: 'site-1', enabled: false, enrolled: false },
        {
          id: 'scanner-3',
          name: 'No profile',
          site: 'site-unknown',
          enabled: true,
          enrolled: true,
        },
      ],
      profiles: [
        { id: 'profile-1', name: 'Line A', scanner: 'scanner-1', credentialsConfigured: true },
        {
          id: 'profile-2',
          name: 'Line A deep scan',
          scanner: 'scanner-1',
          credentialsConfigured: false,
        },
      ],
      sites: [
        { id: 'site-1', name: 'Plant / Line A' },
        { id: 'site-2', name: 'Plant / Line B' },
      ],
      writableSites: [
        { id: 'site-1', name: 'Plant / Line A' },
        { id: 'site-2', name: 'Plant / Line B' },
      ],
      runs: [
        { id: 'run-1', name: 'Line A scan', scanner: 'scanner-1', status: 'running' },
        {
          id: 'run-2',
          name: 'Finished scan',
          scanner: 'scanner-1',
          status: 'completed',
          import: 'import-1',
        },
        {
          id: 'run-3',
          name: 'Unknown scanner result',
          scanner: 'removed-scanner',
          status: 'failed',
          message: 'Partial data.',
        },
      ],
    }
    const fetchMock = vi.fn(async (url: string | URL | Request, options?: RequestInit) => {
      if (String(url) === '/api/otter/v1/overview')
        return { ok: true, json: async () => overview } as Response
      if (options?.body && String(url) === '/api/otter/v1/runs')
        return { ok: true, json: async () => ({ id: 'run-3' }) } as Response
      if (String(url) === '/api/otter/v1/scanners') {
        overview.scanners.push({
          id: 'scanner-new',
          name: 'New scanner',
          site: 'site-2',
          enabled: true,
          enrolled: false,
        })
        return {
          ok: true,
          json: async () => ({
            enrollmentToken: 'new-enrollment-token',
            expiresAt: new Date().toISOString(),
            controllerUrl: 'https://otserver.example',
            scanner: { id: 'scanner-new', name: 'New scanner', site: 'site-2' },
          }),
        } as Response
      }
      if (String(url).endsWith('/reenroll'))
        return {
          ok: true,
          json: async () => ({
            enrollmentToken: 'enrollment-token',
            controllerUrl: 'https://otserver.example',
          }),
        } as Response
      if (String(url).endsWith('/revoke') || String(url).endsWith('/cancel'))
        return { ok: true, json: async () => ({ revoked: true }) } as Response
      return { ok: false, json: async () => ({ message: 'Unexpected request.' }) } as Response
    })
    vi.stubGlobal('fetch', fetchMock)
    await render(createElement(OtterManagement, { adminRoute: '/admin' }))
    expect(container.textContent).toContain('Line A')
    expect(container.textContent).toContain('Online')
    expect(container.textContent).toContain('Disabled')

    const profileSelect = container.querySelector<HTMLSelectElement>(
      'select[aria-label="Profile to run on Line A"]',
    )!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(
        profileSelect,
        'profile-2',
      )
      profileSelect.dispatchEvent(new Event('change', { bubbles: true }))
    })
    const runNow = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Run now'),
    )!
    await act(async () => runNow.click())
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/otter/v1/runs',
      expect.objectContaining({
        body: JSON.stringify({ scannerID: 'scanner-1', profileID: 'profile-2' }),
      }),
    )
    const runButtons = [...container.querySelectorAll('button')].filter((button) =>
      button.textContent?.includes('Run now'),
    )
    await act(async () => runButtons[2]!.click())
    expect(container.textContent).toContain('Create a scan profile for this scanner')

    const cancel = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Cancel'),
    )!
    await act(async () => cancel.click())
    expect(fetchMock).toHaveBeenCalledWith('/api/otter/v1/runs/run-1/cancel', expect.anything())

    const reenroll = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Re-enroll'),
    )!
    await act(async () => reenroll.click())
    expect(container.textContent).toContain('enrollment-token')
    expect(container.textContent).toContain('Controller URL:')

    const revoke = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Revoke'),
    )!
    await act(async () => revoke.click())
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/otter/v1/scanners/scanner-1/revoke',
      expect.anything(),
    )

    const name = container.querySelector<HTMLInputElement>('input[maxlength="120"]')!
    const siteSelect = container.querySelectorAll<HTMLSelectElement>('select')[0]!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(
        siteSelect,
        'site-2',
      )
      siteSelect.dispatchEvent(new Event('change', { bubbles: true }))
    })
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        name,
        'New scanner',
      )
      name.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await act(async () => {
      const enroll = [...container.querySelectorAll('button')].find((button) =>
        button.textContent?.includes('Generate enrollment token'),
      )!
      enroll.click()
    })
    expect(container.textContent).toContain('new-enrollment-token')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/otter/v1/scanners',
      expect.objectContaining({ body: JSON.stringify({ name: 'New scanner', site: 'site-2' }) }),
    )
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const copy = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Copy token'),
    )!
    await act(async () => copy.click())
    expect(writeText).toHaveBeenCalledWith('new-enrollment-token')

    fetchMock.mockImplementationOnce(async (url: string | URL | Request) => {
      if (String(url) === '/api/otter/v1/runs')
        return {
          ok: false,
          json: async () => {
            throw new Error('not JSON')
          },
        } as unknown as Response
      return { ok: true, json: async () => overview } as Response
    })
    const updatedRunButton = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Run now'),
    )!
    await act(async () => updatedRunButton.click())
    expect(container.textContent).toContain('The Otter action failed')

    fetchMock.mockImplementationOnce(
      async () =>
        ({
          ok: false,
          json: async () => ({ errors: [{ message: 'Cancellation denied.' }] }),
        }) as Response,
    )
    const cancelAgain = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Cancel'),
    )!
    await act(async () => cancelAgain.click())
    expect(container.textContent).toContain('Cancellation denied')

    fetchMock.mockImplementationOnce(
      async () =>
        ({
          ok: false,
          json: async () => ({ message: 'Re-enrollment denied.' }),
        }) as Response,
    )
    const reenrollAgain = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Re-enroll'),
    )!
    await act(async () => reenrollAgain.click())
    expect(container.textContent).toContain('Re-enrollment denied')
  })

  it('guides a new scanner from enrollment through a first queued scan', async () => {
    const overview = {
      controllerUrl: 'https://otserver.example',
      scanners: [] as Array<Record<string, unknown>>,
      profiles: [] as Array<Record<string, unknown>>,
      sites: [{ id: 'site-1', name: 'Plant' }],
      writableSites: [{ id: 'site-1', name: 'Plant' }],
      runs: [] as Array<Record<string, unknown>>,
    }
    const fetchMock = vi.fn(async (url: string | URL | Request) => {
      const path = String(url)
      if (path === '/api/otter/v1/overview')
        return { ok: true, json: async () => overview } as Response
      if (path === '/api/otter/v1/scanners') {
        overview.scanners.push({
          id: 'scanner-1',
          name: 'Plant Otter',
          site: 'site-1',
          enabled: true,
          enrolled: false,
        })
        return {
          ok: true,
          json: async () => ({
            enrollmentToken: 'single-use-token',
            expiresAt: '2026-10-11T18:00:00.000Z',
            controllerUrl: 'https://otserver.example',
            scanner: { id: 'scanner-1', name: 'Plant Otter' },
          }),
        } as Response
      }
      if (path === '/api/otter/v1/runs') {
        overview.runs.unshift({
          id: 'run-1',
          name: 'Plant Otter scan',
          scanner: 'scanner-1',
          status: 'queued',
        })
        return { ok: true, json: async () => ({ id: 'run-1', status: 'queued' }) } as Response
      }
      return { ok: false, json: async () => ({ message: 'Unexpected request.' }) } as Response
    })
    vi.stubGlobal('fetch', fetchMock)
    await render(createElement(OtterManagement, { adminRoute: '/admin' }))
    expect(container.textContent).toContain('Download the latest Otter release')

    const name = container.querySelector<HTMLInputElement>('.otter-management__enroll input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        name,
        'Plant Otter',
      )
      name.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await act(async () => {
      container
        .querySelector<HTMLFormElement>('.otter-management__enroll')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    expect(container.textContent).toContain('single-use-token')
    expect(container.textContent).toContain('--enroll --ack-authorized')
    expect(container.textContent).toContain('Paste it at the Otter prompt')

    overview.scanners[0]!.enrolled = true
    overview.scanners[0]!.lastSeenAt = new Date().toISOString()
    overview.scanners[0]!.computerName = 'plant-otter-host'
    overview.scanners[0]!.inventoryReportedAt = new Date().toISOString()
    overview.scanners[0]!.networkAdapters = [
      {
        name: 'eth0',
        friendlyName: 'Industrial Ethernet',
        description: 'Production network adapter',
        macAddress: '00:11:22:33:44:55',
        ipAddresses: ['192.168.1.2'],
      },
    ]
    overview.profiles.push({
      id: 'profile-1',
      name: 'Plant Otter scan',
      scanner: 'scanner-1',
      credentialsConfigured: false,
    })
    const checkConnection = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Check connection now'),
    )!
    await act(async () => checkConnection.click())
    expect(container.textContent).toContain('Restart Otter without --enroll')
    expect(container.textContent).not.toContain('single-use-token')
    expect(container.textContent).toContain('plant-otter-host')
    expect(container.textContent).toContain('00:11:22:33:44:55')
    expect(
      [...container.querySelectorAll('a[href="/admin/collections/otter-profiles"]')].some((link) =>
        link.textContent?.includes('Payload profile editor'),
      ),
    ).toBe(true)

    const firstScan = [...container.querySelectorAll('button')].find((button) =>
      button.textContent?.includes('Run first scan'),
    )!
    await act(async () => firstScan.click())
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/otter/v1/runs',
      expect.objectContaining({
        body: JSON.stringify({ scannerID: 'scanner-1', profileID: 'profile-1' }),
      }),
    )
    expect(container.textContent).toContain('First scan: queued')
  })

  it('shows empty and failed load states', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ scanners: [], profiles: [], sites: [], writableSites: [], runs: [] }),
      }),
    )
    await render(createElement(OtterManagement, { adminRoute: '/admin' }))
    expect(container.textContent).toContain('No scanners registered yet')
    expect(container.textContent).toContain('No scan runs yet')

    await act(async () => root.unmount())
    root = createRoot(container)
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => {
          throw new Error('not JSON')
        },
      }),
    )
    await render(createElement(OtterManagement, { adminRoute: '/admin' }))
    expect(container.textContent).toContain('Could not load Otter management data')
  })

  it('aborts the initial overview request when unmounted', async () => {
    let signal: AbortSignal | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, options?: RequestInit) => {
        signal = options?.signal as AbortSignal
        return new Promise((_resolve, reject) =>
          signal?.addEventListener('abort', () =>
            reject(new DOMException('Aborted', 'AbortError')),
          ),
        )
      }),
    )
    await render(createElement(OtterManagement, { adminRoute: '/admin' }))
    await act(async () => root.unmount())
    root = createRoot(container)
    await act(async () => new Promise((resolve) => setTimeout(resolve, 0)))
    expect(signal?.aborted).toBe(true)
    expect(container.textContent).not.toContain('AbortError')
  })
})
