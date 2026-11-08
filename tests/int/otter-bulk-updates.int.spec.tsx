// @vitest-environment jsdom

import { act, type ComponentProps, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  action: vi.fn(),
  openModal: vi.fn(),
  refresh: vi.fn(),
  selection: {
    count: 0,
    selected: {} as Record<string, boolean>,
    selectAll: 'none',
  },
}))

vi.mock('@payloadcms/ui', () => ({
  Banner: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  Button: ({
    buttonStyle,
    el = 'button',
    children,
    url,
    ...props
  }: ComponentProps<'button'> & {
    buttonStyle?: string
    el?: 'button' | 'link'
    url?: string
  }) => {
    void buttonStyle
    return el === 'link' ? <a href={url}>{children}</a> : <button {...props}>{children}</button>
  },
  ConfirmationModal: ({
    body,
    confirmLabel,
    heading,
    onConfirm,
  }: {
    body: ReactNode
    confirmLabel: string
    heading: string
    onConfirm: () => void
  }) => (
    <div>
      <h2>{heading}</h2>
      <div>{body}</div>
      <button onClick={onConfirm}>{confirmLabel}</button>
    </div>
  ),
  useConfig: () => ({ config: { routes: { admin: '/admin', api: '/api' } } }),
  useModal: () => ({ openModal: mocks.openModal }),
  useSelection: () => mocks.selection,
}))
vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: mocks.refresh }) }))
vi.mock('../../src/components/OtterEnrollment', () => ({ otterAction: mocks.action }))

import OtterBulkUpdates from '../../src/components/OtterBulkUpdates'

let container: HTMLDivElement
let root: Root
const response = (data: unknown, ok = true) => ({ ok, json: async () => data })
const render = () => act(async () => root.render(<OtterBulkUpdates />))
const renderFresh = async () => {
  await act(async () => root.unmount())
  root = createRoot(container)
  await render()
}
const click = (label: string) =>
  act(async () => {
    const button = [...container.querySelectorAll('button')].find(
      (entry) => entry.textContent === label,
    )
    if (!button) throw new Error(`Missing button: ${label}`)
    button.click()
  })

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.clearAllMocks()
  mocks.action.mockReset()
  mocks.selection = { count: 0, selected: {}, selectAll: 'none' }
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  document.body.replaceChildren()
  vi.unstubAllGlobals()
})

describe('Otter bulk updates', () => {
  it('shows loading, load-error, and no-release states', async () => {
    mocks.selection = { count: 1, selected: { scannerOne: true }, selectAll: 'some' }
    let signal: AbortSignal | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, options: { signal: AbortSignal }) => {
        signal = options.signal
        return new Promise((_, reject) => {
          signal!.addEventListener('abort', () => reject('offline'))
        })
      }),
    )
    await render()
    expect(container.querySelector('[role="status"]')?.textContent).toContain(
      'Loading signed releases',
    )
    await act(async () => root.unmount())
    expect(signal?.aborted).toBe(true)

    root = createRoot(container)
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue('offline'))
    await render()
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load signed releases',
    )

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({}, false)))
    await renderFresh()
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load signed Otter releases.',
    )

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ releases: [] })))
    await renderFresh()
    expect(
      container.querySelector('a[href="/admin/collections/otter-releases"]')?.textContent,
    ).toBe('Upload a signed release')

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ releases: null })))
    await renderFresh()
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load signed Otter releases.',
    )
  })

  it('queues selected scanners, reports failures, and blocks all-scanner selection', async () => {
    const releases = [
      { id: 'release-1', version: 'v1.2.0', target: 'x86_64-unknown-linux-gnu' },
      { id: 'release-2', version: 'v1.3.0', target: 'x86_64-pc-windows-msvc' },
      { id: 'release-3', version: 'v1.3.0', target: 'x86_64-unknown-linux-gnu' },
    ]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ releases })))
    mocks.selection = {
      count: 1,
      selected: { scannerOne: true, scannerTwo: false },
      selectAll: 'some',
    }
    mocks.action.mockResolvedValue({ queued: [{ id: 'scannerOne' }] })
    await render()

    await click('Update selected')
    expect(mocks.openModal).toHaveBeenCalledWith('otter-bulk-update-confirm')
    const select = container.querySelector('select')!
    expect([...select.options].map((option) => option.value)).toEqual(['v1.2.0', 'v1.3.0'])
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(
        select,
        'v1.3.0',
      )
      select.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(container.textContent).toContain('Queue v1.3.0 for 1 selected scanner?')
    await click('Queue updates')
    expect(mocks.action).toHaveBeenCalledWith('/api/otter/v1/updates', {
      version: 'v1.3.0',
      scannerIDs: ['scannerOne'],
    })
    expect(container.querySelector('[role="status"]')?.textContent).toBe(
      'Update queued for 1 scanner.',
    )
    expect(mocks.refresh).toHaveBeenCalledOnce()

    mocks.action.mockRejectedValueOnce(new Error('Permission denied.'))
    await click('Update selected')
    await click('Queue updates')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Permission denied')

    mocks.action.mockRejectedValueOnce('offline')
    await click('Update selected')
    await click('Queue updates')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not queue the update',
    )

    mocks.selection = { count: 2, selected: { scannerOne: true }, selectAll: 'allAvailable' }
    await renderFresh()
    expect(container.textContent).toContain('Select individual scanners')
    expect(
      [...container.querySelectorAll('button')].find(
        (button) => button.textContent === 'Update selected',
      )?.disabled,
    ).toBe(true)

    mocks.selection = { count: 1, selected: { scannerOne: false }, selectAll: 'some' }
    await renderFresh()
    expect(container.querySelector('button')?.disabled).toBe(true)

    mocks.selection = {
      count: 2,
      selected: { scannerOne: true, scannerTwo: true },
      selectAll: 'some',
    }
    mocks.action.mockResolvedValueOnce({ queued: [{ id: 'scannerOne' }, { id: 'scannerTwo' }] })
    await renderFresh()
    await click('Update selected')
    await click('Queue updates')
    expect(container.querySelector('[role="status"]')?.textContent).toBe(
      'Update queued for 2 scanners.',
    )
  })
})
