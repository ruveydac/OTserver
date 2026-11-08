// @vitest-environment jsdom

import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  openModal: vi.fn(),
  refresh: vi.fn(),
}))

vi.mock('@payloadcms/ui', () => ({
  Banner: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  Button: ({ children, onClick }: { children: ReactNode; onClick: () => void }) => (
    <button onClick={onClick} type="button">
      {children}
    </button>
  ),
  ConfirmationModal: ({
    body,
    cancelLabel,
    confirmLabel,
    onConfirm,
  }: {
    body: ReactNode
    cancelLabel: string
    confirmLabel: string
    onConfirm: () => void
  }) => (
    <div>
      {body}
      <button onClick={onConfirm} type="button">
        {confirmLabel}
      </button>
      <button type="button">{cancelLabel}</button>
    </div>
  ),
  useConfig: () => ({ config: { routes: { api: '/api' } } }),
  useModal: () => ({ openModal: mocks.openModal }),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh: mocks.refresh }) }))

import ManualAssetTags from '@/components/AssetView/ManualAssetTags'

let container: HTMLDivElement
let root: Root

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
  mocks.openModal.mockClear()
  mocks.refresh.mockClear()
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  container.remove()
  vi.unstubAllGlobals()
})

const render = async (
  availableTags: Array<{
    id: string
    name: string
    color: string
    group?: { id: string; name: string }
  }>,
  manualTagIDs: string[],
) =>
  act(async () => {
    root.render(
      <ManualAssetTags
        assetID="asset/1"
        availableTags={availableTags}
        manualTagIDs={manualTagIDs}
      />,
    )
    await Promise.resolve()
  })

describe('manual asset tags', () => {
  it('opens the empty state when no manual tags are configured', async () => {
    await render([], [])

    await act(async () => container.querySelector('button')?.click())

    expect(mocks.openModal).toHaveBeenCalledWith('asset-manual-tags-asset/1')
    expect(container.textContent).toContain('No manual tags are configured.')
  })

  it('edits grouped selections and saves them to the asset', async () => {
    const availableTags = [
      {
        id: 'critical',
        name: 'Critical',
        color: '#B91C1C',
        group: { id: 'severity', name: 'Severity' },
      },
      {
        id: 'review',
        name: 'Review',
        color: '#64748B',
        group: { id: 'operations', name: 'Operations' },
      },
    ]
    await render(availableTags, ['critical'])

    await act(async () => container.querySelector('button')?.click())
    const severity = [...container.querySelectorAll('button')].find(
      (button) => button.textContent === 'Severity',
    )!
    await act(async () => severity.click())
    const critical = container.querySelector<HTMLInputElement>('input[type="checkbox"]')!
    expect(critical.checked).toBe(true)
    await act(async () => critical.click())
    const operations = [...container.querySelectorAll('button')].find(
      (button) => button.textContent === 'Operations',
    )!
    await act(async () => operations.click())
    const review = container.querySelector<HTMLInputElement>('input[type="checkbox"]')!
    await act(async () => review.click())

    const fetch = vi.fn(async (_url: string, init: RequestInit) => ({
      ok: true,
      json: async () => ({}),
      init,
    }))
    vi.stubGlobal('fetch', fetch)
    await act(async () => {
      ;[...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Save tags')
        ?.click()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(fetch).toHaveBeenCalledWith('/api/assets/asset%2F1', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manualTags: ['review'] }),
    })
    expect(mocks.refresh).toHaveBeenCalledOnce()
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('shows server and network errors without refreshing', async () => {
    await render([{ id: 'critical', name: 'Critical', color: '#B91C1C' }], [])
    await act(async () => container.querySelector('button')?.click())

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: false,
        json: async () => ({ errors: [{ message: 'No permission.' }] }),
      })),
    )
    await act(async () => {
      ;[...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Save tags')
        ?.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('No permission.')

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw 'offline'
      }),
    )
    await act(async () => {
      ;[...container.querySelectorAll('button')]
        .find((button) => button.textContent === 'Save tags')
        ?.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not save manual tags.',
    )
    expect(mocks.refresh).not.toHaveBeenCalled()
  })
})
