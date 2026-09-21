// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import IdentityActions from '@/components/DeviceIdentity/Actions'

const { refresh } = vi.hoisted(() => ({ refresh: vi.fn() }))
vi.mock('next/navigation', () => ({ useRouter: () => ({ refresh }) }))
;(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
).IS_REACT_ACT_ENVIRONMENT = true
afterEach(() => {
  vi.unstubAllGlobals()
  refresh.mockClear()
})

describe('identity action form', () => {
  it('submits selected associations and reports API failures without discarding the form', async () => {
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ action: 'split' }) })
    vi.stubGlobal('fetch', fetch)
    await act(async () =>
      root.render(
        <IdentityActions
          assetID="asset-1"
          apiRoute="/api"
          endpoints={[{ id: 'endpoint-1', label: 'Ethernet 1' }]}
          identifiers={[{ id: 'key-1', label: 'CPU serial' }]}
          targets={[{ id: 'asset-2', label: 'Replacement' }]}
          sites={[{ id: 'site-2', label: 'Destination' }]}
        />,
      ),
    )
    const select = container.querySelector('select')!
    const change = async (value: string) =>
      act(async () => {
        select.value = value
        select.dispatchEvent(new Event('change', { bubbles: true }))
      })
    await change('split')
    container.querySelector<HTMLInputElement>('input[name="endpoints"]')!.checked = true
    container.querySelector<HTMLInputElement>('input[name="identifiers"]')!.checked = true
    container.querySelector<HTMLTextAreaElement>('textarea')!.value = 'Confirmed module separation'
    await act(async () => {
      container
        .querySelector('form')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toMatchObject({
      action: 'split',
      endpoints: ['endpoint-1'],
      identifiers: ['key-1'],
      reason: 'Confirmed module separation',
    })
    expect(refresh).toHaveBeenCalledOnce()
    await change('transfer')
    expect(container.textContent).toContain('Destination site')
    await change('close-endpoint')
    expect(container.querySelector('select[name="endpoint"]')).toBeTruthy()
    fetch.mockResolvedValue({
      ok: false,
      json: async () => ({ errors: [{ message: 'Write access is required.' }] }),
    })
    await act(async () => {
      container
        .querySelector('form')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Write access')
    expect(container.querySelector('button')?.disabled).toBe(false)
    await change('retire')
    expect(container.querySelector('select[name="target"]')).toBeNull()
    await act(async () => root.unmount())
    container.remove()
  })
})
