// @vitest-environment jsdom

import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ router: { refresh: vi.fn() } }))
vi.mock('next/navigation', () => ({ useRouter: () => mocks.router }))
vi.mock('@payloadcms/ui', () => ({
  Button: ({ children, ...props }: { children: ReactNode; buttonStyle?: string }) => {
    delete props.buttonStyle
    return <button {...props}>{children}</button>
  },
  Gutter: ({ children, ...props }: { children: ReactNode }) => <div {...props}>{children}</div>,
  useConfig: () => ({ config: { routes: { api: '/api' } } }),
}))
import OtterReleaseActions from '../../src/components/OtterReleaseActions'
import { ApplicationSettings } from '../../src/globals/ApplicationSettings'

let container: HTMLDivElement
let root: Root
const idle = { enabled: false, active: false, processing: false }
const response = (data: unknown, ok = true) => ({ ok, json: async () => data })
const render = () =>
  act(async () => {
    root.render(<OtterReleaseActions />)
  })
const button = (label: string) =>
  [...container.querySelectorAll('button')].find((item) => item.textContent === label)!
const click = (label: string) =>
  act(async () => {
    button(label).click()
  })

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.clearAllMocks()
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})
afterEach(async () => {
  await act(async () => root.unmount())
  document.body.replaceChildren()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('Otter release import controls', () => {
  it('offers daily imports as a checkbox in application settings', () => {
    const dailyImports = ApplicationSettings.fields.find(
      (field) => 'name' in field && field.name === 'otterReleaseImports',
    )
    expect(dailyImports).toMatchObject({
      type: 'checkbox',
      label: 'Enable daily Otter release imports',
      defaultValue: false,
    })
  })

  it('shows loading and empty states, queues imports and refreshes the list on completion', async () => {
    const control = { ...idle, version: '', lastCheckedAt: '', lastSyncedAt: '' }
    let completeLoad: (value: ReturnType<typeof response>) => void
    const fetch = vi
      .fn(async (url: string) => {
        if (url.endsWith('/refresh')) {
          control.active = true
          return response({ jobID: 'job-1' })
        }
        return response({ ...control })
      })
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            completeLoad = resolve
          }),
      )
    vi.stubGlobal('fetch', fetch)
    vi.useFakeTimers()
    await render()
    expect(container.textContent).toContain('Loading release import status')
    expect(button('Import releases now').disabled).toBe(true)
    await act(async () => completeLoad(response({ ...idle })))
    expect(container.textContent).toContain('have not been checked yet')
    await click('Import releases now')
    expect(fetch).toHaveBeenCalledWith(
      '/api/otter-releases/refresh',
      expect.objectContaining({ method: 'POST' }),
    )
    expect(button('Import releases now').disabled).toBe(true)
    expect(container.textContent).toContain('You can leave this page')
    control.processing = true
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(container.textContent).toContain('Importing Otter releases')
    Object.assign(control, {
      active: false,
      processing: false,
      version: 'v0.14.1',
      lastCheckedAt: '2026-11-06T12:00:00Z',
      lastSyncedAt: '2026-11-06T12:01:00Z',
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(button('Import releases now').disabled).toBe(false)
    expect(container.textContent).toContain('Last successful import: v0.14.1')
    expect(mocks.router.refresh).toHaveBeenCalled()
    expect(container.querySelector('a')?.href).toBe(
      'https://github.com/ruveydac/otserver-otter/releases',
    )
  })

  it('shows the daily-import setting status and reports rejected manual imports', async () => {
    const control = { ...idle, error: '' }
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/refresh'))
        return response({ errors: [{ message: 'Administrator access required.' }] }, false)
      return response(control)
    })
    vi.stubGlobal('fetch', fetch)
    await render()
    expect(container.textContent).toContain('Daily imports are disabled')
    expect([...container.querySelectorAll('button')].map((item) => item.textContent)).toEqual([
      'Import releases now',
    ])
    await click('Import releases now')
    expect(container.querySelector('[role=alert]')?.textContent).toContain(
      'Administrator access required',
    )
    expect(button('Import releases now').disabled).toBe(false)
  })

  it('reports unavailable status and recovers on the next poll', async () => {
    const fetch = vi
      .fn(async () => response({ ...idle, error: 'Invalid executable signature.' }))
      .mockRejectedValueOnce(new Error('Network unavailable'))
    vi.stubGlobal('fetch', fetch)
    vi.useFakeTimers()
    await render()
    expect(container.textContent).toContain('Reconnecting automatically')
    expect(container.querySelector('[role=alert]')?.textContent).toContain('Network unavailable')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(button('Import releases now').disabled).toBe(false)
    expect(container.querySelector('[role=alert]')?.textContent).toContain(
      'Invalid executable signature',
    )
  })
})
