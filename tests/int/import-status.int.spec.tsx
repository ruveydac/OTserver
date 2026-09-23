// @vitest-environment jsdom

import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  documentID: undefined as string | undefined,
  fields: {} as Record<string, string | undefined>,
}))

vi.mock('@payloadcms/ui', async () => {
  const { createElement } = await import('react')
  return {
    Button: ({ children, ...props }: Record<string, unknown>) =>
      createElement('button', props, children as never),
    useDocumentInfo: () => ({ id: mocks.documentID }),
    useField: ({ path }: { path: string }) => ({ value: mocks.fields[path] }),
  }
})

import ImportStatus from '../../src/components/ImportStatus'

let container: HTMLDivElement
let root: Root

const response = (body: unknown, ok = true) => ({
  json: () => Promise.resolve(body),
  ok,
})

const render = async () => {
  await act(async () => {
    root.render(createElement(ImportStatus))
    await Promise.resolve()
  })
}

beforeEach(() => {
  ;(
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true
  mocks.documentID = undefined
  mocks.fields = {}
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  vi.useRealTimers()
  await act(async () => root.unmount())
  document.body.replaceChildren()
  vi.unstubAllGlobals()
})

describe('queued import status', () => {
  it('stays hidden for a new or synchronous import', async () => {
    await render()
    expect(container.textContent).toBe('')

    mocks.documentID = 'sync/id'
    mocks.fields = { executionMode: 'sync', status: 'completed' }
    await render()
    expect(container.textContent).toBe('')
  })

  it('polls active imports until completion and renders server progress', async () => {
    vi.useFakeTimers()
    mocks.documentID = 'queued/id'
    mocks.fields = { executionMode: 'queued', status: 'pending' }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response({ status: 'pending', attemptCount: 0 }))
      .mockResolvedValueOnce(response({ status: 'running', attemptCount: 1 }))
      .mockResolvedValueOnce(
        response({ status: 'completed', attemptCount: 2, error: 'retained detail' }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await render()
    expect(container.textContent).toContain('Import: pending. Attempts: 0.')
    expect(fetchMock).toHaveBeenCalledWith('/api/asset-imports/queued%2Fid?depth=0', {
      signal: expect.any(AbortSignal),
    })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(container.textContent).toContain('Import: running. Attempts: 1.')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(container.textContent).toContain('Import: completed. Attempts: 2.')
    expect(container.textContent).toContain('retained detail')
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('shows a reconnect message for failed status requests', async () => {
    mocks.documentID = 'unavailable'
    mocks.fields = { executionMode: 'queued', status: 'pending' }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({}, false)))

    await render()
    expect(container.textContent).toContain('Status could not be loaded')
  })

  it('ignores a response that arrives after unmount', async () => {
    mocks.documentID = 'cancelled'
    mocks.fields = { executionMode: 'queued', status: 'pending' }
    let resolveFetch: (value: ReturnType<typeof response>) => void = () => undefined
    vi.stubGlobal(
      'fetch',
      vi.fn(
        () =>
          new Promise<ReturnType<typeof response>>((resolve) => {
            resolveFetch = resolve
          }),
      ),
    )

    await render()
    await act(async () => root.unmount())
    root = createRoot(container)
    await act(async () => {
      resolveFetch(response({ status: 'completed', attemptCount: 1 }))
      await Promise.resolve()
    })
    expect(container.textContent).toBe('')
  })

  it('retries a failed import and resumes polling', async () => {
    mocks.documentID = 'failed import'
    mocks.fields = { executionMode: 'queued', status: 'failed' }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response({ status: 'failed', attemptCount: 2 }))
      .mockResolvedValueOnce(response({ doc: { status: 'pending', attemptCount: 2 } }))
      .mockResolvedValueOnce(response({ status: 'completed', attemptCount: 3 }))
    vi.stubGlobal('fetch', fetchMock)

    await render()
    const button = container.querySelector('button')!
    expect(button.textContent).toBe('Retry import')
    await act(async () => button.click())
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/asset-imports/failed%20import/retry', {
      method: 'POST',
    })
    expect(container.textContent).toContain('Import: completed. Attempts: 3.')
  })

  it('explains a rejected retry', async () => {
    mocks.documentID = 'failed'
    mocks.fields = { executionMode: 'queued', status: 'failed' }
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(response({ status: 'failed', attemptCount: 1 }))
        .mockResolvedValueOnce(response({}, false)),
    )

    await render()
    await act(async () => container.querySelector('button')!.click())
    expect(container.textContent).toContain('Retry was rejected')
  })
})
