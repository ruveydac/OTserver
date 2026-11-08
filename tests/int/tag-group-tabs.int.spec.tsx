// @vitest-environment jsdom

import { act, useState } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import TagGroupTabs, { type TagGroupTabOption } from '@/components/TagGroupTabs'
import TagListGroupTabs from '@/components/TagListGroupTabs'

const payloadUIMocks = vi.hoisted(() => ({
  api: '/api',
  query: { where: {} as Record<string, unknown> },
  refineListData: vi.fn(),
}))

vi.mock('@payloadcms/ui', () => ({
  useConfig: () => ({ config: { routes: { api: payloadUIMocks.api } } }),
  useListQuery: () => ({
    query: payloadUIMocks.query,
    refineListData: payloadUIMocks.refineListData,
  }),
}))

let root: Root
let container: HTMLDivElement

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
  payloadUIMocks.query.where = { status: { equals: 'online' } }
  payloadUIMocks.refineListData.mockReset()
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  container.remove()
})

describe('tag group tabs', () => {
  const renderListTabs = async () =>
    act(async () => {
      root.render(<TagListGroupTabs />)
      for (let index = 0; index < 5; index++) await Promise.resolve()
    })

  it('switches the active group with a button click', async () => {
    const groups: TagGroupTabOption[] = [
      { id: 'all', name: 'All tags' },
      { id: 'criticality', name: 'Criticality' },
    ]
    const Tabs = () => {
      const [selected, setSelected] = useState('all')
      return (
        <TagGroupTabs
          groups={groups}
          label="Tag groups"
          onSelect={setSelected}
          selected={selected}
        />
      )
    }

    await act(async () => root.render(<Tabs />))
    const buttons = container.querySelectorAll('button')
    expect(buttons[0]?.getAttribute('aria-pressed')).toBe('true')

    await act(async () => buttons[1]?.click())

    expect(buttons[0]?.getAttribute('aria-pressed')).toBe('false')
    expect(buttons[1]?.getAttribute('aria-pressed')).toBe('true')
  })

  it('renders no group control when there are no choices', async () => {
    const onSelect = vi.fn()
    await act(async () =>
      root.render(<TagGroupTabs groups={[]} label="Tag groups" onSelect={onSelect} selected="" />),
    )

    expect(container.querySelector('[role="group"]')).toBeNull()
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('loads list groups, preserves other filters, and falls back to all for unknown groups', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ docs: [{ id: 'ops', name: 'Operations' }] }),
      })),
    )
    payloadUIMocks.query.where = {
      status: { equals: 'online' },
      group: { equals: 'missing-group' },
    }

    await renderListTabs()

    expect(container.querySelector('[role="status"]')).toBeNull()
    expect(container.querySelector('button[aria-pressed="true"]')?.textContent).toBe('All tags')
    const operations = [...container.querySelectorAll('button')].find(
      (button) => button.textContent === 'Operations',
    )!
    await act(async () => operations.click())
    expect(payloadUIMocks.refineListData).toHaveBeenCalledWith({
      page: 1,
      where: {
        and: [{ status: { equals: 'online' } }, { group: { equals: 'ops' } }],
      },
    })
  })

  it('shows an empty state when no groups are configured', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, json: async () => ({ docs: [] }) })),
    )

    await renderListTabs()

    expect(container.textContent).toContain('No tag groups configured.')
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('shows an error state when loading groups fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, json: async () => ({}) })),
    )

    await renderListTabs()

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      'Could not load tag groups.',
    )
    expect(container.textContent).not.toContain('No tag groups configured.')
  })
})
