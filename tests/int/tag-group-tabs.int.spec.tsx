// @vitest-environment jsdom

import { act, useState } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import TagGroupTabs, { type TagGroupTabOption } from '@/components/TagGroupTabs'

let root: Root
let container: HTMLDivElement

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
})

afterEach(async () => {
  await act(async () => root.unmount())
  container.remove()
})

describe('tag group tabs', () => {
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
})
