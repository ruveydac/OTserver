'use client'

import { startTransition, useEffect, useState } from 'react'

type Density = 'comfortable' | 'compact'

const STORAGE_KEY = 'otserver-asset-density'

export default function DensityToggle() {
  const [density, setDensity] = useState<Density>('comfortable')

  useEffect(() => {
    const saved = window.localStorage.getItem(STORAGE_KEY)
    if (saved === 'compact') startTransition(() => setDensity('compact'))
  }, [])

  useEffect(() => {
    const view = document.querySelector<HTMLElement>('.asset-view')
    if (view) view.dataset.density = density
    window.localStorage.setItem(STORAGE_KEY, density)
  }, [density])

  const nextDensity: Density = density === 'compact' ? 'comfortable' : 'compact'

  return (
    <button
      aria-label={`Switch to ${nextDensity} density`}
      aria-pressed={density === 'compact'}
      className="asset-view__density"
      onClick={() => setDensity(nextDensity)}
      type="button"
    >
      {density === 'compact' ? 'Compact' : 'Comfortable'}
    </button>
  )
}
