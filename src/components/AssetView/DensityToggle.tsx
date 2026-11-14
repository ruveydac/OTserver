'use client'

import { Button } from '@payloadcms/ui'
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
    <Button
      aria-label={`Switch to ${nextDensity} density`}
      buttonStyle="secondary"
      className="asset-view__action"
      extraButtonProps={{ 'aria-pressed': density === 'compact' }}
      margin={false}
      onClick={() => setDensity(nextDensity)}
      size="medium"
      type="button"
    >
      {density === 'compact' ? 'Compact' : 'Comfortable'}
    </Button>
  )
}
