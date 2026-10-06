'use client'

import { useState } from 'react'

export default function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button
      aria-label={copied ? `Copied ${value}` : `Copy ${value}`}
      className="asset-view__copy"
      onClick={copy}
      type="button"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}
