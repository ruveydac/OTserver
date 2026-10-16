'use client'

import { CopyToClipboard } from '@payloadcms/ui'

export default function CopyButton({ value }: { value: string }) {
  return <CopyToClipboard value={value} defaultMessage="Copy value" successMessage="Value copied" />
}
