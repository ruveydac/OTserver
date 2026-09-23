'use client'

import { useDocumentInfo, useField, Button } from '@payloadcms/ui'
import { useEffect, useState } from 'react'

type Progress = { status?: string; error?: string; attemptCount?: number }

export default function ImportStatus() {
  const { id } = useDocumentInfo()
  const { value: mode } = useField<string>({ path: 'executionMode' })
  const { value: initialStatus } = useField<string>({ path: 'status' })
  const [progress, setProgress] = useState<Progress>({})
  const [message, setMessage] = useState('')
  const [pollKey, setPollKey] = useState(0)
  const status = progress.status || initialStatus

  useEffect(() => {
    if (!id || mode !== 'queued') return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>
    const controller = new AbortController()
    const poll = async () => {
      try {
        const response = await fetch(`/api/asset-imports/${encodeURIComponent(id)}?depth=0`, {
          signal: controller.signal,
        })
        if (!response.ok) throw new Error('Could not load import status.')
        const doc = (await response.json()) as Progress
        if (cancelled) return
        setProgress(doc)
        setMessage('')
        if (doc.status === 'pending' || doc.status === 'running') timer = setTimeout(poll, 2000)
      } catch {
        if (!cancelled) setMessage('Status could not be loaded. Refresh this page to reconnect.')
      }
    }
    void poll()
    return () => {
      cancelled = true
      clearTimeout(timer)
      controller.abort()
    }
  }, [id, mode, pollKey])

  if (!id || mode !== 'queued') return null
  return (
    <div role="status" aria-live="polite">
      <p>
        Import: {status}. Attempts: {progress.attemptCount || 0}.
      </p>
      {progress.error && <p>{progress.error}</p>}
      {message && <p>{message}</p>}
      {status === 'failed' && (
        <Button
          type="button"
          onClick={async () => {
            try {
              const response = await fetch(`/api/asset-imports/${encodeURIComponent(id)}/retry`, {
                method: 'POST',
              })
              if (!response.ok) throw new Error()
              const result = await response.json()
              setProgress(result.doc)
              setPollKey((value) => value + 1)
            } catch {
              setMessage(
                'Retry was rejected. Check your current site permissions and the import status.',
              )
            }
          }}
        >
          Retry import
        </Button>
      )}
    </div>
  )
}
