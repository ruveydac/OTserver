'use client'

import { Button, Gutter, useConfig } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useCallback, useEffect, useRef, useState } from 'react'
import '../VulnerabilityFeedActions/index.scss'

type Control = {
  enabled: boolean
  active: boolean
  processing: boolean
  lastCheckedAt?: string | null
  lastSyncedAt?: string | null
  version?: string | null
  error?: string | null
}
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : 'The release import action failed.'
async function result(response: Response) {
  const data = await response.json()
  if (!response.ok)
    throw new Error(data.errors?.[0]?.message || 'The release import action failed.')
  return data
}

export default function OtterReleaseActions() {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const router = useRouter()
  const base = `${api}/otter-releases`
  const [control, setControl] = useState<Control>()
  const [error, setError] = useState('')
  const [statusError, setStatusError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const activeBefore = useRef(false)
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const data = (await result(
        await fetch(`${base}/control`, { signal, cache: 'no-store' }),
      )) as Control
      setControl(data)
      setStatusError('')
      if (activeBefore.current && !data.active) router.refresh()
      activeBefore.current = data.active
    },
    [base, router],
  )

  useEffect(() => {
    const abort = new AbortController()
    const poll = () =>
      void load(abort.signal).catch((error: unknown) => {
        if (!abort.signal.aborted) setStatusError(errorText(error))
      })
    poll()
    const timer = setInterval(poll, 5000)
    return () => {
      abort.abort()
      clearInterval(timer)
    }
  }, [load])

  const action = async () => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await result(await fetch(`${base}/refresh`, { method: 'POST' }))
      setNotice('Release import queued. You can leave this page while the worker runs.')
      await load()
    } catch (error) {
      setError(errorText(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Gutter className="vulnerability-feed-actions">
      <p>
        Import the latest stable release from{' '}
        <a href="https://github.com/ruveydac/otserver-otter/releases">Otter on GitHub</a> for Linux
        x86_64, Linux ARM64, and Windows. Scanner updates are assigned separately.
      </p>
      <div className="vulnerability-feed-actions__buttons">
        <Button
          type="button"
          disabled={busy || !control || control.active}
          onClick={() => void action()}
        >
          Import releases now
        </Button>
      </div>
      <div role="status" aria-live="polite">
        {!control ? (
          <p>
            {statusError
              ? 'Release import status is unavailable. Reconnecting automatically.'
              : 'Loading release import status...'}
          </p>
        ) : (
          <>
            <p>Daily imports are {control.enabled ? 'enabled (every 24 hours)' : 'disabled'}.</p>
            {control.active && (
              <p>{control.processing ? 'Importing Otter releases...' : 'Release import queued.'}</p>
            )}
            <p>
              {control.lastCheckedAt
                ? `Last check: ${new Date(control.lastCheckedAt).toLocaleString()}.`
                : 'GitHub releases have not been checked yet.'}
              {control.version &&
                control.lastSyncedAt &&
                ` Last successful import: ${control.version}, ${new Date(control.lastSyncedAt).toLocaleString()}.`}
            </p>
          </>
        )}
        {notice && <p>{notice}</p>}
      </div>
      {(error || statusError || control?.error) && (
        <p role="alert">{error || statusError || control?.error}</p>
      )}
    </Gutter>
  )
}
