'use client'

import {
  Banner,
  Button,
  ConfirmationModal,
  useConfig,
  useModal,
  useSelection,
} from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'
import { otterAction } from '../OtterEnrollment'

type Release = { version: string }

export default function OtterBulkUpdates() {
  const {
    config: {
      routes: { admin, api },
    },
  } = useConfig()
  const { count, selectAll, selected } = useSelection()
  const { openModal } = useModal()
  const router = useRouter()
  const [releases, setReleases] = useState<Release[]>([])
  const [version, setVersion] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const modal = 'otter-bulk-update-confirm'
  const scannerIDs = useMemo(
    () =>
      Object.entries(selected)
        .filter(([, value]) => value)
        .map(([id]) => id),
    [selected],
  )

  useEffect(() => {
    const abort = new AbortController()
    void fetch(`${api}/otter/v1/updates/releases`, { cache: 'no-store', signal: abort.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not load signed Otter releases.')
        return response.json() as Promise<{ releases?: Release[] }>
      })
      .then(({ releases: available }) => {
        if (!Array.isArray(available)) throw new Error('Could not load signed Otter releases.')
        setReleases(available)
        setVersion(available[0]?.version || '')
      })
      .catch((reason: unknown) => {
        if (!abort.signal.aborted)
          setError(reason instanceof Error ? reason.message : 'Could not load signed releases.')
      })
      .finally(() => {
        if (!abort.signal.aborted) setLoading(false)
      })
    return () => abort.abort()
  }, [api])

  const versions = useMemo(() => [...new Set(releases.map(({ version }) => version))], [releases])

  const queue = async () => {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const result = await otterAction(`${api}/otter/v1/updates`, { version, scannerIDs })
      setMessage(
        `Update queued for ${result.queued.length} scanner${result.queued.length === 1 ? '' : 's'}.`,
      )
      router.refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not queue the update.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button el="link" url={`${admin}/collections/otter-updates`}>
        Update history
      </Button>
      {count > 0 ? (
        <>
          <Button
            disabled={
              busy ||
              loading ||
              !versions.length ||
              selectAll === 'allAvailable' ||
              !scannerIDs.length
            }
            type="button"
            onClick={() => openModal(modal)}
          >
            Update selected
          </Button>
          {loading ? <span role="status">Loading signed releases…</span> : null}
          {selectAll === 'allAvailable' ? (
            <span>Select individual scanners for a bulk update.</span>
          ) : null}
          {error && !versions.length ? (
            <div role="alert">
              <Banner type="error">{error}</Banner>
            </div>
          ) : null}
          {!loading && !error && !versions.length ? (
            <Button el="link" url={`${admin}/collections/otter-releases`}>
              Upload a signed release
            </Button>
          ) : null}
          {message ? <span role="status">{message}</span> : null}
          {error && versions.length ? (
            <div role="alert">
              <Banner type="error">{error}</Banner>
            </div>
          ) : null}
          <ConfirmationModal
            modalSlug={modal}
            heading="Queue Otter updates?"
            body={
              <>
                <label>
                  Version tag{' '}
                  <select
                    className="field-type__input"
                    value={version}
                    onChange={(event) => setVersion(event.target.value)}
                  >
                    {versions.map((tag) => (
                      <option key={tag} value={tag}>
                        {tag}
                      </option>
                    ))}
                  </select>
                </label>
                <p>
                  Queue {version} for {scannerIDs.length} selected scanner
                  {scannerIDs.length === 1 ? '' : 's'}? The matching signed executable is chosen for
                  each scanner automatically. Scanners finish active scans before updating.
                </p>
              </>
            }
            confirmLabel="Queue updates"
            cancelLabel="Cancel"
            onConfirm={() => void queue()}
          />
        </>
      ) : null}
    </>
  )
}
