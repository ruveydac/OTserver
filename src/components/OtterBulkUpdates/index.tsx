'use client'

import {
  Banner,
  Button,
  ConfirmationModal,
  useConfig,
  useModal,
  useSelection,
} from '@payloadcms/ui'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'
import { otterAction } from '../OtterEnrollment'

type Release = { id: string; version: string; target: string }

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
  const [releaseID, setReleaseID] = useState('')
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
        setReleaseID(available[0]?.id || '')
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

  const queue = async () => {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const result = await otterAction(`${api}/otter/v1/updates`, { releaseID, scannerIDs })
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

  if (loading) return <p role="status">Loading signed Otter releases…</p>
  if (error && !releases.length)
    return (
      <div role="alert">
        <Banner type="error">{error}</Banner>
      </div>
    )
  if (!releases.length)
    return (
      <p>
        No signed Otter executables have been uploaded.{' '}
        <Link href={`${admin}/collections/otter-releases`}>Upload a signed release</Link>.
      </p>
    )

  return (
    <section>
      <label>
        Signed release{' '}
        <select
          className="field-type__input"
          value={releaseID}
          onChange={(event) => setReleaseID(event.target.value)}
        >
          {releases.map((release) => (
            <option key={release.id} value={release.id}>
              {release.version} ({release.target})
            </option>
          ))}
        </select>
      </label>{' '}
      <Button
        disabled={busy || count === 0 || selectAll === 'allAvailable' || !scannerIDs.length}
        type="button"
        onClick={() => openModal(modal)}
      >
        Update selected Otters
      </Button>
      {selectAll === 'allAvailable' ? (
        <p>Select individual scanner rows for a bulk update.</p>
      ) : null}
      {message ? <p role="status">{message}</p> : null}
      {error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      <ConfirmationModal
        modalSlug={modal}
        heading="Queue Otter updates?"
        body={`Queue ${releaseID ? releases.find(({ id }) => id === releaseID)?.version : 'this release'} for ${scannerIDs.length} selected scanner${scannerIDs.length === 1 ? '' : 's'}? Scanners finish active scans before updating.`}
        confirmLabel="Queue updates"
        cancelLabel="Cancel"
        onConfirm={() => void queue()}
      />
      <p>
        <Link href={`${admin}/collections/otter-updates`}>View update history and outcomes</Link>
      </p>
    </section>
  )
}
