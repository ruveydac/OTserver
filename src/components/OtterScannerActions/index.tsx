'use client'

import {
  Banner,
  Button,
  ConfirmationModal,
  useConfig,
  useDocumentInfo,
  useFormFields,
  useModal,
} from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useEffect, useState } from 'react'
import { EnrollmentInstructions, otterAction, type Enrollment } from '../OtterEnrollment'

type Release = { id: string; version: string; target: string }

export default function OtterScannerActions() {
  const {
    config: {
      routes: { api, admin },
    },
  } = useConfig()
  const { id, collectionSlug, docPermissions } = useDocumentInfo()
  const scanner = useFormFields(([fields]) => fields.scanner?.value)
  const { openModal } = useModal()
  const router = useRouter()
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const [releases, setReleases] = useState<Release[]>([])
  const [releaseID, setReleaseID] = useState('')
  const [loadingReleases, setLoadingReleases] = useState(true)
  const updateModal = 'otter-single-update-confirm'

  useEffect(() => {
    if (collectionSlug !== 'otter-scanners' || !id) return
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
        if (!abort.signal.aborted) setLoadingReleases(false)
      })
    return () => abort.abort()
  }, [api, collectionSlug, id])
  const act = async (path: string, data?: unknown) => {
    setBusy(true)
    setMessage('')
    setError('')
    try {
      const result = await otterAction(path, data)
      if (result.enrollmentToken) {
        setEnrollment(result)
        openModal('otter-reenrollment-token')
      } else if (path.endsWith('/updates')) {
        setMessage(
          `Update queued for ${result.queued.length} scanner${result.queued.length === 1 ? '' : 's'}.`,
        )
      } else
        setMessage(
          result.status === 'queued'
            ? 'Scan queued. Otter will receive it on its next poll.'
            : 'Scanner credential revoked.',
        )
      router.refresh()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'The action failed.')
    } finally {
      setBusy(false)
    }
  }

  if (!id || !docPermissions?.update) return null
  if (collectionSlug === 'otter-profiles')
    return (
      <section>
        <p>
          Save this configuration before running a scan. Scan options and import overrides are saved
          with the run.
        </p>
        <Button disabled={busy} type="button" onClick={() => openModal('otter-run-confirm')}>
          Run now
        </Button>
        <ConfirmationModal
          modalSlug="otter-run-confirm"
          heading="Are you authorized to run this scan?"
          body="Only run discovery on networks you are allowed to assess. Do you confirm that you have permission to run this configuration?"
          confirmLabel="Yes"
          cancelLabel="No"
          onConfirm={() =>
            act(`${api}/otter/v1/runs`, {
              scannerID:
                typeof scanner === 'string'
                  ? scanner
                  : scanner && typeof scanner === 'object' && 'value' in scanner
                    ? scanner.value
                    : '',
              profileID: id,
            })
          }
        />
        {message ? <p role="status">{message}</p> : null}
        {error ? (
          <div role="alert">
            <Banner type="error">{error}</Banner>
          </div>
        ) : null}
      </section>
    )
  return (
    <section>
      <p>
        Configure and run scans from{' '}
        <Link href={`${admin}/collections/otter-profiles`}>Otter configurations</Link>.
      </p>
      <Button
        disabled={busy}
        type="button"
        buttonStyle="secondary"
        onClick={() => openModal('otter-reenroll-confirm')}
      >
        Re-enroll
      </Button>
      <Button
        disabled={busy}
        type="button"
        buttonStyle="error"
        onClick={() => openModal('otter-revoke-confirm')}
      >
        Revoke
      </Button>
      <div>
        <label>
          Signed release{' '}
          <select
            className="field-type__input"
            value={releaseID}
            disabled={loadingReleases || !releases.length}
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
          disabled={busy || loadingReleases || !releaseID}
          type="button"
          onClick={() => openModal(updateModal)}
        >
          Update Otter
        </Button>
        {loadingReleases ? <p role="status">Loading signed releases…</p> : null}
        {!loadingReleases && !error && !releases.length ? (
          <p>No signed releases are available.</p>
        ) : null}
      </div>
      {message ? <p role="status">{message}</p> : null}
      {error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      <ConfirmationModal
        modalSlug="otter-reenroll-confirm"
        heading="Re-enroll scanner?"
        body="This revokes the existing credential and generates a new single-use enrollment token."
        onConfirm={() => act(`${api}/otter/v1/scanners/${id}/reenroll`)}
      />
      <ConfirmationModal
        modalSlug={updateModal}
        heading="Queue Otter update?"
        body="The scanner finishes any active scan before downloading and verifying the selected signed release."
        confirmLabel="Queue update"
        cancelLabel="Cancel"
        onConfirm={() => act(`${api}/otter/v1/updates`, { releaseID, scannerIDs: [id] })}
      />
      <ConfirmationModal
        modalSlug="otter-revoke-confirm"
        heading="Revoke scanner?"
        body="This disables the scanner and revokes its credential. Re-enroll it to connect again."
        onConfirm={() => act(`${api}/otter/v1/scanners/${id}/revoke`)}
      />
      <ConfirmationModal
        modalSlug="otter-reenrollment-token"
        heading="Connect your scanner"
        body={enrollment ? <EnrollmentInstructions enrollment={enrollment} /> : null}
        confirmLabel="Done"
        cancelLabel="Close"
        onConfirm={() => setEnrollment(undefined)}
        onCancel={() => setEnrollment(undefined)}
      />
    </section>
  )
}
