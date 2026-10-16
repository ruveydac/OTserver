'use client'

import {
  Button,
  ConfirmationModal,
  CopyToClipboard,
  Gutter,
  useAuth,
  useConfig,
  useModal,
} from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import './index.scss'

export type Enrollment = {
  enrollmentToken: string
  expiresAt: string
  controllerUrl: string
  scanner?: { id: string }
}

export const EnrollmentInstructions = ({ enrollment }: { enrollment: Enrollment }) => (
  <div className="otter-enrollment__instructions">
    <p>
      Copy this single-use token now. It expires {new Date(enrollment.expiresAt).toLocaleString()}{' '}
      and is shown only once.
    </p>
    <code>{enrollment.enrollmentToken}</code>
    <CopyToClipboard value={enrollment.enrollmentToken} defaultMessage="Copy enrollment token" />
    <p>Run the command on the scanner host, then paste the token at the prompt:</p>
    {['otserver-otter', '.\\otserver-otter.exe'].map((binary) => {
      const command = `${binary} controller --server-url ${enrollment.controllerUrl} --enroll --ack-authorized`
      return (
        <div key={binary}>
          <code>{command}</code>
          <CopyToClipboard value={command} defaultMessage="Copy command" />
        </div>
      )
    })}
    <p>
      After enrollment, restart with the same command without <code>--enroll</code> to use the saved
      credential.
    </p>
  </div>
)

export async function otterAction(path: string, data?: unknown) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  })
  const result = await response.json()
  if (!response.ok)
    throw new Error(result.errors?.[0]?.message || result.message || 'The Otter action failed.')
  return result
}

export default function OtterEnrollment() {
  const { permissions } = useAuth()
  const {
    config: {
      routes: { admin, api },
    },
  } = useConfig()
  const { openModal, isModalOpen } = useModal()
  const router = useRouter()
  const [sites, setSites] = useState<Array<{ id: string; name: string }>>([])
  const [name, setName] = useState('')
  const [site, setSite] = useState('')
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loadingSites, setLoadingSites] = useState(true)
  const slug = 'otter-scanner-enrollment'
  const opened = isModalOpen(slug)

  useEffect(() => {
    if (!opened) return
    const abort = new AbortController()
    void fetch(`${api}/otter/v1/overview`, { cache: 'no-store', signal: abort.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not load enrollment sites.')
        return response.json() as Promise<{ writableSites: Array<{ id: string; name: string }> }>
      })
      .then((result) => {
        setSites(result.writableSites)
        setSite(result.writableSites[0]?.id || '')
      })
      .catch((error: unknown) => {
        if (!abort.signal.aborted)
          setError(error instanceof Error ? error.message : 'Could not load sites.')
      })
      .finally(() => {
        if (!abort.signal.aborted) setLoadingSites(false)
      })
    return () => abort.abort()
  }, [api, opened])

  const clear = () => {
    setLoadingSites(true)
    setSites([])
    setSite('')
    setEnrollment(undefined)
    setName('')
    setError('')
    router.refresh()
  }

  if (!permissions?.collections?.['otter-profiles']?.create) return null
  return (
    <Gutter className="otter-enrollment">
      <Button
        onClick={() => {
          clear()
          openModal(slug)
        }}
        type="button"
      >
        Enroll scanner
      </Button>
      <ConfirmationModal
        className="otter-enrollment"
        modalSlug={slug}
        heading="Enroll an Otter scanner"
        cancelLabel="Close"
        confirmLabel={enrollment ? 'Configure scanner' : 'Close'}
        onCancel={clear}
        onConfirm={() => {
          const id = enrollment?.scanner?.id
          clear()
          if (id) router.push(`${admin}/collections/otter-scanners/${id}`)
        }}
        body={
          <>
            <p>
              <a
                href="https://github.com/ruveydac/otserver-otter/releases/latest"
                target="_blank"
                rel="noreferrer"
              >
                Download Otter for Windows or Linux
              </a>{' '}
              on a host that can reach the network you are authorized to scan.
            </p>
            {error ? <p role="alert">{error}</p> : null}
            {enrollment ? (
              <EnrollmentInstructions enrollment={enrollment} />
            ) : (
              <form
                onSubmit={(event) => {
                  event.preventDefault()
                  setBusy(true)
                  setError('')
                  void otterAction(`${api}/otter/v1/scanners`, { name, site })
                    .then((result: Enrollment) => setEnrollment(result))
                    .catch((error: unknown) =>
                      setError(error instanceof Error ? error.message : 'Enrollment failed.'),
                    )
                    .finally(() => setBusy(false))
                }}
              >
                {loadingSites ? (
                  <p role="status">Loading sites…</p>
                ) : !error && !sites.length ? (
                  <p>No writable sites are available. Ask an administrator for site access.</p>
                ) : null}
                <label>
                  Scanner name
                  <input
                    className="field-type__input"
                    autoComplete="off"
                    required
                    maxLength={120}
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                  />
                </label>
                <label>
                  Site
                  <select
                    className="field-type__input"
                    required
                    value={site}
                    onChange={(event) => setSite(event.target.value)}
                  >
                    <option value="">Select a site</option>
                    {sites.map((entry) => (
                      <option key={entry.id} value={entry.id}>
                        {entry.name}
                      </option>
                    ))}
                  </select>
                </label>
                <Button type="submit" disabled={busy || !name.trim() || !site}>
                  Generate enrollment token
                </Button>
              </form>
            )}
          </>
        }
      />
    </Gutter>
  )
}
