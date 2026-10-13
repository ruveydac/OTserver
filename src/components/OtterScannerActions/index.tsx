'use client'

import { Button, ConfirmationModal, useDocumentInfo, useFormFields, useModal } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useState } from 'react'
import { EnrollmentInstructions, otterAction, type Enrollment } from '../OtterEnrollment'

export default function OtterScannerActions() {
  const { id, collectionSlug, docPermissions } = useDocumentInfo()
  const scanner = useFormFields(([fields]) => fields.scanner?.value)
  const { openModal } = useModal()
  const router = useRouter()
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [enrollment, setEnrollment] = useState<Enrollment>()
  const act = async (path: string, data?: unknown) => {
    setBusy(true)
    setMessage('')
    try {
      const result = await otterAction(path, data)
      if (result.enrollmentToken) {
        setEnrollment(result)
        openModal('otter-reenrollment-token')
      } else
        setMessage(
          result.status === 'queued'
            ? 'Scan queued. Otter will receive it on its next poll.'
            : 'Scanner credential revoked.',
        )
      router.refresh()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The action failed.')
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
            act('/api/otter/v1/runs', {
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
      </section>
    )
  return (
    <section>
      <p>
        Configure and run scans from{' '}
        <Link href="/admin/collections/otter-profiles">Otter Configurations</Link>.
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
      {message ? <p role="status">{message}</p> : null}
      <ConfirmationModal
        modalSlug="otter-reenroll-confirm"
        heading="Re-enroll scanner?"
        body="This revokes the existing credential and generates a new single-use enrollment token."
        onConfirm={() => act(`/api/otter/v1/scanners/${id}/reenroll`)}
      />
      <ConfirmationModal
        modalSlug="otter-revoke-confirm"
        heading="Revoke scanner?"
        body="This disables the scanner and revokes its credential. Re-enroll it to connect again."
        onConfirm={() => act(`/api/otter/v1/scanners/${id}/revoke`)}
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
