'use client'

import {
  Button,
  ConfirmationModal,
  CopyToClipboard,
  useDocumentInfo,
  useField,
  useModal,
} from '@payloadcms/ui'
import { useEffect, useRef } from 'react'

import { importSources, type ImportSource } from '@/importers/sources'

import './index.scss'

const modalSlug = 'asset-import-instructions'

const ImportInstructions = () => {
  const { id } = useDocumentInfo()
  const { setValue, value } = useField<ImportSource | undefined>({ path: 'source' })
  const { openModal } = useModal()
  const opened = useRef(false)

  useEffect(() => {
    if (!id && !opened.current) {
      opened.current = true
      openModal(modalSlug)
    }
  }, [id, openModal])

  return (
    <div className="import-instructions-field">
      <Button buttonStyle="secondary" onClick={() => openModal(modalSlug)} type="button">
        How to create an import file
      </Button>

      <ConfirmationModal
        body={
          <div className="import-instructions">
            <p>
              Choose an importer, prepare its XML as described below, select the destination site,
              and upload the file. Assets are merged only by MAC address.
            </p>

            {importSources.map((source) => (
              <label
                className={value === source.value ? 'import-instructions__source--selected' : ''}
                key={source.value}
              >
                <div className="import-instructions__heading">
                  <input
                    checked={value === source.value}
                    name="import-source"
                    onChange={() => setValue(source.value)}
                    type="radio"
                    value={source.value}
                  />
                  <h3>
                    {source.fileLabel}
                    {value === source.value ? <span>Selected</span> : null}
                  </h3>
                </div>
                <ol>
                  {source.steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                {'command' in source ? (
                  <div className="import-instructions__command">
                    <code>{source.command}</code>
                    <CopyToClipboard
                      defaultMessage="Copy command"
                      successMessage="Command copied"
                      value={source.command}
                    />
                  </div>
                ) : null}
                <p>
                  <strong>Required:</strong> {source.required}
                </p>
                <p>{source.note}</p>
              </label>
            ))}
          </div>
        }
        cancelLabel="Close"
        confirmLabel="Continue to import"
        heading="Prepare a discovery file"
        modalSlug={modalSlug}
        onConfirm={() => undefined}
      />
    </div>
  )
}

export default ImportInstructions
