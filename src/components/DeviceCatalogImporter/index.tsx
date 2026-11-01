'use client'

import { Button, Gutter, useConfig } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react'
import './index.scss'

const subscribe = () => () => {}

export default function DeviceCatalogImporter() {
  const { config } = useConfig()
  const router = useRouter()
  const ready = useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  )
  const [opened, setOpened] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    setResult('')
    try {
      if (
        !files.length ||
        files.length > 50 ||
        files.reduce((sum, file) => sum + file.size, 0) > 8 * 1024 * 1024
      )
        throw new Error('Select 1 to 50 JSON files, up to 8 MiB in total.')
      const contents = await Promise.all(
        files.map(async (file) => {
          try {
            return { name: file.name, content: JSON.parse(await file.text()) }
          } catch {
            throw new Error(`${file.name}: invalid JSON.`)
          }
        }),
      )
      const response = await fetch(`${config.routes.api}/device-catalog/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: contents }),
      })
      const data = await response.json()
      if (!response.ok)
        throw new Error(
          data.errors?.[0]?.message || 'Catalog import failed. No records were changed.',
        )
      setResult(
        `Manufacturers: ${data.manufacturers.added} added, ${data.manufacturers.updated} updated, ${data.manufacturers.unchanged} unchanged. Devices: ${data.devices.added} added, ${data.devices.updated} updated, ${data.devices.unchanged} unchanged. ${data.changed ? 'Background reclassification queued.' : 'Catalog already up to date.'}`,
      )
      router.refresh()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Catalog import failed.')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (opened) fileInput.current?.focus()
  }, [opened])

  return (
    <Gutter className="device-catalog-importer">
      <div className="device-catalog-importer__buttons">
        <Button
          type="button"
          buttonStyle="secondary"
          extraButtonProps={{
            'aria-controls': 'device-catalog-import',
            'aria-expanded': opened,
          }}
          onClick={() => setOpened(!opened)}
        >
          Import JSON files
        </Button>
      </div>
      {busy || result ? (
        <p role="status" aria-live="polite">
          {busy ? 'Validating and saving the selected files…' : result}
        </p>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      {opened ? (
        <form
          id="device-catalog-import"
          className="device-catalog-importer__form"
          aria-busy={busy}
          onSubmit={submit}
        >
          <label htmlFor="device-catalog-files">JSON files (up to 50 files, 8 MiB total)</label>
          <input
            ref={fileInput}
            id="device-catalog-files"
            type="file"
            accept=".json,application/json"
            multiple
            disabled={!ready || busy}
            onChange={(event) => {
              setFiles(Array.from(event.target.files || []))
              setError('')
              setResult('')
            }}
          />
          <Button type="submit" disabled={!ready || busy || !files.length}>
            {busy ? 'Importing catalog…' : 'Import selected files'}
          </Button>
        </form>
      ) : null}
    </Gutter>
  )
}
