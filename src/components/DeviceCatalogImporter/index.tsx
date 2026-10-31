'use client'

import { Button, useConfig } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useState, useSyncExternalStore, type FormEvent } from 'react'
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
  const [files, setFiles] = useState<File[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState('')
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
  return (
    <section className="device-catalog-importer">
      <h2>Import manufacturer and device JSON</h2>
      <p>
        No manufacturer or device data ships with the application. Import JSON to load the catalog
        into the database, where it is shared with workers. The complete catalog is limited to 6 MiB
        of compact JSON.
      </p>
      <p>
        Select one or several files together. Each file can contain one record or an array of
        records. IDs are the update key: existing records are replaced, new records are added, and
        absent records are kept.
      </p>
      <p>
        Manufacturer and device files can be mixed in one import. The entire selection is validated
        before saving. Existing class mappings and human assignments are preserved.
      </p>
      <form onSubmit={submit} aria-busy={busy}>
        <label htmlFor="device-catalog-files">JSON files (up to 50 files, 8 MiB total)</label>
        <input
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
          {busy ? 'Importing catalog…' : 'Import JSON files'}
        </Button>
      </form>
      {error ? <p role="alert">{error}</p> : null}
      <p role="status">
        {result ||
          (busy
            ? 'Validating and saving the selected files…'
            : files.length
              ? `${files.length} files selected.`
              : 'No files selected. Select JSON files to load or update the database catalog.')}
      </p>
    </section>
  )
}
