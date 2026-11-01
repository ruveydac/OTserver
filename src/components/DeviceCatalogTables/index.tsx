'use client'

import { Pagination, PerPage, Table, useField } from '@payloadcms/ui'
import type { ClientField, UIFieldClientComponent } from 'payload'
import { useState } from 'react'

import './index.scss'

type Entry = {
  id?: string
  data?: Record<string, unknown>
  [key: string]: unknown
}

type Catalog = {
  devices?: Entry[]
  manufacturers?: Entry[]
}

const PAGE_LIMITS = [5, 10, 25, 50, 100]
const DEFAULT_LIMIT = 10

const dataOf = (entry: Entry) =>
  entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {}

const labelFor = (key: string) =>
  key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/\bUrl\b/g, 'URL')
    .replace(/\bId\b/g, 'ID')
    .replace(/\bHq\b/g, 'HQ')

const safeURL = (value: string) => {
  try {
    const url = new URL(value)
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password
      ? url.href
      : undefined
  } catch {
    return undefined
  }
}

const renderValue = (key: string, value: unknown) => {
  if (value === undefined || value === null || value === '') return '—'
  if (typeof value === 'string') {
    const href = /url|website/i.test(key) ? safeURL(value) : undefined
    return href ? (
      <a href={href} target="_blank" rel="noopener noreferrer">
        {value}
      </a>
    ) : (
      value
    )
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value) && value.every((item) => typeof item !== 'object'))
    return value.length ? value.map(String).join(', ') : '—'
  const entries = Array.isArray(value) ? value : [value]
  return (
    <details>
      <summary>
        {Array.isArray(value)
          ? `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`
          : 'Details'}
      </summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  )
}

const columnsFor = (rows: Entry[], leading: string[] = []) => {
  const keys = new Set(['id', ...leading])
  for (const row of rows) for (const key of Object.keys(dataOf(row))) keys.add(key)
  for (const row of rows)
    for (const key of Object.keys(row)) if (key !== 'id' && key !== 'data') keys.add(key)
  return [...keys]
}

const CatalogTable = ({ rows, leading }: { rows: Entry[]; leading?: string[] }) => {
  const [limit, setLimit] = useState(DEFAULT_LIMIT)
  const [page, setPage] = useState(1)
  const columns = columnsFor(rows, leading)
  const totalPages = Math.max(1, Math.ceil(rows.length / limit))
  const currentPage = Math.min(page, totalPages)
  const visibleRows = rows.slice((currentPage - 1) * limit, currentPage * limit)
  const tableColumns = columns.map((column) => ({
    accessor: column,
    active: true,
    Heading: labelFor(column),
    field: { name: column, type: 'text' } as ClientField,
    renderedCells: visibleRows.map((row) => {
      const data = dataOf(row)
      return renderValue(column, column in data ? data[column] : row[column])
    }),
  }))

  return (
    <>
      <Table appearance="condensed" columns={tableColumns} data={visibleRows} />
      <div className="page-controls">
        <Pagination
          hasNextPage={currentPage < totalPages}
          hasPrevPage={currentPage > 1}
          nextPage={currentPage + 1}
          onChange={setPage}
          page={currentPage}
          prevPage={currentPage - 1}
          totalPages={totalPages}
        />
        <div className="page-controls__page-info">
          {`${(currentPage - 1) * limit + 1}–${Math.min(currentPage * limit, rows.length)} of ${rows.length}`}
        </div>
        <PerPage
          handleChange={(value) => {
            setLimit(value)
            setPage(1)
          }}
          limit={limit}
          limits={PAGE_LIMITS}
        />
      </div>
    </>
  )
}

const labelOf = (entry: Entry) => String(entry.id ?? '')

const DeviceCatalogTables: UIFieldClientComponent = () => {
  const { value } = useField<Catalog | null>({ path: 'catalog' })
  const catalog = value ?? {}
  const manufacturers = [...(catalog.manufacturers ?? [])].sort((a, b) =>
    String(dataOf(a).name ?? labelOf(a)).localeCompare(String(dataOf(b).name ?? labelOf(b))),
  )
  const names = new Map(manufacturers.map((entry) => [entry.id, String(dataOf(entry).name ?? '')]))
  const devices = [...(catalog.devices ?? [])].sort(
    (a, b) =>
      (names.get(String(a.manufacturer_id)) ?? '').localeCompare(
        names.get(String(b.manufacturer_id)) ?? '',
      ) || String(dataOf(a).model ?? '').localeCompare(String(dataOf(b).model ?? '')),
  )

  if (!manufacturers.length && !devices.length)
    return <p className="device-catalog-tables__empty">No manufacturer or device data imported.</p>

  return (
    <div className="device-catalog-tables">
      <section className="device-catalog-tables__section">
        <h2>
          Manufacturers <span className="device-catalog-tables__count">{manufacturers.length}</span>
        </h2>
        {manufacturers.length ? (
          <CatalogTable rows={manufacturers} />
        ) : (
          <p>No manufacturers imported.</p>
        )}
      </section>
      <section className="device-catalog-tables__section">
        <h2>
          Devices <span className="device-catalog-tables__count">{devices.length}</span>
        </h2>
        {devices.length ? (
          <CatalogTable leading={['manufacturer_id', 'device_type_id']} rows={devices} />
        ) : (
          <p>No devices imported.</p>
        )}
      </section>
    </div>
  )
}

export default DeviceCatalogTables
