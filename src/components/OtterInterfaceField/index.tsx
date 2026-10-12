'use client'

import {
  FieldError,
  FieldLabel,
  ReactSelect,
  TextInput,
  useDocumentInfo,
  useField,
  useFormFields,
} from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { ChangeEvent } from 'react'
import type { TextFieldClientComponent } from 'payload'

type Adapter = {
  name: string
  friendlyName: string
  description: string
  macAddress?: string
  ipAddresses: string[]
}

const OtterInterfaceField: TextFieldClientComponent = ({ field, path }) => {
  const { setValue, value } = useField<string>({ path })
  const { id, collectionSlug } = useDocumentInfo()
  const scanner = useFormFields(([fields]) => fields.scanner?.value)
  const scannerID =
    collectionSlug === 'otter-scanners'
      ? String(id || '')
      : typeof scanner === 'string'
        ? scanner
        : scanner && typeof scanner === 'object' && 'value' in scanner
          ? String(scanner.value)
          : ''
  const [inventory, setInventory] = useState<{ scannerID: string; adapters: Adapter[] }>()

  useEffect(() => {
    if (!scannerID) return
    const abort = new AbortController()
    void fetch('/api/otter/v1/overview', { cache: 'no-store', signal: abort.signal })
      .then((response) =>
        response.ok
          ? (response.json() as Promise<{
              scanners?: Array<{ id: string; networkAdapters?: Adapter[] }>
            }>)
          : null,
      )
      .then((overview) =>
        setInventory({
          scannerID,
          adapters:
            overview?.scanners?.find((entry) => entry.id === scannerID)?.networkAdapters || [],
        }),
      )
      .catch(() => setInventory({ scannerID, adapters: [] }))
    return () => abort.abort()
  }, [scannerID])

  const adapters = inventory?.scannerID === scannerID ? inventory.adapters : []
  const options = adapters.map((adapter) => ({
    value: adapter.name,
    label: `${adapter.friendlyName} · ${adapter.ipAddresses.join(', ') || 'no IP'} · ${adapter.macAddress || 'no MAC'}`,
  }))
  if (value && !options.some((option) => option.value === value))
    options.unshift({ value, label: `${value} · not currently reported by scanner` })
  const selected = options.find((option) => option.value === value)
  const selectedAdapter = adapters.find((adapter) => adapter.name === value)

  return (
    <div className="field-type text otter-interface-field">
      <FieldLabel
        label={field.label || 'Network interface'}
        path={path}
        required={field.required}
      />
      {options.length ? (
        <ReactSelect
          isClearable
          onChange={(option) =>
            setValue(
              Array.isArray(option)
                ? ''
                : typeof option === 'object' && option
                  ? String(option.value)
                  : '',
            )
          }
          options={options}
          placeholder="Choose a reported network adapter"
          value={selected}
        />
      ) : null}
      <TextInput
        path={path}
        placeholder="e.g. eth0 or Ethernet adapter identifier"
        value={value || ''}
        onChange={(event: ChangeEvent<HTMLInputElement>) => setValue(event.target.value)}
      />
      <FieldError path={path} />
      {selectedAdapter ? (
        <p className="field-description">
          {selectedAdapter.description} · {selectedAdapter.name} ·{' '}
          {selectedAdapter.macAddress || 'MAC not reported'} ·{' '}
          {selectedAdapter.ipAddresses.join(', ') || 'No IP addresses'}
        </p>
      ) : (
        <p className="field-description">
          {value
            ? 'The selected adapter is not currently reported; its name is preserved.'
            : options.length
              ? 'Choose a reported adapter or enter its technical name.'
              : 'Enroll the scanner to select a reported adapter, or enter its technical name.'}
        </p>
      )}
    </div>
  )
}

export default OtterInterfaceField
