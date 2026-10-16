'use client'

import {
  Banner,
  ReactSelect,
  TextInput,
  useDocumentInfo,
  useField,
  useFormFields,
  useConfig,
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

const OtterInterfaceField: TextFieldClientComponent = ({ field, path, readOnly }) => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
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
  const [inventory, setInventory] = useState<{
    scannerID: string
    adapters: Adapter[]
    error?: string
  }>()
  const inventoryError = inventory?.scannerID === scannerID ? inventory.error : undefined

  useEffect(() => {
    if (!scannerID) return
    const abort = new AbortController()
    void fetch(`${api}/otter/v1/scanners/${encodeURIComponent(scannerID)}`, {
      cache: 'no-store',
      signal: abort.signal,
    })
      .then((response) => {
        if (!response.ok)
          throw new Error(
            'Could not load scanner adapters. Enter the technical name or reload this page to try again.',
          )
        return response.json() as Promise<{ networkAdapters?: Adapter[] }>
      })
      .then((scanner) =>
        setInventory({
          scannerID,
          adapters: scanner?.networkAdapters || [],
        }),
      )
      .catch(() => {
        if (!abort.signal.aborted) {
          setInventory({
            scannerID,
            adapters: [],
            error:
              'Could not load scanner adapters. Enter the technical name or reload this page to try again.',
          })
        }
      })
    return () => abort.abort()
  }, [api, scannerID])

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
      {scannerID && inventory?.scannerID !== scannerID ? (
        <p role="status">Loading scanner adapters…</p>
      ) : null}
      {inventoryError ? (
        <div role="alert">
          <Banner type="error">{inventoryError}</Banner>
        </div>
      ) : null}
      {options.length ? (
        <ReactSelect
          disabled={readOnly}
          inputId={`${path}-adapter`}
          aria-label="Reported network adapter"
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
          placeholder="Select a reported network adapter"
          value={selected}
        />
      ) : null}
      <TextInput
        label={field.label || 'Network interface'}
        required={field.required}
        readOnly={readOnly}
        path={path}
        placeholder="e.g. eth0 or Ethernet adapter identifier"
        value={value || ''}
        onChange={(event: ChangeEvent<HTMLInputElement>) => setValue(event.target.value)}
      />
      {selectedAdapter ? (
        <p className="field-description">
          {selectedAdapter.description} · {selectedAdapter.name} ·{' '}
          {selectedAdapter.macAddress || 'MAC not reported'} ·{' '}
          {selectedAdapter.ipAddresses.join(', ') || 'No IP addresses'}
        </p>
      ) : inventoryError || (scannerID && inventory?.scannerID !== scannerID) ? null : (
        <p className="field-description">
          {value
            ? 'The selected adapter is not currently reported; its name is preserved.'
            : options.length
              ? 'Select a reported adapter or enter its technical name.'
              : scannerID
                ? 'No adapters have been reported. Enter the adapter’s technical name or wait for the scanner to report its inventory.'
                : 'Select a scanner to load its reported adapters, or enter a technical name.'}
        </p>
      )}
      <p className="field-description">
        Layer-2 capture and ARP/DCP use this adapter. TCP/UDP, SNMP, and other native IP probes use
        the operating system route table; configure host routes for multi-homed scanners.
      </p>
    </div>
  )
}

export default OtterInterfaceField
