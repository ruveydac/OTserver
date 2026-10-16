'use client'

import { Banner, useConfig, useFormFields } from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { UIFieldClientComponent } from 'payload'
import './index.scss'

type Site = { id: string; name: string }
type Scanner = { id: string; enabled: boolean; enrolled: boolean }
type Overview = { controllerUrl?: string; sites?: Site[]; scanners?: Scanner[] }

const idOf = (value: unknown) => {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && 'value' in value) return String(value.value)
  return ''
}

const OtterManagedSettingsField: UIFieldClientComponent = () => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const [name, siteValue, scannerValue] = useFormFields(([fields]) => [
    fields.name?.value,
    fields.site?.value,
    fields.scanner?.value,
  ])
  const [overview, setOverview] = useState<Overview>({})
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const abort = new AbortController()
    void fetch(`${api}/otter/v1/overview`, { cache: 'no-store', signal: abort.signal })
      .then((response) => {
        if (!response.ok)
          throw new Error('Could not load managed settings. Reload this page to try again.')
        return response.json() as Promise<Overview>
      })
      .then(setOverview)
      .catch(() => {
        if (!abort.signal.aborted)
          setError('Could not load managed settings. Reload this page to try again.')
      })
      .finally(() => {
        if (!abort.signal.aborted) setLoading(false)
      })
    return () => abort.abort()
  }, [api])

  const siteID = idOf(siteValue)
  const scannerID = idOf(scannerValue)
  const siteName =
    overview.sites?.find((site) => site.id === siteID)?.name || siteID || 'Select a site'
  const scanner = overview.scanners?.find((item) => item.id === scannerID)
  const credential = !scanner
    ? 'Available after choosing a scanner'
    : !scanner.enabled
      ? 'Scanner is disabled'
      : scanner.enrolled
        ? 'Enrolled machine credential'
        : 'Awaiting enrollment'

  return (
    <section className="otter-managed-settings">
      <h3>Managed settings</h3>
      <p>
        These otter.json values are fixed by the controller and cannot be overridden by a scan
        configuration.
      </p>
      {loading ? (
        <p role="status">Loading managed settings…</p>
      ) : error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      <dl>
        <div>
          <dt>Configuration name</dt>
          <dd>{typeof name === 'string' ? name : 'Enter a configuration name'}</dd>
        </div>
        <div>
          <dt>Site</dt>
          <dd>{siteName}</dd>
        </div>
        <div>
          <dt>serverUrl</dt>
          <dd>
            {loading || error
              ? 'Unavailable'
              : overview.controllerUrl || 'Set OTSERVER_PUBLIC_URL on the OTserver deployment'}
          </dd>
        </div>
        <div>
          <dt>output</dt>
          <dd>Run-specific export in Otter’s private state directory</dd>
        </div>
        <div>
          <dt>apiKey</dt>
          <dd>
            {loading || error ? 'Scanner credential status unavailable' : credential}; scanner
            authentication is managed by OTserver
          </dd>
        </div>
      </dl>
    </section>
  )
}

export default OtterManagedSettingsField
