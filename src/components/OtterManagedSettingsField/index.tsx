'use client'

import { useFormFields } from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { UIFieldClientComponent } from 'payload'

type Site = { id: string; name: string }
type Scanner = { id: string; enabled: boolean; enrolled: boolean }
type Overview = { controllerUrl?: string; sites?: Site[]; scanners?: Scanner[] }

const idOf = (value: unknown) => {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && 'value' in value) return String(value.value)
  return ''
}

const OtterManagedSettingsField: UIFieldClientComponent = () => {
  const [name, siteValue, scannerValue] = useFormFields(([fields]) => [
    fields.name?.value,
    fields.site?.value,
    fields.scanner?.value,
  ])
  const [overview, setOverview] = useState<Overview>({})

  useEffect(() => {
    const abort = new AbortController()
    void fetch('/api/otter/v1/overview', { cache: 'no-store', signal: abort.signal })
      .then((response) => (response.ok ? (response.json() as Promise<Overview>) : {}))
      .then(setOverview)
      .catch(() => undefined)
    return () => abort.abort()
  }, [])

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
        profile.
      </p>
      <dl>
        <div>
          <dt>Profile name</dt>
          <dd>{typeof name === 'string' ? name : 'Enter a profile name'}</dd>
        </div>
        <div>
          <dt>Site</dt>
          <dd>{siteName}</dd>
        </div>
        <div>
          <dt>serverUrl</dt>
          <dd>{overview.controllerUrl || 'Set OTSERVER_PUBLIC_URL on the OTserver deployment'}</dd>
        </div>
        <div>
          <dt>output</dt>
          <dd>Run-specific export in Otter’s private state directory</dd>
        </div>
        <div>
          <dt>apiKey</dt>
          <dd>{credential}; scanner authentication is managed by OTserver</dd>
        </div>
      </dl>
    </section>
  )
}

export default OtterManagedSettingsField
