'use client'

import { useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'

export default function IdentityActions({
  assetID,
  apiRoute,
  endpoints,
  identifiers,
  targets,
  sites,
}: {
  assetID: string
  apiRoute: string
  endpoints: { id: string; label: string }[]
  identifiers: { id: string; label: string }[]
  targets: { id: string; label: string }[]
  sites: { id: string; label: string }[]
}) {
  const [action, setAction] = useState('merge')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const router = useRouter()
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`${apiRoute}/assets/${assetID}/identity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          reason: data.get('reason'),
          target: data.get('target'),
          site: data.get('site'),
          endpoint: data.get('endpoint'),
          endpoints: data.getAll('endpoints'),
          identifiers: data.getAll('identifiers'),
          name: data.get('name'),
        }),
      })
      const body = await response.json()
      if (!response.ok)
        throw new Error(body.errors?.[0]?.message || body.message || 'Identity action failed.')
      router.refresh()
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Identity action failed.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="device-identity__actions">
      <summary>Reconcile identity or lifecycle</summary>
      <form onSubmit={submit}>
        <label>
          Action
          <select value={action} onChange={(event) => setAction(event.target.value)}>
            <option value="merge">Merge into another asset</option>
            <option value="split">Split selected endpoints</option>
            <option value="replace">Confirm hardware replacement</option>
            <option value="transfer">Transfer to another site</option>
            <option value="retire">Retire hardware</option>
            <option value="restore">Restore hardware</option>
            <option value="close-endpoint">Close endpoint association</option>
          </select>
        </label>
        {['merge', 'replace', 'split'].includes(action) ? (
          <label>
            Target asset
            <select name="target" required={action !== 'split'}>
              <option value="">
                {action === 'split' ? 'Create a new provisional asset' : 'Select an asset'}
              </option>
              {targets.map(({ id, label }) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {action === 'split' ? (
          <>
            <label>
              New asset name
              <input name="name" />
            </label>
            <fieldset>
              <legend>Move endpoints</legend>
              {endpoints.map(({ id, label }) => (
                <label key={id}>
                  <input type="checkbox" name="endpoints" value={id} />
                  {label}
                </label>
              ))}
            </fieldset>
            <fieldset>
              <legend>Move hardware identifiers</legend>
              {identifiers.map(({ id, label }) => (
                <label key={id}>
                  <input type="checkbox" name="identifiers" value={id} />
                  {label}
                </label>
              ))}
            </fieldset>
          </>
        ) : null}
        {action === 'close-endpoint' ? (
          <label>
            Endpoint
            <select name="endpoint" required>
              <option value="">Select an endpoint</option>
              {endpoints.map(({ id, label }) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {action === 'transfer' ? (
          <label>
            Destination site
            <select name="site" required>
              <option value="">Select a site</option>
              {sites.map(({ id, label }) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <label>
          Reason
          <textarea name="reason" required maxLength={2000} />
        </label>
        <button disabled={busy} type="submit">
          {busy ? 'Applying…' : 'Apply identity action'}
        </button>
        {error ? <p role="alert">{error}</p> : null}
      </form>
    </details>
  )
}
