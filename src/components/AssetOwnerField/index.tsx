'use client'

import { TextInput, useConfig, useField } from '@payloadcms/ui'
import type { TextFieldClientComponent } from 'payload'
import { useEffect, useId, useState, type ChangeEvent, type InputHTMLAttributes } from 'react'

type UserSuggestion = { email: string; name?: string | null }

const AssetOwnerField: TextFieldClientComponent = ({ field, path, readOnly }) => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { setValue, showError, value } = useField<string>({ path })
  const [suggestions, setSuggestions] = useState<UserSuggestion[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const listID = `asset-owner-${useId().replaceAll(':', '')}`
  const htmlAttributes: InputHTMLAttributes<HTMLInputElement> = { list: listID }

  useEffect(() => {
    const controller = new AbortController()
    const query = new URLSearchParams({
      depth: '0',
      limit: '1000',
      sort: 'name',
      'select[name]': 'true',
      'select[email]': 'true',
    })

    void fetch(`${api}/users?${query}`, {
      cache: 'no-store',
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error('Could not load user suggestions.')
        return response.json() as Promise<{ docs: UserSuggestion[] }>
      })
      .then(({ docs }) => setSuggestions(docs))
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === 'AbortError')) setError(true)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })

    return () => controller.abort()
  }, [api])

  return (
    <>
      <TextInput
        htmlAttributes={htmlAttributes}
        label={field.label}
        onChange={(event: ChangeEvent<HTMLInputElement>) => setValue(event.target.value)}
        path={path}
        placeholder={field.admin?.placeholder}
        readOnly={readOnly}
        required={field.required}
        showError={showError}
        value={value || ''}
      />
      <datalist id={listID}>
        {suggestions.map(({ email, name }) => {
          const userName = name?.trim()
          return (
            <option
              key={email}
              label={userName && userName !== email ? email : undefined}
              value={userName || email}
            />
          )
        })}
      </datalist>
      {loading ? <p role="status">Loading registered users…</p> : null}
      {error ? (
        <p role="status">User suggestions are unavailable. You can still enter free text.</p>
      ) : null}
      {!loading && !error && suggestions.length === 0 ? (
        <p role="status">No registered users are available as suggestions.</p>
      ) : null}
    </>
  )
}

export default AssetOwnerField
