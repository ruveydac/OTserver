'use client'

import { SelectInput, useConfig, useField } from '@payloadcms/ui'
import type { TextFieldClientComponent } from 'payload'
import { useEffect, useState } from 'react'

import { tagRuleFieldOptions, type CustomTagRuleField } from '@/tags/fields'

const TagRuleField: TextFieldClientComponent = ({ field, path, readOnly }) => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { setValue, showError, value: storedValue } = useField<string>({ path })
  const [customFields, setCustomFields] = useState<CustomTagRuleField[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const value = typeof storedValue === 'string' ? storedValue : ''
  const options = tagRuleFieldOptions(customFields, field.name !== 'compareField')

  useEffect(() => {
    const controller = new AbortController()

    void fetch(`${api}/asset-fields?limit=1000&sort=label`, {
      cache: 'no-store',
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error('Could not load custom asset fields.')
        return response.json() as Promise<{ docs: CustomTagRuleField[] }>
      })
      .then(({ docs }) => setCustomFields(docs))
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
      <SelectInput
        description={field.admin?.description}
        isClearable={!field.required}
        label={field.label}
        name={path}
        onChange={(selected) => setValue(Array.isArray(selected) ? '' : selected?.value || '')}
        options={options}
        path={path}
        placeholder="Select a field"
        readOnly={readOnly}
        required={field.required}
        showError={showError}
        value={value}
      />
      {loading ? <p role="status">Loading available fields…</p> : null}
      {error ? (
        <p role="alert">
          Custom asset fields could not be loaded. Other field choices remain available.
        </p>
      ) : null}
    </>
  )
}

export default TagRuleField
