'use client'

import { useField } from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { JSONFieldClientComponent } from 'payload'

import './index.scss'

type Definition = {
  description?: null | string
  id: number | string
  label: string
  type: 'checkbox' | 'date' | 'number' | 'text' | 'textarea'
}

type Values = Record<string, boolean | number | string>

const CustomAssetFields: JSONFieldClientComponent = ({ field, path }) => {
  const { setValue, value = {} } = useField<Values>({ path })
  const [definitions, setDefinitions] = useState<Definition[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()

    void fetch('/api/asset-fields?limit=1000&sort=label', { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('Could not load custom asset fields.')
        return response.json() as Promise<{ docs: Definition[] }>
      })
      .then(({ docs }) => setDefinitions(docs))
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === 'AbortError')) {
          setError(reason instanceof Error ? reason.message : 'Could not load custom asset fields.')
        }
      })
      .finally(() => setLoading(false))

    return () => controller.abort()
  }, [])

  const update = (id: string, nextValue: boolean | number | string | undefined) => {
    const next = { ...value }
    if (nextValue === undefined || nextValue === '') delete next[id]
    else next[id] = nextValue
    setValue(next)
  }

  const heading = typeof field.label === 'string' ? field.label : 'Custom fields'

  return (
    <fieldset className="custom-asset-fields">
      <legend>{heading}</legend>
      {loading ? <p>Loading fields…</p> : null}
      {error ? <p className="custom-asset-fields__error">{error}</p> : null}
      {!loading && !error && !definitions.length ? (
        <p>No custom fields have been configured.</p>
      ) : null}

      <div className="custom-asset-fields__grid">
        {definitions.map((definition) => {
          const id = String(definition.id)
          const inputID = `${path}-${id}`
          const fieldValue = value[id]

          return (
            <div
              className={
                definition.type === 'textarea'
                  ? 'custom-asset-fields__field custom-asset-fields__field--wide'
                  : 'custom-asset-fields__field'
              }
              key={id}
            >
              {definition.type === 'checkbox' ? (
                <label className="custom-asset-fields__checkbox" htmlFor={inputID}>
                  <input
                    checked={fieldValue === true}
                    id={inputID}
                    onChange={(event) => update(id, event.target.checked)}
                    type="checkbox"
                  />
                  <span>{definition.label}</span>
                </label>
              ) : (
                <>
                  <label htmlFor={inputID}>{definition.label}</label>
                  {definition.type === 'textarea' ? (
                    <textarea
                      id={inputID}
                      onChange={(event) => update(id, event.target.value)}
                      value={typeof fieldValue === 'string' ? fieldValue : ''}
                    />
                  ) : (
                    <input
                      id={inputID}
                      onChange={(event) =>
                        update(
                          id,
                          definition.type === 'number' && event.target.value
                            ? Number(event.target.value)
                            : event.target.value,
                        )
                      }
                      type={definition.type}
                      value={
                        typeof fieldValue === 'number' || typeof fieldValue === 'string'
                          ? fieldValue
                          : ''
                      }
                    />
                  )}
                </>
              )}
              {definition.description ? <small>{definition.description}</small> : null}
            </div>
          )
        })}
      </div>
    </fieldset>
  )
}

export default CustomAssetFields
