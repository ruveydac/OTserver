'use client'

import { Banner, FieldError, useConfig, useField } from '@payloadcms/ui'
import { useEffect, useState } from 'react'
import type { JSONFieldClientComponent } from 'payload'
import type { AssetField } from '@/payload-types'

import './index.scss'

type Definition = Pick<AssetField, 'description' | 'id' | 'label' | 'type'>

type Values = Record<string, boolean | number | string>

const CustomAssetFields: JSONFieldClientComponent = ({ field, path, readOnly }) => {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { setValue, value: storedValue } = useField<Values | null>({ path })
  const value = storedValue ?? {}
  const [definitions, setDefinitions] = useState<Definition[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()

    void fetch(`${api}/asset-fields?limit=1000&sort=label`, { signal: controller.signal })
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
  }, [api])

  const update = (id: string, nextValue: boolean | number | string | undefined) => {
    if (readOnly) return
    const next = { ...value }
    if (nextValue === undefined || nextValue === '') delete next[id]
    else next[id] = nextValue
    setValue(next)
  }

  const heading = typeof field.label === 'string' ? field.label : 'Custom fields'

  return (
    <fieldset className="custom-asset-fields" disabled={Boolean(readOnly)}>
      <legend>{heading}</legend>
      <FieldError path={path} />
      {loading ? <p role="status">Loading fields…</p> : null}
      {error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
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
                    aria-describedby={definition.description ? `${inputID}-description` : undefined}
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
                      aria-describedby={
                        definition.description ? `${inputID}-description` : undefined
                      }
                      id={inputID}
                      onChange={(event) => update(id, event.target.value)}
                      value={typeof fieldValue === 'string' ? fieldValue : ''}
                    />
                  ) : (
                    <input
                      aria-describedby={
                        definition.description ? `${inputID}-description` : undefined
                      }
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
              {definition.description ? (
                <small id={`${inputID}-description`}>{definition.description}</small>
              ) : null}
            </div>
          )
        })}
      </div>
    </fieldset>
  )
}

export default CustomAssetFields
