'use client'

import { Button, Link, TextInput, useAuth, useConfig } from '@payloadcms/ui'
import { useEffect, useRef, useState } from 'react'
import { Brand } from '@/components/Brand'
import type { Asset } from '@/payload-types'
import { assetSearchHints } from '@/search/assetSearchHints'

import './index.scss'

type Match = Pick<Asset, 'id' | 'name' | 'ipAddress' | 'site'>
type Preview = { docs?: Match[]; message?: string; invalid?: boolean }

export default function AssetSearchHeader() {
  const { permissions } = useAuth()
  const {
    config: {
      routes: { admin, api },
    },
  } = useConfig()
  return (
    <header className="asset-search-header">
      <Link href={admin} className="asset-search-header__home">
        <Brand alt="OTserver dashboard" />
      </Link>
      {permissions?.collections?.assets?.read && <AssetSearch admin={admin} api={api} />}
      <a
        className="asset-search-header__help"
        href="https://www.otserver.org/docs/"
        aria-label="OTserver documentation"
        title="OTserver documentation"
      >
        ?
      </a>
    </header>
  )
}

function AssetSearch({ admin, api }: { admin: string; api: string }) {
  const input = useRef<HTMLInputElement>(null!)
  const submitAfterPreview = useRef(false)
  const [query, setQuery] = useState('')
  const [caret, setCaret] = useState(0)
  const [open, setOpen] = useState(false)
  const [preview, setPreview] = useState<Preview>()
  const { suggestions, hint } = assetSearchHints(query, caret)
  const list = `${admin}/collections/assets`

  useEffect(() => {
    const term = query.trim()
    if (!open || !term || hint) return
    const controller = new AbortController()
    const timer = setTimeout(async () => {
      const params = new URLSearchParams({
        search: term,
        limit: '3',
        pagination: 'false',
        depth: '1',
        'select[name]': 'true',
        'select[ipAddress]': 'true',
        'select[site]': 'true',
        'populate[sites][path]': 'true',
        'populate[sites][name]': 'true',
      })
      try {
        const response = await fetch(`${api}/assets?${params}`, {
          cache: 'no-store',
          signal: controller.signal,
        })
        const data = await response.json()
        if (controller.signal.aborted) return
        if (response.ok) setPreview({ docs: data.docs })
        else if (response.status === 400) {
          setPreview({
            invalid: true,
            message: data.errors?.[0]?.message || 'Invalid asset search.',
          })
          submitAfterPreview.current = false
        } else throw new Error()
      } catch {
        if (controller.signal.aborted) return
        setPreview({ message: 'Could not load asset previews.' })
      }
      if (submitAfterPreview.current) {
        submitAfterPreview.current = false
        input.current?.form?.submit()
      }
    }, 250)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [api, hint, open, query])

  const message = hint || preview?.message || (query.trim() && !preview ? 'Searching assets…' : '')
  const attributes = {
    autoComplete: 'off',
    name: 'search',
    'aria-label': 'Search assets',
    'aria-describedby': open ? 'header-search-status' : undefined,
    onFocus: () => setOpen(true),
    onClick: () => setOpen(true),
    onSelect: () => setCaret(input.current?.selectionStart ?? query.length),
  }
  return (
    <form
      action={list}
      aria-label="Search assets"
      method="get"
      role="search"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) {
          submitAfterPreview.current = false
          setOpen(false)
          setPreview(undefined)
        }
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          submitAfterPreview.current = false
          input.current?.focus()
          setOpen(false)
          setPreview(undefined)
        }
      }}
      onSubmit={(event) => {
        if (hint || preview?.invalid || (query.trim() && !preview)) {
          event.preventDefault()
          submitAfterPreview.current = !hint && !preview
          input.current?.focus()
          setOpen(true)
        }
      }}
    >
      <TextInput
        hasMany={false}
        path="header-asset-search"
        placeholder="Search assets"
        htmlAttributes={attributes}
        inputRef={input}
        value={query}
        onChange={(event) => {
          submitAfterPreview.current = false
          setQuery(event.target.value)
          setCaret(event.target.selectionStart ?? event.target.value.length)
          setPreview(undefined)
          setOpen(true)
        }}
      />
      <Button type="submit" buttonStyle="secondary">
        Search
      </Button>
      {open && (
        <div className="asset-search-header__panel">
          <div id="header-search-status" role="status">
            {message ||
              (preview?.docs &&
                (preview.docs.length
                  ? `Matching assets: ${preview.docs.length} shown`
                  : 'No matching assets.'))}
          </div>
          {!!preview?.docs?.length && (
            <ul aria-label="Matching assets">
              {preview.docs.map((asset) => (
                <li key={asset.id}>
                  <Link href={`${list}/${encodeURIComponent(asset.id)}`} prefetch={false}>
                    <strong>{asset.name}</strong>
                    <span>
                      {[
                        asset.site &&
                          typeof asset.site === 'object' &&
                          (asset.site.path || asset.site.name),
                        asset.ipAddress,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
          {suggestions.length > 0 && (
            <div className="asset-search-header__filters">
              <span>Suggested filters</span>
              {suggestions.map((suggestion) => (
                <Button
                  key={suggestion.field}
                  type="button"
                  buttonStyle="pill"
                  onClick={() => {
                    submitAfterPreview.current = false
                    setQuery(suggestion.query)
                    setCaret(suggestion.caret)
                    if (suggestion.query !== query) setPreview(undefined)
                    input.current?.focus()
                    requestAnimationFrame(() =>
                      input.current?.setSelectionRange(suggestion.caret, suggestion.caret),
                    )
                  }}
                >
                  {suggestion.field}:
                </Button>
              ))}
            </div>
          )}
        </div>
      )}
    </form>
  )
}
