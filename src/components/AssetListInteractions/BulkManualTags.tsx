'use client'

import {
  Banner,
  Button,
  ConfirmationModal,
  useConfig,
  useModal,
  useSelection,
} from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'

type Tag = {
  id: string
  name: string
  color: string
  group?: { name?: string } | string | null
}

export default function BulkManualTags() {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { count, selectAll, selected } = useSelection()
  const { isModalOpen, openModal } = useModal()
  const router = useRouter()
  const modal = 'asset-bulk-manual-tags'
  const opened = isModalOpen(modal)
  const assetIDs = useMemo(
    () =>
      Object.entries(selected)
        .filter(([, value]) => value)
        .map(([id]) => id),
    [selected],
  )
  const [tags, setTags] = useState<Tag[]>([])
  const [tagIDs, setTagIDs] = useState<string[]>([])
  const [action, setAction] = useState<'add' | 'remove'>('add')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!opened) return
    const abort = new AbortController()
    void fetch(`${api}/tags?where[manual][equals]=true&limit=1000&depth=1&sort=name`, {
      cache: 'no-store',
      signal: abort.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not load manual tags.')
        return response.json() as Promise<{ docs?: Tag[] }>
      })
      .then(({ docs }) => setTags(Array.isArray(docs) ? docs : []))
      .catch((reason: unknown) => {
        if (!abort.signal.aborted)
          setError(reason instanceof Error ? reason.message : 'Could not load manual tags.')
      })
      .finally(() => {
        if (!abort.signal.aborted) setLoading(false)
      })
    return () => abort.abort()
  }, [api, opened])

  const save = async () => {
    if (busy || !assetIDs.length || assetIDs.length > 200) return
    if (!tagIDs.length) {
      setError('Select at least one manual tag.')
      return
    }
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const response = await fetch(`${api}/assets/bulk-tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, assetIDs, tagIDs }),
      })
      const result = (await response.json()) as {
        errors?: Array<{ message?: string }>
        message?: string
        updated?: number
      }
      if (!response.ok)
        throw new Error(result.errors?.[0]?.message || result.message || 'Could not update tags.')
      setMessage(
        `Updated manual tags on ${result.updated || 0} asset${result.updated === 1 ? '' : 's'}.`,
      )
      router.refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not update manual tags.')
    } finally {
      setBusy(false)
    }
  }

  if (!count) return null
  return (
    <>
      <Button
        buttonStyle="none"
        className="list-selection__button"
        disabled={selectAll === 'allAvailable' || assetIDs.length > 200}
        onClick={() => {
          setMessage('')
          setLoading(true)
          setError('')
          setTagIDs([])
          openModal(modal)
        }}
        type="button"
      >
        Set manual tags
      </Button>
      {selectAll === 'allAvailable' ? <span>Select individual assets to assign tags.</span> : null}
      {assetIDs.length > 200 ? <span>Bulk tag actions support up to 200 assets.</span> : null}
      {message ? <span role="status">{message}</span> : null}
      {error && !opened ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      <ConfirmationModal
        modalSlug={modal}
        heading="Set manual tags"
        confirmLabel={busy ? 'Saving…' : 'Apply tags'}
        cancelLabel="Cancel"
        onConfirm={save}
        body={
          <div className="asset-bulk-tags">
            <label>
              Action
              <select
                className="field-type__input"
                value={action}
                onChange={(event) => setAction(event.target.value as 'add' | 'remove')}
              >
                <option value="add">Add selected tags</option>
                <option value="remove">Remove selected tags</option>
              </select>
            </label>
            <p>
              {assetIDs.length} selected asset{assetIDs.length === 1 ? '' : 's'}
            </p>
            {loading ? <p role="status">Loading manual tags…</p> : null}
            {error && opened ? <p role="alert">{error}</p> : null}
            {!loading && !error && !tags.length ? <p>No manual tags are configured.</p> : null}
            {tags.map((tag) => (
              <label className="asset-bulk-tags__option" key={tag.id}>
                <input
                  type="checkbox"
                  checked={tagIDs.includes(tag.id)}
                  onChange={(event) =>
                    setTagIDs((current) =>
                      event.target.checked
                        ? [...current, tag.id]
                        : current.filter((id) => id !== tag.id),
                    )
                  }
                />
                <span
                  aria-hidden="true"
                  className="asset-view__tag-swatch"
                  style={{ backgroundColor: tag.color }}
                />
                {tag.name}
                {typeof tag.group === 'object' && tag.group?.name ? (
                  <small>{tag.group.name}</small>
                ) : null}
              </label>
            ))}
          </div>
        }
      />
    </>
  )
}
