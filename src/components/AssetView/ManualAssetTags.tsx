'use client'

import { Banner, Button, ConfirmationModal, useConfig, useModal } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

import TagGroupTabs from '@/components/TagGroupTabs'
import { groupTags } from '@/tags/grouping'

export type ManualTagOption = {
  id: string
  name: string
  color: string
  group?: { id: string; name: string }
}

export default function ManualAssetTags({
  assetID,
  availableTags,
  manualTagIDs,
}: {
  assetID: string
  availableTags: ManualTagOption[]
  manualTagIDs: string[]
}) {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { openModal } = useModal()
  const router = useRouter()
  const modal = `asset-manual-tags-${assetID}`
  const [selected, setSelected] = useState(manualTagIDs)
  const [activeGroup, setActiveGroup] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const groups = groupTags(availableTags)
  const selectedGroup = groups.find(({ id }) => id === activeGroup) || groups[0]
  const save = async () => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`${api}/assets/${encodeURIComponent(assetID)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manualTags: selected }),
      })
      const result = (await response.json()) as {
        errors?: Array<{ message?: string }>
        message?: string
      }
      if (!response.ok)
        throw new Error(result.errors?.[0]?.message || result.message || 'Could not save tags.')
      router.refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not save manual tags.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        buttonStyle="secondary"
        className="asset-view__action"
        margin={false}
        onClick={() => {
          setSelected(manualTagIDs)
          setError('')
          setActiveGroup(groups[0]?.id || 'ungrouped')
          openModal(modal)
        }}
        size="medium"
        type="button"
      >
        Manage manual tags
      </Button>
      {error ? (
        <div role="alert">
          <Banner type="error">{error}</Banner>
        </div>
      ) : null}
      <ConfirmationModal
        modalSlug={modal}
        heading="Manage manual tags"
        confirmLabel={busy ? 'Saving…' : 'Save tags'}
        cancelLabel="Cancel"
        onConfirm={save}
        body={
          <fieldset disabled={busy} className="asset-manual-tags__list">
            <legend>Choose tags for this asset</legend>
            {groups.length ? (
              <>
                <TagGroupTabs
                  groups={groups}
                  label="Manual tag groups"
                  onSelect={setActiveGroup}
                  selected={selectedGroup?.id || ''}
                />
                <div aria-label={`${selectedGroup?.name} tags`} role="group">
                  {selectedGroup?.tags.map((tag) => (
                    <label className="asset-manual-tags__option" key={tag.id}>
                      <input
                        type="checkbox"
                        checked={selected.includes(tag.id)}
                        onChange={(event) =>
                          setSelected((currentIDs) =>
                            event.target.checked
                              ? [...new Set([...currentIDs, tag.id])]
                              : currentIDs.filter((id) => id !== tag.id),
                          )
                        }
                      />
                      <span>
                        <span
                          aria-hidden="true"
                          className="asset-view__tag-swatch"
                          style={{ backgroundColor: tag.color }}
                        />
                        {tag.name}
                      </span>
                    </label>
                  ))}
                </div>
              </>
            ) : (
              <p>No manual tags are configured.</p>
            )}
          </fieldset>
        }
      />
    </>
  )
}
