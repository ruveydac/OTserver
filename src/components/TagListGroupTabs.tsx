'use client'

import { useConfig, useListQuery } from '@payloadcms/ui'
import { useEffect, useState } from 'react'

import TagGroupTabs, { type TagGroupTabOption } from '@/components/TagGroupTabs'
import { filterTagsByGroup, selectedTagGroup } from '@/tags/grouping'

type TagGroup = TagGroupTabOption

export default function TagListGroupTabs() {
  const {
    config: {
      routes: { api },
    },
  } = useConfig()
  const { query, refineListData } = useListQuery()
  const [groups, setGroups] = useState<TagGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let mounted = true
    void fetch(`${api}/tag-groups?depth=0&limit=1000&pagination=false&sort=name`)
      .then(async (response) => {
        if (!response.ok) throw new Error()
        const result = (await response.json()) as { docs?: TagGroup[] }
        if (mounted) setGroups(result.docs || [])
      })
      .catch(() => {
        if (mounted) setError('Could not load tag groups.')
      })
      .finally(() => {
        if (mounted) setLoading(false)
      })
    return () => {
      mounted = false
    }
  }, [api])

  const tabs = [{ id: 'all', name: 'All tags' }, ...groups, { id: 'ungrouped', name: 'Ungrouped' }]
  const selected = selectedTagGroup(query.where)

  return (
    <div className="tag-list-group-tabs">
      <TagGroupTabs
        groups={tabs}
        label="Filter tags by group"
        onSelect={(id) =>
          void refineListData({ page: 1, where: filterTagsByGroup(query.where, id) })
        }
        selected={tabs.some(({ id }) => id === selected) ? selected : 'all'}
      />
      {loading ? <p role="status">Loading tag groups…</p> : null}
      {error ? <p role="alert">{error}</p> : null}
      {!loading && !error && !groups.length ? <p>No tag groups configured.</p> : null}
    </div>
  )
}
