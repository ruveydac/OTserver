'use client'

import { Button, useListQuery, useSelection } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

import { whereToLucene } from '@/search/whereToLucene'

const AssetListInteractions = () => {
  const router = useRouter()
  const { query, refineListData } = useListQuery()
  const { count, getQueryParams, selectAll } = useSelection()
  const [actionsTarget, setActionsTarget] = useState<HTMLElement | null>(null)
  const luceneFilter = whereToLucene(query?.where)
  const hasGraphicalFilters = Boolean(query?.where && Object.keys(query.where).length)

  const downloadCSV = async () => {
    // getQueryParams() loses a typed Lucene search when selecting everything, so
    // send it directly; the placeholder where would mask the search hook instead.
    const params =
      selectAll === 'allAvailable' && !hasGraphicalFilters && query?.search
        ? `?search=${encodeURIComponent(query.search)}`
        : getQueryParams()
    const response = await fetch(`/api/assets/export-csv${params}`)
    if (!response.ok) return
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.download = 'assets.csv'
    link.href = url
    link.click()
    URL.revokeObjectURL(url)
  }

  useEffect(() => {
    if (!hasGraphicalFilters || (query.search ?? '') === luceneFilter) return
    void refineListData({ page: 1, search: luceneFilter || undefined })
  }, [hasGraphicalFilters, luceneFilter, query.search, refineListData])

  useEffect(() => {
    const search = document.querySelector<HTMLInputElement>(
      '.collection-list--assets #search-filter-input',
    )
    if (search) {
      search.ariaLabel = 'Lucene asset search and filter'
      search.placeholder = 'Lucene: status:online AND vendor:Siemens'
    }

    // ponytail: Payload has no row event hook; remove this delegate when it exposes one.
    const openAsset = (event: MouseEvent) => {
      if (!(event.target instanceof Element)) return
      if (event.target.closest('a, button, input, select, textarea, [role="button"]')) return

      const row = event.target.closest<HTMLTableRowElement>(
        '.collection-list--assets tbody tr[data-id]',
      )
      if (row?.dataset.id)
        router.push(`/admin/collections/assets/${encodeURIComponent(row.dataset.id)}`)
    }

    document.addEventListener('dblclick', openAsset)
    return () => document.removeEventListener('dblclick', openAsset)
  }, [router])

  // ponytail: Payload exposes no slot for custom selection-bar actions; portal into
  // the native bar and re-resolve the target when the bar appears or disappears.
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      const actions = document.querySelectorAll('.collection-list--assets .list-selection__actions')
      setActionsTarget(actions.length ? (actions[actions.length - 1] as HTMLElement) : null)
    })
    return () => cancelAnimationFrame(frame)
  }, [count])

  return (
    <>
      {count > 0 &&
        actionsTarget &&
        createPortal(
          <Button
            buttonStyle="none"
            className="list-selection__button asset-export-csv"
            onClick={() => void downloadCSV()}
          >
            Download CSV
          </Button>,
          actionsTarget,
        )}
      <p className="asset-search-help">
        Type Lucene directly or use <strong>Filters</strong> to build it graphically. Examples:{' '}
        <code>status:online AND vendor:Siemens</code>, <code>class:PLC</code>, or{' '}
        <code>osAccuracy:[80 TO 100]</code>.
      </p>
    </>
  )
}

export default AssetListInteractions
