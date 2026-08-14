'use client'

import { useListQuery } from '@payloadcms/ui'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

import { whereToLucene } from '@/search/whereToLucene'

const AssetListInteractions = () => {
  const router = useRouter()
  const { query, refineListData } = useListQuery()
  const luceneFilter = whereToLucene(query?.where)
  const hasGraphicalFilters = Boolean(query?.where && Object.keys(query.where).length)

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

  return (
    <p className="asset-search-help">
      Type Lucene directly or use <strong>Filters</strong> to build it graphically. Examples:{' '}
      <code>status:online AND vendor:Siemens</code>, <code>class:PLC</code>, or{' '}
      <code>osAccuracy:[80 TO 100]</code>.
    </p>
  )
}

export default AssetListInteractions
