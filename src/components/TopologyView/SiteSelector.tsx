'use client'

import { useRouter } from 'next/navigation'

export const SiteSelector = ({
  adminRoute,
  filter,
  selectedSiteId,
  sites,
}: {
  adminRoute: string
  filter?: string
  selectedSiteId?: string
  sites: { id: string; name: string }[]
}) => {
  const router = useRouter()

  return (
    <div className="topology-view__selector">
      <label htmlFor="topology-site">Site</label>
      <select
        defaultValue={selectedSiteId ?? ''}
        id="topology-site"
        onChange={(event) => {
          const value = event.target.value
          router.push(
            value
              ? `${adminRoute}/topology?site=${value}${filter ? `&filter=${encodeURIComponent(filter)}` : ''}`
              : `${adminRoute}/topology`,
          )
        }}
      >
        <option value="">Choose a site…</option>
        {sites.map((site) => (
          <option key={site.id} value={site.id}>
            {site.name}
          </option>
        ))}
      </select>
      {selectedSiteId ? (
        <form action={`${adminRoute}/topology`} method="get">
          <input name="site" type="hidden" value={selectedSiteId} />
          <label htmlFor="topology-filter">Asset filter</label>
          <input
            defaultValue={filter}
            id="topology-filter"
            name="filter"
            placeholder="Name, IP, or MAC"
            type="search"
          />
          <button type="submit">Apply</button>
        </form>
      ) : null}
    </div>
  )
}
