'use client'

import { useRouter } from 'next/navigation'

export const SiteSelector = ({
  adminRoute,
  selectedSiteId,
  sites,
}: {
  adminRoute: string
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
          router.push(value ? `${adminRoute}/topology?site=${value}` : `${adminRoute}/topology`)
        }}
      >
        <option value="">Choose a site…</option>
        {sites.map((site) => (
          <option key={site.id} value={site.id}>
            {site.name}
          </option>
        ))}
      </select>
    </div>
  )
}
