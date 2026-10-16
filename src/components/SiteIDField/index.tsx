'use client'

import { CopyToClipboard, useDocumentInfo } from '@payloadcms/ui'

import './index.scss'

const SiteIDField = () => {
  const { id } = useDocumentInfo()
  if (id === null || id === undefined) return null

  const siteID = String(id)

  return (
    <div className="site-id-field">
      <span>Site ID</span>
      <div className="site-id-field__value">
        <code>{siteID}</code>
        <CopyToClipboard
          defaultMessage="Copy site ID"
          successMessage="Site ID copied"
          value={siteID}
        />
      </div>
      <p>Use this ID for OTserver Otter direct or automatic imports into this site.</p>
    </div>
  )
}

export default SiteIDField
