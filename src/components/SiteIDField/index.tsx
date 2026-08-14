'use client'

import { CopyToClipboard, useDocumentInfo } from '@payloadcms/ui'

import './index.scss'

const SiteIDField = () => {
  const { id } = useDocumentInfo()
  if (id === null || id === undefined) return null

  const siteID = String(id)

  return (
    <div className="site-id-field">
      <label>Site ID</label>
      <div className="site-id-field__value">
        <code>{siteID}</code>
        <CopyToClipboard
          defaultMessage="Copy Site ID"
          successMessage="Site ID copied"
          value={siteID}
        />
      </div>
      <p>Use this ID for OTserver Scanner direct or automatic imports into this site.</p>
    </div>
  )
}

export default SiteIDField
