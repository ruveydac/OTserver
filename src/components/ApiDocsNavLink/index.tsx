'use client'

import { NavGroup, useConfig } from '@payloadcms/ui'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

const ApiDocsNavLink = () => {
  const pathname = usePathname()
  const {
    config: {
      routes: { admin },
    },
  } = useConfig()
  const href = `${admin}/api-docs`

  return (
    <NavGroup label="Documentation">
      <Link className="nav__link" href={href} prefetch={false}>
        {pathname === href && <div className="nav__link-indicator" />}
        <span className="nav__link-label">API documentation</span>
      </Link>
    </NavGroup>
  )
}

export default ApiDocsNavLink
