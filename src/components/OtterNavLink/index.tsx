'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth, useConfig } from '@payloadcms/ui'

const OtterNavLink = () => {
  const pathname = usePathname()
  const { permissions } = useAuth()
  const {
    config: {
      routes: { admin },
    },
  } = useConfig()
  const href = `${admin}/otters`

  if (!permissions?.collections?.['otter-scanners']?.read) return null

  return (
    <Link className="nav__link otter-nav-link" href={href} prefetch={false}>
      {pathname === href ? <div className="nav__link-indicator" /> : null}
      <span className="nav__link-label">Manage Otters</span>
    </Link>
  )
}

export default OtterNavLink
