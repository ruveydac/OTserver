'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useConfig } from '@payloadcms/ui'

import './index.scss'

export const TopologyNavLink = () => {
  const pathname = usePathname()
  const {
    config: {
      routes: { admin },
    },
  } = useConfig()

  const href = `${admin}/topology`
  const isActive = pathname === href

  return (
    <Link className="nav__link topology-nav-link" href={href} prefetch={false}>
      {isActive && <div className="nav__link-indicator" />}
      <span className="nav__link-label">Network topology</span>
    </Link>
  )
}

export default TopologyNavLink
