import './index.scss'

import Link from 'next/link'

export default function LogoutButton() {
  return (
    <Link className="logout-button" href="/admin/logout" prefetch={false}>
      Log out
    </Link>
  )
}
