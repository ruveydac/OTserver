'use client'

import { Button, useConfig } from '@payloadcms/ui'

export default function LogoutButton() {
  const {
    config: {
      routes: { admin },
    },
  } = useConfig()
  return (
    <Button buttonStyle="secondary" el="link" url={`${admin}/logout`}>
      Log out
    </Button>
  )
}
