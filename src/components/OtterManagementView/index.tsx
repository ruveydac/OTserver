import type { AdminViewServerProps } from 'payload'
import { redirect } from 'next/navigation'

const OtterManagementView = async (props: AdminViewServerProps) => {
  redirect(`${props.payload.config.routes.admin}/collections/otter-scanners`)
}

export default OtterManagementView
