import { DefaultListView } from '@payloadcms/ui'
import type { ListViewServerProps } from 'payload'
import OtterBulkUpdates from '@/components/OtterBulkUpdates'
import { forwardListViewProps } from '@/components/forwardListViewProps'

export default function OtterScannerListView(props: ListViewServerProps) {
  const listProps = forwardListViewProps(props)
  return (
    <DefaultListView
      {...listProps}
      beforeActions={[
        ...(listProps.beforeActions || []),
        <OtterBulkUpdates key="otter-bulk-updates" />,
      ]}
    />
  )
}
