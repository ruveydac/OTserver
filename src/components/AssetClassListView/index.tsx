import { DefaultListView } from '@payloadcms/ui'
import type { ListViewServerProps } from 'payload'
import { forwardListViewProps } from '@/components/forwardListViewProps'

export default function AssetClassListView(props: ListViewServerProps) {
  return <DefaultListView {...forwardListViewProps(props)} />
}
