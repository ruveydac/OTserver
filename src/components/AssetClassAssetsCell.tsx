import Link from 'next/link'
import type { DefaultServerCellComponentProps } from 'payload'
import { assetListURL } from '@/components/assetListURL'

export default function AssetClassAssetsCell({
  payload,
  rowData,
}: DefaultServerCellComponentProps) {
  const id: unknown = rowData.id
  if (typeof id !== 'string' && typeof id !== 'number') return null

  return <Link href={assetListURL(payload.config.routes.admin, 'assetClass', id)}>View assets</Link>
}
