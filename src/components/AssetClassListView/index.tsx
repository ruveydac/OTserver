import { DefaultListView } from '@payloadcms/ui'
import Link from 'next/link'
import type { ListViewClientProps, ListViewServerProps } from 'payload'

import { assetListURL } from '@/components/assetListURL'

import './index.scss'

const AssetClassListView = async (props: ListViewServerProps) => {
  if (!props.enableRowSelections) {
    const clientProps: ListViewClientProps = {
      AfterList: props.AfterList,
      AfterListTable: props.AfterListTable,
      beforeActions: props.beforeActions,
      BeforeList: props.BeforeList,
      BeforeListTable: props.BeforeListTable,
      collectionSlug: props.collectionSlug,
      columnState: props.columnState,
      Description: props.Description,
      disableBulkDelete: props.disableBulkDelete,
      disableBulkEdit: props.disableBulkEdit,
      disableQueryPresets: props.disableQueryPresets,
      enableRowSelections: props.enableRowSelections,
      hasCreatePermission: props.hasCreatePermission,
      hasDeletePermission: props.hasDeletePermission,
      hasTrashPermission: props.hasTrashPermission,
      listMenuItems: props.listMenuItems,
      listPreferences: props.listPreferences,
      newDocumentURL: props.newDocumentURL,
      queryPreset: props.queryPreset,
      queryPresetPermissions: props.queryPresetPermissions,
      renderedFilters: props.renderedFilters,
      resolvedFilterOptions: props.resolvedFilterOptions,
      Table: props.Table,
      viewType: props.viewType,
    }
    return <DefaultListView {...clientProps} />
  }

  const classes = await props.payload.find({
    collection: 'asset-classes',
    depth: 0,
    overrideAccess: false,
    pagination: false,
    sort: 'name',
    user: props.user,
  })
  const adminRoute = props.payload.config.routes.admin

  return (
    <main className="asset-class-list-view">
      <header className="asset-class-list-view__header">
        <div>
          <h1>Asset Classes</h1>
          <p>Classes are reusable asset categories. Select one to edit it or view its assets.</p>
        </div>
        {props.hasCreatePermission ? (
          <Link className="asset-class-list-view__create" href={props.newDocumentURL}>
            Add asset class
          </Link>
        ) : null}
      </header>

      {classes.docs.length ? (
        <div className="asset-class-list-view__table-wrap">
          <table>
            <thead>
              <tr>
                <th>Class</th>
                <th>Description</th>
                <th>Rules</th>
                <th>Priority</th>
                <th>Assets</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {classes.docs.map((assetClass) => (
                <tr key={assetClass.id}>
                  <td>
                    <Link href={`${adminRoute}/collections/asset-classes/${assetClass.id}`}>
                      {assetClass.name}
                    </Link>
                  </td>
                  <td>{assetClass.description || '—'}</td>
                  <td>{assetClass.assignmentRules?.length || 0}</td>
                  <td>{assetClass.assignmentPriority}</td>
                  <td>
                    <Link href={assetListURL(adminRoute, 'assetClass', assetClass.id)}>
                      View assets
                    </Link>
                  </td>
                  <td>{new Date(assetClass.updatedAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="asset-class-list-view__empty">
          <h2>No asset classes yet</h2>
          <p>Add a class before creating assets.</p>
        </div>
      )}
    </main>
  )
}

export default AssetClassListView
