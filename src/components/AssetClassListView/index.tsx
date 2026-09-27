import { DefaultListView } from '@payloadcms/ui'
import Link from 'next/link'
import type { ListViewServerProps } from 'payload'

import { forwardListViewProps } from '@/components/forwardListViewProps'
import { assetListURL } from '@/components/assetListURL'

import './index.scss'

const AssetClassListView = async (props: ListViewServerProps) => {
  if (!props.enableRowSelections) {
    return <DefaultListView {...forwardListViewProps(props)} />
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
    <main className="table-view">
      <header className="table-view__header">
        <div>
          <h1>Asset Classes</h1>
          <p>Classes are reusable asset categories. Select one to edit it or view its assets.</p>
        </div>
        {props.hasCreatePermission ? (
          <Link className="table-view__create" href={props.newDocumentURL}>
            Add asset class
          </Link>
        ) : null}
      </header>

      {classes.docs.length ? (
        <div className="table-view__table-wrap">
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
        <div className="table-view__empty">
          <h2>No asset classes yet</h2>
          <p>Add a class before creating assets.</p>
        </div>
      )}
    </main>
  )
}

export default AssetClassListView
