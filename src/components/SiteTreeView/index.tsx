import { Button, DefaultListView } from '@payloadcms/ui'
import Link from 'next/link'
import type { ListViewServerProps } from 'payload'

import { forwardListViewProps } from '@/components/forwardListViewProps'
import type { Site } from '@/payload-types'

import { assetListURL } from '@/components/assetListURL'
import { authenticatedAdminUser } from '@/integrations/payload/adminUser'
import { formatDateTime } from '@/components/labels'

import './index.scss'

const relationID = (value: Site['parent']): null | string =>
  typeof value === 'object' && value ? value.id : value || null

export const buildSiteTree = (sites: Site[]) => {
  const byID = new Map(sites.map((site) => [site.id, site]))
  const children = new Map<string, Site[]>()
  const compare = (left: Site, right: Site) =>
    left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: 'base' })

  for (const site of sites) {
    const parentID = relationID(site.parent)
    const key = parentID && byID.has(parentID) ? parentID : ''
    children.set(key, [...(children.get(key) || []), site])
  }
  for (const sitesAtLevel of children.values()) sitesAtLevel.sort(compare)

  const rows: { depth: number; parentName: string; path: string; site: Site }[] = []
  const visited = new Set<string>()
  const visit = (site: Site, depth: number, parentPath: string[]) => {
    if (visited.has(site.id)) return
    visited.add(site.id)

    const path = [...parentPath, site.name]
    const parentID = relationID(site.parent)
    rows.push({
      depth,
      parentName: parentID ? byID.get(parentID)?.name || '—' : '—',
      path: path.join(' / '),
      site,
    })
    for (const child of children.get(site.id) || []) visit(child, depth + 1, path)
  }

  for (const root of children.get('') || []) visit(root, 0, [])
  for (const site of [...sites].sort(compare)) visit(site, 0, [])

  return rows
}

const SiteTreeView = async (props: ListViewServerProps) => {
  if (!props.enableRowSelections) {
    return <DefaultListView {...forwardListViewProps(props)} />
  }

  // ponytail: the hierarchy is rendered in memory; add pagination only if site counts reach thousands.
  const user = await authenticatedAdminUser(props.payload)
  const result = await props.payload.find({
    collection: 'sites',
    depth: 1,
    overrideAccess: false,
    pagination: false,
    sort: 'name',
    user,
  })
  const rows = buildSiteTree(result.docs)
  const adminRoute = props.payload.config.routes.admin
  const typeName = (type: Site['type']) =>
    typeof type === 'object' && type ? type.name : 'Unavailable'

  return (
    <main className="table-view site-tree-view">
      <header className="table-view__header">
        <div>
          <h1>Sites</h1>
          <p>Organize geographic and production sites in one hierarchy.</p>
        </div>
        <div className="site-tree-view__actions">
          <Button el="link" url={`${adminRoute}/purdue`}>
            Purdue overview
          </Button>
          {props.hasCreatePermission ? (
            <Button el="link" url={props.newDocumentURL}>
              Create site
            </Button>
          ) : null}
        </div>
      </header>

      {rows.length ? (
        <div className="table-view__table-wrap">
          <table>
            <thead>
              <tr>
                <th>Site</th>
                <th>Type</th>
                <th>Parent</th>
                <th>Assets</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ depth, parentName, path, site }) => (
                <tr key={site.id}>
                  <td>
                    <div
                      className="site-tree-view__identity"
                      style={{ marginInlineStart: `${depth * 1.5}rem` }}
                    >
                      <span aria-hidden="true" className="site-tree-view__branch">
                        {depth ? '↳' : '•'}
                      </span>
                      <div>
                        <Link href={`${adminRoute}/collections/sites/${site.id}`}>{site.name}</Link>
                        <span className="site-tree-view__path">{path}</span>
                      </div>
                    </div>
                  </td>
                  <td>
                    {typeName(site.type)}
                    {typeof site.type === 'object' && site.type?.blockImports ? (
                      <div>Imports blocked</div>
                    ) : null}
                  </td>
                  <td>{parentName}</td>
                  <td>
                    <Link href={assetListURL(adminRoute, 'site', site.id)}>View assets</Link>
                  </td>
                  <td>{formatDateTime(site.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="table-view__empty">
          <h2>No sites yet</h2>
          <p>Create the first site before creating or importing assets.</p>
        </div>
      )}
    </main>
  )
}

export default SiteTreeView
