import { DefaultTemplate } from '@payloadcms/next/templates'
import { Button } from '@payloadcms/ui'
import Link from 'next/link'
import type { AdminViewServerProps, Where } from 'payload'
import { purdueLevels } from '@/domain/purdue'
import { whereToLucene } from '@/search/whereToLucene'

import '@/styles/shared.scss'

const PurdueView = async (props: AdminViewServerProps) => {
  const { payload, initPageResult } = props
  const user = initPageResult.req.user
  const admin = payload.config.routes.admin
  const sites = await payload.find({
    collection: 'sites',
    depth: 0,
    pagination: false,
    overrideAccess: false,
    user,
    sort: 'path',
  })
  const parameter = props.searchParams?.site
  const selected = sites.docs.find(
    ({ id }) => id === (Array.isArray(parameter) ? parameter[0] : parameter),
  )
  const bands = [
    ...purdueLevels.map(({ label, value }) => ({
      label,
      condition: { purdueLevels: { equals: value } } as Where,
    })),
    {
      label: 'Unclassified',
      condition: { purdueLevels: { not_in: purdueLevels.map(({ value }) => value) } } as Where,
    },
  ]
  const scope: Where = { site: { equals: selected?.id } }
  const counts = selected
    ? await Promise.all(
        bands.map(({ condition }) =>
          payload.count({
            collection: 'assets',
            overrideAccess: false,
            user,
            where: { and: [scope, condition] },
          }),
        ),
      )
    : []
  const total = selected
    ? await payload.count({ collection: 'assets', overrideAccess: false, user, where: scope })
    : undefined
  return (
    <DefaultTemplate
      i18n={props.i18n}
      locale={props.locale}
      params={props.params}
      payload={payload}
      permissions={initPageResult.permissions}
      req={initPageResult.req}
      searchParams={props.searchParams}
      user={props.user}
      viewType={props.viewType}
      visibleEntities={initPageResult.visibleEntities}
    >
      <main className="table-view">
        <header className="table-view__header">
          <div>
            <h1>Purdue classification</h1>
            <p>
              Functional classifications within one exact inventory scope. Levels do not establish
              security zones.
            </p>
          </div>
          <Link href={`${admin}/collections/sites`}>View site hierarchy</Link>
        </header>
        <form action={`${admin}/purdue`} method="get">
          <label htmlFor="purdue-site">Site </label>
          <select id="purdue-site" name="site" defaultValue={selected?.id || ''} required>
            <option value="">Select a site</option>
            {sites.docs.map((site) => (
              <option key={site.id} value={site.id}>
                {site.path || site.name}
              </option>
            ))}
          </select>{' '}
          <Button type="submit">Show classification</Button>
        </form>
        {selected ? (
          <>
            <p>
              {selected.path || selected.name}: {total!.totalDocs} unique assets, excluding Trash.
              Assets with several levels appear in each relevant row.
            </p>
            <div className="table-view__table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Classification</th>
                    <th scope="col">Assets</th>
                  </tr>
                </thead>
                <tbody>
                  {bands.map(({ label, condition }, index) => (
                    <tr key={label}>
                      <th scope="row">{label}</th>
                      <td>
                        <Link
                          href={`${admin}/collections/assets?${new URLSearchParams({ search: whereToLucene({ and: [scope, condition] }) })}`}
                        >
                          {counts[index].totalDocs} assets
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="table-view__empty">
            <p>
              {sites.docs.length
                ? 'Select an accessible site to review its classifications.'
                : 'No accessible sites yet.'}
            </p>
          </div>
        )}
      </main>
    </DefaultTemplate>
  )
}

export default PurdueView
