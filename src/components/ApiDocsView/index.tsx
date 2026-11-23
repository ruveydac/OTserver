import { DefaultTemplate } from '@payloadcms/next/templates'
import { Gutter, Link } from '@payloadcms/ui'
import { redirect } from 'next/navigation'
import type { AdminViewServerProps } from 'payload'

import { getApiDocument } from '@/apiDocs/openapi'

import './index.scss'

const ApiDocsView = async (props: AdminViewServerProps) => {
  const { payload, initPageResult } = props
  if (!initPageResult.req.user || 'otterScannerID' in initPageResult.req.user)
    redirect(`${payload.config.routes.admin}/login`)

  const document = await getApiDocument(payload)
  const operations = Object.entries(document.paths || {}).flatMap(([path, methods]) =>
    Object.entries(methods || {})
      .filter(([method]) => ['get', 'post', 'patch', 'put', 'delete'].includes(method))
      .map(([method, operation]) => ({
        method: method.toUpperCase(),
        path,
        operation,
        summary:
          operation &&
          typeof operation === 'object' &&
          'summary' in operation &&
          typeof operation.summary === 'string'
            ? operation.summary
            : undefined,
      })),
  )

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
      <Gutter>
        <main className="api-docs">
          <h1>API documentation</h1>
          <p>
            OTserver provides a REST API at <code>/api</code>. Requests use the same site
            permissions as the application. A role with read-only access cannot write, and imports
            belong to one exact site.
          </p>
          <h2>Authenticate</h2>
          <p>
            Log in with your OTserver account to receive a short-lived token. Send it as a{' '}
            <code>JWT</code> authorization header. Use HTTPS outside localhost. Do not put tokens in
            URLs or share them.
          </p>
          <pre>{`curl -X POST "$OTSERVER_URL/api/users/login" \\
  -H 'Content-Type: application/json' \\
  -d '{"email":"user@example.com","password":"YOUR_PASSWORD"}'

curl "$OTSERVER_URL/api/assets?limit=10&page=1" \\
  -H "Authorization: JWT $TOKEN"`}</pre>
          <p>
            If an administrator has provisioned a user API key, use{' '}
            <code>Authorization: users API-Key &lt;key&gt;</code> instead. Keys are not available
            from the user profile screen. Keep credentials out of shell history and logs.
          </p>
          <h2>Find assets</h2>
          <p>
            List results are paginated. Use Payload REST query parameters such as{' '}
            <code>where[site][equals]</code>, <code>page</code>, <code>limit</code>, and{' '}
            <code>depth</code>. Site filters narrow results; they never grant access.
          </p>
          <pre>{`curl -G "$OTSERVER_URL/api/assets" \\
  -H "Authorization: JWT $TOKEN" \\
  --data-urlencode 'where[site][equals]=SITE_ID' \\
  --data-urlencode 'limit=10' \\
  --data-urlencode 'page=1'`}</pre>
          <h2>Create an asset</h2>
          <p>
            A write-enabled role can create an asset in a writable site. Select an existing asset
            class; neither the site nor the class is inferred from the name. This request creates a
            new document each time it is sent.
          </p>
          <pre>{`curl -X POST "$OTSERVER_URL/api/assets" \\
  -H "Authorization: JWT $TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"name":"PLC 1","site":"SITE_ID","assetClass":"CLASS_ID"}'`}</pre>
          <h2>Endpoint reference</h2>
          <p>
            This reference is generated from OTserver&apos;s Payload collections. It covers
            inventory endpoints, not scanner control, administrator maintenance, or custom actions.
            An endpoint in this list is not a grant of permission; the server checks your current
            role on every request. Generated schemas describe field shapes, not field-level write
            access or validation performed by OTserver.
          </p>
          <p>
            <Link href="/api-docs/openapi.json">Download OpenAPI JSON</Link> for request fields,
            response schemas, and query parameters.
          </p>
          {operations.length ? (
            <div className="api-docs__operations">
              {operations.map(({ method, path, operation, summary }) => (
                <details className="api-docs__operation" key={`${method} ${path}`}>
                  <summary>
                    <strong>{method}</strong> <code>{path}</code>
                    {summary && <span>{summary}</span>}
                  </summary>
                  <pre>{JSON.stringify(operation, null, 2)}</pre>
                </details>
              ))}
            </div>
          ) : (
            <p>No inventory endpoints are available in this reference.</p>
          )}
        </main>
      </Gutter>
    </DefaultTemplate>
  )
}

export default ApiDocsView
