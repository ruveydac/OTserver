import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { mcpPlugin } from '@payloadcms/plugin-mcp'
import { openapi } from '@seshuk/payload-plugin-openapi'
import path from 'node:path'
import { buildConfig, UnauthorizedError, type Payload } from 'payload'

import { adminOnly, getAuthorization, hideFromNonAdmins } from './access/authorization'
import { readApplicationSettings } from './application/settings'
import { Assets } from './collections/Assets'
import { AssetClasses, initializeAssetClasses } from './collections/AssetClasses'
import { AssetImports } from './collections/AssetImports'
import { AssetFields } from './collections/AssetFields'
import { AssetObservations } from './collections/AssetObservations'
import { AssetVulnerabilityReviews } from './collections/AssetVulnerabilityReviews'
import { AuditLogs, withAudit } from './collections/AuditLogs'
import { Sites } from './collections/Sites'
import { SiteTypes, initializeSiteTypes } from './collections/SiteTypes'
import { initializeAuthorization, UserRoles } from './collections/UserRoles'
import { Users } from './collections/Users'
import { TopologyLinks } from './collections/TopologyLinks'
import { Vulnerabilities, VulnerabilityFeeds } from './collections/Vulnerabilities'
import { VulnerabilityFeedUploads } from './collections/VulnerabilityFeedUploads'
import { MAX_IMPORT_FILE_SIZE } from './importers/proneta'
import { MAX_OTTER_IMPORT_FILE_SIZE } from './importers/otserverOtter'
import { jobs } from './jobs/config'
import { WorkerLeases, WorkerHeartbeats } from './collections/WorkerState'
import { readiness, workerDiagnostics } from './jobs/diagnostics'
import { superviseWorker } from './jobs/worker'
import { migrations } from './migrations'
import { otterEndpoints } from './otter/controller'
import {
  NetworkEndpoints,
  ServiceBindings,
  AssetIdentifiers,
  AssetInstallations,
  IdentityCases,
} from './collections/Identity'
import {
  OtterProfiles,
  OtterReleases,
  OtterRuns,
  OtterScanners,
  OtterSchedules,
  OtterUpdates,
} from './collections/Otter'
import { ApplicationSettings } from './globals/ApplicationSettings'
import { initializeMetadataCatalog } from './metadata/initialize'
import { DeviceCatalog } from './collections/DeviceCatalog'
import { initializeAssetTags, TagGroups, Tags } from './collections/Tags'

const dirname = import.meta.dirname || path.resolve('src')

const initializeApplication = async (payload: Payload) => {
  await initializeSiteTypes(payload)
  await initializeAssetClasses(payload)
  await initializeAssetTags(payload)
  await initializeAuthorization(payload)
  await initializeMetadataCatalog(payload)

  const workerMode = process.env.OTSERVER_WORKER_MODE || 'standalone'
  if (workerMode !== 'standalone' && workerMode !== 'external')
    throw new Error('OTSERVER_WORKER_MODE must be standalone or external.')
  if (workerMode === 'external' || process.env.NODE_ENV === 'test') return

  const signal = new AbortController().signal
  for (const queue of ['imports', 'maintenance'] as const)
    void superviseWorker(payload, queue, signal)
}

export default buildConfig({
  jobs,
  plugins: [
    mcpPlugin({
      collections: {
        assets: { enabled: { find: true } },
        sites: { enabled: { find: true } },
      },
      overrideAuth: async (req, getDefaultMcpAccessSettings) => {
        if ((await readApplicationSettings(req.payload, req)).mcpEnabled !== true)
          throw new UnauthorizedError()
        return getDefaultMcpAccessSettings()
      },
      overrideApiKeyCollection: (collection) =>
        withAudit({
          ...collection,
          labels: { singular: 'MCP key', plural: 'MCP keys' },
          access: {
            ...collection.access,
            admin: async ({ req }) => (await getAuthorization(req)).isAdmin,
            create: adminOnly,
            delete: adminOnly,
            read: adminOnly,
            unlock: adminOnly,
            update: adminOnly,
          },
          admin: { ...collection.admin, group: 'Settings', hidden: hideFromNonAdmins },
          fields: collection.fields.map((field) =>
            field.type === 'relationship' && field.name === 'user'
              ? {
                  ...field,
                  access: {
                    ...field.access,
                    create: async ({ req }) => (await getAuthorization(req)).isAdmin,
                  },
                }
              : field,
          ),
        }),
    }),
    openapi({
      metadata: { title: 'OTserver API', version: '1.0.0' },
      openapiVersion: '3.1',
      serve: false,
      filters: {
        include: ['assets', 'sites', 'asset-classes', 'tags', 'tag-groups', 'asset-imports'],
        includeHidden: true,
        includeAuth: false,
        includeCustom: false,
        includeJobs: false,
        includeVersions: false,
      },
      extensions: [
        {
          transform: (document) => {
            document.components!.securitySchemes!.PayloadToken = {
              type: 'apiKey',
              in: 'header',
              name: 'Authorization',
              description: 'Use JWT <token> or users API-Key <key>.',
            }
            const schemas = document.components!.schemas!
            // Relationships can reference collections deliberately omitted from this inventory spec.
            for (const [, name] of JSON.stringify(document).matchAll(
              /"\$ref":"#\/components\/schemas\/([^"]+)"/g,
            ))
              schemas[name] ??= {
                type: 'object',
                additionalProperties: true,
                description: 'Related document omitted from this inventory reference.',
              }
            return document
          },
        },
      ],
    }),
  ],
  endpoints: [
    { path: '/health/ready', method: 'get', handler: readiness },
    { path: '/operations', method: 'get', handler: workerDiagnostics },
    ...otterEndpoints,
  ],
  admin: {
    components: {
      afterNavLinks: ['@/components/TopologyNavLink', '@/components/ApiDocsNavLink'],
      beforeDashboard: ['@/components/BeforeDashboard'],
      graphics: {
        Icon: '@/components/Brand#Icon',
        Logo: '@/components/Brand#Logo',
      },
      logout: {
        Button: '@/components/LogoutButton',
      },
      views: {
        apiDocs: {
          Component: '@/components/ApiDocsView',
          path: '/api-docs',
        },
        purdue: {
          Component: '@/components/PurdueView',
          path: '/purdue',
        },
        custom: {
          Component: '@/components/TopologyView',
          path: '/topology',
        },
        otters: {
          Component: '@/components/OtterManagementView',
          path: '/otters',
        },
      },
    },
    importMap: {
      baseDir: dirname,
    },
    meta: {
      description: 'OTserver industrial asset inventory and discovery platform',
      icons: { icon: '/otserver-icon.svg' },
      titleSuffix: ' · OTserver',
    },
    user: Users.slug,
  },
  collections: [
    SiteTypes,
    Sites,
    AssetClasses,
    TagGroups,
    Tags,
    Assets,
    NetworkEndpoints,
    ServiceBindings,
    AssetIdentifiers,
    AssetInstallations,
    IdentityCases,
    AssetImports,
    OtterScanners,
    OtterReleases,
    OtterUpdates,
    OtterProfiles,
    OtterSchedules,
    OtterRuns,
    UserRoles,
    Users,
    AssetObservations,
    AssetVulnerabilityReviews,
    TopologyLinks,
    Vulnerabilities,
    VulnerabilityFeedUploads,
    AuditLogs,
    WorkerLeases,
    WorkerHeartbeats,
    DeviceCatalog,
    AssetFields,
    VulnerabilityFeeds,
  ].map(withAudit),
  globals: [ApplicationSettings],
  db: mongooseAdapter({
    url: process.env.DATABASE_URL,
    migrationDir: path.resolve(dirname, 'migrations'),
    prodMigrations: migrations,
    // Identity and review uniqueness must exist before the first transaction or import can run.
    ensureIndexes: true,
  }),
  secret: process.env.OTSERVER_SECRET,
  onInit: initializeApplication,
  upload: {
    requestSizeLimit: 520 * 1024 * 1024,
    abortOnLimit: true,
    limits: {
      fileSize: Math.max(MAX_IMPORT_FILE_SIZE, MAX_OTTER_IMPORT_FILE_SIZE, 512 * 1024 * 1024),
    },
    preserveExtension: true,
    safeFileNames: true,
  },
  typescript: {
    outputFile: path.resolve(dirname, 'payload-types.ts'),
  },
})
