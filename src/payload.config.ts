import { mongooseAdapter } from '@payloadcms/db-mongodb'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildConfig, type Payload } from 'payload'

import { Assets } from './collections/Assets'
import { AssetClasses, initializeAssetClasses } from './collections/AssetClasses'
import { AssetImports } from './collections/AssetImports'
import { AssetFields } from './collections/AssetFields'
import { AssetObservations } from './collections/AssetObservations'
import { AuditLogs, withAudit } from './collections/AuditLogs'
import { Sites } from './collections/Sites'
import { initializeAuthorization, UserRoles } from './collections/UserRoles'
import { Users } from './collections/Users'
import { TopologyLinks } from './collections/TopologyLinks'
import { Vulnerabilities, VulnerabilityFeeds } from './collections/Vulnerabilities'
import { MAX_IMPORT_FILE_SIZE } from './importers/proneta'
import { jobs } from './jobs/config'
import { WorkerLeases, WorkerHeartbeats } from './collections/WorkerState'
import { readiness, workerDiagnostics } from './jobs/diagnostics'
import { migrations } from './migrations'
import {
  NetworkEndpoints,
  ServiceBindings,
  AssetIdentifiers,
  AssetInstallations,
  IdentityCases,
} from './collections/Identity'

const dirname = path.dirname(fileURLToPath(import.meta.url))

const initializeApplication = async (payload: Payload) => {
  await initializeAssetClasses(payload)
  await initializeAuthorization(payload)
}

export default buildConfig({
  jobs,
  endpoints: [
    { path: '/health/ready', method: 'get', handler: readiness },
    { path: '/operations', method: 'get', handler: workerDiagnostics },
  ],
  admin: {
    components: {
      afterNavLinks: ['@/components/TopologyNavLink'],
      beforeDashboard: ['@/components/BeforeDashboard'],
      graphics: {
        Icon: '@/components/Brand#Icon',
        Logo: '@/components/Brand#Logo',
      },
      logout: {
        Button: '@/components/LogoutButton',
      },
      views: {
        custom: {
          Component: '@/components/TopologyView',
          path: '/topology',
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
    Sites,
    AssetClasses,
    Assets,
    NetworkEndpoints,
    ServiceBindings,
    AssetIdentifiers,
    AssetInstallations,
    IdentityCases,
    AssetImports,
    AssetFields,
    UserRoles,
    Users,
    AssetObservations,
    TopologyLinks,
    Vulnerabilities,
    VulnerabilityFeeds,
    AuditLogs,
    WorkerLeases,
    WorkerHeartbeats,
  ].map(withAudit),
  db: mongooseAdapter({
    url: process.env.DATABASE_URL,
    migrationDir: path.resolve(dirname, 'migrations'),
    prodMigrations: migrations,
    // Identity uniqueness must exist before the first transaction or import can run.
    ensureIndexes: true,
  }),
  secret: process.env.OTSERVER_SECRET,
  onInit: initializeApplication,
  upload: {
    requestSizeLimit: 52 * 1024 * 1024,
    abortOnLimit: true,
    limits: { fileSize: Math.max(MAX_IMPORT_FILE_SIZE, 50 * 1024 * 1024) },
    preserveExtension: true,
    safeFileNames: true,
  },
  typescript: {
    outputFile: path.resolve(dirname, 'payload-types.ts'),
  },
})
