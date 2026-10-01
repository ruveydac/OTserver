import { mongooseAdapter } from '@payloadcms/db-mongodb'
import path from 'node:path'
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
import { MAX_OTTER_IMPORT_FILE_SIZE } from './importers/otserverOtter'
import { jobs } from './jobs/config'
import { WorkerLeases, WorkerHeartbeats } from './collections/WorkerState'
import { readiness, workerDiagnostics } from './jobs/diagnostics'
import { superviseWorker } from './jobs/worker'
import { migrations } from './migrations'
import {
  NetworkEndpoints,
  ServiceBindings,
  AssetIdentifiers,
  AssetInstallations,
  IdentityCases,
} from './collections/Identity'

const dirname = import.meta.dirname || path.resolve('src')

const initializeApplication = async (payload: Payload) => {
  await initializeAssetClasses(payload)
  await initializeAuthorization(payload)

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
  // Import diagnostics can exceed Payload's default 40,000-character text limit.
  defaultMaxTextLength: 0,
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
    requestSizeLimit: 520 * 1024 * 1024,
    abortOnLimit: true,
    limits: { fileSize: Math.max(MAX_IMPORT_FILE_SIZE, MAX_OTTER_IMPORT_FILE_SIZE) },
    preserveExtension: true,
    safeFileNames: true,
  },
  typescript: {
    outputFile: path.resolve(dirname, 'payload-types.ts'),
  },
})
