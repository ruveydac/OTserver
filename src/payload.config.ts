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
import { MAX_IMPORT_FILE_SIZE } from './importers/proneta'

const dirname = path.dirname(fileURLToPath(import.meta.url))

const TRASH_RETENTION_DAYS = 90
const CLEANUP_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000

const cleanupTrashedAssets = async (payload: Payload) => {
  const cutoff = new Date(Date.now() - TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString()
  const result = await payload.delete({
    collection: 'assets',
    overrideAccess: true,
    trash: true,
    where: { deletedAt: { less_than_equal: cutoff } },
  })
  if ('docs' in result && result.docs.length) {
    payload.logger.info(
      `Permanently deleted ${result.docs.length} trashed asset(s) older than ${TRASH_RETENTION_DAYS} days.`,
    )
  }
}

const initializeApplication = async (payload: Payload) => {
  await initializeAssetClasses(payload)
  await initializeAuthorization(payload)
  await cleanupTrashedAssets(payload)
  setInterval(() => void cleanupTrashedAssets(payload), CLEANUP_INTERVAL_MS)
}

export default buildConfig({
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
    AssetImports,
    AssetFields,
    UserRoles,
    Users,
    AssetObservations,
    TopologyLinks,
    AuditLogs,
  ].map(withAudit),
  db: mongooseAdapter({
    url: process.env.DATABASE_URL,
  }),
  secret: process.env.OTSERVER_SECRET,
  onInit: initializeApplication,
  upload: {
    abortOnLimit: true,
    limits: { fileSize: Math.max(MAX_IMPORT_FILE_SIZE, 50 * 1024 * 1024) },
    preserveExtension: true,
    safeFileNames: true,
  },
  typescript: {
    outputFile: path.resolve(dirname, 'payload-types.ts'),
  },
})
