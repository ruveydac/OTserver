import { existsSync } from 'node:fs'

if (
  !process.env.OTSERVER_TEST_DATABASE_OWNER ||
  !process.env.TEST_DATABASE_URL ||
  process.env.DATABASE_URL !== process.env.TEST_DATABASE_URL ||
  !process.env.OTSERVER_TEST_UPLOAD_DIR ||
  !existsSync(process.env.OTSERVER_TEST_UPLOAD_DIR)
) {
  throw new Error(
    'Tests require a test-owned MongoDB replica set and upload directory. Run them with `pnpm test` or `pnpm test:coverage`.',
  )
}
