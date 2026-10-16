#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUNTIME=${CONTAINER_RUNTIME:-}

if [ -n "$RUNTIME" ]; then
  command -v "$RUNTIME" >/dev/null 2>&1 || {
    echo "Container runtime '$RUNTIME' was not found." >&2
    exit 1
  }
  "$RUNTIME" info >/dev/null 2>&1 || {
    echo "Container runtime '$RUNTIME' is not available." >&2
    exit 1
  }
else
  for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
      RUNTIME=$candidate
      break
    fi
  done
fi

if [ -z "$RUNTIME" ]; then
  echo 'Docker or Podman is required for the container bootstrap test.' >&2
  exit 1
fi

PREFIX="otserver-bootstrap-$$"
APP="$PREFIX-app"
IMPORT_WORKER="$PREFIX-import-worker"
MAINTENANCE_WORKER="$PREFIX-maintenance-worker"
RESTORED_APP="$PREFIX-restored-app"
IMAGE="$PREFIX"
MONGO="$PREFIX-mongo"
NETWORK="$PREFIX"
UPLOADS="$PREFIX-import-files"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    "$RUNTIME" logs "$APP" >&2 || true
    "$RUNTIME" logs "$IMPORT_WORKER" >&2 || true
    "$RUNTIME" logs "$MAINTENANCE_WORKER" >&2 || true
    "$RUNTIME" logs "$RESTORED_APP" >&2 || true
    "$RUNTIME" logs "$MONGO" >&2 || true
  fi
  "$RUNTIME" rm --force "$APP" "$IMPORT_WORKER" "$MAINTENANCE_WORKER" "$RESTORED_APP" "$MONGO" >/dev/null 2>&1 || true
  "$RUNTIME" volume rm "$UPLOADS" >/dev/null 2>&1 || true
  "$RUNTIME" network rm "$NETWORK" >/dev/null 2>&1 || true
  "$RUNTIME" image rm "$IMAGE" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

echo "Building the production image with $RUNTIME..."
"$RUNTIME" build --tag "$IMAGE" "$ROOT"
"$RUNTIME" run --rm "$IMAGE" node -e \
  'const assert = require("node:assert/strict"); assert.equal(process.env.NODE_OPTIONS, "--max-old-space-size=2048"); assert.ok(require("node:v8").getHeapStatistics().heap_size_limit >= 2048 * 1024 ** 2)'
"$RUNTIME" run --rm --env NODE_OPTIONS=--max-old-space-size=768 "$IMAGE" node -e \
  'const assert = require("node:assert/strict"); const heap = require("node:v8").getHeapStatistics().heap_size_limit / 1024 ** 2; assert.ok(heap >= 768 && heap < 900)'
"$RUNTIME" network create "$NETWORK" >/dev/null
"$RUNTIME" volume create "$UPLOADS" >/dev/null
"$RUNTIME" run --detach \
  --name "$MONGO" \
  --hostname mongo \
  --network "$NETWORK" \
  --network-alias mongo \
  docker.io/library/mongo:8 \
  --replSet rs0 \
  --bind_ip_all >/dev/null

attempt=0
until "$RUNTIME" exec "$MONGO" mongosh --quiet --eval \
  'if (!db.runCommand({ ping: 1 }).ok) quit(1)' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo 'MongoDB did not become ready within 60 seconds.' >&2
    exit 1
  fi
  sleep 1
done

"$RUNTIME" exec "$MONGO" mongosh --quiet --eval \
  'const result = rs.initiate({_id:"rs0",members:[{_id:0,host:"mongo:27017"}]}); if (!result.ok) quit(1)' \
  >/dev/null

attempt=0
until "$RUNTIME" exec "$MONGO" mongosh --quiet --eval \
  'if (!db.hello().isWritablePrimary) quit(1)' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo 'MongoDB replica set did not elect a primary within 60 seconds.' >&2
    exit 1
  fi
  sleep 1
done

"$RUNTIME" run --detach \
  --name "$APP" \
  --network "$NETWORK" \
  --env DATABASE_URL='mongodb://mongo:27017/otserver?replicaSet=rs0' \
  --env OTSERVER_SECRET='container-bootstrap-test-secret-change-me' \
  --env OTSERVER_OTTER_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --env OTSERVER_QUEUED_IMPORTS=on \
  --env OTSERVER_WORKER_MODE=external \
  --env OTSERVER_VULNERABILITY_FEEDS=off \
  --volume "$UPLOADS:/app/import-files" \
  "$IMAGE" >/dev/null

attempt=0
until "$RUNTIME" exec "$APP" node -e \
  "fetch('http://127.0.0.1:3000/api/user-roles').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))" \
  >/dev/null 2>&1; do
  if [ "$("$RUNTIME" inspect --format '{{.State.Running}}' "$APP" 2>/dev/null || true)" != 'true' ]; then
    echo 'OTserver exited before becoming ready.' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ]; then
    echo 'OTserver did not become ready within 120 seconds.' >&2
    exit 1
  fi
  sleep 1
done

for worker in "$IMPORT_WORKER" "$MAINTENANCE_WORKER"; do
  queue=imports
  if [ "$worker" = "$MAINTENANCE_WORKER" ]; then queue=maintenance; fi
  "$RUNTIME" run --detach \
    --name "$worker" \
    --network "$NETWORK" \
    --env DATABASE_URL='mongodb://mongo:27017/otserver?replicaSet=rs0' \
    --env OTSERVER_SECRET='container-bootstrap-test-secret-change-me' \
    --env OTSERVER_OTTER_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    --env OTSERVER_QUEUED_IMPORTS=on \
    --env OTSERVER_WORKER_MODE=external \
    --env OTSERVER_VULNERABILITY_FEEDS=off \
    --volume "$UPLOADS:/app/import-files:ro" \
    "$IMAGE" node_modules/.bin/tsx src/worker.ts "$queue" >/dev/null
  "$RUNTIME" exec "$worker" sh -c 'test ! -e /app/.env'
done

"$RUNTIME" exec --interactive "$APP" node --import tsx --input-type=module <<'NODE'
import assert from 'node:assert/strict'
import { getPayload } from 'payload'
import config from './src/payload.config.ts'
import { systemRequest } from './src/integrations/payload/requests.ts'

const baseURL = 'http://127.0.0.1:3000'
const json = async (path, options) => {
  const response = await fetch(`${baseURL}${path}`, options)
  assert.equal(response.status, 200, `${path} responded with ${response.status}`)
  return response.json()
}
const relationshipID = (value) => (typeof value === 'object' && value ? value.id : value)

assert.deepEqual(await json('/health/live'), { alive: true })
assert.deepEqual(await json('/api/health/ready'), { ready: true })

const firstUserPage = await fetch(`${baseURL}/admin/create-first-user`)
assert.equal(firstUserPage.status, 200)
assert.equal(new URL(firstUserPage.url).pathname, '/admin/create-first-user')

const rolesBeforeRegistration = await json('/api/user-roles?depth=0&limit=10')
assert.equal(rolesBeforeRegistration.totalDocs, 1)
const adminRole = rolesBeforeRegistration.docs[0]
assert.equal(adminRole.name, 'Admin')
assert.equal(adminRole.isAdmin, true)
assert.deepEqual(adminRole.permissions, [])

const password = 'container-bootstrap-test-password'
const registration = await json('/api/users/first-register', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    email: 'container-bootstrap@example.test',
    name: 'Container bootstrap administrator',
    password,
    'confirm-password': password,
  }),
})
assert.ok(registration.token)
assert.equal(relationshipID(registration.user.role), adminRole.id)

const authorization = { Authorization: `JWT ${registration.token}` }
const currentUser = await json('/api/users/me?depth=0', { headers: authorization })
assert.equal(currentUser.user.email, 'container-bootstrap@example.test')
assert.equal(relationshipID(currentUser.user.role), adminRole.id)

const classes = await json('/api/asset-classes?depth=0&limit=100', { headers: authorization })
const expectedClassKeys = [
  'engineering-workstation',
  'hmi',
  'network-device',
  'other',
  'plc',
  'rtu',
  'scada-server',
  'sensor-actuator',
]
assert.equal(classes.totalDocs, expectedClassKeys.length)
assert.deepEqual(
  classes.docs.map(({ legacyKey }) => legacyKey).sort(),
  expectedClassKeys,
)
assert.ok(classes.docs.find(({ legacyKey }) => legacyKey === 'plc').assignmentRules.length > 0)

const payload = await getPayload({ config })
try {
  const user = await payload.findByID({
    collection: 'users',
    id: currentUser.user.id,
    depth: 0,
    overrideAccess: true,
  })
  const site = await payload.create({
    collection: 'sites',
    data: { name: 'External worker smoke site', type: 'Test' },
    overrideAccess: false,
    user,
  })
  const bytes = Buffer.from(`<!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
    <host endtime="1700000000"><status state="up" reason="arp-response" />
    <address addr="192.0.2.42" addrtype="ipv4" /><address addr="02:00:00:00:80:01" addrtype="mac" vendor="Test Vendor" />
    <hostnames><hostname name="external-worker-smoke" type="user" /></hostnames></host></nmaprun>`)
  const accepted = await payload.create({
    collection: 'asset-imports',
    data: {
      executionMode: 'queued',
      site: site.id,
      source: 'nmap',
      sourceVersion: '7.95',
    },
    file: {
      data: bytes,
      mimetype: 'application/xml',
      name: 'external-worker-smoke.xml',
      size: bytes.length,
    },
    overrideAccess: false,
    user,
  })
  const imported = await payload.findByID({
    collection: 'asset-imports',
    id: accepted.id,
    depth: 0,
    overrideAccess: true,
  })
  const scanner = await payload.create({
    collection: 'otter-scanners',
    data: { name: 'External worker restore scanner', site: site.id },
    overrideAccess: true,
    user,
  })
  await payload.create({
    collection: 'otter-profiles',
    data: {
      name: 'External worker restore configuration',
      site: site.id,
      scanner: scanner.id,
      configuration: { targets: ['192.0.2.42'] },
    },
    overrideAccess: false,
    user,
  })
  const maintenance = await payload.jobs.queue({
    task: 'maintenance-v1',
    queue: 'maintenance',
    input: { version: 1 },
    req: await systemRequest(payload),
  })

  let importStatus
  let maintenanceJob
  for (let attempt = 0; attempt < 60; attempt += 1) {
    importStatus = (await payload.findByID({
      collection: 'asset-imports',
      id: accepted.id,
      depth: 0,
      overrideAccess: true,
    })).status
    maintenanceJob = await payload.db.collections['payload-jobs'].findById(maintenance.id).lean()
    if (importStatus === 'failed' || maintenanceJob?.hasError)
      throw new Error('An external worker failed its smoke-test job.')
    if (importStatus === 'completed' && maintenanceJob?.completedAt) break
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  assert.equal(importStatus, 'completed')
  assert.ok(maintenanceJob?.completedAt)
  assert.equal(
    (await payload.count({ collection: 'assets', where: { site: { equals: site.id } } })).totalDocs,
    1,
  )
  assert.ok(imported.jobID)
} finally {
  await payload.destroy()
}

let operations
for (let attempt = 0; attempt < 60; attempt += 1) {
  operations = await json('/api/operations', { headers: authorization })
  if (operations.queues.every(({ healthy }) => healthy)) break
  await new Promise((resolve) => setTimeout(resolve, 500))
}
assert.deepEqual(
  operations.queues.map(({ queue, healthy }) => ({ queue, healthy })),
  [
    { queue: 'imports', healthy: true },
    { queue: 'maintenance', healthy: true },
  ],
)

console.log('Fresh database initialized; external workers processed an import and maintenance job.')
NODE

# Rehearse the MongoDB archive portion of disaster recovery against a separate namespace.
"$RUNTIME" exec "$MONGO" mongodump \
  --db otserver \
  --archive=otserver-restore-drill.archive.gz \
  --gzip >/dev/null
"$RUNTIME" exec "$MONGO" mongorestore \
  --archive=otserver-restore-drill.archive.gz \
  --gzip \
  --drop \
  --nsFrom='otserver.*' \
  --nsTo='otserver-restore-drill.*' >/dev/null
"$RUNTIME" exec "$MONGO" mongosh --quiet --eval \
  'const restored = db.getSiblingDB("otserver-restore-drill"); if (restored.users.countDocuments({}) !== 1 || restored["user-roles"].countDocuments({name:"Admin"}) !== 1 || restored["asset-classes"].countDocuments({}) !== 8 || restored.assets.countDocuments({}) !== 1 || restored["asset-imports"].countDocuments({filename:"external-worker-smoke.xml",status:"completed"}) !== 1) quit(1)' \
  >/dev/null

"$RUNTIME" run --detach \
  --name "$RESTORED_APP" \
  --network "$NETWORK" \
  --env DATABASE_URL='mongodb://mongo:27017/otserver-restore-drill?replicaSet=rs0' \
  --env OTSERVER_SECRET='container-bootstrap-test-secret-change-me' \
  --env OTSERVER_OTTER_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --env OTSERVER_WORKER_MODE=external \
  --env OTSERVER_VULNERABILITY_FEEDS=off \
  --volume "$UPLOADS:/app/import-files" \
  "$IMAGE" >/dev/null

attempt=0
until "$RUNTIME" exec "$RESTORED_APP" node -e \
  "fetch('http://127.0.0.1:3000/api/health/ready').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))" \
  >/dev/null 2>&1; do
  if [ "$("$RUNTIME" inspect --format '{{.State.Running}}' "$RESTORED_APP" 2>/dev/null || true)" != 'true' ]; then
    echo 'Restored OTserver exited before becoming ready.' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ]; then
    echo 'Restored OTserver did not become ready within 120 seconds.' >&2
    exit 1
  fi
  sleep 1
done

"$RUNTIME" exec --interactive "$RESTORED_APP" node --import tsx --input-type=module <<'NODE'
import assert from 'node:assert/strict'
import { access } from 'node:fs/promises'
import path from 'node:path'
import { getPayload } from 'payload'
import config from './src/payload.config.ts'
import { decryptOtterCredentials } from './src/otter/security.ts'

const payload = await getPayload({ config })
try {
  const importResult = await payload.find({
    collection: 'asset-imports',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    where: { filename: { equals: 'external-worker-smoke.xml' } },
  })
  const imported = importResult.docs[0]
  assert.ok(imported)
  assert.equal(imported.status, 'completed')
  assert.ok(imported.filename)
  await access(path.join('/app/import-files', imported.filename))

  const profileResult = await payload.find({
    collection: 'otter-profiles',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    where: { name: { equals: 'External worker restore configuration' } },
  })
  const profile = profileResult.docs[0]
  assert.ok(profile)
  const stored = await payload.db.collections['otter-profiles'].findById(profile.id).lean()
  assert.deepEqual(decryptOtterCredentials(stored?.encryptedCredentials), {
    snmp: [{ version: '2c', community: 'public' }],
  })
} finally {
  await payload.destroy()
}
NODE

"$RUNTIME" exec "$MONGO" mongosh --quiet --eval \
  'db.getSiblingDB("otserver-restore-drill").dropDatabase()' >/dev/null

echo "Container bootstrap, external workers, and database/upload/secret restore passed with $RUNTIME."
