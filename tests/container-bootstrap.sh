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
IMAGE="$PREFIX"
MONGO="$PREFIX-mongo"
NETWORK="$PREFIX"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    "$RUNTIME" logs "$APP" >&2 || true
    "$RUNTIME" logs "$MONGO" >&2 || true
  fi
  "$RUNTIME" rm --force "$APP" "$MONGO" >/dev/null 2>&1 || true
  "$RUNTIME" network rm "$NETWORK" >/dev/null 2>&1 || true
  "$RUNTIME" image rm "$IMAGE" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

echo "Building the production image with $RUNTIME..."
"$RUNTIME" build --tag "$IMAGE" "$ROOT"
"$RUNTIME" network create "$NETWORK" >/dev/null
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
  --env OTSERVER_VULNERABILITY_FEEDS=off \
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

"$RUNTIME" exec --interactive "$APP" node --input-type=module <<'NODE'
import assert from 'node:assert/strict'

const baseURL = 'http://127.0.0.1:3000'
const json = async (path, options) => {
  const response = await fetch(`${baseURL}${path}`, options)
  assert.equal(response.status, 200, `${path} responded with ${response.status}`)
  return response.json()
}
const relationshipID = (value) => (typeof value === 'object' && value ? value.id : value)

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

console.log('Fresh database initialized with the Admin role, first user, and default asset classes.')
NODE

echo "Container bootstrap test passed with $RUNTIME."
