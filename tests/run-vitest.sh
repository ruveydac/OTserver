#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
RUNTIME=${CONTAINER_RUNTIME:-}
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ -n ${OTSERVER_TEST_DATABASE_OWNER:-} ]]; then
  [[ -n ${TEST_DATABASE_URL:-} && -n ${OTSERVER_TEST_UPLOAD_DIR:-} && -d ${OTSERVER_TEST_UPLOAD_DIR} ]] || \
    fail 'An owned test run must provide TEST_DATABASE_URL and an existing OTSERVER_TEST_UPLOAD_DIR.'
  export DATABASE_URL="$TEST_DATABASE_URL"
  exec pnpm --dir "$ROOT" exec vitest run --config "$ROOT/vitest.config.mts" "$@"
fi

if [[ -z "$RUNTIME" ]]; then
  for candidate in docker podman; do
    if command -v "$candidate" >/dev/null && "$candidate" info >/dev/null 2>&1; then
      RUNTIME=$candidate
      break
    fi
  done
fi
[[ -n "$RUNTIME" ]] || fail 'Docker or Podman is required to create a disposable test database.'
"$RUNTIME" info >/dev/null 2>&1 || fail "Container runtime is unavailable: $RUNTIME"

UPLOADS=$(mktemp -d "${TMPDIR:-/tmp}/otserver-test-uploads.XXXXXX")
RUN_ID=${UPLOADS##*/}
CONTAINER="${RUN_ID//./-}-mongo"
CONTAINER_ID=''
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$CONTAINER_ID" ]]; then
    if [[ "$status" -ne 0 ]]; then "$RUNTIME" logs "$CONTAINER_ID" >&2 || true; fi
    "$RUNTIME" rm --force --volumes "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$UPLOADS"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CONTAINER_ID=$("$RUNTIME" run --detach --name "$CONTAINER" \
  --publish 127.0.0.1::27017 docker.io/library/mongo:8 --replSet rs0 --bind_ip_all)
wait_for_mongo() {
  local expression=$1 running details
  for ((attempt = 0; attempt < 60; attempt++)); do
    if "$RUNTIME" exec "$CONTAINER_ID" mongosh --quiet --eval "$expression" >/dev/null 2>&1; then
      return
    fi
    running=$("$RUNTIME" inspect --format '{{.State.Running}}' "$CONTAINER_ID" 2>/dev/null || true)
    if [[ "$running" != true ]]; then
      details=$("$RUNTIME" inspect --format \
        'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' \
        "$CONTAINER_ID" 2>/dev/null || true)
      fail "Disposable MongoDB exited before becoming ready: ${details:-container unavailable}."
    fi
    sleep 1
  done
  fail 'Disposable MongoDB did not become ready within 60 seconds.'
}
wait_for_mongo 'if (!db.runCommand({ping: 1}).ok) quit(1)'
"$RUNTIME" exec "$CONTAINER_ID" mongosh --quiet --eval \
  'const result = rs.initiate({_id:"rs0",members:[{_id:0,host:"localhost:27017"}]}); if (!result.ok) quit(1)' \
  >/dev/null
wait_for_mongo 'if (!db.hello().isWritablePrimary) quit(1)'

ADDRESS=$("$RUNTIME" port "$CONTAINER_ID" 27017/tcp)
[[ "$ADDRESS" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail 'Expected one loopback-only MongoDB port mapping.'
export TEST_DATABASE_URL="mongodb://$ADDRESS/otserver_test?replicaSet=rs0&directConnection=true"
export DATABASE_URL="$TEST_DATABASE_URL"
export OTSERVER_TEST_DATABASE_OWNER="$RUN_ID"
export OTSERVER_TEST_UPLOAD_DIR="$UPLOADS"
export OTSERVER_SECRET
OTSERVER_SECRET=$(node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("hex"))')
export OTSERVER_OTTER_ENCRYPTION_KEY
OTSERVER_OTTER_ENCRYPTION_KEY=$(node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("hex"))')
export OTSERVER_VULNERABILITY_FEEDS=off

pnpm --dir "$ROOT" exec vitest run --config "$ROOT/vitest.config.mts" "$@"
