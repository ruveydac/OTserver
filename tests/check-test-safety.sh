#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
if output=$(env \
  -u DATABASE_URL \
  -u TEST_DATABASE_URL \
  -u OTSERVER_TEST_DATABASE_OWNER \
  -u OTSERVER_TEST_UPLOAD_DIR \
  pnpm --dir "$ROOT" exec vitest run --config "$ROOT/vitest.config.mts" \
    "$ROOT/tests/int/coverage.int.spec.ts" 2>&1); then
  printf '%s\n' 'Vitest unexpectedly ran without a test-owned database.' >&2
  exit 1
fi

case "$output" in
  *'Tests require a test-owned MongoDB replica set and upload directory'*) ;;
  *) printf '%s\n' "$output" >&2; exit 1 ;;
esac
