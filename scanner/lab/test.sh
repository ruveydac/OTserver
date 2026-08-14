#!/bin/sh
set -u

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_NAME="otserver-scanner-lab-${CI_JOB_ID:-$$}"
COMPOSE="docker compose -p $PROJECT_NAME -f $LAB_DIR/compose.yml"

mkdir -p "$LAB_DIR/artifacts"
chmod a+rwx "$LAB_DIR/artifacts"

cleanup() {
  $COMPOSE logs --no-color >"$LAB_DIR/artifacts/compose.log" 2>&1 || true
  $COMPOSE down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

$COMPOSE up --build --abort-on-container-exit --exit-code-from test
