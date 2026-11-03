#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"

echo "Starting docker services..."
docker compose up -d --wait

INTEGRATION_TEST_EXIT_CODE=0
npx vitest run --project integration || INTEGRATION_TEST_EXIT_CODE="$?"

echo "==> integration tests exited with code: $INTEGRATION_TEST_EXIT_CODE"
docker compose down -v
exit $INTEGRATION_TEST_EXIT_CODE
