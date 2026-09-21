#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Docker services ==="
docker compose ps

echo
echo "=== Gateway health ==="
if health="$(curl -sS --fail --max-time 5 http://localhost:3000/health)"; then
  echo "$health"
  echo
  echo "Gateway is healthy."
else
  echo "Gateway health check failed."
  exit 1
fi
