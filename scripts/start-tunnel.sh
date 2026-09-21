#!/usr/bin/env bash
set -euo pipefail

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared is not installed."
  echo "Install it with:"
  echo "  brew install cloudflared"
  exit 1
fi

echo "Starting a temporary Cloudflare quick tunnel to http://localhost:3000"
echo
echo "When cloudflared prints an https://*.trycloudflare.com URL:"
echo "  1. Copy that URL into .env as PUBLIC_BASE_URL"
echo "  2. Set TRUST_PROXY=true and COOKIE_SECURE=true"
echo "  3. Restart: docker compose up -d --build access-gateway telegram-bot"
echo
echo "The trycloudflare.com URL changes when this tunnel restarts."
echo

exec cloudflared tunnel --url http://localhost:3000
