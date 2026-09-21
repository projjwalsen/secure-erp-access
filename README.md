# Secure ERP Access (Phase 2 + local SERPA)

Local development prototype of a temporary-access gateway in front of a mock ERP, plus the local SERPA Telegram bot (`@agserpa_bot`). This does not include Telegram webhooks, wildcard DNS, Cloudflare, Nginx production routing, or PostgreSQL.

## Requirements

- Docker Desktop

## Start the system

```bash
docker compose up --build
```

Or run it in the background:

```bash
docker compose up --build -d
```

## Access lifetimes

- **Temporary Access TTL:** 15 minutes (`ACCESS_TTL_SECONDS=900`)
- **Authenticated ERP Session:** 30 minutes (`SESSION_TTL_SECONDS=1800`)

## Flow

```text
Create Access
    ↓
Temporary URL + passkey
    ↓
Argon2 verification
    ↓
Temporary record deleted
    ↓
Secure session cookie
    ↓
ERP accessed through gateway
    ↓
Logout/session expiry
```

The browser reaches the ERP only at `http://localhost:3000/erp`. `http://localhost:4000` is not published to the host.

## Test gateway health

```bash
curl http://localhost:3000/health
```

Expected:

```json
{"status":"ok","service":"access-gateway","redis":"connected"}
```

## Generate temporary access

```bash
curl -X POST http://localhost:3000/dev/create-access
```

The response includes:

- `accessId`
- `passkey` (shown once; never stored in Redis)
- `url`
- `expiresInSeconds`

## Open the access URL

Copy the returned `url` into a browser. Enter the returned `passkey` and choose **Continue**.

If the passkey is correct, the gateway:

1. Deletes the one-time access record
2. Creates an authenticated Redis session
3. Sets an HttpOnly `erp_session` cookie
4. Redirects to `/erp`

## Confirm one-time use

Revisit the same temporary URL. It should now show **Access expired**.

## Confirm ERP protection

```bash
curl http://localhost:4000
```

This should fail. The mock ERP is only reachable on the Docker private network.

```bash
curl http://localhost:3000/erp
```

Without a session cookie this should be denied.

## Session status

```bash
curl --cookie-jar cookies.txt --cookie cookies.txt http://localhost:3000/dev/session-status
```

## Logout

```bash
curl -X POST --cookie-jar cookies.txt --cookie cookies.txt http://localhost:3000/logout
```

## SERPA Telegram bot

The local bot uses long polling. It never stores the BotFather token in source or README.

1. Paste the BotFather token into `.env` as `TELEGRAM_BOT_TOKEN`.
2. Start or rebuild the bot:

```bash
docker compose up -d --build access-gateway telegram-bot
```

3. Open `@agserpa_bot` and send `/whoami`.
4. Put the numeric Telegram user ID into `.env`:

```bash
TELEGRAM_ALLOWED_USER_IDS=<your-numeric-id>
```

5. Restart the bot:

```bash
docker compose restart telegram-bot
```

6. Then test `/start`, `/access`, and `/status`.

`/whoami` works even before any administrator IDs are configured. Privileged commands stay denied until your ID is added.

## Automated checks

With the stack running:

```bash
node scripts/validate-phase2.js
```

## Stop the system

```bash
docker compose down
```

## Remove containers and Redis data

```bash
docker compose down -v
```
