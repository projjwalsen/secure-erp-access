const TelegramBot = require("node-telegram-bot-api");

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_ALLOWED_USER_IDS = process.env.TELEGRAM_ALLOWED_USER_IDS || "";
const ACCESS_GATEWAY_INTERNAL_URL = (
  process.env.ACCESS_GATEWAY_INTERNAL_URL || "http://access-gateway:3000"
).replace(/\/$/, "");
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || "";
const TELEGRAM_POLLING = process.env.TELEGRAM_POLLING !== "false";

const PRIVILEGED_COMMANDS = new Set(["/access", "/status", "/revoke", "/revokeall", "/help"]);

function sanitizeError(error) {
  return String(error?.message || error)
    .replace(/bot\d+:[A-Za-z0-9_-]+/g, "bot[redacted]")
    .replace(/\/bot[^/\s]+/g, "/bot[redacted]");
}

function parseAllowedUserIds(value) {
  return String(value)
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function commandName(text = "") {
  const [raw] = String(text).trim().split(/\s+/);
  return raw.split("@")[0].toLowerCase();
}

function isAuthorized(userId, allowedIds) {
  return allowedIds.includes(String(userId));
}

function formatDuration(seconds) {
  const safe = Math.max(0, Number(seconds) || 0);
  const minutes = Math.floor(safe / 60);
  const remainingSeconds = safe % 60;
  return `${minutes}m ${String(remainingSeconds).padStart(2, "0")}s`;
}

function formatMinutes(seconds) {
  const minutes = Math.max(1, Math.round((Number(seconds) || 0) / 60));
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function startHelpMessage() {
  return [
    "🔐 SERPA Secure ERP Access",
    "",
    "Available commands:",
    "",
    "/access",
    "Create temporary ERP access",
    "",
    "/status",
    "Show active temporary accesses",
    "",
    "/revoke <accessId>",
    "Revoke one access",
    "",
    "/revokeall",
    "Revoke all temporary accesses",
    "",
    "/whoami",
    "Show your Telegram user ID",
    "",
    "/help",
    "Show available commands",
  ].join("\n");
}

async function gatewayRequest(pathname, options = {}) {
  const response = await fetch(`${ACCESS_GATEWAY_INTERNAL_URL}${pathname}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      "X-Internal-API-Key": INTERNAL_API_KEY,
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let body = {};

  try {
    body = text ? JSON.parse(text) : {};
  } catch (_error) {
    body = {};
  }

  return { status: response.status, body };
}

function startBot() {
  if (!TELEGRAM_BOT_TOKEN) {
    console.error("TELEGRAM_BOT_TOKEN is missing. Paste the BotFather token into the project .env file.");
    process.exit(1);
  }

  if (!INTERNAL_API_KEY) {
    console.error("INTERNAL_API_KEY is missing. Add a local internal API key to the project .env file.");
    process.exit(1);
  }

  const allowedIds = parseAllowedUserIds(TELEGRAM_ALLOWED_USER_IDS);

  if (allowedIds.length === 0) {
    console.log("No authorized Telegram administrators configured.");
  }

  const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: TELEGRAM_POLLING });

  bot.on("polling_error", (error) => {
    console.error("Telegram polling error:", sanitizeError(error));
  });

  bot.on("message", async (msg) => {
    if (!msg?.text || !msg.text.startsWith("/")) {
      return;
    }

    const chatId = msg.chat.id;
    const userId = msg.from?.id;
    const command = commandName(msg.text);
    const authorized = isAuthorized(userId, allowedIds);

    try {
      if (command === "/whoami") {
        const username = msg.from?.username ? `@${msg.from.username}` : "Not set";
        await bot.sendMessage(
          chatId,
          ["👤 SERPA Identity", "", "Telegram User ID:", String(userId), "", "Username:", username].join("\n")
        );
        return;
      }

      if (command === "/start") {
        if (!authorized) {
          await bot.sendMessage(chatId, "🔒 SERPA is restricted to authorized administrators.");
          return;
        }

        await bot.sendMessage(chatId, startHelpMessage());
        return;
      }

      if (!authorized && PRIVILEGED_COMMANDS.has(command)) {
        await bot.sendMessage(chatId, "⛔ Unauthorized.");
        return;
      }

      if (command === "/help") {
        await bot.sendMessage(chatId, startHelpMessage());
        return;
      }

      if (command === "/access") {
        const { status, body } = await gatewayRequest("/internal/access/create", {
          method: "POST",
        });

        if (status !== 201 || !body.accessId || !body.passkey || !body.url) {
          await bot.sendMessage(chatId, "🔒 SERPA\n\nTemporary access could not be created. Try again later.");
          return;
        }

        await bot.sendMessage(
          chatId,
          [
            "🔐 SERPA Secure ERP Access",
            "",
            "Temporary access created.",
            "",
            "URL:",
            body.url,
            "",
            "Passkey:",
            body.passkey,
            "",
            "Valid for:",
            formatMinutes(body.expiresInSeconds),
            "",
            "Access ID:",
            body.accessId,
            "",
            "⚠️ This code is one-time use.",
          ].join("\n")
        );
        return;
      }

      if (command === "/status") {
        const { status, body } = await gatewayRequest("/internal/access/status");

        if (status !== 200) {
          await bot.sendMessage(chatId, "🔒 SERPA\n\nUnable to read temporary access status.");
          return;
        }

        const accesses = Array.isArray(body.accesses) ? body.accesses : [];

        if (accesses.length === 0) {
          await bot.sendMessage(chatId, "🔒 SERPA\n\nNo active temporary ERP access sessions.");
          return;
        }

        const lines = [
          "🔐 SERPA Active Access",
          "",
          `Active temporary accesses: ${accesses.length}`,
        ];

        accesses.forEach((access, index) => {
          lines.push("");
          lines.push(`${index + 1}. ${access.accessId}`);
          lines.push(`Expires in: ${formatDuration(access.expiresInSeconds)}`);
          lines.push(`Failed attempts: ${access.attempts}`);
        });

        await bot.sendMessage(chatId, lines.join("\n"));
        return;
      }

      if (command === "/revoke") {
        const accessId = String(msg.text).trim().split(/\s+/)[1];

        if (!accessId) {
          await bot.sendMessage(chatId, "Usage:\n/revoke <accessId>");
          return;
        }

        const { status } = await gatewayRequest(`/internal/access/revoke/${encodeURIComponent(accessId)}`, {
          method: "POST",
        });

        if (status === 200) {
          await bot.sendMessage(chatId, `✅ SERPA\n\nAccess ${accessId} revoked.`);
          return;
        }

        await bot.sendMessage(
          chatId,
          `ℹ️ SERPA\n\nAccess ${accessId} was already expired or does not exist.`
        );
        return;
      }

      if (command === "/revokeall") {
        const { status, body } = await gatewayRequest("/internal/access/revoke-all", {
          method: "POST",
        });

        if (status !== 200) {
          await bot.sendMessage(chatId, "🔒 SERPA\n\nUnable to revoke temporary access links.");
          return;
        }

        await bot.sendMessage(
          chatId,
          ["🔒 SERPA", "", "All temporary ERP access links revoked.", "", "Revoked:", String(body.revoked || 0)].join("\n")
        );
      }
    } catch (error) {
      console.error("SERPA command error:", sanitizeError(error));
      await bot.sendMessage(chatId, "🔒 SERPA\n\nA temporary error occurred. Try again later.");
    }
  });

  console.log("SERPA Telegram bot started.");
}

startBot();
