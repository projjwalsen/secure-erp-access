const path = require("path");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const { rateLimit } = require("express-rate-limit");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { createClient } = require("redis");
const argon2 = require("argon2");
const { securityLog, requestAudit } = require("./lib/audit");
const { createAccessService } = require("./lib/accessService");
const {
  loginPage,
  expiredPage,
  invalidPasskeyPage,
  revokedPage,
  loggedOutPage,
  errorPage,
  rateLimitedPage,
} = require("./lib/pages");
const { createRequireErpSession, sessionKey } = require("./middleware/requireErpSession");
const { createRequireInternalApiKey } = require("./middleware/requireInternalApiKey");

const PORT = Number(process.env.PORT || 3000);
const REDIS_HOST = process.env.REDIS_HOST || "redis";
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS || 900);
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 1800);
const MAX_ACCESS_ATTEMPTS = Number(process.env.MAX_ACCESS_ATTEMPTS || 5);
const COOKIE_NAME = process.env.COOKIE_NAME || "erp_session";
const NODE_ENV = process.env.NODE_ENV || "development";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const ENABLE_DEV_ENDPOINTS = process.env.ENABLE_DEV_ENDPOINTS === "true";
const ERP_UPSTREAM = process.env.ERP_UPSTREAM || "http://mock-erp:4000";
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || "";

function normalizePublicBaseUrl(value) {
  const fallback = `http://localhost:${PORT}`;
  const raw = String(value || "").trim();

  if (!raw) {
    console.log("PUBLIC_BASE_URL is missing; falling back to http://localhost:3000");
    return fallback;
  }

  return raw.replace(/\/+$/, "");
}

const PUBLIC_BASE_URL = normalizePublicBaseUrl(
  process.env.PUBLIC_BASE_URL || process.env.PUBLIC_ACCESS_BASE_URL
);

const redisClient = createClient({
  socket: {
    host: REDIS_HOST,
    port: REDIS_PORT,
    reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
  },
});

redisClient.on("error", (error) => {
  console.error("Redis error:", error.message);
});

const app = express();

if (TRUST_PROXY) {
  app.set("trust proxy", 1);
}

// CSP keeps Helmet enabled. Styles live in /static/styles.css so we do not
// need style-src 'unsafe-inline'. upgrade-insecure-requests is enabled only
// when the public surface is HTTPS (COOKIE_SECURE=true).
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "upgrade-insecure-requests": COOKIE_SECURE ? [] : null,
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "form-action": ["'self'"],
      },
    },
  })
);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser(process.env.SESSION_SECRET));
app.use("/static", express.static(path.join(__dirname, "public")));

function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "strict",
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: SESSION_TTL_SECONDS * 1000,
  };
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: "strict",
    secure: COOKIE_SECURE,
    path: "/",
  });
}

async function loadJson(key) {
  const raw = await redisClient.get(key);

  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw);
  } catch (_error) {
    return null;
  }
}

const accessService = createAccessService({
  redisClient,
  accessTtlSeconds: ACCESS_TTL_SECONDS,
  publicBaseUrl: PUBLIC_BASE_URL,
  loadJson,
  securityLog,
});
const { accessKey } = accessService;
const requireInternalApiKey = createRequireInternalApiKey(INTERNAL_API_KEY);

function requireDevEndpoints(_req, res, next) {
  if (ENABLE_DEV_ENDPOINTS) {
    return next();
  }

  return res.status(404).json({ error: "Not found" });
}

const requireErpSession = createRequireErpSession({
  redisClient,
  cookieName: COOKIE_NAME,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  clearSessionCookie,
});

const rateLimitValidate = TRUST_PROXY
  ? { trustProxy: true }
  : { xForwardedForHeader: false, trustProxy: false };

const accessPageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  validate: rateLimitValidate,
  handler: (req, res) => {
    res.status(429).type("html").send(rateLimitedPage());
  },
});

const accessAttemptLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  validate: rateLimitValidate,
  handler: (req, res) => {
    res.status(429).type("html").send(rateLimitedPage());
  },
});

const createAccessLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  validate: rateLimitValidate,
  handler: (req, res) => {
    res.status(429).json({ error: "Too many requests" });
  },
});

app.get("/health", async (_req, res) => {
  try {
    if (!redisClient.isOpen) {
      throw new Error("Redis client is not open");
    }

    await redisClient.ping();
    return res.json({
      status: "ok",
      service: "access-gateway",
      redis: "connected",
    });
  } catch (_error) {
    return res.status(503).json({
      status: "unhealthy",
      service: "access-gateway",
      redis: "disconnected",
    });
  }
});

app.get("/logged-out", (_req, res) => {
  res.type("html").send(loggedOutPage());
});

app.post("/logout", async (req, res, next) => {
  try {
    const sessionId = req.cookies?.[COOKIE_NAME];

    if (sessionId) {
      await redisClient.del(sessionKey(sessionId));
      securityLog("SESSION_LOGOUT", requestAudit(req));
    }

    clearSessionCookie(res);
    return res.redirect("/logged-out");
  } catch (error) {
    return next(error);
  }
});

app.get("/dev/session-status", requireDevEndpoints, async (req, res, next) => {
  try {
    const sessionId = req.cookies?.[COOKIE_NAME];

    if (!sessionId) {
      return res.json({ authenticated: false });
    }

    const key = sessionKey(sessionId);
    const record = await loadJson(key);
    const expiresInSeconds = await redisClient.ttl(key);

    if (!record || expiresInSeconds < 0) {
      return res.json({ authenticated: false });
    }

    return res.json({
      authenticated: true,
      expiresInSeconds,
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/dev/create-access", requireDevEndpoints, createAccessLimiter, async (req, res, next) => {
  try {
    const created = await accessService.createTemporaryAccess(requestAudit(req));

    return res.status(201).json(created);
  } catch (error) {
    return next(error);
  }
});

app.post("/internal/access/create", requireInternalApiKey, async (req, res, next) => {
  try {
    const created = await accessService.createTemporaryAccess(requestAudit(req));

    return res.status(201).json(created);
  } catch (error) {
    return next(error);
  }
});

app.get("/internal/access/status", requireInternalApiKey, async (_req, res, next) => {
  try {
    const accesses = await accessService.listActiveAccess();
    return res.json({ accesses });
  } catch (error) {
    return next(error);
  }
});

app.post("/internal/access/revoke/:accessId", requireInternalApiKey, async (req, res, next) => {
  try {
    const revoked = await accessService.revokeAccess(req.params.accessId, requestAudit(req));

    if (!revoked) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.json({ revoked: true, accessId: req.params.accessId });
  } catch (error) {
    return next(error);
  }
});

app.post("/internal/access/revoke-all", requireInternalApiKey, async (_req, res, next) => {
  try {
    const revoked = await accessService.revokeAllAccess(requestAudit(req));
    return res.json({ revoked });
  } catch (error) {
    return next(error);
  }
});

app.get("/access/:accessId", accessPageLimiter, async (req, res, next) => {
  try {
    const { accessId } = req.params;
    const record = await loadJson(accessKey(accessId));

    if (!record || record.status !== "active" || !record.passkeyHash) {
      return res.status(410).type("html").send(expiredPage());
    }

    return res.type("html").send(loginPage(accessId));
  } catch (error) {
    return next(error);
  }
});

app.post("/access/:accessId", accessAttemptLimiter, async (req, res, next) => {
  try {
    const { accessId } = req.params;
    const submittedPasskey = String(req.body.passkey || "").trim();
    const key = accessKey(accessId);
    const record = await loadJson(key);
    const audit = requestAudit(req, { accessId });

    if (!record || record.status !== "active" || !record.passkeyHash) {
      return res.status(410).type("html").send(expiredPage());
    }

    let verified = false;

    try {
      verified = await argon2.verify(record.passkeyHash, submittedPasskey);
    } catch (_error) {
      verified = false;
    }

    if (verified) {
      await redisClient.del(key);

      const sessionId = generateSessionId();
      const now = new Date().toISOString();

      await redisClient.set(
        sessionKey(sessionId),
        JSON.stringify({
          createdAt: now,
          lastActivity: now,
          authMethod: "temporary-passkey",
        }),
        { EX: SESSION_TTL_SECONDS }
      );

      res.cookie(COOKIE_NAME, sessionId, sessionCookieOptions());
      securityLog("ACCESS_GRANTED", audit);
      securityLog("SESSION_CREATED", audit);
      return res.redirect("/erp");
    }

    record.attempts = Number(record.attempts || 0) + 1;

    if (record.attempts >= MAX_ACCESS_ATTEMPTS) {
      await redisClient.del(key);
      securityLog("ACCESS_REVOKED", {
        ...audit,
        attempts: record.attempts,
      });
      return res.status(403).type("html").send(revokedPage());
    }

    // KEEPTTL updates the attempt count without resetting ACCESS_TTL_SECONDS.
    await redisClient.set(key, JSON.stringify(record), {
      KEEPTTL: true,
    });

    securityLog("ACCESS_FAILED", {
      ...audit,
      attempts: record.attempts,
    });

    return res.status(401).type("html").send(invalidPasskeyPage(accessId, record.attempts, MAX_ACCESS_ATTEMPTS));
  } catch (error) {
    return next(error);
  }
});

app.use(
  "/erp",
  requireErpSession,
  createProxyMiddleware({
    target: ERP_UPSTREAM,
    changeOrigin: true,
    pathRewrite(path, req) {
      const originalPath = (req.originalUrl || path).split("?")[0];
      const rewritten = originalPath.replace(/^\/erp/, "");
      return rewritten === "" ? "/" : rewritten;
    },
    on: {
      error(error, _req, res) {
        console.error("ERP proxy error:", error.message);

        if (!res.headersSent) {
          res.status(502).type("html").send(errorPage("The ERP service is temporarily unavailable."));
        }
      },
    },
  })
);

app.use((req, res) => {
  if (req.accepts("html")) {
    return res.status(404).type("html").send(errorPage("The requested page was not found."));
  }

  return res.status(404).json({ error: "Not found" });
});

app.use((error, req, res, _next) => {
  console.error(error);

  if (res.headersSent) {
    return;
  }

  if (req.accepts("html")) {
    return res.status(500).type("html").send(errorPage());
  }

  return res.status(500).json({ error: "Internal server error" });
});

async function connectRedis() {
  for (let attempt = 1; attempt <= 30; attempt += 1) {
    try {
      if (!redisClient.isOpen) {
        await redisClient.connect();
      }

      await redisClient.ping();
      return;
    } catch (error) {
      console.error(`Redis connection attempt ${attempt} failed: ${error.message}`);

      if (attempt === 30) {
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

async function start() {
  await connectRedis();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`access-gateway listening on port ${PORT}`);
    console.log(`public base URL: ${PUBLIC_BASE_URL}`);
    console.log(`trust proxy: ${TRUST_PROXY}`);
    console.log(`cookie secure: ${COOKIE_SECURE}`);
    console.log(`dev endpoints: ${ENABLE_DEV_ENDPOINTS}`);
  });
}

start().catch((error) => {
  console.error("Failed to start access-gateway:", error);
  process.exit(1);
});
