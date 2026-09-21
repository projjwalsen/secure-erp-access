#!/usr/bin/env node

const { execSync } = require("child_process");
const { readFileSync } = require("fs");
const { resolve } = require("path");

const BASE = process.env.GATEWAY_BASE || "http://localhost:3000";

function loadDotEnv() {
  const env = {};
  const text = readFileSync(resolve(__dirname, "../.env"), "utf8");

  for (const line of text.split("\n")) {
    if (!line || line.trim().startsWith("#") || !line.includes("=")) {
      continue;
    }

    const index = line.indexOf("=");
    env[line.slice(0, index)] = line.slice(index + 1);
  }

  return env;
}

const DOTENV = loadDotEnv();
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || DOTENV.INTERNAL_API_KEY || "";
const COOKIE_SECURE = (process.env.COOKIE_SECURE || DOTENV.COOKIE_SECURE) === "true";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || DOTENV.PUBLIC_BASE_URL || BASE).replace(/\/+$/, "");
const results = [];

function record(name, passed, detail) {
  results.push({ name, passed, detail });
  const mark = passed ? "PASS" : "FAIL";
  console.log(`${mark}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function fetchRaw(url, options = {}) {
  const response = await fetch(url, { redirect: "manual", ...options });
  const text = await response.text();
  const headers = {};

  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  if (typeof response.headers.getSetCookie === "function") {
    const cookies = response.headers.getSetCookie();
    if (cookies.length) {
      headers["set-cookie"] = cookies[0];
    }
  }

  return { text, headers, status: response.status };
}

function parseSetCookie(headerValue) {
  if (!headerValue) {
    return {};
  }

  const [pair, ...attrs] = headerValue.split(";");
  const eq = pair.indexOf("=");

  return {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1).trim(),
    attrs: attrs.map((item) => item.trim().toLowerCase()),
  };
}

function redis(command) {
  return execSync(`docker compose exec -T redis redis-cli ${command}`, {
    encoding: "utf8",
  }).trim();
}

async function createAccess() {
  const { status, text } = await fetchRaw(`${BASE}/internal/access/create`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Internal-API-Key": INTERNAL_API_KEY,
    },
    body: "{}",
  });

  return { status, body: JSON.parse(text) };
}

async function run() {
  const health = await fetchRaw(`${BASE}/health`);
  const healthBody = JSON.parse(health.text);
  record(
    "Health includes Redis",
    health.status === 200 && healthBody.redis === "connected",
    health.text
  );

  const blockedDev = await fetchRaw(`${BASE}/dev/create-access`, { method: "POST" });
  record(
    "Dev create-access is disabled by default",
    blockedDev.status === 404,
    `status=${blockedDev.status}`
  );

  const created = await createAccess();
  record(
    "TEST 1 Create temporary access",
    created.status === 201 &&
      created.body.accessId &&
      created.body.passkey &&
      created.body.url === `${PUBLIC_BASE_URL}/access/${created.body.accessId}`,
    JSON.stringify({
      accessId: created.body.accessId,
      url: created.body.url,
      expiresInSeconds: created.body.expiresInSeconds,
    })
  );

  const stored = redis(`GET access:${created.body.accessId}`);
  const storedJson = JSON.parse(stored);
  record(
    "Passkey is hashed in Redis",
    Boolean(storedJson.passkeyHash) && !Object.hasOwn(storedJson, "passkey") && !stored.includes(created.body.passkey),
    "Redis record contains passkeyHash only"
  );

  const ttlBefore = Number(redis(`TTL access:${created.body.accessId}`));
  const wrong = await fetchRaw(`${BASE}/access/${created.body.accessId}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "passkey=WRONGCODE",
  });
  const ttlAfter = Number(redis(`TTL access:${created.body.accessId}`));
  const afterFail = JSON.parse(redis(`GET access:${created.body.accessId}`));
  record(
    "TEST 2 Wrong passkey increments attempts without resetting TTL",
    wrong.status === 401 &&
      afterFail.attempts === 1 &&
      ttlAfter > 0 &&
      ttlAfter <= ttlBefore,
    `status=${wrong.status} attempts=${afterFail.attempts} ttl ${ttlBefore}->${ttlAfter}`
  );

  const revokeAccess = await createAccess();
  let revokeStatus = 0;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const result = await fetchRaw(`${BASE}/access/${revokeAccess.body.accessId}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "passkey=WRONGCODE",
    });
    revokeStatus = result.status;
  }

  const revokedRecord = redis(`GET access:${revokeAccess.body.accessId}`);
  record(
    "TEST 3 Five wrong attempts revoke access",
    revokeStatus === 403 && revokedRecord === "",
    `finalStatus=${revokeStatus}`
  );

  const loginAccess = await createAccess();
  const login = await fetchRaw(`${BASE}/access/${loginAccess.body.accessId}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `passkey=${encodeURIComponent(loginAccess.body.passkey)}`,
  });
  const sessionCookie = parseSetCookie(login.headers["set-cookie"]);
  record(
    "TEST 4 Correct passkey creates session and redirects to /erp",
    login.status === 302 &&
      login.headers.location === "/erp" &&
      sessionCookie.name === "erp_session" &&
      sessionCookie.attrs.includes("httponly") &&
      sessionCookie.attrs.includes("samesite=strict") &&
      sessionCookie.attrs.includes("secure") === COOKIE_SECURE,
    `status=${login.status} location=${login.headers.location}`
  );

  const reuse = await fetchRaw(`${BASE}/access/${loginAccess.body.accessId}`);
  record("TEST 5 Reuse original access URL", reuse.status === 410, `status=${reuse.status}`);

  let port4000Failed = false;

  try {
    await fetch("http://localhost:4000/", { signal: AbortSignal.timeout(1500) });
  } catch (error) {
    port4000Failed = /fetch failed|ECONNREFUSED|timeout|AbortError/i.test(String(error));
  }

  record("TEST 6 localhost:4000 is not reachable", port4000Failed, "connection failed as expected");

  const unauth = await fetchRaw(`${BASE}/erp`);
  record("TEST 7 /erp without session is denied", unauth.status === 401, `status=${unauth.status}`);

  const cookieHeader = `${sessionCookie.name}=${sessionCookie.value}`;
  const dashboard = await fetchRaw(`${BASE}/erp`, {
    headers: { cookie: cookieHeader },
  });
  record(
    "TEST 8 /erp with valid session shows dashboard",
    dashboard.status === 200 && dashboard.text.includes("Authenticated ERP session is active."),
    `status=${dashboard.status}`
  );

  const logout = await fetchRaw(`${BASE}/logout`, {
    method: "POST",
    headers: { cookie: cookieHeader },
  });
  record(
    "TEST 9 Logout destroys session",
    logout.status === 302 && logout.headers.location === "/logged-out",
    `status=${logout.status}`
  );

  const afterLogout = await fetchRaw(`${BASE}/erp`, {
    headers: { cookie: cookieHeader },
  });
  record(
    "TEST 10 /erp after logout is denied",
    afterLogout.status === 401,
    `erp=${afterLogout.status}`
  );

  const expiryAccess = await createAccess();
  const expiryLogin = await fetchRaw(`${BASE}/access/${expiryAccess.body.accessId}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `passkey=${encodeURIComponent(expiryAccess.body.passkey)}`,
  });
  const expiryCookie = parseSetCookie(expiryLogin.headers["set-cookie"]);
  const sessionKeys = redis("KEYS session:*")
    .split(/\s+/)
    .filter(Boolean);

  for (const key of sessionKeys) {
    redis(`DEL ${key}`);
  }

  const expiredErp = await fetchRaw(`${BASE}/erp`, {
    headers: { cookie: `${expiryCookie.name}=${expiryCookie.value}` },
  });
  record(
    "TEST 11 Expired session is denied",
    expiredErp.status === 401 && expiredErp.text.includes("Access denied"),
    `status=${expiredErp.status}`
  );

  const failed = results.filter((item) => !item.passed);
  console.log("");
  console.log(`${results.length - failed.length}/${results.length} checks passed`);

  if (failed.length) {
    process.exit(1);
  }
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
