const SENSITIVE_KEYS = new Set([
  "passkey",
  "sessionId",
  "cookie",
  "cookies",
  "passkeyHash",
  "authorization",
  "token",
  "botToken",
  "apiKey",
  "internalApiKey",
]);

function securityLog(event, details = {}) {
  const payload = {
    timestamp: new Date().toISOString(),
    event,
  };

  for (const [key, value] of Object.entries(details)) {
    if (SENSITIVE_KEYS.has(key)) {
      continue;
    }

    payload[key] = value;
  }

  console.log(JSON.stringify(payload));
}

function requestIp(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function requestUserAgent(req) {
  return req.get("user-agent") || "unknown";
}

function requestProtocol(req) {
  return req.protocol || "http";
}

function requestAudit(req, extra = {}) {
  return {
    ip: requestIp(req),
    userAgent: requestUserAgent(req),
    protocol: requestProtocol(req),
    ...extra,
  };
}

module.exports = {
  securityLog,
  requestIp,
  requestUserAgent,
  requestProtocol,
  requestAudit,
};
