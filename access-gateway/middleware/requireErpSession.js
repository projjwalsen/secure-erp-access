const { securityLog, requestIp, requestUserAgent } = require("../lib/audit");
const { accessDeniedPage } = require("../lib/pages");

function sessionKey(sessionId) {
  return `session:${sessionId}`;
}

function createRequireErpSession({
  redisClient,
  cookieName,
  sessionTtlSeconds,
  clearSessionCookie,
}) {
  return async function requireErpSession(req, res, next) {
    try {
      const sessionId = req.cookies?.[cookieName];

      if (!sessionId) {
        return deny(req, res);
      }

      const key = sessionKey(sessionId);
      const raw = await redisClient.get(key);

      if (!raw) {
        securityLog("SESSION_EXPIRED", {
          ip: requestIp(req),
          userAgent: requestUserAgent(req),
        });
        clearSessionCookie(res);
        return deny(req, res);
      }

      let session;

      try {
        session = JSON.parse(raw);
      } catch (_error) {
        clearSessionCookie(res);
        await redisClient.del(key);
        return deny(req, res);
      }

      const now = Date.now();
      const lastActivity = Date.parse(session.lastActivity);
      const shouldPersistActivity =
        Number.isNaN(lastActivity) || now - lastActivity >= 30_000;

      if (shouldPersistActivity) {
        session.lastActivity = new Date().toISOString();
        await redisClient.set(key, JSON.stringify(session), {
          EX: sessionTtlSeconds,
        });
      } else {
        await redisClient.expire(key, sessionTtlSeconds);
      }

      req.erpSession = session;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

function deny(req, res) {
  if (req.accepts("html")) {
    return res.status(401).type("html").send(accessDeniedPage());
  }

  return res.status(401).json({ error: "unauthorized" });
}

module.exports = {
  createRequireErpSession,
  sessionKey,
};
