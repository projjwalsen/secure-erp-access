const crypto = require("crypto");

function timingSafeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function createRequireInternalApiKey(expectedKey) {
  return function requireInternalApiKey(req, res, next) {
    if (!expectedKey || !timingSafeEqual(req.get("X-Internal-API-Key") || "", expectedKey)) {
      return res.status(401).json({ error: "unauthorized" });
    }

    return next();
  };
}

module.exports = {
  createRequireInternalApiKey,
};
