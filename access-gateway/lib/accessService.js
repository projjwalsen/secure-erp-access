const crypto = require("crypto");
const argon2 = require("argon2");

function accessKey(accessId) {
  return `access:${accessId}`;
}

function generateAccessId() {
  return crypto.randomBytes(4).toString("hex");
}

function generatePasskey(length = 8) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let passkey = "";

  for (let index = 0; index < length; index += 1) {
    passkey += alphabet[crypto.randomInt(alphabet.length)];
  }

  return passkey;
}

function createAccessService({ redisClient, accessTtlSeconds, publicBaseUrl, loadJson, securityLog }) {
  async function createTemporaryAccess({ ip, userAgent, protocol } = {}) {
    const accessId = generateAccessId();
    const passkey = generatePasskey();
    const passkeyHash = await argon2.hash(passkey, {
      type: argon2.argon2id,
    });

    const record = {
      passkeyHash,
      createdAt: new Date().toISOString(),
      attempts: 0,
      status: "active",
    };

    await redisClient.set(accessKey(accessId), JSON.stringify(record), {
      EX: accessTtlSeconds,
    });

    securityLog("ACCESS_CREATED", {
      accessId,
      ip,
      userAgent,
      protocol,
    });

    return {
      accessId,
      passkey,
      url: `${publicBaseUrl}/access/${accessId}`,
      expiresInSeconds: accessTtlSeconds,
    };
  }

  async function listAccessKeys() {
    const keys = await redisClient.keys("access:*");
    return Array.isArray(keys) ? keys : [];
  }

  async function listActiveAccess() {
    const accesses = [];

    for (const key of await listAccessKeys()) {
      const record = await loadJson(key);
      const expiresInSeconds = await redisClient.ttl(key);

      if (!record || record.status !== "active" || expiresInSeconds < 0) {
        continue;
      }

      accesses.push({
        accessId: String(key).slice("access:".length),
        expiresInSeconds,
        attempts: Number(record.attempts || 0),
      });
    }

    accesses.sort((left, right) => left.expiresInSeconds - right.expiresInSeconds);
    return accesses;
  }

  async function revokeAccess(accessId, audit = {}) {
    const key = accessKey(accessId);
    const record = await loadJson(key);

    if (!record) {
      return false;
    }

    await redisClient.del(key);
    securityLog("ACCESS_REVOKED", {
      accessId,
      ip: audit.ip,
      userAgent: audit.userAgent,
      protocol: audit.protocol,
    });
    return true;
  }

  async function revokeAllAccess(audit = {}) {
    const keys = await listAccessKeys();
    let revoked = 0;

    for (const key of keys) {
      await redisClient.del(key);
      revoked += 1;
    }

    if (revoked > 0) {
      securityLog("ACCESS_REVOKED", {
        revoked,
        ip: audit.ip,
        userAgent: audit.userAgent,
        protocol: audit.protocol,
      });
    }

    return revoked;
  }

  return {
    accessKey,
    createTemporaryAccess,
    listActiveAccess,
    revokeAccess,
    revokeAllAccess,
  };
}

module.exports = {
  createAccessService,
};
