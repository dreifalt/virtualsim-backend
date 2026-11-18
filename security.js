"use strict";

const crypto = require("node:crypto");

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function normalizePhoneNumber(value) {
  const normalized = String(value || "").replace(/[^\d+]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) {
    throw new TypeError("Phone number must be in E.164 format.");
  }
  return normalized;
}

function extractOtp(message) {
  return String(message || "").match(/(?<!\d)\d{4,8}(?!\d)/)?.[0] || "";
}

function createPhoneOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashPhoneOtp(phoneNumber, code, key) {
  return crypto.createHmac("sha256", key)
    .update(`${phoneNumber}:${code}`, "utf8")
    .digest("hex");
}

function encryptText(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(String(value), "utf8"),
    cipher.final()
  ]);
  return { ciphertext, iv, tag: cipher.getAuthTag() };
}

function decryptText(ciphertext, iv, tag, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]).toString("utf8");
}

function createEd25519PublicKey(value) {
  const key = String(value || "").trim();
  if (!key) throw new TypeError("Telnyx public key is not configured.");
  if (key.includes("BEGIN PUBLIC KEY")) return crypto.createPublicKey(key);

  const bytes = /^[0-9a-f]{64}$/i.test(key)
    ? Buffer.from(key, "hex")
    : Buffer.from(key, "base64");
  if (bytes.length === 32) {
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    return crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, bytes]),
      format: "der",
      type: "spki"
    });
  }
  return crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
}

function verifyTelnyxSignature({ rawBody, signature, timestamp, publicKey, now = Date.now() }) {
  if (!rawBody || !signature || !timestamp || !publicKey || !/^\d+$/.test(String(timestamp))) {
    return false;
  }
  const timestampSeconds = Number(timestamp);
  if (!Number.isSafeInteger(timestampSeconds) ||
      Math.abs(Math.floor(now / 1000) - timestampSeconds) > 300) {
    return false;
  }
  const signatureBytes = Buffer.from(String(signature), "base64");
  if (signatureBytes.length !== 64) return false;

  try {
    const signedPayload = Buffer.concat([
      Buffer.from(`${timestamp}|`, "utf8"),
      Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), "utf8")
    ]);
    return crypto.verify(
      null,
      signedPayload,
      createEd25519PublicKey(publicKey),
      signatureBytes
    );
  } catch (_error) {
    return false;
  }
}

function decodeBase64Key(value) {
  if (value.includes("BEGIN PUBLIC KEY")) return value;
  const der = Buffer.from(value, "base64");
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function verifyAdMobSignature(rawQuery, key) {
  const signatureMarker = "signature=";
  const signatureIndex = rawQuery.indexOf(signatureMarker);
  if (signatureIndex < 2 || rawQuery[signatureIndex - 1] !== "&") return null;

  const keyIdMatch = rawQuery.slice(signatureIndex).match(/(?:^|&)key_id=(\d+)(?:&|$)/);
  const signatureMatch = rawQuery.slice(signatureIndex).match(/(?:^|&)signature=([^&]+)(?:&|$)/);
  if (!keyIdMatch || !signatureMatch) return null;

  const signedQuery = rawQuery.slice(0, signatureIndex - 1);
  const signature = Buffer.from(decodeURIComponent(signatureMatch[1]), "base64url");
  const publicKey = decodeBase64Key(key);
  const valid = crypto.verify(
    "sha256",
    Buffer.from(signedQuery, "utf8"),
    { key: publicKey, dsaEncoding: "der" },
    signature
  );
  if (!valid) return null;

  const params = new URLSearchParams(rawQuery);
  return {
    keyId: keyIdMatch[1],
    params,
    transactionId: params.get("transaction_id"),
    customData: params.get("custom_data"),
    rewardAmount: Number(params.get("reward_amount")),
    timestamp: Number(params.get("timestamp"))
  };
}

module.exports = {
  decryptText,
  encryptText,
  createPhoneOtp,
  extractOtp,
  hashPhoneOtp,
  normalizePhoneNumber,
  safeEqual,
  verifyAdMobSignature,
  verifyTelnyxSignature
};
