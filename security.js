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

function plivoSignaturePayload(url, nonce, params) {
  const fields = Object.entries(params)
    .filter(([key, value]) => key && value !== undefined && value !== null)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => `${key}${value}`)
    .join("");
  return `${url}.${fields}.${nonce}`;
}

function verifyPlivoSignature({ url, nonce, authToken, signature, params }) {
  if (!url || !nonce || !authToken || !signature) return false;
  const expected = crypto
    .createHmac("sha256", authToken)
    .update(plivoSignaturePayload(url, nonce, params), "utf8")
    .digest("base64");
  return String(signature)
    .split(",")
    .some((candidate) => safeEqual(candidate.trim(), expected));
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
  extractOtp,
  normalizePhoneNumber,
  plivoSignaturePayload,
  safeEqual,
  verifyAdMobSignature,
  verifyPlivoSignature
};
