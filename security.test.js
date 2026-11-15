"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  decryptText,
  encryptText,
  extractOtp,
  normalizePhoneNumber,
  plivoSignaturePayload,
  verifyAdMobSignature,
  verifyPlivoSignature
} = require("./security");

test("phone number normalization accepts E.164 and rejects local numbers", () => {
  assert.equal(normalizePhoneNumber("+1 (212) 555-0148"), "+12125550148");
  assert.throws(() => normalizePhoneNumber("2125550148"), /E.164/);
});

test("OTP extraction returns only a bounded standalone code", () => {
  assert.equal(extractOtp("Your code is 482901."), "482901");
  assert.equal(extractOtp("Tracking number 123456789"), "");
});

test("encrypted values round trip and authenticate their ciphertext", () => {
  const key = crypto.randomBytes(32);
  const encrypted = encryptText("private SMS", key);
  assert.equal(decryptText(encrypted.ciphertext, encrypted.iv, encrypted.tag, key), "private SMS");
  const damaged = Buffer.from(encrypted.ciphertext);
  damaged[0] ^= 1;
  assert.throws(() => decryptText(damaged, encrypted.iv, encrypted.tag, key));
});

test("Plivo V3 signatures cover URL, ordered parameters, and nonce", () => {
  const url = "https://example.test/api/webhook/sms";
  const nonce = "unique-nonce";
  const authToken = "plivo-test-auth-token";
  const params = { To: "+12125550148", Text: "OTP 482901", From: "+12125550149" };
  const signature = crypto
    .createHmac("sha256", authToken)
    .update(plivoSignaturePayload(url, nonce, params))
    .digest("base64");
  assert.equal(verifyPlivoSignature({ url, nonce, authToken, signature, params }), true);
  assert.equal(verifyPlivoSignature({ url, nonce, authToken, signature, params: { ...params, Text: "changed" } }), false);
});

test("AdMob SSV callbacks require a valid ECDSA signature", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signedQuery = "ad_network=1&ad_unit=test&custom_data=one-use&reward_amount=1&reward_item=credits&timestamp=1&transaction_id=tx&user_id=user";
  const signature = crypto.sign("sha256", Buffer.from(signedQuery), privateKey).toString("base64url");
  const rawQuery = `${signedQuery}&signature=${signature}&key_id=7`;
  const result = verifyAdMobSignature(rawQuery, publicKey.export({ type: "spki", format: "pem" }));
  assert.equal(result.transactionId, "tx");
  assert.equal(result.customData, "one-use");
  const tamperedQuery = `${signedQuery.replace("reward_amount=1", "reward_amount=2")}&signature=${signature}&key_id=7`;
  assert.equal(verifyAdMobSignature(tamperedQuery, publicKey.export({ type: "spki", format: "pem" })), null);
});
