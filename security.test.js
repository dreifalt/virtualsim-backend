"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  decryptText,
  encryptText,
  extractOtp,
  normalizePhoneNumber,
  verifyAdMobSignature,
  verifyTelnyxSignature
} = require("./security");
const { inventoryRecord, parseInboundSms } = require("./telnyx");

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

test("Telnyx Ed25519 signatures authenticate raw payloads and reject stale callbacks", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const rawBody = Buffer.from('{"data":{"event_type":"message.received"}}');
  const signature = crypto.sign(
    null,
    Buffer.concat([Buffer.from(`${timestamp}|`), rawBody]),
    privateKey
  ).toString("base64");
  const input = { rawBody, signature, timestamp, publicKey: publicKeyPem };
  assert.equal(verifyTelnyxSignature(input), true);
  assert.equal(verifyTelnyxSignature({ ...input, rawBody: Buffer.from("tampered") }), false);
  assert.equal(verifyTelnyxSignature({ ...input, timestamp: "1" }), false);
});

test("Telnyx inventory uses the VIP tag and maps supported countries", () => {
  const number = inventoryRecord({
    id: "provider-id",
    phone_number: "+46701234567",
    country_iso_alpha2: "SE",
    status: "active",
    tags: ["vip"]
  });
  assert.equal(number.country, "Sweden");
  assert.equal(number.numberType, "VIP_PRIVATE");
  assert.equal(inventoryRecord({
    id: "free-id",
    phone_number: "+12125550148",
    country_iso_alpha2: "US",
    status: "active",
    tags: []
  }).numberType, "FREE_POOL");
  assert.equal(inventoryRecord({
    id: "unsupported",
    phone_number: "+999123456",
    country_iso_alpha2: "ZZ",
    status: "active",
    tags: []
  }), null);
});

test("Telnyx inbound parser accepts only complete received-message events", () => {
  const message = parseInboundSms({
    data: {
      id: "event-id",
      event_type: "message.received",
      payload: {
        id: "message-id",
        from: { phone_number: "+12125550149" },
        to: [{ phone_number: "+12125550148" }],
        text: "Your code is 482901."
      }
    }
  });
  assert.equal(message.messageId, "message-id");
  assert.equal(message.to, "+12125550148");
  assert.equal(parseInboundSms({ data: { event_type: "message.sent" } }), null);
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
