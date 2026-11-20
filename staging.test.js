"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

process.env.DATABASE_URL = "postgres://127.0.0.1:1/virtualsim-staging-test";
process.env.JWT_SECRET = crypto.randomBytes(48).toString("base64url");
process.env.ADMIN_API_KEY = crypto.randomBytes(48).toString("base64url");
process.env.DATA_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
process.env.NODE_ENV = "staging";
process.env.STAGING_SHARED_FREE_NUMBERS = "true";
process.env.STAGING_AD_REWARD_FALLBACK = "true";

let credits = 0;
let fallbackGranted = false;
Pool.prototype.query = async function (query) {
  if (query.includes("SELECT id, email, phone_number, credits, token_version, two_factor_enabled FROM users")) {
    return {
      rows: [{
        id: "staging-user",
        email: "tester@example.invalid",
        phone_number: null,
        credits,
        token_version: 0,
        two_factor_enabled: false
      }],
      rowCount: 1
    };
  }
  if (query.includes("FROM phone_numbers")) return { rows: [], rowCount: 0 };
  if (query.includes("FROM sms_messages")) return { rows: [], rowCount: 0 };
  throw new Error(`Unexpected staging test query: ${query}`);
};
Pool.prototype.connect = async function () {
  return {
    async query(query, parameters = []) {
      if (query === "BEGIN" || query === "COMMIT" || query === "ROLLBACK") {
        return { rows: [], rowCount: 0 };
      }
      if (query.includes("SELECT credits FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [{ credits }], rowCount: 1 };
      }
      if (query.includes("INSERT INTO ad_rewards")) {
        if (fallbackGranted) return { rows: [], rowCount: 0 };
        fallbackGranted = true;
        return { rows: [{ transaction_id: parameters[0] }], rowCount: 1 };
      }
      if (query.includes("UPDATE users SET credits = credits + $1")) {
        credits += parameters[0];
        return { rows: [{ credits }], rowCount: 1 };
      }
      throw new Error(`Unexpected staging test transaction query: ${query}`);
    },
    release() {}
  };
};

const { app } = require("./server");
const adminKey = process.env.ADMIN_API_KEY;
const authToken = jwt.sign(
  { sub: "staging-user", ver: 0 },
  process.env.JWT_SECRET,
  { expiresIn: "12h", issuer: "virtualsim-master" }
);

async function withServer(action) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    await action(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
}

test("staging mode shares only synthetic numbers and OTP messages", async () => {
  await withServer(async (baseUrl) => {
    const headers = { authorization: `Bearer ${authToken}` };
    const numbersResponse = await fetch(`${baseUrl}/api/numbers`, { headers });
    const numbers = (await numbersResponse.json()).numbers;
    assert.equal(numbersResponse.status, 200);
    assert.deepEqual(numbers, [{
      id: "staging-shared-free-us",
      country: "United States",
      city: "Synthetic test number",
      dialingCode: "+1",
      number: "+15555550100",
      flag: "🇺🇸",
      label: "FREE_SHARED",
      active: true
    }]);

    const messagesResponse = await fetch(`${baseUrl}/api/messages`, { headers });
    const messages = (await messagesResponse.json()).messages;
    assert.equal(messagesResponse.status, 200);
    assert.equal(messages[0].service, "STAGING SYNTHETIC TEST");
    assert.equal(messages[0].code, "246810");
    assert.match(messages[0].message, /not from Telnyx/);
  });
});

test("staging ad fallback grants 10 credits once per account", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/rewards/staging-fallback`, {
      method: "POST",
      headers: { authorization: `Bearer ${authToken}`, "content-type": "application/json" },
      body: "{}"
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      granted: true,
      alreadyClaimed: false,
      creditsAdded: 10,
      credits: 10
    });

    const secondResponse = await fetch(`${baseUrl}/api/rewards/staging-fallback`, {
      method: "POST",
      headers: { authorization: `Bearer ${authToken}`, "content-type": "application/json" },
      body: "{}"
    });
    assert.equal(secondResponse.status, 200);
    assert.deepEqual(await secondResponse.json(), {
      granted: false,
      alreadyClaimed: true,
      credits: 10
    });
  });
});
