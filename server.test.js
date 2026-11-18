"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

process.env.DATABASE_URL = "postgres://127.0.0.1:1/virtualsim-test";
process.env.JWT_SECRET = crypto.randomBytes(48).toString("base64url");
process.env.ADMIN_API_KEY = crypto.randomBytes(48).toString("base64url");
process.env.DATA_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");

const { app } = require("./server");

test("admin reset requires the admin key and explicit confirmation", async () => {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const url = `http://127.0.0.1:${server.address().port}/admin/reset-users`;

  try {
    const unauthorized = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirm: true })
    });
    assert.equal(unauthorized.status, 401);

    const unconfirmed = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-admin-key": process.env.ADMIN_API_KEY
      },
      body: JSON.stringify({ confirm: false })
    });
    assert.equal(unconfirmed.status, 400);
    assert.deepEqual(await unconfirmed.json(), {
      error: "Set confirm to true to reset all users and number assignments."
    });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
