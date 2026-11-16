"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  createCredentialConnection,
  deleteCredentialConnection,
  isSipProvisioningConfigured,
  sendSms,
  telnyxRequest,
  updatePhoneNumberConnection
} = require("./telnyx");

test("Telnyx API calls use the v2 endpoint, bearer auth, and retry transient failures", async () => {
  const originalFetch = global.fetch;
  const requests = [];
  global.fetch = async (url, options) => {
    requests.push({ url: String(url), options });
    if (requests.length === 1) {
      return new Response("temporary", { status: 503, headers: { "retry-after": "0.001" } });
    }
    return new Response(JSON.stringify({ data: { id: "connection-id" } }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const response = await telnyxRequest("/credential_connections", {
      method: "POST",
      apiKey: "test-api-key",
      body: { user_name: "testuser" }
    });
    assert.equal(response.data.id, "connection-id");
    assert.equal(requests.length, 2);
    assert.equal(requests[0].url, "https://api.telnyx.com/v2/credential_connections");
    assert.equal(requests[1].options.headers.Authorization, "Bearer test-api-key");
    assert.equal(requests[1].options.body, JSON.stringify({ user_name: "testuser" }));
  } finally {
    global.fetch = originalFetch;
  }
});

test("Telnyx SIP provisioning requires and attaches an outbound voice profile", async () => {
  const originalFetch = global.fetch;
  const originalApiKey = process.env.TELNYX_API_KEY;
  const originalVoiceProfileId = process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID;
  process.env.TELNYX_API_KEY = "test-api-key";
  delete process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID;

  try {
    await assert.rejects(
      createCredentialConnection({ username: "testuser", password: "test-password", userId: "user-id" }),
      (error) => error.status === 503
    );
    assert.equal(isSipProvisioningConfigured(), false);
    delete process.env.TELNYX_API_KEY;
    assert.equal(isSipProvisioningConfigured(), false);
    process.env.TELNYX_API_KEY = "test-api-key";
    process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID = "voice-profile-id";
    assert.equal(isSipProvisioningConfigured(), true);
    let requestBody;
    global.fetch = async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return new Response(JSON.stringify({ data: { id: "connection-id" } }), {
        status: 201,
        headers: { "content-type": "application/json" }
      });
    };
    assert.equal(
      await createCredentialConnection({
        username: "testuser",
        password: "test-password",
        userId: "user-id"
      }),
      "connection-id"
    );
    assert.equal(requestBody.outbound.outbound_voice_profile_id, "voice-profile-id");
  } finally {
    global.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.TELNYX_API_KEY;
    else process.env.TELNYX_API_KEY = originalApiKey;
    if (originalVoiceProfileId === undefined) delete process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID;
    else process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID = originalVoiceProfileId;
  }
});

test("Telnyx cleanup treats already-removed resources as idempotent", async () => {
  const originalFetch = global.fetch;
  const originalApiKey = process.env.TELNYX_API_KEY;
  process.env.TELNYX_API_KEY = "test-api-key";
  global.fetch = async () => new Response(JSON.stringify({ errors: [{ code: "not_found" }] }), {
    status: 404,
    headers: { "content-type": "application/json" }
  });
  try {
    await deleteCredentialConnection("missing-connection");
    await updatePhoneNumberConnection("missing-number", null);
    await assert.rejects(
      updatePhoneNumberConnection("missing-number", "connection-id"),
      /Telnyx rejected/
    );
  } finally {
    global.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.TELNYX_API_KEY;
    else process.env.TELNYX_API_KEY = originalApiKey;
  }
});

test("Telnyx sends app sign-in SMS through the configured messaging profile", async () => {
  const originalFetch = global.fetch;
  const originalApiKey = process.env.TELNYX_API_KEY;
  const originalMessagingProfileId = process.env.TELNYX_MESSAGING_PROFILE_ID;
  process.env.TELNYX_API_KEY = "test-api-key";
  process.env.TELNYX_MESSAGING_PROFILE_ID = "messaging-profile-id";
  let requestBody;
  global.fetch = async (_url, options) => {
    requestBody = JSON.parse(options.body);
    return new Response(JSON.stringify({ data: { id: "message-id" } }), {
      status: 202,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    await sendSms({ to: "+15551234567", text: "Your sign-in code is 123456." });
    assert.deepEqual(requestBody, {
      to: "+15551234567",
      messaging_profile_id: "messaging-profile-id",
      text: "Your sign-in code is 123456."
    });
  } finally {
    global.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.TELNYX_API_KEY;
    else process.env.TELNYX_API_KEY = originalApiKey;
    if (originalMessagingProfileId === undefined) delete process.env.TELNYX_MESSAGING_PROFILE_ID;
    else process.env.TELNYX_MESSAGING_PROFILE_ID = originalMessagingProfileId;
  }
});

test("Telnyx SMS rejections return a friendly message and log the provider response", async () => {
  const originalFetch = global.fetch;
  const originalConsoleError = console.error;
  const originalApiKey = process.env.TELNYX_API_KEY;
  const originalMessagingProfileId = process.env.TELNYX_MESSAGING_PROFILE_ID;
  const providerResponse = JSON.stringify({ errors: [{ detail: "Invalid destination number." }] });
  const loggedMessages = [];
  process.env.TELNYX_API_KEY = "test-api-key";
  process.env.TELNYX_MESSAGING_PROFILE_ID = "messaging-profile-id";
  global.fetch = async () => new Response(providerResponse, {
    status: 400,
    headers: { "content-type": "application/json" }
  });
  console.error = (...args) => loggedMessages.push(args.join(" "));

  try {
    await assert.rejects(
      sendSms({ to: "+15551234567", text: "Your sign-in code is 123456." }),
      (error) => error.status === 400 &&
        error.message === "Unable to send SMS to this number right now. Please try another country code or use Email & Password login."
    );
    assert.ok(loggedMessages.some((message) => message.includes(providerResponse)));
  } finally {
    global.fetch = originalFetch;
    console.error = originalConsoleError;
    if (originalApiKey === undefined) delete process.env.TELNYX_API_KEY;
    else process.env.TELNYX_API_KEY = originalApiKey;
    if (originalMessagingProfileId === undefined) delete process.env.TELNYX_MESSAGING_PROFILE_ID;
    else process.env.TELNYX_MESSAGING_PROFILE_ID = originalMessagingProfileId;
  }
});
