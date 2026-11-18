"use strict";

const { normalizePhoneNumber } = require("./security");

const API_BASE_URL = "https://api.telnyx.com/v2";
const SMS_SEND_ERROR = "Unable to send SMS to this number right now. Please try another country code or use Email & Password login.";
const COUNTRY_DETAILS = Object.freeze({
  CA: { name: "Canada", dialingCode: "+1" },
  DE: { name: "Germany", dialingCode: "+49" },
  ES: { name: "Spain", dialingCode: "+34" },
  FR: { name: "France", dialingCode: "+33" },
  GB: { name: "United Kingdom", dialingCode: "+44" },
  NL: { name: "Netherlands", dialingCode: "+31" },
  SE: { name: "Sweden", dialingCode: "+46" },
  US: { name: "United States", dialingCode: "+1" },
  AT: { name: "Austria", dialingCode: "+43" },
  AU: { name: "Australia", dialingCode: "+61" },
  BE: { name: "Belgium", dialingCode: "+32" },
  CH: { name: "Switzerland", dialingCode: "+41" },
  DK: { name: "Denmark", dialingCode: "+45" },
  IE: { name: "Ireland", dialingCode: "+353" },
  IT: { name: "Italy", dialingCode: "+39" },
  NO: { name: "Norway", dialingCode: "+47" },
  PL: { name: "Poland", dialingCode: "+48" },
  PT: { name: "Portugal", dialingCode: "+351" },
  PR: { name: "Puerto Rico", dialingCode: "+1" }
});

class TelnyxApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "TelnyxApiError";
    this.status = status;
  }
}

function countryFlag(countryCode) {
  const code = String(countryCode || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "🌐";
  return String.fromCodePoint(
    ...Array.from(code, (letter) => 0x1f1e6 + letter.charCodeAt(0) - 65)
  );
}

function inventoryRecord(record, vipTag = "vip") {
  if (!record || record.status !== "active" || !record.id || !record.phone_number) return null;
  const countryCode = String(record.country_iso_alpha2 || "").toUpperCase();
  const country = COUNTRY_DETAILS[countryCode];
  if (!country) return null;

  const tags = Array.isArray(record.tags) ? record.tags : [];
  const isVip = tags.some((tag) => String(tag).toLowerCase() === String(vipTag).toLowerCase());
  return {
    telnyxPhoneNumberId: String(record.id),
    phoneNumber: normalizePhoneNumber(record.phone_number),
    country: country.name,
    countryCode,
    city: String(record.locality || record.city || "").slice(0, 80),
    dialingCode: country.dialingCode,
    flag: countryFlag(countryCode),
    numberType: isVip ? "VIP_PRIVATE" : "FREE_POOL"
  };
}

function parseInboundSms(event) {
  const data = event && event.data;
  const payload = data && data.payload;
  const recipient = Array.isArray(payload && payload.to) ? payload.to[0] : null;
  if (!data || data.event_type !== "message.received" || !payload || !recipient) return null;

  const from = payload.from && payload.from.phone_number;
  const to = recipient.phone_number;
  const messageId = payload.id || data.id;
  const text = payload.text;
  if (!from || !to || !messageId || typeof text !== "string" || !text.length) return null;
  return {
    eventId: String(data.id || ""),
    messageId: String(messageId),
    from: String(from),
    to: normalizePhoneNumber(to),
    text: text.slice(0, 4096)
  };
}

function retryDelay(response, attempt) {
  const retryAfter = Number(response && response.headers.get("retry-after"));
  if (Number.isFinite(retryAfter) && retryAfter > 0) {
    return Math.min(retryAfter * 1000, 5000);
  }
  return 250 * (2 ** attempt);
}

async function telnyxRequest(path, { method = "GET", body, apiKey = process.env.TELNYX_API_KEY } = {}) {
  if (!apiKey) throw new TelnyxApiError(503, "Telnyx API is not configured.");
  const url = new URL(String(path).replace(/^\/+/, ""), `${API_BASE_URL}/`);

  for (let attempt = 0; attempt < 3; attempt += 1) {
    let response;
    try {
      response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          Accept: "application/json",
          ...(body ? { "Content-Type": "application/json" } : {})
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(15000)
      });
    } catch (error) {
      if (attempt === 2) throw new TelnyxApiError(502, "Telnyx API request failed.");
      await new Promise((resolve) => setTimeout(resolve, 250 * (2 ** attempt)));
      continue;
    }

    const rawResponse = await response.text();
    let payload = null;
    if (rawResponse) {
      try {
        payload = JSON.parse(rawResponse);
      } catch (error) {
        if (response.ok) throw new TelnyxApiError(502, "Telnyx returned an invalid response.");
      }
    }
    if ((response.status === 429 || response.status >= 500) && attempt < 2) {
      await new Promise((resolve) => setTimeout(resolve, retryDelay(response, attempt)));
      continue;
    }
    if (!response.ok) {
      if (url.pathname === "/v2/messages") {
        console.error(`Telnyx SMS API rejected the request (${response.status}): ${rawResponse}`);
      }
      throw new TelnyxApiError(response.status, "Telnyx rejected the API request.");
    }
    return payload;
  }
  throw new TelnyxApiError(502, "Telnyx API request failed.");
}

async function listPurchasedNumbers() {
  const numbers = [];
  const pageSize = 100;
  for (let pageNumber = 1; ; pageNumber += 1) {
    const query = new URLSearchParams({
      "page[number]": String(pageNumber),
      "page[size]": String(pageSize),
      "filter[source]": "purchased",
      "filter[status]": "active"
    });
    const response = await telnyxRequest(`/phone_numbers?${query}`);
    if (!response || !Array.isArray(response.data)) {
      throw new TelnyxApiError(502, "Telnyx returned an invalid phone-number inventory.");
    }
    const data = response.data;
    numbers.push(...data);
    const totalPages = Number(response && response.meta && response.meta.total_pages);
    if (Number.isInteger(totalPages) && totalPages > 0) {
      if (pageNumber >= totalPages) break;
    } else if (data.length < pageSize) {
      break;
    }
  }
  return numbers;
}

async function createCredentialConnection({ username, password, userId }) {
  const outboundVoiceProfileId = String(process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID || "").trim();
  if (!outboundVoiceProfileId) {
    throw new TelnyxApiError(503, "Telnyx outbound calling is not configured.");
  }
  const response = await telnyxRequest("/credential_connections", {
    method: "POST",
    body: {
      connection_name: `VirtualSIM-${String(userId).slice(0, 8)}`,
      user_name: username,
      password,
      outbound: { outbound_voice_profile_id: outboundVoiceProfileId }
    }
  });
  if (!response || !response.data || !response.data.id) {
    throw new TelnyxApiError(502, "Telnyx did not return a SIP connection ID.");
  }
  return String(response.data.id);
}

async function sendSms({ to, text }) {
  const messagingProfileId = String(process.env.TELNYX_MESSAGING_PROFILE_ID || "").trim();
  if (!messagingProfileId) {
    throw new TelnyxApiError(503, "Telnyx messaging is not configured.");
  }
  try {
    return await telnyxRequest("/messages", {
      method: "POST",
      body: {
        to,
        messaging_profile_id: messagingProfileId,
        text
      }
    });
  } catch (error) {
    if (error instanceof TelnyxApiError &&
        error.message !== "Telnyx messaging is not configured." &&
        error.message !== "Telnyx API is not configured.") {
      throw new TelnyxApiError(error.status, SMS_SEND_ERROR);
    }
    throw error;
  }
}

function isSipProvisioningConfigured() {
  return Boolean(
    String(process.env.TELNYX_API_KEY || "").trim() &&
    String(process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID || "").trim()
  );
}

async function updatePhoneNumberConnection(phoneNumberId, connectionId) {
  try {
    await telnyxRequest(`/phone_numbers/${encodeURIComponent(phoneNumberId)}`, {
      method: "PATCH",
      body: { connection_id: connectionId || null }
    });
  } catch (error) {
    if (error instanceof TelnyxApiError && error.status === 404 && !connectionId) return;
    throw error;
  }
}

async function deleteCredentialConnection(connectionId) {
  try {
    await telnyxRequest(`/credential_connections/${encodeURIComponent(connectionId)}`, {
      method: "DELETE"
    });
  } catch (error) {
    if (error instanceof TelnyxApiError && error.status === 404) return;
    throw error;
  }
}

async function getAvailablePhoneNumbers(countries) {
  const countryCodes = [...new Set((countries || []).map((code) => String(code).toUpperCase()).filter(Boolean))];
  const numbers = [];

  for (const countryCode of countryCodes) {
    const country = COUNTRY_DETAILS[countryCode];
    if (!country) continue;

    for (let pageNumber = 1; pageNumber <= 10 && numbers.filter((number) => number.countryCode === countryCode).length < 2; pageNumber += 1) {
      const query = new URLSearchParams({
        "filter[country_code]": countryCode,
        "filter[number_type]": "local",
        "page[size]": "2",
        "page[number]": String(pageNumber)
      });
      const response = await telnyxRequest(`/available_phone_numbers?${query}`);
      if (!response || !Array.isArray(response.data)) {
        throw new TelnyxApiError(502, "Telnyx returned an invalid available-phone-number inventory.");
      }
      if (response.data.length === 0) break;

      for (const record of response.data) {
        const phoneNumber = normalizePhoneNumber(record.phone_number || record.phoneNumber);
        if (!phoneNumber) continue;
        if (numbers.some((number) => number.phoneNumber === phoneNumber)) continue;
        numbers.push({
          telnyxPhoneNumberId: String(record.id || record.phone_number_id || phoneNumber),
          phoneNumber,
          country: country.name,
          countryCode,
          city: String(record.locality || record.city || record.region || "").slice(0, 80),
          dialingCode: country.dialingCode,
          flag: countryFlag(countryCode),
          numberType: "VIP_PRIVATE"
        });
        if (numbers.filter((number) => number.countryCode === countryCode).length >= 2) break;
      }

      const totalPages = Number(response.meta && response.meta.total_pages);
      if (Number.isInteger(totalPages) && pageNumber >= totalPages) break;
      if (!Number.isInteger(totalPages) && response.data.length < 2) break;
    }
  }

  return numbers;
}

async function purchasePhoneNumber(phoneNumber) {
  const connectionId = process.env.TELNYX_CONNECTION_ID;
  const messagingProfileId = process.env.TELNYX_MESSAGING_PROFILE_ID;
  if (!connectionId || !messagingProfileId) {
      throw new Error("Missing TELNYX_CONNECTION_ID or TELNYX_MESSAGING_PROFILE_ID");
  }
  const response = await telnyxRequest("/number_orders", {
    method: "POST",
    body: {
      phone_numbers: [{ phone_number: phoneNumber }],
      customer_reference: "VIP_PURCHASE",
      connection_id: connectionId,
      messaging_profile_id: messagingProfileId
    }
  });
  return response.data;
}

module.exports = {
  COUNTRY_DETAILS,
  TelnyxApiError,
  createCredentialConnection,
  deleteCredentialConnection,
  getAvailablePhoneNumbers,
  inventoryRecord,
  isSipProvisioningConfigured,
  listPurchasedNumbers,
  parseInboundSms,
  purchasePhoneNumber,
  sendSms,
  telnyxRequest,
  updatePhoneNumberConnection
};

