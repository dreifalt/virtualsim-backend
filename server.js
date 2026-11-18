"use strict";

require("dotenv").config();

const crypto = require("node:crypto");
const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { rateLimit } = require("express-rate-limit");
const { Pool } = require("pg");
const { google } = require("googleapis");
const {
  createPhoneOtp,
  decryptText,
  encryptText,
  extractOtp,
  hashPhoneOtp,
  normalizePhoneNumber,
  safeEqual,
  verifyAdMobSignature,
  verifyTelnyxSignature
} = require("./security");
const {
  TelnyxApiError,
  createCredentialConnection,
  deleteCredentialConnection,
  getAvailablePhoneNumbers,
  inventoryRecord,
  isSipProvisioningConfigured,
  listPurchasedNumbers,
  parseInboundSms,
  sendSms,
  telnyxRequest,
  updatePhoneNumberConnection
} = require("./telnyx");

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const TELNYX_API_KEY = process.env.TELNYX_API_KEY;
const TELNYX_PUBLIC_KEY = process.env.TELNYX_PUBLIC_KEY;
const TELNYX_VIP_TAG = process.env.TELNYX_VIP_TAG || "vip";
const TELNYX_SYNC_INTERVAL_MS = Number(process.env.TELNYX_SYNC_INTERVAL_MS || 15 * 60 * 1000);
const PLAY_PACKAGE_NAME = process.env.PLAY_PACKAGE_NAME || "com.virtualsim.pro";
const VIP_PRODUCT_ID = process.env.VIP_PRODUCT_ID || "virtualsim_vip_number";
const VIP_CREDIT_COST = 50;
const REWARD_CREDITS = 10;
const STAGING_SHARED_FREE_NUMBERS_ENABLED =
  process.env.NODE_ENV === "staging" && process.env.STAGING_SHARED_FREE_NUMBERS === "true";
const STAGING_AD_REWARD_FALLBACK_ENABLED =
  process.env.NODE_ENV === "staging" && process.env.STAGING_AD_REWARD_FALLBACK === "true";
const STAGING_AD_FALLBACK_CREDITS = 10;
const STAGING_SHARED_FREE_NUMBER = Object.freeze({
  id: "staging-shared-free-us",
  country: "United States",
  city: "Synthetic test number",
  dialingCode: "+1",
  number: "+15555550100",
  flag: "🇺🇸",
  label: "FREE_SHARED",
  active: true
});
const DATA_KEY = process.env.DATA_ENCRYPTION_KEY
  ? Buffer.from(process.env.DATA_ENCRYPTION_KEY, "base64")
  : null;

if (!DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (!JWT_SECRET || Buffer.byteLength(JWT_SECRET) < 32) {
  throw new Error("JWT_SECRET must be at least 32 bytes.");
}
if (!ADMIN_API_KEY || Buffer.byteLength(ADMIN_API_KEY) < 32) {
  throw new Error("ADMIN_API_KEY must be at least 32 bytes.");
}
if (!DATA_KEY || DATA_KEY.length !== 32) {
  throw new Error("DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
}
if (!Number.isInteger(TELNYX_SYNC_INTERVAL_MS) || TELNYX_SYNC_INTERVAL_MS < 60000) {
  throw new Error("TELNYX_SYNC_INTERVAL_MS must be at least 60000.");
}

const pool = new Pool({ connectionString: DATABASE_URL });
const app = express();
const dummyPasswordHash = bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), 12);
app.set("trust proxy", 1);
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
const phoneOtpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
const phoneOtpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({
  limit: "32kb",
  verify(req, _res, buffer) {
    if (req.path === "/api/webhook/sms") req.rawBody = Buffer.from(buffer);
  }
}));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text UNIQUE,
  password_hash text,
  phone_number text,
  phone_verified_at timestamptz,
  credits integer NOT NULL DEFAULT 0 CHECK (credits >= 0),
  token_version integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_identity_check CHECK (email IS NOT NULL OR phone_number IS NOT NULL)
);
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_at timestamptz;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_identity_check') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_identity_check CHECK (email IS NOT NULL OR phone_number IS NOT NULL);
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_number_idx ON users(phone_number);
CREATE TABLE IF NOT EXISTS phone_numbers (
  id text PRIMARY KEY,
  user_id text REFERENCES users(id) ON DELETE SET NULL,
  phone_number text NOT NULL UNIQUE,
  country text NOT NULL,
  city text NOT NULL DEFAULT '',
  dialing_code text NOT NULL DEFAULT '',
  flag text NOT NULL DEFAULT '🌐',
  number_type text NOT NULL CHECK (number_type IN ('FREE_POOL', 'FREE_ASSIGNED', 'VIP_PRIVATE')),
  telnyx_phone_number_id text,
  telnyx_connection_id text,
  vip_expires_at timestamptz,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS phone_auth_challenges (
  phone_number text PRIMARY KEY,
  code_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  sent_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS telnyx_phone_number_id text;
ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS telnyx_connection_id text;
ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS vip_expires_at timestamptz;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'phone_numbers_number_type_check'
      AND pg_get_constraintdef(oid) NOT LIKE '%FREE_POOL%'
  ) THEN
    ALTER TABLE phone_numbers DROP CONSTRAINT phone_numbers_number_type_check;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'phone_numbers_number_type_check'
  ) THEN
    ALTER TABLE phone_numbers
      ADD CONSTRAINT phone_numbers_number_type_check
      CHECK (number_type IN ('FREE_POOL', 'FREE_ASSIGNED', 'VIP_PRIVATE'));
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS phone_numbers_telnyx_id_idx
  ON phone_numbers(telnyx_phone_number_id) WHERE telnyx_phone_number_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS phone_numbers_user_idx ON phone_numbers(user_id, active);
CREATE TABLE IF NOT EXISTS sms_messages (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  number_id text NOT NULL REFERENCES phone_numbers(id) ON DELETE CASCADE,
  sender text NOT NULL,
  body_ciphertext bytea NOT NULL,
  body_iv bytea NOT NULL,
  body_tag bytea NOT NULL,
  code_ciphertext bytea NOT NULL,
  code_iv bytea NOT NULL,
  code_tag bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sms_messages_user_time_idx ON sms_messages(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS sip_accounts (
  user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  sip_domain text NOT NULL,
  sip_username text NOT NULL,
  password_ciphertext bytea NOT NULL,
  password_iv bytea NOT NULL,
  password_tag bytea NOT NULL,
  telnyx_connection_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE sip_accounts ADD COLUMN IF NOT EXISTS telnyx_connection_id text;
CREATE UNIQUE INDEX IF NOT EXISTS sip_accounts_telnyx_id_idx
  ON sip_accounts(telnyx_connection_id) WHERE telnyx_connection_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS webhook_nonces (
  nonce text PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS processed_sms (
  provider_message_id text PRIMARY KEY,
  processed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ad_reward_tokens (
  token_hash text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
CREATE TABLE IF NOT EXISTS ad_rewards (
  transaction_id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credits integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vip_purchases (
  purchase_token_hash text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id text NOT NULL,
  number_id text UNIQUE REFERENCES phone_numbers(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE vip_purchases ALTER COLUMN number_id DROP NOT NULL;
ALTER TABLE vip_purchases ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'vip_purchases_status_check'
  ) THEN
    ALTER TABLE vip_purchases
      ADD CONSTRAINT vip_purchases_status_check
      CHECK (status IN ('active', 'pending_provision'));
  END IF;
END $$;
`;

function createToken(user) {
  return jwt.sign(
    { sub: user.id, ver: user.token_version },
    JWT_SECRET,
    { expiresIn: "12h", issuer: "virtualsim-master" }
  );
}

async function authenticate(req, res, next) {
  res.set("Cache-Control", "no-store");
  const match = req.get("authorization")?.match(/^Bearer (.+)$/i);
  if (!match) return res.status(401).json({ error: "Authentication required." });
  try {
    const claims = jwt.verify(match[1], JWT_SECRET, { issuer: "virtualsim-master" });
    const result = await pool.query(
      "SELECT id, email, phone_number, credits, token_version FROM users WHERE id = $1",
      [claims.sub]
    );
    const user = result.rows[0];
    if (!user || user.token_version !== claims.ver) {
      return res.status(401).json({ error: "Session expired. Please sign in again." });
    }
    req.user = user;
    return next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: "Session expired. Please sign in again." });
    }
    return next(error);
  }
}

function requireAdmin(req, res, next) {
  const supplied = req.get("x-admin-key");
  if (!supplied || !safeEqual(supplied, ADMIN_API_KEY)) {
    return res.status(401).json({ error: "Unauthorized." });
  }
  return next();
}

app.post("/admin/reset-users", adminLimiter, requireAdmin, async (req, res, next) => {
  if (!req.body || req.body.confirm !== true) {
    return res.status(400).json({ error: "Set confirm to true to reset all users and number assignments." });
  }

  let client;
  let transactionStarted = false;
  try {
    const [numbers, sipAccounts] = await Promise.all([
      pool.query(
        `SELECT telnyx_phone_number_id, telnyx_connection_id
         FROM phone_numbers
         WHERE user_id IS NOT NULL OR number_type = 'FREE_ASSIGNED'`
      ),
      pool.query("SELECT telnyx_connection_id FROM sip_accounts WHERE telnyx_connection_id IS NOT NULL")
    ]);
    const assignedCarrierNumbers = numbers.rows.filter(
      (number) => number.telnyx_phone_number_id && number.telnyx_connection_id
    );
    const connectionIds = new Set(
      [
        ...sipAccounts.rows.map((account) => account.telnyx_connection_id),
        ...numbers.rows.map((number) => number.telnyx_connection_id)
      ].filter(Boolean)
    );
    if ((assignedCarrierNumbers.length || connectionIds.size) && !TELNYX_API_KEY) {
      throw new TelnyxApiError(503, "Telnyx is unavailable for account cleanup. Please retry later.");
    }

    for (const number of assignedCarrierNumbers) {
      await updatePhoneNumberConnection(number.telnyx_phone_number_id, null);
    }
    for (const connectionId of connectionIds) {
      await deleteCredentialConnection(connectionId);
    }

    client = await pool.connect();
    await client.query("BEGIN");
    transactionStarted = true;
    const resetNumbers = await client.query(
      `UPDATE phone_numbers
       SET user_id = NULL,
           number_type = CASE WHEN number_type = 'FREE_ASSIGNED' THEN 'FREE_POOL' ELSE number_type END,
           active = CASE WHEN number_type = 'FREE_ASSIGNED' THEN true ELSE active END,
           telnyx_connection_id = NULL
       WHERE user_id IS NOT NULL OR number_type = 'FREE_ASSIGNED'
       RETURNING id`
    );
    const deletedUsers = await client.query("DELETE FROM users RETURNING id");
    const deletedChallenges = await client.query("DELETE FROM phone_auth_challenges");
    await client.query("COMMIT");
    transactionStarted = false;
    return res.json({
      usersDeleted: deletedUsers.rowCount,
      numbersReset: resetNumbers.rowCount,
      phoneAuthChallengesDeleted: deletedChallenges.rowCount
    });
  } catch (error) {
    if (client && transactionStarted) await client.query("ROLLBACK");
    return next(error);
  } finally {
    if (client) client.release();
  }
});

function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new TypeError("Enter a valid email address.");
  }
  return email;
}

function encryptedFields(value) {
  const { ciphertext, iv, tag } = encryptText(value, DATA_KEY);
  return [ciphertext, iv, tag];
}

function decryptBody(row) {
  return decryptText(
    row.body_ciphertext,
    row.body_iv,
    row.body_tag,
    DATA_KEY
  );
}

function decryptCode(row) {
  return decryptText(
    row.code_ciphertext,
    row.code_iv,
    row.code_tag,
    DATA_KEY
  );
}

function publicSipAccount(row) {
  return {
    domain: row.sip_domain,
    username: row.sip_username,
    password: decryptText(
      row.password_ciphertext,
      row.password_iv,
      row.password_tag,
      DATA_KEY
    ),
    connectionId: row.telnyx_connection_id
  };
}

async function ensureTelnyxSipAccount(userId) {
  const existing = await pool.query(
    `SELECT sip_domain, sip_username, password_ciphertext, password_iv,
            password_tag, telnyx_connection_id
     FROM sip_accounts WHERE user_id = $1 AND telnyx_connection_id IS NOT NULL`,
    [userId]
  );
  if (existing.rowCount > 0) return publicSipAccount(existing.rows[0]);
  if (!TELNYX_API_KEY) throw new TelnyxApiError(503, "Telnyx SIP provisioning is not configured.");

  const configuredDomain = String(process.env.TELNYX_SIP_DOMAIN || "").trim();
  const sipDomain = configuredDomain || "sip.telnyx.com";
  const username = `vs${crypto.randomBytes(15).toString("hex")}`;
  const password = crypto.randomBytes(32).toString("base64url");
  let connectionId = null;
  try {
    connectionId = await createCredentialConnection({ username, password, userId });
    const [ciphertext, iv, tag] = encryptedFields(password);
    const inserted = await pool.query(
      `INSERT INTO sip_accounts
       (user_id, sip_domain, sip_username, password_ciphertext, password_iv,
        password_tag, telnyx_connection_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (user_id) DO UPDATE SET
         sip_domain = EXCLUDED.sip_domain,
         sip_username = EXCLUDED.sip_username,
         password_ciphertext = EXCLUDED.password_ciphertext,
         password_iv = EXCLUDED.password_iv,
         password_tag = EXCLUDED.password_tag,
         telnyx_connection_id = EXCLUDED.telnyx_connection_id,
         updated_at = now()
       WHERE sip_accounts.telnyx_connection_id IS NULL
       RETURNING sip_domain, sip_username, password_ciphertext, password_iv,
                 password_tag, telnyx_connection_id`,
      [userId, sipDomain, username, ciphertext, iv, tag, connectionId]
    );
    if (inserted.rowCount > 0) return publicSipAccount(inserted.rows[0]);

    const concurrent = await pool.query(
      `SELECT sip_domain, sip_username, password_ciphertext, password_iv,
              password_tag, telnyx_connection_id
       FROM sip_accounts WHERE user_id = $1 AND telnyx_connection_id IS NOT NULL`,
      [userId]
    );
    if (concurrent.rowCount === 0) {
      throw new Error("Telnyx SIP account could not be saved.");
    }
    await deleteCredentialConnection(connectionId);
    connectionId = null;
    return publicSipAccount(concurrent.rows[0]);
  } catch (error) {
    if (connectionId) {
      try {
        await deleteCredentialConnection(connectionId);
      } catch (cleanupError) {
        console.error(`Unable to remove an unused Telnyx SIP connection: ${cleanupError.message}`);
      }
    }
    throw error;
  }
}

function vipNumberResponse(row) {
  return {
    id: row.id,
    phoneNumber: row.phone_number,
    country: row.country,
    city: row.city,
    dialingCode: row.dialing_code,
    flag: row.flag,
    validUntil: row.vip_expires_at
  };
}

async function orderTelnyxVipNumber() {
  const connectionId = String(process.env.TELNYX_CONNECTION_ID || "").trim();
  const messagingProfileId = String(process.env.TELNYX_MESSAGING_PROFILE_ID || "").trim();
  if (!connectionId || !messagingProfileId) {
    throw new TelnyxApiError(503, "Telnyx number ordering is not configured.");
  }

  const query = new URLSearchParams();
  query.set("filter[country_code]", "US");
  query.append("filter[features][]", "sms");
  query.append("filter[features][]", "voice");
  query.set("filter[limit]", "1");
  const available = await telnyxRequest(`/available_phone_numbers?${query}`);
  const candidate = available && Array.isArray(available.data) && available.data[0];
  if (!candidate || !candidate.phone_number) {
    throw new TelnyxApiError(404, "Telnyx has no available US number with SMS and voice.");
  }

  const order = await telnyxRequest("/number_orders", {
    method: "POST",
    body: {
      phone_numbers: [{ phone_number: candidate.phone_number }],
      connection_id: connectionId,
      messaging_profile_id: messagingProfileId
    }
  });
  const orderNumbers = order && order.data && order.data.phone_numbers;
  const orderedNumber = Array.isArray(orderNumbers)
    ? orderNumbers.find((number) => number.phone_number === candidate.phone_number) || orderNumbers[0]
    : null;
  const telnyxPhoneNumberId = orderedNumber && (orderedNumber.id || orderedNumber.phone_number_id);
  if (!orderedNumber || !orderedNumber.phone_number || !telnyxPhoneNumberId) {
    throw new TelnyxApiError(502, "Telnyx did not return the ordered phone number.");
  }

  return {
    phoneNumber: normalizePhoneNumber(orderedNumber.phone_number),
    telnyxPhoneNumberId: String(telnyxPhoneNumberId),
    country: "United States",
    city: String(candidate.locality || candidate.city || "").slice(0, 80),
    dialingCode: "+1",
    flag: "🇺🇸"
  };
}

async function fulfillVipPurchase({ tokenHash, userId, productId, requestedNumberId = null }) {
  const client = await pool.connect();
  let transactionStarted = false;
  let attachedNumberId = null;
  let newlyOrderedNumber = null;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    const purchase = await client.query(
      `SELECT user_id, product_id, number_id, status
       FROM vip_purchases WHERE purchase_token_hash = $1 FOR UPDATE`,
      [tokenHash]
    );
    if (purchase.rowCount === 0) throw new Error("The verified VIP purchase could not be saved.");
    if (purchase.rows[0].user_id !== userId || purchase.rows[0].product_id !== productId) {
      throw new TelnyxApiError(409, "This Play purchase has already been applied to another account.");
    }

    if (purchase.rows[0].status === "active" && purchase.rows[0].number_id) {
      const active = await client.query(
        `SELECT id, phone_number, country, city, dialing_code, flag, vip_expires_at, active
         FROM phone_numbers WHERE id = $1 AND user_id = $2`,
        [purchase.rows[0].number_id, userId]
      );
      if (active.rowCount > 0) {
        if (!active.rows[0].active ||
            (active.rows[0].vip_expires_at && new Date(active.rows[0].vip_expires_at).getTime() <= Date.now())) {
          await client.query("COMMIT");
          transactionStarted = false;
          return { status: "expired" };
        }
        await client.query("COMMIT");
        transactionStarted = false;
        const sipAccount = await ensureTelnyxSipAccount(userId);
        return { status: "active", number: vipNumberResponse(active.rows[0]), sipConfig: sipAccount };
      }
    }

    const available = await client.query(
      `SELECT id, phone_number, country, city, dialing_code, flag, telnyx_phone_number_id
       FROM phone_numbers
       WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       ORDER BY CASE WHEN id = $1 THEN 0 ELSE 1 END, created_at
       LIMIT 1 FOR UPDATE SKIP LOCKED`,
      [requestedNumberId]
    );
    let number = available.rows[0] || null;
    const shouldProvision = process.env.AUTO_PROVISION_TELNYX === "true";
    if (!number && !shouldProvision) {
      await client.query("COMMIT");
      transactionStarted = false;
      return { status: "pending_provision" };
    }

    const sipAccount = await ensureTelnyxSipAccount(userId);
    if (!number) {
      newlyOrderedNumber = await orderTelnyxVipNumber();
      attachedNumberId = newlyOrderedNumber.telnyxPhoneNumberId;
      await updatePhoneNumberConnection(attachedNumberId, sipAccount.connectionId);
      const inserted = await client.query(
        `INSERT INTO phone_numbers
         (id, user_id, phone_number, country, city, dialing_code, flag, number_type,
          telnyx_phone_number_id, telnyx_connection_id, vip_expires_at, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'VIP_PRIVATE', $8, $9,
                 now() + interval '30 days', true)
         ON CONFLICT (phone_number) DO UPDATE SET
           user_id = EXCLUDED.user_id,
           country = EXCLUDED.country,
           city = EXCLUDED.city,
           dialing_code = EXCLUDED.dialing_code,
           flag = EXCLUDED.flag,
           number_type = 'VIP_PRIVATE',
           telnyx_phone_number_id = EXCLUDED.telnyx_phone_number_id,
           telnyx_connection_id = EXCLUDED.telnyx_connection_id,
           vip_expires_at = EXCLUDED.vip_expires_at,
           active = true
         WHERE phone_numbers.user_id IS NULL
         RETURNING id, phone_number, country, city, dialing_code, flag, vip_expires_at`,
        [
          crypto.randomUUID(),
          userId,
          newlyOrderedNumber.phoneNumber,
          newlyOrderedNumber.country,
          newlyOrderedNumber.city,
          newlyOrderedNumber.dialingCode,
          newlyOrderedNumber.flag,
          newlyOrderedNumber.telnyxPhoneNumberId,
          sipAccount.connectionId
        ]
      );
      if (inserted.rowCount === 0) throw new Error("The ordered VIP number is already assigned.");
      number = inserted.rows[0];
    } else {
      attachedNumberId = number.telnyx_phone_number_id;
      await updatePhoneNumberConnection(attachedNumberId, sipAccount.connectionId);
      const assigned = await client.query(
        `UPDATE phone_numbers
         SET user_id = $1, telnyx_connection_id = $2,
             vip_expires_at = now() + interval '30 days'
         WHERE id = $3 AND user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         RETURNING id, phone_number, country, city, dialing_code, flag, vip_expires_at`,
        [userId, sipAccount.connectionId, number.id]
      );
      if (assigned.rowCount === 0) throw new Error("The VIP number could not be assigned.");
      number = assigned.rows[0];
    }

    await client.query(
      `UPDATE vip_purchases
       SET number_id = $1, status = 'active'
       WHERE purchase_token_hash = $2`,
      [number.id, tokenHash]
    );
    await client.query("COMMIT");
    transactionStarted = false;
    attachedNumberId = null;
    newlyOrderedNumber = null;
    return { status: "active", number: vipNumberResponse(number), sipConfig: sipAccount };
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    if (newlyOrderedNumber) {
      try {
        await updatePhoneNumberConnection(newlyOrderedNumber.telnyxPhoneNumberId, null);
      } catch (cleanupError) {
        console.error(`Unable to detach an unassigned ordered VIP number: ${cleanupError.message}`);
      }
      try {
        await pool.query(
          `INSERT INTO phone_numbers
           (id, phone_number, country, city, dialing_code, flag, number_type,
            telnyx_phone_number_id, active)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'VIP_PRIVATE', $8, true)
           ON CONFLICT (phone_number) DO NOTHING`,
          [
            crypto.randomUUID(),
            newlyOrderedNumber.phoneNumber,
            newlyOrderedNumber.country,
            newlyOrderedNumber.city,
            newlyOrderedNumber.dialingCode,
            newlyOrderedNumber.flag,
            newlyOrderedNumber.telnyxPhoneNumberId
          ]
        );
      } catch (saveError) {
        console.error(`Unable to save the ordered VIP number for retry: ${saveError.message}`);
      }
    } else if (attachedNumberId) {
      try {
        await updatePhoneNumberConnection(attachedNumberId, null);
      } catch (cleanupError) {
        console.error(`Unable to detach an unassigned VIP Telnyx number: ${cleanupError.message}`);
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

let telnyxSyncStatus = { lastSuccessAt: null, importedNumbers: 0, skippedNumbers: 0 };

async function syncTelnyxInventory() {
  const providerNumbers = await listPurchasedNumbers();
  const records = [];
  let skippedNumbers = 0;
  for (const providerNumber of providerNumbers) {
    try {
      const record = inventoryRecord(providerNumber, TELNYX_VIP_TAG);
      if (record) records.push(record);
      else skippedNumbers += 1;
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      skippedNumbers += 1;
    }
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const record of records) {
      await client.query(
        `INSERT INTO phone_numbers
         (id, phone_number, country, city, dialing_code, flag, number_type,
          telnyx_phone_number_id, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
         ON CONFLICT (phone_number) DO UPDATE SET
           telnyx_phone_number_id = EXCLUDED.telnyx_phone_number_id,
           country = EXCLUDED.country,
           city = EXCLUDED.city,
           dialing_code = EXCLUDED.dialing_code,
           flag = EXCLUDED.flag,
           number_type = CASE
             WHEN phone_numbers.user_id IS NULL THEN EXCLUDED.number_type
             ELSE phone_numbers.number_type
           END,
           active = true`,
        [
          crypto.randomUUID(),
          record.phoneNumber,
          record.country,
          record.city,
          record.dialingCode,
          record.flag,
          record.numberType,
          record.telnyxPhoneNumberId
        ]
      );
    }
    await client.query(
      `UPDATE phone_numbers SET active = false
       WHERE telnyx_phone_number_id IS NOT NULL
         AND NOT (telnyx_phone_number_id = ANY($1::text[]))`,
      [records.map((record) => record.telnyxPhoneNumberId)]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  telnyxSyncStatus = {
    lastSuccessAt: new Date().toISOString(),
    importedNumbers: records.length,
    skippedNumbers
  };
  console.log(`Telnyx inventory sync completed: ${records.length} active numbers.`);
  return telnyxSyncStatus;
}

app.get("/", (_req, res) => {
  return res.status(200).json({ status: "ok" });
});

app.get("/health", async (_req, res, next) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "ok",
      telnyx: {
        configured: Boolean(TELNYX_API_KEY),
        webhookConfigured: Boolean(TELNYX_PUBLIC_KEY),
        messagingProfileConfigured: Boolean(String(process.env.TELNYX_MESSAGING_PROFILE_ID || "").trim()),
        outboundVoiceProfileConfigured: Boolean(String(process.env.TELNYX_OUTBOUND_VOICE_PROFILE_ID || "").trim()),
        lastInventorySync: telnyxSyncStatus.lastSuccessAt
      }
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/phone/request", phoneOtpRequestLimiter, async (req, res, next) => {
  let phoneNumber;
  try {
    phoneNumber = normalizePhoneNumber(req.body?.phoneNumber);
  } catch (error) {
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }

  const code = createPhoneOtp();
  const codeHash = hashPhoneOtp(phoneNumber, code, DATA_KEY);
  try {
    const challenge = await pool.query(
      `INSERT INTO phone_auth_challenges (phone_number, code_hash, expires_at, attempts, sent_at)
       VALUES ($1, $2, now() + interval '10 minutes', 0, now())
       ON CONFLICT (phone_number) DO UPDATE SET
         code_hash = EXCLUDED.code_hash,
         expires_at = EXCLUDED.expires_at,
         attempts = 0,
         sent_at = now()
       WHERE phone_auth_challenges.sent_at <= now() - interval '60 seconds'
       RETURNING phone_number`,
      [phoneNumber, codeHash]
    );
    if (challenge.rowCount === 0) {
      return res.status(429).json({ error: "Please wait before requesting another code." });
    }

    try {
      await sendSms({
        to: phoneNumber,
        text: `Your VirtualSIM Pro sign-in code is ${code}. It expires in 10 minutes.`
      });
    } catch (error) {
      try {
        await pool.query(
          "DELETE FROM phone_auth_challenges WHERE phone_number = $1 AND code_hash = $2",
          [phoneNumber, codeHash]
        );
      } catch (cleanupError) {
        console.error(`Unable to remove an unsent phone sign-in challenge: ${cleanupError.message}`);
      }
      return next(error);
    }
    return res.json({ sent: true, expiresInSeconds: 600 });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/auth/phone/verify", phoneOtpVerifyLimiter, async (req, res, next) => {
  let phoneNumber;
  try {
    phoneNumber = normalizePhoneNumber(req.body?.phoneNumber);
  } catch (error) {
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
  const code = String(req.body?.code || "").trim();
  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Enter the 6-digit verification code." });
  }

  const client = await pool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    const challenge = await client.query(
      `SELECT code_hash, expires_at, attempts
       FROM phone_auth_challenges
       WHERE phone_number = $1
       FOR UPDATE`,
      [phoneNumber]
    );
    if (challenge.rowCount === 0) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(401).json({ error: "The verification code is invalid or expired." });
    }

    const row = challenge.rows[0];
    if (new Date(row.expires_at).getTime() <= Date.now()) {
      await client.query("DELETE FROM phone_auth_challenges WHERE phone_number = $1", [phoneNumber]);
      await client.query("COMMIT");
      transactionStarted = false;
      return res.status(401).json({ error: "The verification code is invalid or expired." });
    }

    if (Number(row.attempts) >= 5) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(401).json({ error: "The verification code is invalid or expired." });
    }

    if (!safeEqual(hashPhoneOtp(phoneNumber, code, DATA_KEY), row.code_hash)) {
      const attempts = Number(row.attempts) + 1;
      await client.query(
        "UPDATE phone_auth_challenges SET attempts = $2 WHERE phone_number = $1",
        [phoneNumber, attempts]
      );
      await client.query("COMMIT");
      transactionStarted = false;
      return res.status(401).json({ error: "The verification code is invalid or expired." });
    }

    await client.query("DELETE FROM phone_auth_challenges WHERE phone_number = $1", [phoneNumber]);
    const result = await client.query(
      `INSERT INTO users (id, email, password_hash, phone_number, phone_verified_at)
       VALUES ($1, NULL, NULL, $2, now())
       ON CONFLICT (phone_number) DO UPDATE SET phone_verified_at = now()
       RETURNING id, email, phone_number, credits, token_version`,
      [crypto.randomUUID(), phoneNumber]
    );
    await client.query("COMMIT");
    transactionStarted = false;
    const user = result.rows[0];
    const hasVipNumber = await userHasActiveVipNumber(user.id);
    return res.json({
      token: createToken(user),
      profile: publicProfile(user, false, hasVipNumber)
    });
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    return next(error);
  } finally {
    client.release();
  }
});

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    if (password.length < 12 || Buffer.byteLength(password) > 72) {
      return res.status(400).json({ error: "Password must be 12–72 bytes." });
    }
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, phone_number, credits, token_version",
      [id, email, passwordHash]
    );
    const user = result.rows[0];
    return res.status(201).json({
      token: createToken(user),
      profile: publicProfile(user)
    });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "An account already exists for that email." });
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const result = await pool.query(
      "SELECT id, email, phone_number, password_hash, credits, token_version FROM users WHERE email = $1",
      [email]
    );
    const user = result.rows[0];
    const valid = await bcrypt.compare(String(req.body.password || ""), user?.password_hash || dummyPasswordHash);
    if (!user || !valid) return res.status(401).json({ error: "Email or password is incorrect." });
    const hasVipNumber = await userHasActiveVipNumber(user.id);
    return res.json({
      token: createToken(user),
      profile: publicProfile(user, false, hasVipNumber)
    });
  } catch (error) {
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
});

async function userHasActiveVipNumber(userId) {
  const result = await pool.query(
    `SELECT EXISTS (
       SELECT 1 FROM phone_numbers
       WHERE user_id = $1 AND active AND number_type = 'VIP_PRIVATE'
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
     ) AS has_vip`,
    [userId]
  );
  return Boolean(result.rows[0]?.has_vip);
}

function publicProfile(user, vipAvailable = false, hasVipNumber = false) {
  return {
    id: user.id,
    email: user.email || user.phone_number,
    credits: user.credits,
    vipAvailable,
    hasVipNumber
  };
}

app.get("/api/profile", authenticate, async (req, res, next) => {
  try {
    const [available, vip] = await Promise.all([
      pool.query("SELECT EXISTS (SELECT 1 FROM phone_numbers WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE' AND telnyx_phone_number_id IS NOT NULL AND (vip_expires_at IS NULL OR vip_expires_at > now())) AS available"),
      pool.query("SELECT EXISTS (SELECT 1 FROM phone_numbers WHERE user_id = $1 AND active AND number_type = 'VIP_PRIVATE' AND (vip_expires_at IS NULL OR vip_expires_at > now())) AS has_vip", [req.user.id])
    ]);
    return res.json({
      profile: publicProfile(
        req.user,
        Boolean(available.rows[0].available),
        Boolean(vip.rows[0].has_vip)
      )
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/numbers", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT country, city, dialing_code, phone_number, flag,
              CASE
                WHEN number_type IN ('FREE_POOL', 'FREE_ASSIGNED') THEN 'FREE_ASSIGNED'
                ELSE number_type
              END AS number_type,
              active
       FROM phone_numbers
       WHERE active = true
         AND (
           number_type IN ('FREE_POOL', 'FREE_ASSIGNED')
           OR (number_type = 'VIP_PRIVATE' AND user_id = $1
               AND (vip_expires_at IS NULL OR vip_expires_at > now()))
         )
       ORDER BY CASE number_type
         WHEN 'FREE_POOL' THEN 0
         WHEN 'FREE_ASSIGNED' THEN 1
         ELSE 2
       END, country`,
      [req.user.id]
    );
    const numbers = result.rows.map((row) => ({
      country: row.country,
      city: row.city,
      dialingCode: row.dialing_code,
      number: row.phone_number,
      flag: row.flag,
      label: row.number_type,
      active: row.active
    }));
    if (STAGING_SHARED_FREE_NUMBERS_ENABLED) numbers.unshift(STAGING_SHARED_FREE_NUMBER);
    return res.json({
      numbers
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/numbers/vip", authenticate, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, country, city, dialing_code, phone_number, flag
       FROM phone_numbers
       WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       ORDER BY country, city, phone_number`
    );
    return res.json({
      numbers: result.rows.map((row) => ({
        id: row.id,
        country: row.country,
        city: row.city,
        dialingCode: row.dialing_code,
        number: row.phone_number,
        flag: row.flag
      }))
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/numbers/unlock-vip", authenticate, async (req, res, next) => {
  const numberId = String(req.body?.numberId || "").trim();
  if (!numberId) return res.status(400).json({ error: "Select an available VIP number." });

  let sipAccount = null;
  try {
    const user = await pool.query("SELECT credits FROM users WHERE id = $1", [req.user.id]);
    if (user.rowCount === 0) return res.status(404).json({ error: "User not found." });
    if (user.rows[0].credits < VIP_CREDIT_COST) {
      return res.status(402).json({ error: "You need 50 credits to unlock a VIP number." });
    }
    const number = await pool.query(
      `SELECT 1 FROM phone_numbers
       WHERE id = $1 AND user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())`,
      [numberId]
    );
    if (number.rowCount === 0) {
      return res.status(409).json({ error: "The selected VIP number is no longer available." });
    }
    if (isSipProvisioningConfigured()) {
      sipAccount = await ensureTelnyxSipAccount(req.user.id);
    }
  } catch (error) {
    return next(error);
  }

  const client = await pool.connect();
  let transactionStarted = false;
  let attachedNumberId = null;
  let committed = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    const user = await client.query(
      "SELECT credits FROM users WHERE id = $1 FOR UPDATE",
      [req.user.id]
    );
    if (user.rowCount === 0) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(404).json({ error: "User not found." });
    }
    if (user.rows[0].credits < VIP_CREDIT_COST) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(402).json({ error: "You need 50 credits to unlock a VIP number." });
    }

app.get(["/api/vip/available", "/api/vip/numbers"], authenticate, async (_req, res, next) => {
  try {
    const countries = ["US", "GB", "CA", "DK", "PR"];
    const providerNumbers = await getAvailablePhoneNumbers(countries);
    const providerDatabaseIds = new Map();

    for (const number of providerNumbers) {
      const normalizedNumber = normalizePhoneNumber(number.phoneNumber);
      const upserted = await pool.query(
        `INSERT INTO phone_numbers
         (id, phone_number, country, city, dialing_code, flag, number_type,
          telnyx_phone_number_id, active)
         VALUES ($1, $2, $3, $4, $5, $6, 'VIP_PRIVATE', $7, true)
         ON CONFLICT (phone_number) DO UPDATE SET
           country = EXCLUDED.country,
           city = EXCLUDED.city,
           dialing_code = EXCLUDED.dialing_code,
           flag = EXCLUDED.flag,
           number_type = 'VIP_PRIVATE',
           telnyx_phone_number_id = EXCLUDED.telnyx_phone_number_id,
           user_id = NULL,
           telnyx_connection_id = NULL,
           vip_expires_at = NULL,
           active = true
         RETURNING id, phone_number`,
        [
          `telnyx-${number.telnyxPhoneNumberId}`,
          number.phoneNumber,
          number.country,
          number.city,
          number.dialingCode,
          number.flag,
          number.telnyxPhoneNumberId
        ]
      );
      const savedId = upserted.rows && upserted.rows[0]
        ? upserted.rows[0].id
        : `telnyx-${number.telnyxPhoneNumberId}`;
      providerDatabaseIds.set(normalizedNumber, savedId);
    }

    const databaseNumbers = await pool.query(
      `SELECT id, country, city, dialing_code, phone_number, flag
       FROM phone_numbers
       WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       ORDER BY created_at, id`
    );

    const merged = new Map();
    for (const row of databaseNumbers.rows) {
      const number = normalizePhoneNumber(row.phone_number);
      if (!number) continue;
      merged.set(number, {
        id: row.id,
        country: row.country,
        city: row.city,
        dialingCode: row.dialing_code,
        number,
        flag: row.flag
      });
    }
    for (const number of providerNumbers) {
      const normalizedNumber = normalizePhoneNumber(number.phoneNumber);
      if (merged.has(normalizedNumber)) continue;
      merged.set(normalizedNumber, {
        id: providerDatabaseIds.get(normalizedNumber) || `telnyx-${number.telnyxPhoneNumberId}`,
        country: number.country,
        city: number.city,
        dialingCode: number.dialingCode,
        number: number.phoneNumber,
        flag: number.flag
      });
    }

    res.json({ numbers: [...merged.values()] });
  } catch (error) {
    next(error);
  }
});

app.post("/api/vip/purchase", authenticate, async (req, res, next) => {
  const { numberId } = req.body;
  if (!numberId) return res.status(400).json({ error: "Number ID is required." });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 1. Verify number availability
    const resNum = await client.query(
      `SELECT id, telnyx_phone_number_id, phone_number
       FROM phone_numbers
       WHERE id = $1 AND user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       FOR UPDATE`,
      [numberId]
    );

    if (resNum.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "The selected VIP number is no longer available." });
    }

    const number = resNum.rows[0];

    // 2. Assign to user
    await client.query(
      "UPDATE phone_numbers SET user_id = $1 WHERE id = $2",
      [req.user.id, numberId]
    );

    // 3. Update connection
    if (isSipProvisioningConfigured()) {
       const sipAccount = await ensureTelnyxSipAccount(req.user.id);
       await updatePhoneNumberConnection(number.telnyx_phone_number_id, sipAccount);
    }

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});


    const number = await client.query(
      `SELECT id, telnyx_phone_number_id FROM phone_numbers
       WHERE id = $1 AND user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         AND telnyx_phone_number_id IS NOT NULL
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       FOR UPDATE SKIP LOCKED`,
      [numberId]
    );
    if (number.rowCount === 0) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(409).json({ error: "The selected VIP number is no longer available." });
    }

    const connectionId = sipAccount ? sipAccount.connectionId : null;
    if (connectionId) {
      attachedNumberId = number.rows[0].telnyx_phone_number_id;
      await updatePhoneNumberConnection(attachedNumberId, connectionId);
    }
    const assigned = await client.query(
      `UPDATE phone_numbers
       SET user_id = $1, telnyx_connection_id = $2
       WHERE id = $3 AND user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
       RETURNING id`,
      [req.user.id, connectionId, numberId]
    );
    if (assigned.rowCount === 0) throw new Error("The VIP number could not be assigned.");

    const debit = await client.query(
      "UPDATE users SET credits = credits - $1 WHERE id = $2 AND credits >= $1 RETURNING credits",
      [VIP_CREDIT_COST, req.user.id]
    );
    if (debit.rowCount === 0) throw new Error("The VIP credit balance changed before assignment.");

    await client.query("COMMIT");
    transactionStarted = false;
    committed = true;
    attachedNumberId = null;
    return res.json({ unlocked: true, numberId, credits: debit.rows[0].credits });
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    if (attachedNumberId && !committed) {
      try {
        await updatePhoneNumberConnection(attachedNumberId, null);
      } catch (cleanupError) {
        console.error(`Unable to detach an unassigned VIP Telnyx number: ${cleanupError.message}`);
      }
    }
    return next(error);
  } finally {
    client.release();
  }
});

app.post(["/api/numbers/claim-free", "/api/numbers/claim"], authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, country, city, dialing_code, phone_number, flag, active
       FROM phone_numbers
       WHERE active AND number_type IN ('FREE_POOL', 'FREE_ASSIGNED')
       ORDER BY CASE number_type WHEN 'FREE_POOL' THEN 0 ELSE 1 END,
                created_at, phone_number
       LIMIT 1`
    );
    if (result.rowCount === 0) {
      return res.status(409).json({ error: "No free numbers are currently available." });
    }

    const row = result.rows[0];
    return res.json({ number: {
      id: row.id,
      country: row.country,
      city: row.city,
      dialingCode: row.dialing_code,
      number: row.phone_number,
      flag: row.flag,
      label: "FREE_ASSIGNED",
      active: row.active,
      mode: "PUBLIC_POOL"
    } });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/messages", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, sender, body_ciphertext, body_iv, body_tag, code_ciphertext,
              code_iv, code_tag, created_at
       FROM sms_messages
       WHERE user_id = $1 AND created_at > now() - interval '24 hours'
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.user.id]
    );
    const messages = result.rows.map((row) => {
      const message = decryptBody(row);
      return {
        id: row.id,
        sender: row.sender,
        service: row.sender,
        time: row.created_at.toISOString(),
        code: decryptCode(row),
        message,
        flag: "✉️"
      };
    });
    if (STAGING_SHARED_FREE_NUMBERS_ENABLED) {
      messages.unshift({
        id: "staging-shared-free-test-message",
        sender: "VirtualSIM Test",
        service: "STAGING SYNTHETIC TEST",
        time: new Date().toISOString(),
        code: "246810",
        message: "Synthetic staging-only OTP for testing. This message is not from Telnyx or a third-party service.",
        flag: "🧪"
      });
    }
    return res.json({ messages });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/voip-config", authenticate, async (req, res, next) => {
  try {
    res.set("Cache-Control", "no-store");
    const vip = await pool.query(
      `SELECT id, phone_number, telnyx_phone_number_id, telnyx_connection_id
       FROM phone_numbers
       WHERE user_id = $1 AND active AND number_type = 'VIP_PRIVATE'
         AND (vip_expires_at IS NULL OR vip_expires_at > now())
       ORDER BY created_at, id
       LIMIT 1`,
      [req.user.id]
    );
    if (vip.rowCount === 0) {
      return res.json({
        configured: false,
        message: "Unlock a VIP number (50 CR) to enable outbound VoIP calling"
      });
    }
    if (!vip.rows[0].telnyx_phone_number_id) {
      return res.json({
        configured: false,
        message: "Your VIP number is not linked to Telnyx for outbound VoIP calling."
      });
    }
    if (!isSipProvisioningConfigured()) {
      return res.json({
        configured: false,
        message: "Telnyx SIP provisioning is not configured for this VIP account."
      });
    }

    const account = await ensureTelnyxSipAccount(req.user.id);
    const number = vip.rows[0];
    if (number.telnyx_connection_id !== account.connectionId) {
      const restoreConnection = async () => {
        try {
          await updatePhoneNumberConnection(
            number.telnyx_phone_number_id,
            number.telnyx_connection_id || null
          );
        } catch (cleanupError) {
          console.error(`Unable to restore the VIP number connection: ${cleanupError.message}`);
        }
      };
      try {
        await updatePhoneNumberConnection(number.telnyx_phone_number_id, account.connectionId);
        const updated = await pool.query(
          `UPDATE phone_numbers
           SET telnyx_connection_id = $1
           WHERE id = $2 AND user_id = $3 AND active AND number_type = 'VIP_PRIVATE'
             AND (vip_expires_at IS NULL OR vip_expires_at > now())
           RETURNING id`,
          [account.connectionId, number.id, req.user.id]
        );
        if (updated.rowCount === 0) {
          await restoreConnection();
          return res.status(409).json({
            configured: false,
            message: "The VIP number assignment changed. Refresh and retry."
          });
        }
      } catch (error) {
        await restoreConnection();
        throw error;
      }
    }
    return res.json({
      configured: true,
      domain: account.domain,
      username: account.username,
      password: account.password,
      callerId: number.phone_number,
      transport: "TLS",
      port: 5061
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/admin/numbers", adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const number = normalizePhoneNumber(req.body.phoneNumber);
    const type = String(req.body.type || "");
    if (!["FREE_ASSIGNED", "VIP_PRIVATE"].includes(type)) {
      return res.status(400).json({ error: "type must be FREE_ASSIGNED or VIP_PRIVATE." });
    }
    const userId = req.body.userId ? String(req.body.userId) : null;
    if (type === "FREE_ASSIGNED" && !userId) {
      return res.status(400).json({ error: "Free numbers must be assigned to a specific user." });
    }
    if (userId) {
      const owner = await pool.query("SELECT 1 FROM users WHERE id = $1", [userId]);
      if (owner.rowCount === 0) return res.status(404).json({ error: "User not found." });
    }
    const result = await pool.query(
      `INSERT INTO phone_numbers
       (id, user_id, phone_number, country, city, dialing_code, flag, number_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, phone_number, number_type`,
      [
        crypto.randomUUID(),
        userId,
        number,
        String(req.body.country || "Unknown").slice(0, 80),
        String(req.body.city || "").slice(0, 80),
        String(req.body.dialingCode || "").slice(0, 8),
        String(req.body.flag || "🌐").slice(0, 16),
        type
      ]
    );
    return res.status(201).json({ number: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "That number is already assigned or in inventory." });
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
});

app.put("/api/admin/users/:userId/voip", adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const user = await pool.query("SELECT 1 FROM users WHERE id = $1", [req.params.userId]);
    if (user.rowCount === 0) return res.status(404).json({ error: "User not found." });
    if (!await userHasActiveVipNumber(req.params.userId)) {
      return res.status(409).json({
        error: "Unlock a VIP number (50 CR) to enable outbound VoIP calling"
      });
    }
    await ensureTelnyxSipAccount(req.params.userId);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.delete("/api/account", authenticate, async (req, res, next) => {
  let client;
  let transactionStarted = false;
  try {
    const [numbers, sip] = await Promise.all([
      pool.query(
        "SELECT telnyx_phone_number_id, telnyx_connection_id FROM phone_numbers WHERE user_id = $1",
        [req.user.id]
      ),
      pool.query(
        "SELECT telnyx_connection_id FROM sip_accounts WHERE user_id = $1",
        [req.user.id]
      )
    ]);
    const connectionId = sip.rows[0] && sip.rows[0].telnyx_connection_id;
    if ((connectionId || numbers.rows.some((number) => number.telnyx_phone_number_id)) && !TELNYX_API_KEY) {
      throw new TelnyxApiError(503, "Telnyx is unavailable for account cleanup. Please retry later.");
    }
    for (const number of numbers.rows) {
      if (number.telnyx_phone_number_id && number.telnyx_connection_id) {
        await updatePhoneNumberConnection(number.telnyx_phone_number_id, null);
      }
    }
    if (connectionId) await deleteCredentialConnection(connectionId);

    client = await pool.connect();
    await client.query("BEGIN");
    transactionStarted = true;
    await client.query(
      `UPDATE phone_numbers
       SET user_id = NULL,
           active = CASE WHEN number_type = 'FREE_ASSIGNED' THEN true ELSE false END,
           number_type = CASE WHEN number_type = 'FREE_ASSIGNED' THEN 'FREE_POOL' ELSE number_type END,
           telnyx_connection_id = NULL
       WHERE user_id = $1`,
      [req.user.id]
    );
    await client.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    await client.query("COMMIT");
    transactionStarted = false;
    return res.status(204).end();
  } catch (error) {
    if (client && transactionStarted) await client.query("ROLLBACK");
    return next(error);
  } finally {
    if (client) client.release();
  }
});

app.post("/api/rewards/ad-token", authenticate, async (req, res, next) => {
  try {
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    await pool.query(
      "INSERT INTO ad_reward_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '10 minutes')",
      [tokenHash, req.user.id]
    );
    return res.json({ customData: token, rewardCredits: REWARD_CREDITS });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/rewards/staging-fallback", authenticate, async (req, res, next) => {
  if (!STAGING_AD_REWARD_FALLBACK_ENABLED) {
    return res.status(404).json({ error: "Staging ad fallback is not enabled." });
  }

  const client = await pool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    const user = await client.query(
      "SELECT credits FROM users WHERE id = $1 FOR UPDATE",
      [req.user.id]
    );
    if (user.rowCount === 0) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      return res.status(404).json({ error: "User not found." });
    }

    const transactionId = `staging-ad-fallback:${req.user.id}`;
    const reward = await client.query(
      `INSERT INTO ad_rewards (transaction_id, user_id, credits)
       VALUES ($1, $2, $3)
       ON CONFLICT (transaction_id) DO NOTHING
       RETURNING transaction_id`,
      [transactionId, req.user.id, STAGING_AD_FALLBACK_CREDITS]
    );
    if (reward.rowCount === 0) {
      await client.query("COMMIT");
      transactionStarted = false;
      return res.json({
        granted: false,
        alreadyClaimed: true,
        credits: user.rows[0].credits
      });
    }

    const updatedUser = await client.query(
      "UPDATE users SET credits = credits + $1 WHERE id = $2 RETURNING credits",
      [STAGING_AD_FALLBACK_CREDITS, req.user.id]
    );
    if (updatedUser.rowCount === 0) throw new Error("The staging reward could not be applied.");

    await client.query("COMMIT");
    transactionStarted = false;
    return res.json({
      granted: true,
      alreadyClaimed: false,
      creditsAdded: STAGING_AD_FALLBACK_CREDITS,
      credits: updatedUser.rows[0].credits
    });
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    return next(error);
  } finally {
    client.release();
  }
});

let admobKeysCache = { expiresAt: 0, keys: new Map() };
async function getAdMobKey(keyId) {
  if (Date.now() >= admobKeysCache.expiresAt) {
    const response = await fetch("https://gstatic.com/admob/reward/verifier-keys.json");
    if (!response.ok) throw new Error("AdMob verification keys are unavailable.");
    const payload = await response.json();
    admobKeysCache = {
      expiresAt: Date.now() + 23 * 60 * 60 * 1000,
      keys: new Map(payload.keys.map((item) => [String(item.keyId), item.pem || item.key]))
    };
  }
  return admobKeysCache.keys.get(String(keyId)) || null;
}

app.get("/api/webhooks/admob", async (req, res, next) => {
  try {
    const rawQuery = req.originalUrl.split("?")[1] || "";
    const keyId = new URLSearchParams(rawQuery).get("key_id");
    const key = keyId ? await getAdMobKey(keyId) : null;
    const verified = key ? verifyAdMobSignature(rawQuery, key) : null;
    if (!verified || !verified.transactionId || !verified.customData) {
      return res.status(400).send("Invalid reward verification.");
    }
    if (!Number.isFinite(verified.rewardAmount) || !Number.isInteger(verified.rewardAmount) || verified.rewardAmount < 1 ||
        !Number.isFinite(verified.timestamp) ||
        Math.abs(Date.now() - verified.timestamp) > 24 * 60 * 60 * 1000) {
      return res.status(400).send("Invalid reward callback.");
    }

    const tokenHash = crypto.createHash("sha256").update(verified.customData).digest("hex");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        "SELECT 1 FROM ad_rewards WHERE transaction_id = $1",
        [verified.transactionId]
      );
      if (existing.rowCount > 0) {
        await client.query("COMMIT");
        return res.status(200).send("Already processed.");
      }
      const token = await client.query(
        `SELECT user_id FROM ad_reward_tokens
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
         FOR UPDATE`,
        [tokenHash]
      );
      if (token.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(400).send("Reward token is invalid or expired.");
      }
      const userId = token.rows[0].user_id;
      await client.query(
        "INSERT INTO ad_rewards (transaction_id, user_id, credits) VALUES ($1, $2, $3)",
        [verified.transactionId, userId, REWARD_CREDITS]
      );
      await client.query(
        "UPDATE users SET credits = credits + $1 WHERE id = $2",
        [REWARD_CREDITS, userId]
      );
      await client.query("UPDATE ad_reward_tokens SET used_at = now() WHERE token_hash = $1", [tokenHash]);
      await client.query("COMMIT");
      return res.status(200).send("Reward granted.");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    return next(error);
  }
});

app.post("/api/store/verify-vip", authenticate, async (req, res, next) => {
  const purchaseToken = String(req.body.purchaseToken || "");
  const productId = String(req.body.productId || "");
  const requestedNumberId = String(req.body.numberId || "").trim() || null;
  if (!purchaseToken || productId !== VIP_PRODUCT_ID) {
    return res.status(400).json({ error: "Invalid VIP purchase." });
  }
  let credentials;
  try {
    credentials = process.env.GOOGLE_SERVICE_ACCOUNT_JSON
      ? JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON)
      : null;
  } catch (_error) {
    return res.status(503).json({ error: "Google Play verification is not configured." });
  }
  if (!credentials) return res.status(503).json({ error: "Google Play verification is not configured." });

  try {
    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ["https://www.googleapis.com/auth/androidpublisher"]
    });
    const publisher = google.androidpublisher({ version: "v3", auth });
    const purchase = await publisher.purchases.products.get({
      packageName: PLAY_PACKAGE_NAME,
      productId,
      token: purchaseToken
    });
    if (purchase.data.purchaseState !== 0) {
      return res.status(402).json({ error: "The Play purchase has not completed." });
    }

    const tokenHash = crypto.createHash("sha256").update(purchaseToken).digest("hex");
    const saved = await pool.query(
      `INSERT INTO vip_purchases (purchase_token_hash, user_id, product_id, status)
       VALUES ($1, $2, $3, 'pending_provision')
       ON CONFLICT (purchase_token_hash) DO NOTHING`,
      [tokenHash, req.user.id, productId]
    );
    if (saved.rowCount === 0) {
      const existing = await pool.query(
        "SELECT user_id, product_id FROM vip_purchases WHERE purchase_token_hash = $1",
        [tokenHash]
      );
      if (existing.rowCount === 0) {
        throw new Error("The verified VIP purchase could not be saved.");
      }
      if (existing.rows[0].user_id !== req.user.id || existing.rows[0].product_id !== productId) {
        return res.status(409).json({ error: "This Play purchase has already been applied to another account." });
      }
    }

    try {
      const result = await fulfillVipPurchase({
        tokenHash,
        userId: req.user.id,
        productId,
        requestedNumberId
      });
      if (result.status === "pending_provision") {
        return res.status(202).json({
          verified: true,
          status: "pending_provision",
          message: "Your purchase is verified. Number provisioning will be retried automatically."
        });
      }
      if (result.status === "expired") {
        return res.status(410).json({
          verified: true,
          status: "expired",
          message: "The 30-day validity period for this VIP purchase has ended."
        });
      }
      return res.json({
        verified: true,
        status: "active",
        numberId: result.number.id,
        number: result.number,
        sipConfig: result.sipConfig
      });
    } catch (error) {
      if (!(error instanceof TelnyxApiError)) throw error;
      console.error(
        `Telnyx VIP provisioning failed for purchase ${tokenHash.slice(0, 12)} ` +
        `(status ${error.status}): ${error.message}`
      );
      return res.status(202).json({
        verified: true,
        status: "pending_provision",
        message: "Your purchase is verified. Number provisioning will be retried automatically."
      });
    }
  } catch (error) {
    return next(error);
  }
});

app.post("/api/webhook/sms", async (req, res, next) => {
  try {
    if (!TELNYX_PUBLIC_KEY) {
      return res.status(503).json({ error: "Telnyx webhook verification is not configured." });
    }
    const signature = req.get("telnyx-signature-ed25519");
    const timestamp = req.get("telnyx-timestamp");
    if (!req.rawBody || !verifyTelnyxSignature({
      rawBody: req.rawBody,
      signature,
      timestamp,
      publicKey: TELNYX_PUBLIC_KEY
    })) {
      return res.status(401).json({ error: "Invalid Telnyx webhook signature." });
    }
    if (req.body?.data?.event_type !== "message.received") {
      return res.status(200).json({ status: "ignored" });
    }
    const message = parseInboundSms(req.body);
    if (!message) return res.status(400).json({ error: "Required Telnyx message fields are missing." });
    const providerMessageId = `telnyx:${message.messageId}`;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const eventInsert = await client.query(
        "INSERT INTO processed_sms (provider_message_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING provider_message_id",
        [providerMessageId]
      );
      if (eventInsert.rowCount === 0) {
        await client.query("COMMIT");
        return res.status(200).json({ status: "duplicate" });
      }
      const number = await client.query(
        "SELECT id, user_id FROM phone_numbers WHERE phone_number = $1 AND active AND user_id IS NOT NULL AND (vip_expires_at IS NULL OR vip_expires_at > now()) FOR SHARE",
        [message.to]
      );
      if (number.rowCount === 0) {
        await client.query("COMMIT");
        return res.status(202).json({ status: "unassigned number; message discarded" });
      }
      const owner = number.rows[0];
      const body = encryptedFields(message.text);
      const code = encryptedFields(extractOtp(message.text));
      await client.query(
        `INSERT INTO sms_messages
         (id, user_id, number_id, sender, body_ciphertext, body_iv, body_tag,
          code_ciphertext, code_iv, code_tag)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          providerMessageId,
          owner.user_id,
          owner.id,
          message.from.slice(0, 32),
          body[0], body[1], body[2],
          code[0], code[1], code[2]
        ]
      );
      await client.query("COMMIT");
      return res.status(200).json({ status: "accepted" });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return res.status(200).json({ status: "duplicate" });
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
});

const errorHandler = (error, _req, res, _next) => {
  if (process.env.NODE_ENV !== "test") console.error(error.message);
  if (error instanceof TelnyxApiError) {
    const status = error.status === 503 ? 503 : 502;
    return res.status(status).json({ error: error.message });
  }
  return res.status(500).json({ error: "The server could not complete the request." });
};
app.use(errorHandler);

async function retryPendingVipPurchases() {
  if (process.env.AUTO_PROVISION_TELNYX !== "true") return;
  const pending = await pool.query(
    `SELECT purchase_token_hash, user_id, product_id
     FROM vip_purchases
     WHERE status = 'pending_provision'
     ORDER BY created_at
     LIMIT 10`
  );
  for (const purchase of pending.rows) {
    try {
      await fulfillVipPurchase({
        tokenHash: purchase.purchase_token_hash,
        userId: purchase.user_id,
        productId: purchase.product_id
      });
    } catch (error) {
      console.error(
        `VIP purchase retry failed for ${purchase.purchase_token_hash.slice(0, 12)}: ${error.message}`
      );
    }
  }
}

async function start() {
  await pool.query(schema);
  await pool.query("DELETE FROM sms_messages WHERE created_at < now() - interval '24 hours'");
  await pool.query("DELETE FROM webhook_nonces WHERE received_at < now() - interval '24 hours'");
  await pool.query("DELETE FROM phone_auth_challenges WHERE expires_at < now()");
  await pool.query("DELETE FROM ad_reward_tokens WHERE expires_at < now() OR used_at < now() - interval '24 hours'");
  await pool.query(
    `UPDATE phone_numbers SET active = false
     WHERE number_type = 'VIP_PRIVATE' AND user_id IS NOT NULL
       AND active AND vip_expires_at <= now()`
  );
  const cleanup = setInterval(async () => {
    try {
      await pool.query("DELETE FROM sms_messages WHERE created_at < now() - interval '24 hours'");
      await pool.query("DELETE FROM webhook_nonces WHERE received_at < now() - interval '24 hours'");
      await pool.query("DELETE FROM phone_auth_challenges WHERE expires_at < now()");
      await pool.query("DELETE FROM ad_reward_tokens WHERE expires_at < now() OR used_at < now() - interval '24 hours'");
      await pool.query(
        `UPDATE phone_numbers SET active = false
         WHERE number_type = 'VIP_PRIVATE' AND user_id IS NOT NULL
           AND active AND vip_expires_at <= now()`
      );
    } catch (error) {
      console.error(`Cleanup failed: ${error.message}`);
    }
  }, 60 * 60 * 1000);
  cleanup.unref();
  const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`VirtualSIM backend listening on ${PORT}`);
  });
  let retryingVipPurchases = false;
  const runVipProvisionRetries = async () => {
    if (retryingVipPurchases) return;
    retryingVipPurchases = true;
    try {
      await retryPendingVipPurchases();
    } catch (error) {
      console.error(`VIP purchase retry scan failed: ${error.message}`);
    } finally {
      retryingVipPurchases = false;
    }
  };
  const vipRetryTimer = setInterval(runVipProvisionRetries, 5 * 60 * 1000);
  vipRetryTimer.unref();
  setImmediate(runVipProvisionRetries);
  server.on("close", () => clearInterval(vipRetryTimer));
  if (TELNYX_API_KEY) {
    let syncing = false;
    const runTelnyxSync = async () => {
      if (syncing) return;
      syncing = true;
      try {
        await syncTelnyxInventory();
      } catch (error) {
        console.error(`Telnyx inventory sync failed: ${error.message}`);
      } finally {
        syncing = false;
      }
    };
    const syncTimer = setInterval(runTelnyxSync, TELNYX_SYNC_INTERVAL_MS);
    syncTimer.unref();
    setImmediate(runTelnyxSync);
    server.on("close", () => clearInterval(syncTimer));
  } else {
    console.warn("Telnyx inventory sync is disabled because TELNYX_API_KEY is not configured.");
  }
  return server;
}

if (require.main === module) {
  start().catch((error) => {
    console.error(`Backend startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { app, start, syncTelnyxInventory };
