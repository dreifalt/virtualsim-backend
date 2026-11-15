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
  decryptText,
  encryptText,
  extractOtp,
  normalizePhoneNumber,
  safeEqual,
  verifyAdMobSignature,
  verifyPlivoSignature
} = require("./security");

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const PLIVO_AUTH_TOKEN = process.env.PLIVO_AUTH_TOKEN;
const PLIVO_WEBHOOK_URL = process.env.PLIVO_WEBHOOK_URL;
const PLAY_PACKAGE_NAME = process.env.PLAY_PACKAGE_NAME || "com.virtualsim.pro";
const VIP_PRODUCT_ID = process.env.VIP_PRODUCT_ID || "virtualsim_vip_number";
const REWARD_CREDITS = Number(process.env.AD_REWARD_CREDITS || 1);
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
if (!Number.isInteger(REWARD_CREDITS) || REWARD_CREDITS < 1) {
  throw new Error("AD_REWARD_CREDITS must be a positive integer.");
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
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  credits integer NOT NULL DEFAULT 0 CHECK (credits >= 0),
  token_version integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS phone_numbers (
  id text PRIMARY KEY,
  user_id text REFERENCES users(id) ON DELETE SET NULL,
  phone_number text NOT NULL UNIQUE,
  country text NOT NULL,
  city text NOT NULL DEFAULT '',
  dialing_code text NOT NULL DEFAULT '',
  flag text NOT NULL DEFAULT '🌐',
  number_type text NOT NULL CHECK (number_type IN ('FREE_ASSIGNED', 'VIP_PRIVATE')),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
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
  updated_at timestamptz NOT NULL DEFAULT now()
);
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
  number_id text NOT NULL UNIQUE REFERENCES phone_numbers(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
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
      "SELECT id, email, credits, token_version FROM users WHERE id = $1",
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

app.get("/health", async (_req, res, next) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (error) {
    next(error);
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
      "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, credits, token_version",
      [id, email, passwordHash]
    );
    const user = result.rows[0];
    return res.status(201).json({ token: createToken(user), profile: publicProfile(user) });
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
      "SELECT id, email, password_hash, credits, token_version FROM users WHERE email = $1",
      [email]
    );
    const user = result.rows[0];
    const valid = await bcrypt.compare(String(req.body.password || ""), user?.password_hash || dummyPasswordHash);
    if (!user || !valid) return res.status(401).json({ error: "Email or password is incorrect." });
    return res.json({ token: createToken(user), profile: publicProfile(user) });
  } catch (error) {
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    return next(error);
  }
});

function publicProfile(user, vipAvailable = false) {
  return {
    id: user.id,
    email: user.email,
    credits: user.credits,
    vipAvailable
  };
}

app.get("/api/profile", authenticate, async (req, res, next) => {
  try {
    const [available, vip] = await Promise.all([
      pool.query("SELECT EXISTS (SELECT 1 FROM phone_numbers WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE') AS available"),
      pool.query("SELECT EXISTS (SELECT 1 FROM phone_numbers WHERE user_id = $1 AND active AND number_type = 'VIP_PRIVATE') AS has_vip", [req.user.id])
    ]);
    return res.json({
      profile: {
        ...publicProfile(req.user, available.rows[0].available),
        hasVipNumber: vip.rows[0].has_vip
      }
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/numbers", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT country, city, dialing_code, phone_number, flag, number_type, active
       FROM phone_numbers
       WHERE user_id = $1 AND active = true
       ORDER BY CASE number_type WHEN 'FREE_ASSIGNED' THEN 0 ELSE 1 END, country`,
      [req.user.id]
    );
    return res.json({
      numbers: result.rows.map((row) => ({
        country: row.country,
        city: row.city,
        dialingCode: row.dialing_code,
        number: row.phone_number,
        flag: row.flag,
        label: row.number_type,
        active: row.active
      }))
    });
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
    return res.json({
      messages: result.rows.map((row) => {
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
      })
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/voip-config", authenticate, async (req, res, next) => {
  try {
    res.set("Cache-Control", "no-store");
    const result = await pool.query(
      "SELECT sip_domain, sip_username, password_ciphertext, password_iv, password_tag FROM sip_accounts WHERE user_id = $1",
      [req.user.id]
    );
    const account = result.rows[0];
    if (!account) return res.json({ configured: false });
    const password = decryptText(
      account.password_ciphertext,
      account.password_iv,
      account.password_tag,
      DATA_KEY
    );
    return res.json({
      configured: true,
      domain: account.sip_domain,
      username: account.sip_username,
      password
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
    const domain = String(req.body.domain || "").trim();
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!domain || domain.includes("@") || /[\s/]/.test(domain) || !username || !password) {
      return res.status(400).json({ error: "Provide a SIP domain, username, and password." });
    }
    const user = await pool.query("SELECT 1 FROM users WHERE id = $1", [req.params.userId]);
    if (user.rowCount === 0) return res.status(404).json({ error: "User not found." });
    const [ciphertext, iv, tag] = encryptedFields(password);
    await pool.query(
      `INSERT INTO sip_accounts (user_id, sip_domain, sip_username, password_ciphertext, password_iv, password_tag)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id) DO UPDATE SET
         sip_domain = EXCLUDED.sip_domain,
         sip_username = EXCLUDED.sip_username,
         password_ciphertext = EXCLUDED.password_ciphertext,
         password_iv = EXCLUDED.password_iv,
         password_tag = EXCLUDED.password_tag,
         updated_at = now()`,
      [req.params.userId, domain, username, ciphertext, iv, tag]
    );
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.delete("/api/account", authenticate, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "UPDATE phone_numbers SET user_id = NULL, active = false WHERE user_id = $1",
      [req.user.id]
    );
    await client.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    await client.query("COMMIT");
    return res.status(204).end();
  } catch (error) {
    await client.query("ROLLBACK");
    return next(error);
  } finally {
    client.release();
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
    if (!Number.isFinite(verified.timestamp) ||
        Math.abs(Date.now() - verified.timestamp) > 24 * 60 * 60 * 1000 ||
        verified.rewardAmount !== REWARD_CREDITS) {
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
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const duplicate = await client.query(
        "SELECT 1 FROM vip_purchases WHERE purchase_token_hash = $1",
        [tokenHash]
      );
      if (duplicate.rowCount > 0) {
        await client.query("COMMIT");
        return res.json({ verified: true, alreadyApplied: true });
      }
      const number = await client.query(
        `SELECT id FROM phone_numbers
         WHERE user_id IS NULL AND active AND number_type = 'VIP_PRIVATE'
         ORDER BY created_at
         FOR UPDATE SKIP LOCKED LIMIT 1`
      );
      if (number.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "No VIP numbers are currently available." });
      }
      const numberId = number.rows[0].id;
      await client.query(
        "UPDATE phone_numbers SET user_id = $1 WHERE id = $2 AND user_id IS NULL",
        [req.user.id, numberId]
      );
      await client.query(
        "INSERT INTO vip_purchases (purchase_token_hash, user_id, product_id, number_id) VALUES ($1, $2, $3, $4)",
        [tokenHash, req.user.id, productId, numberId]
      );
      await client.query("COMMIT");
      return res.json({ verified: true, numberId });
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

app.post("/api/webhook/sms", async (req, res, next) => {
  try {
    if (!PLIVO_AUTH_TOKEN || !PLIVO_WEBHOOK_URL) {
      return res.status(503).json({ error: "Plivo webhook verification is not configured." });
    }
    const nonce = req.get("x-plivo-signature-v3-nonce");
    const signature = req.get("x-plivo-signature-v3");
    if (!verifyPlivoSignature({
      url: PLIVO_WEBHOOK_URL,
      nonce,
      authToken: PLIVO_AUTH_TOKEN,
      signature,
      params: req.body
    })) {
      return res.status(401).json({ error: "Invalid Plivo webhook signature." });
    }
    const from = String(req.body.From || "");
    const to = normalizePhoneNumber(req.body.To);
    const text = String(req.body.Text || "").slice(0, 4096);
    const providerMessageId = String(req.body.MessageUUID || req.body.MessageUuid || "");
    if (!from || !text || !providerMessageId) {
      return res.status(400).json({ error: "Required Plivo message fields are missing." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nonceInsert = await client.query(
        "INSERT INTO webhook_nonces (nonce) VALUES ($1) ON CONFLICT DO NOTHING RETURNING nonce",
        [nonce]
      );
      if (nonceInsert.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Webhook nonce has already been used." });
      }
      const eventInsert = await client.query(
        "INSERT INTO processed_sms (provider_message_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING provider_message_id",
        [providerMessageId]
      );
      if (eventInsert.rowCount === 0) {
        await client.query("COMMIT");
        return res.status(200).json({ status: "duplicate" });
      }
      const number = await client.query(
        "SELECT id, user_id FROM phone_numbers WHERE phone_number = $1 AND active AND user_id IS NOT NULL FOR SHARE",
        [to]
      );
      if (number.rowCount === 0) {
        await client.query("COMMIT");
        return res.status(202).json({ status: "unassigned number; message discarded" });
      }
      const owner = number.rows[0];
      const body = encryptedFields(text);
      const code = encryptedFields(extractOtp(text));
      await client.query(
        `INSERT INTO sms_messages
         (id, user_id, number_id, sender, body_ciphertext, body_iv, body_tag,
          code_ciphertext, code_iv, code_tag)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          providerMessageId,
          owner.user_id,
          owner.id,
          from.slice(0, 32),
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
  return res.status(500).json({ error: "The server could not complete the request." });
};
app.use(errorHandler);

async function start() {
  await pool.query(schema);
  await pool.query("DELETE FROM sms_messages WHERE created_at < now() - interval '24 hours'");
  await pool.query("DELETE FROM webhook_nonces WHERE received_at < now() - interval '24 hours'");
  await pool.query("DELETE FROM ad_reward_tokens WHERE expires_at < now() OR used_at < now() - interval '24 hours'");
  const cleanup = setInterval(async () => {
    try {
      await pool.query("DELETE FROM sms_messages WHERE created_at < now() - interval '24 hours'");
      await pool.query("DELETE FROM webhook_nonces WHERE received_at < now() - interval '24 hours'");
      await pool.query("DELETE FROM ad_reward_tokens WHERE expires_at < now() OR used_at < now() - interval '24 hours'");
    } catch (error) {
      console.error(`Cleanup failed: ${error.message}`);
    }
  }, 60 * 60 * 1000);
  cleanup.unref();
  return app.listen(PORT, "0.0.0.0", () => {
    console.log(`VirtualSIM backend listening on ${PORT}`);
  });
}

if (require.main === module) {
  start().catch((error) => {
    console.error(`Backend startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { app, start };
