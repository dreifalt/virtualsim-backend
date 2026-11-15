# VirtualSIM Master Backend

Node.js 20+ / Express / PostgreSQL backend. It never publishes an unauthenticated shared SMS inbox or shared SIP credentials. Numbers, OTP messages, wallet state, and SIP credentials are scoped to the authenticated user.

## Run locally

1. Create a PostgreSQL database.
2. Copy `.env.example` to `.env` and set `DATABASE_URL`, a random `JWT_SECRET`, a separate random `ADMIN_API_KEY`, and `DATA_ENCRYPTION_KEY`.
3. Generate secrets with Node:

   ```powershell
   node -e "const c=require('node:crypto'); console.log('JWT_SECRET='+c.randomBytes(48).toString('base64url')); console.log('ADMIN_API_KEY='+c.randomBytes(48).toString('base64url')); console.log('DATA_ENCRYPTION_KEY='+c.randomBytes(32).toString('base64'))"
   ```

4. Configure `PLIVO_AUTH_TOKEN` and the exact public callback URL in `PLIVO_WEBHOOK_URL`. Set the Plivo inbound-message URL to `POST https://<your-host>/api/webhook/sms`; the server validates Plivo V3 signatures and rejects replayed nonces.
5. Run `npm install`, `npm test`, and `npm start`.

The server creates its schema at startup. `/health` checks database connectivity. Deploy behind HTTPS (for example, as a Render web service with a managed PostgreSQL database) and configure every secret as a deployment environment variable; do not commit `.env`.

## API

- `POST /api/auth/register` — create an account; requires email and a 12–72 byte password.
- `POST /api/auth/login` — authenticate and return a 12-hour bearer token.
- `GET /api/profile` — return the caller's profile, wallet credits, and VIP availability.
- `GET /api/numbers` — return only numbers assigned to the caller.
- `GET /api/messages` — return only the caller's SMS messages from the last 24 hours.
- `GET /api/voip-config` — return only the caller's SIP account; requires bearer auth and uses `Cache-Control: no-store`.
- `DELETE /api/account` — delete the caller's account and messages; assigned numbers are deactivated and detached.
- `POST /api/webhook/sms` — Plivo inbound SMS callback; signature verified using `PLIVO_WEBHOOK_URL` and `PLIVO_AUTH_TOKEN`.
- `POST /api/rewards/ad-token` — mint a short-lived one-use AdMob custom-data token.
- `GET /api/webhooks/admob` — verify AdMob ECDSA SSV callback before crediting the wallet; transaction IDs are idempotent.
- `POST /api/store/verify-vip` — verify a Play product purchase server-side before assigning one private VIP number.
- `POST /api/admin/numbers` — admin-only inventory/assignment operation using `X-Admin-Key`. `FREE_ASSIGNED` requires a user ID; VIP inventory can be added without an owner.
- `PUT /api/admin/users/:userId/voip` — admin-only per-user SIP credential provisioning; SIP passwords are AES-256-GCM encrypted at rest.

All SMS bodies, extracted OTP codes, and SIP passwords are encrypted at rest using `DATA_ENCRYPTION_KEY`. OTP messages and webhook nonces are removed after 24 hours; provider message IDs are retained for idempotency so a replayed signed callback cannot re-deliver an expired message. Deleted user data is removed via foreign-key cascades. Assigned numbers are deactivated and detached on account deletion; arrange carrier release separately through your number-provider operations. Free numbers are assigned to a specific account; SMS received on unassigned numbers are discarded.

## Store configuration

For rewarded ads, create a rewarded AdMob unit and enable server-side verification with `https://<your-host>/api/webhooks/admob`. Google SSV is verified against Google's rotating public keys; credits are granted only after a valid, unexpired, one-use token is received.

For VIP purchases, create the `VIP_PRODUCT_ID` in Play Console and grant the service account in `GOOGLE_SERVICE_ACCOUNT_JSON` the Android Publisher permission for `PLAY_PACKAGE_NAME`. Test purchases require a Play internal testing track/license tester. No purchase is credited solely from a client callback.

Admin routes provision individual SIP accounts. Connect them to your SIP provider's provisioning workflow before production; this backend does not create upstream carrier/SIP accounts by itself.
