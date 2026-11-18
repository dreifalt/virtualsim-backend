# VirtualSIM Master Backend

Node.js 20+ / Express / PostgreSQL backend. Telnyx is the carrier for imported phone numbers, inbound SMS, and per-user SIP credential connections. The Telnyx API key remains on the backend; numbers, OTP messages, wallet state, and SIP credentials are scoped to an authenticated account.

## Run locally

1. Create a PostgreSQL database and copy `.env.example` to `.env`.
2. Set `DATABASE_URL`, a random `JWT_SECRET`, a separate random `ADMIN_API_KEY`, and `DATA_ENCRYPTION_KEY`.
3. Generate application secrets with Node:

   ```powershell
   node -e "const c=require('node:crypto'); console.log('JWT_SECRET='+c.randomBytes(48).toString('base64url')); console.log('ADMIN_API_KEY='+c.randomBytes(48).toString('base64url')); console.log('DATA_ENCRYPTION_KEY='+c.randomBytes(32).toString('base64'))"
   ```

4. Configure the Telnyx environment variables described below, then run `npm install`, `npm test`, and `npm start`.

The server creates and migrates its schema at startup. `/health` checks the database and reports whether Telnyx is configured and when inventory was last synced. Deploy behind HTTPS and set secrets in the hosting provider; do not commit `.env`.

## Telnyx setup

- Set `TELNYX_API_KEY` to a backend-only API key with permission to list purchased phone numbers, send SMS, manage phone-number connections, and create/delete credential connections. Never put it in the Android app.
- Set `TELNYX_MESSAGING_PROFILE_ID` to the profile used to send VirtualSIM Pro sign-in codes. Phone authentication sends a six-digit code that expires after 10 minutes; requests are rate-limited and verification permits at most five guesses.
- Purchased numbers in these countries are imported: Australia, Austria, Belgium, Canada, Denmark, France, Germany, Ireland, Italy, Netherlands, Norway, Poland, Portugal, Spain, Sweden, Switzerland, United Kingdom, and United States. Active numbers tagged with `TELNYX_VIP_TAG` (default `vip`) enter the private VIP pool; other supported active purchased numbers enter the free pool. Tag numbers in Telnyx Mission Control and the sync applies changes every 15 minutes by default (`TELNYX_SYNC_INTERVAL_MS`).
- A signed-in user claims one free number at `POST /api/numbers/claim-free`; it is exclusively assigned and attached to that user's SIP connection when SIP provisioning is configured. Without it, the claim succeeds in `SMS_ONLY` mode. VIP assignment is performed only after the backend verifies the Google Play purchase.
- For inbound OTPs, configure each Telnyx Messaging Profile used by these numbers to send the `message.received` event to `https://<your-host>/api/webhook/sms`. Set `TELNYX_PUBLIC_KEY` to the webhook verification public key shown in Telnyx Mission Control. The backend verifies the Ed25519 signature over the original request body and rejects stale callbacks. Do not disable signature verification.
- SIP credentials are generated individually for each account and encrypted at rest. The authenticated `GET /api/voip-config` endpoint returns only that user's credentials and instructs the app to register to `sip.telnyx.com` over TLS on port 5061. `TELNYX_OUTBOUND_VOICE_PROFILE_ID` is required before the backend provisions SIP credentials; configure that profile's allowed destinations, caller-ID policy, and spend limits in Telnyx. The backend does not grant free PSTN calling—Telnyx account configuration and rates apply.
- Account deletion detaches assigned Telnyx numbers and deletes the user's credential connection before removing local account data.

After adding these values in Render (or another host), redeploy the backend and check `/health` for Telnyx configuration and a successful inventory sync. No live carrier requests are made by the test suite.

For isolated staging tests, set `NODE_ENV=staging` and explicitly enable `STAGING_SHARED_FREE_NUMBERS=true` and/or `STAGING_AD_REWARD_FALLBACK=true`. The shared number and OTP are synthetic and never sourced from or routed through Telnyx. The ad fallback grants 10 credits once per account only in staging; production continues to require a verified rewarded-ad callback, which grants exactly 10 app credits.

## API

- `POST /api/auth/register` and `POST /api/auth/login` — create an account or receive a 12-hour bearer token.
- `POST /api/auth/phone/request` and `POST /api/auth/phone/verify` — send and verify a six-digit sign-in code, then create or authenticate a phone-based account.
- `GET /api/profile` — return the caller's profile, wallet credits, and VIP availability.
- `GET /api/numbers` — return only numbers assigned to the caller.
- `GET /api/numbers/vip` — list currently available VIP numbers for selection.
- `POST /api/numbers/unlock-vip` — atomically spend 50 wallet credits and assign the selected VIP number.
- `POST /api/numbers/claim-free` — claim one free number; repeats return the user's existing free assignment.
- `GET /api/messages` — return only the caller's SMS messages from the last 24 hours.
- `GET /api/voip-config` — automatically provision or return the caller's Telnyx SIP account; requires bearer auth and uses `Cache-Control: no-store`.
- `DELETE /api/account` — detach the caller's Telnyx numbers, delete their SIP connection, and remove their account data.
- `POST /api/webhook/sms` — signature-verified Telnyx inbound SMS callback.
- `POST /api/rewards/ad-token` and `GET /api/webhooks/admob` — issue one-use reward tokens and verify AdMob SSV before crediting a wallet.
- `POST /api/rewards/staging-fallback` — staging-only, once-per-account 10-credit fallback when a rewarded ad fails to fill.
- `POST /api/store/verify-vip` — verify a Play product purchase before assigning the selected private VIP number.
- `POST /api/admin/numbers` — admin-only inventory/assignment operation using `X-Admin-Key`.
- `PUT /api/admin/users/:userId/voip` — admin-only Telnyx SIP provisioning trigger; credentials are not returned by this route.
- `POST /admin/reset-users` — destructive test-database reset using `X-Admin-Key`; requires JSON `{ "confirm": true }`, deletes all users and phone sign-in challenges, releases assigned numbers, and detaches associated Telnyx resources.

SMS bodies, extracted OTP codes, and SIP passwords are encrypted at rest using `DATA_ENCRYPTION_KEY`. Inbox messages expire after 24 hours; phone sign-in challenge codes are stored as keyed digests and expire after 10 minutes. Telnyx message IDs are retained for idempotency. Free numbers are never exposed in a shared inbox; messages to unassigned numbers are discarded.

## Store configuration

For rewarded ads, enable server-side verification with `https://<your-host>/api/webhooks/admob`. For VIP purchases, create the `VIP_PRODUCT_ID` in Play Console and grant the service account in `GOOGLE_SERVICE_ACCOUNT_JSON` Android Publisher access for `PLAY_PACKAGE_NAME`. Purchases are verified server-side; no purchase is credited solely from a client callback.
