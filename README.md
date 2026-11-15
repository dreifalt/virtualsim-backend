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

- Set `TELNYX_API_KEY` to a backend-only API key with permission to list purchased phone numbers, manage phone-number connections, and create/delete credential connections. Never put it in the Android app.
- Purchased numbers in these countries are imported: Australia, Austria, Belgium, Canada, Denmark, France, Germany, Ireland, Italy, Netherlands, Norway, Poland, Portugal, Spain, Sweden, Switzerland, United Kingdom, and United States. Active numbers tagged with `TELNYX_VIP_TAG` (default `vip`) enter the private VIP pool; other supported active purchased numbers enter the free pool. Tag numbers in Telnyx Mission Control and the sync applies changes every 15 minutes by default (`TELNYX_SYNC_INTERVAL_MS`).
- A signed-in user claims one free number at `POST /api/numbers/claim-free`; it is exclusively assigned and attached to that user's SIP connection. VIP assignment is performed only after the backend verifies the Google Play purchase.
- For inbound OTPs, configure each Telnyx Messaging Profile used by these numbers to send the `message.received` event to `https://<your-host>/api/webhook/sms`. Set `TELNYX_PUBLIC_KEY` to the webhook verification public key shown in Telnyx Mission Control. The backend verifies the Ed25519 signature over the original request body and rejects stale callbacks. Do not disable signature verification.
- SIP credentials are generated individually for each account and encrypted at rest. The authenticated `GET /api/voip-config` endpoint returns only that user's credentials and instructs the app to register to `sip.telnyx.com` over TLS on port 5061. `TELNYX_OUTBOUND_VOICE_PROFILE_ID` is required before the backend provisions SIP credentials; configure that profile's allowed destinations, caller-ID policy, and spend limits in Telnyx. The backend does not grant free PSTN calling—Telnyx account configuration and rates apply.
- Account deletion detaches assigned Telnyx numbers and deletes the user's credential connection before removing local account data.

After adding these values in Render (or another host), redeploy the backend and check `/health` for Telnyx configuration and a successful inventory sync. No live carrier requests are made by the test suite.

## API

- `POST /api/auth/register` and `POST /api/auth/login` — create an account or receive a 12-hour bearer token.
- `GET /api/profile` — return the caller's profile, wallet credits, and VIP availability.
- `GET /api/numbers` — return only numbers assigned to the caller.
- `POST /api/numbers/claim-free` — claim one free number; repeats return the user's existing free assignment.
- `GET /api/messages` — return only the caller's SMS messages from the last 24 hours.
- `GET /api/voip-config` — automatically provision or return the caller's Telnyx SIP account; requires bearer auth and uses `Cache-Control: no-store`.
- `DELETE /api/account` — detach the caller's Telnyx numbers, delete their SIP connection, and remove their account data.
- `POST /api/webhook/sms` — signature-verified Telnyx inbound SMS callback.
- `POST /api/rewards/ad-token` and `GET /api/webhooks/admob` — issue one-use reward tokens and verify AdMob SSV before crediting a wallet.
- `POST /api/store/verify-vip` — verify a Play product purchase before assigning a private VIP number.
- `POST /api/admin/numbers` — admin-only inventory/assignment operation using `X-Admin-Key`.
- `PUT /api/admin/users/:userId/voip` — admin-only Telnyx SIP provisioning trigger; credentials are not returned by this route.

SMS bodies, extracted OTP codes, and SIP passwords are encrypted at rest using `DATA_ENCRYPTION_KEY`. OTP messages expire after 24 hours and Telnyx message IDs are retained for idempotency. Free numbers are never exposed in a shared inbox; messages to unassigned numbers are discarded.

## Store configuration

For rewarded ads, enable server-side verification with `https://<your-host>/api/webhooks/admob`. For VIP purchases, create the `VIP_PRODUCT_ID` in Play Console and grant the service account in `GOOGLE_SERVICE_ACCOUNT_JSON` Android Publisher access for `PLAY_PACKAGE_NAME`. Purchases are verified server-side; no purchase is credited solely from a client callback.
