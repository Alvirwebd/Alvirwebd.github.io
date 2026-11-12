# AlvirOS Private Guestbook Backend Deployment & Security Guide

This backend provides a secure, anonymous, private guestbook for AlvirOS powered by Cloudflare Workers and Cloudflare D1.

---

## 1. Automated Test Suite

A comprehensive test suite verifying all 17 security and reliability invariants is included in `backend/test.js`.

### Run Tests Locally:
```bash
node backend/test.js
```

### Verified Behaviors (35/35 Assertions):
1. **Query-string Token Rejection (HTTP 400)**: URL query parameters (`?token=...`, `?tokens=...`) are rejected per Mandatory Security Rule 1.
2. **Payload Size Limits (HTTP 413)**: Request bodies exceeding 10KB are rejected.
3. **Input Validation (HTTP 400)**: Empty, missing, or malformed inputs are rejected.
4. **Anonymous Visitor Submissions (HTTP 201)**: Issues 32-byte cryptographically secure visitor tokens (`thk_...`).
5. **Token Hashing in D1**: Database stores ONLY SHA-256 hashes (`token_hash`), never raw tokens.
6. **Multiple Thoughts Per Visitor**: Visitors can submit multiple notes and retrieve their collection via `POST /api/thoughts/my`.
7. **Strict Visitor Isolation**: Each visitor sees ONLY thoughts matching their own token collection.
8. **Owner Authentication & Rate Limiting**: Durable brute-force protection locks out repeated failed logins (5 attempts / 15-minute lockout).
9. **Hashed Owner Session Tokens**: Admin sessions (`adm_...`) are stored in D1 as SHA-256 hashes only.
10. **Atomic Rate Limiting**: Simultaneous concurrent requests are handled atomically using SQLite `ON CONFLICT ... RETURNING` statements, preventing race conditions.

---

## 2. Deployment Steps

From your terminal, navigate to the `backend/` directory:

```bash
cd backend
```

### Step 1: Login to Cloudflare
```bash
npx wrangler login
```

### Step 2: Create the D1 Database
```bash
npx wrangler d1 create alviros-guestbook-db
```
*Note the returned `database_id` and paste it into `backend/wrangler.toml` under `database_id`.*

### Step 3: Initialize the Database Schema
Execute the schema against your remote D1 database:
```bash
npx wrangler d1 execute alviros-guestbook-db --remote --file=./schema.sql
```

### Step 4: Set the Owner Admin Secret
Set the secret passphrase used to access the owner admin panel:
```bash
npx wrangler secret put ADMIN_KEY
```
*(Enter a strong, private passphrase when prompted. Never commit this to Git.)*

### Step 5: Deploy the Worker
```bash
npx wrangler deploy
```
*Wrangler will output your live worker URL, for example:*
`https://alviros-guestbook.<your-subdomain>.workers.dev`

---

## 3. Configuring the Portfolio Frontend

The frontend does **NOT** contain any hardcoded production endpoints. To connect the frontend to your deployed Worker:

1. In `index.html`, set `CONFIGURED_GUESTBOOK_ENDPOINT`:
   ```javascript
   const CONFIGURED_GUESTBOOK_ENDPOINT = 'https://alviros-guestbook.<your-subdomain>.workers.dev';
   ```
2. Or set `window.ALVIROS_GUESTBOOK_ENDPOINT` in your environment / hosting configuration.
3. If no endpoint is configured, the guestbook UI displays an honest "Backend Not Configured" notification rather than silently failing or faking success.

### Browser-Storage Limitation Note:
Visitor entries are keyed to unguessable cryptographic tokens stored in the browser's `localStorage` (`alvir_guestbook_tokens`). If a visitor clears their browser cookies/storage, their device will no longer be able to display their previously submitted notes, although the notes remain safely archived in Alvir's private owner inbox.

---

## 4. Revocation of Compromised JSONBin Credential

The legacy JSONBin master key previously committed in early prototype iterations must be revoked:
1. Log in to your [JSONBin.io](https://jsonbin.io/) dashboard.
2. Navigate to **API Keys**.
3. Locate key starting with `$2a$10$a1X5jECE0YEZX1lXHb3Yp...` and **delete / revoke** it.
