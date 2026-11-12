# AlvirOS Private Guestbook Backend Deployment & Security Guide

This backend provides a secure, anonymous, private guestbook for AlvirOS powered by Cloudflare Workers and Cloudflare D1.

---

## 1. Automated Test Suite

A comprehensive test suite verifying all security, concurrency, and reliability invariants is included in `backend/test.js`.

### Run Tests Locally:
```bash
node backend/test.js
```

### Test Suite Structure:

The test suite clearly distinguishes between two testing layers:

#### Suite 1: Real SQLite / D1 Integration Tests (32 Assertions)
Executes the actual `backend/schema.sql` and Worker against Node.js's native SQLite engine (`node:sqlite` / `DatabaseSync`), testing real SQL statements:
- **Independent Body Size & Stream Limiting (HTTP 413)**: Rejects bodies exceeding 10KB even when `Content-Length` is absent, spoofed, or streamed via `ReadableStream` chunks, avoiding unbounded `request.json()` memory exhaustion.
- **Crypto Visitor Token Generation**: Generates 32-byte cryptographically secure tokens (`thk_...`).
- **Token Hashing in Real SQLite**: Verifies raw tokens are NEVER stored in the database; only 64-character SHA-256 hashes are persisted.
- **Strict Visitor Isolation**: Each visitor sees ONLY thoughts matching their own token collection. Visitor A cannot access Visitor B's thoughts.
- **Real Concurrency-Safe Owner Brute-Force Lockout**: 10 simultaneous failed logins executed via `Promise.all`: exactly 4 receive HTTP 401, attempt 5 triggers lockout with HTTP 429, and attempts 6–10 are rejected with HTTP 429.
- **Lockout Expiration & Recovery**: Verifies lockout expiration and automatic attempt counter reset.
- **Session Security**: Owner session tokens (`adm_...`) are stored in D1 as SHA-256 hashes only. Successful login clears failed attempt records.
- **Real Concurrency Submission Rate Limiting**: 10 simultaneous visitor submissions executed via `Promise.all`: exactly 5 succeed (HTTP 201), and the remaining 5 are atomically blocked with HTTP 429 using SQLite `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING`.

#### Suite 2: Lightweight Mock Unit Tests (10 Assertions)
Fast, dependency-free logical unit tests using `MockD1` to verify request routing and payload validation in environments without native SQLite bindings.

---

## 2. Visitor Token Transport Rationale

The backend supports multiple secure transport options for visitor tokens while strictly adhering to security invariants:

1. **Why `POST /api/thoughts/my` with JSON Body `{ tokens: string[] }` is Used:**
   - **RFC 6750 Standard Compliance**: RFC 6750 defines `Authorization: Bearer <token>` for a *single* credentials string. There is no standard specification for transmitting an arbitrary collection of multiple bearer tokens in a single `Authorization` header.
   - **Header Size Limits**: A visitor who submits multiple thoughts across sessions may hold 10, 20, or up to 50 tokens (3.4KB+ of token strings alone). Large request headers risk exceeding edge proxy / WAF header size limits and triggering `431 Request Header Fields Too Large`.
   - **CDN / Proxy Body Dropping**: Standard HTTP `GET` requests with a payload body are stripped or rejected by intermediate proxies, CDNs, and caches.
   - **URL Query String Prohibition**: Visitor tokens must **never** be passed in URL query parameters, as URLs are routinely recorded in browser histories, access logs, and HTTP Referer headers.
   - Therefore, a `POST` request with a JSON body is the standard, secure, and robust pattern for querying by a collection of identifiers.

2. **Authorization Header Support:**
   - Single-token retrieval is supported via `GET /api/thoughts/my` with `Authorization: Bearer <token>`.
   - In addition, `POST /api/thoughts/my` also accepts tokens passed in the `Authorization: Bearer <token1>, <token2>` header and merges them with any tokens provided in the body.
   - In all cases, raw visitor tokens are never logged, and only SHA-256 hashes are queried against the database.

---

## 3. Deployment Steps

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

## 4. Configuring the Portfolio Frontend

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

## 5. Revocation of Compromised JSONBin Credential

The legacy JSONBin master key previously committed in early prototype iterations must be revoked:
1. Log in to your [JSONBin.io](https://jsonbin.io/) dashboard.
2. Navigate to **API Keys**.
3. Locate key starting with `$2a$10$a1X5jECE0YEZX1lXHb3Yp...` and **delete / revoke** it.
