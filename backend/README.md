# AlvirOS Private Guestbook Backend Deployment Guide

This backend provides a secure, anonymous private guestbook for AlvirOS powered by Cloudflare Workers and Cloudflare D1.

---

## 1. Prerequisites

- A free [Cloudflare](https://dash.cloudflare.com/) account.
- Node.js (v18+) and npm installed locally.

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
*Note the returned `database_id` and paste it into `wrangler.toml` under `database_id`.*

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

## 3. Connecting to the Portfolio

Open `index.html` and update the `GUESTBOOK_API_ENDPOINT` constant:

```javascript
const GUESTBOOK_API_ENDPOINT = 'https://alviros-guestbook.<your-subdomain>.workers.dev';
```

---

## 4. Immediate Security Recommendation: Revoke JSONBin Key

The legacy JSONBin master key previously committed in early iterations must be revoked:
1. Log in to your [JSONBin.io](https://jsonbin.io/) dashboard.
2. Navigate to **API Keys**.
3. Locate key starting with `$2a$10$a1X5jECE0YEZX1lXHb3Yp...` and **delete / revoke** it.
