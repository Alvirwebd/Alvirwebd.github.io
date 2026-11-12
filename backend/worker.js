/**
 * AlvirOS Anonymous Private Guestbook Backend
 * Cloudflare Worker + D1 Database
 */

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '*';
    const allowedOrigin = env.ALLOWED_ORIGIN || '*';
    const corsHeaders = {
      'Access-Control-Allow-Origin': (allowedOrigin === '*' || origin === allowedOrigin) ? origin : allowedOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Visitor-Token',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Reject visitor tokens passed in query params (Mandatory Security Rule 1)
    if (url.searchParams.has('token') || url.searchParams.has('tokens') || url.searchParams.has('visitor_token')) {
      return jsonResponse({
        error: 'Forbidden: Tokens must never be passed in URL query parameters. Use the Authorization header or request body.'
      }, 400, corsHeaders);
    }

    // Reject oversized request payloads (> 10KB)
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > 10240) {
      return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
    }

    try {
      // 1. POST /api/thoughts (Visitor submission with atomic rate-limiting)
      if (request.method === 'POST' && path === '/api/thoughts') {
        const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
        const rateLimitOk = await checkSubmissionRateLimit(env.DB, clientIp);
        if (!rateLimitOk) {
          return jsonResponse({
            error: 'Rate limit exceeded: Maximum 5 submissions per 10 minutes. Please try again later.'
          }, 429, corsHeaders);
        }

        const body = await request.json().catch(() => null);
        if (!body || typeof body !== 'object') {
          return jsonResponse({ error: 'Invalid JSON request body.' }, 400, corsHeaders);
        }

        let { text, nickname, color } = body;

        if (!text || typeof text !== 'string' || text.trim().length === 0) {
          return jsonResponse({ error: 'Thought text cannot be empty.' }, 400, corsHeaders);
        }

        if (text.length > 1000) {
          return jsonResponse({ error: 'Thought text exceeds 1000 characters limit.' }, 400, corsHeaders);
        }

        text = text.trim();
        nickname = (typeof nickname === 'string' && nickname.trim()) ? nickname.trim().slice(0, 48) : 'Anonymous';
        const validColors = ['yellow', 'peach', 'mint', 'sky'];
        color = validColors.includes(color) ? color : 'yellow';

        // Generate 32-byte cryptographically secure visitor token
        const tokenBytes = new Uint8Array(32);
        crypto.getRandomValues(tokenBytes);
        const visitorToken = 'thk_' + Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        const tokenHash = await sha256Hex(visitorToken);

        const stmt = env.DB.prepare(
          'INSERT INTO guestbook_thoughts (token_hash, text, nickname, color) VALUES (?, ?, ?, ?)'
        );
        const result = await stmt.bind(tokenHash, text, nickname, color).run();
        const id = result.meta ? result.meta.last_row_id : null;

        return jsonResponse({
          success: true,
          token: visitorToken,
          thought: {
            id,
            text,
            nickname,
            color,
            created_at: new Date().toISOString()
          }
        }, 201, corsHeaders);
      }

      // 2. POST /api/thoughts/my (Retrieve multiple thoughts for visitor's stored token collection)
      if (request.method === 'POST' && path === '/api/thoughts/my') {
        const body = await request.json().catch(() => null);
        if (!body || !Array.isArray(body.tokens)) {
          return jsonResponse({ error: 'Invalid request: "tokens" array is required.' }, 400, corsHeaders);
        }

        const tokens = body.tokens.filter(t => typeof t === 'string' && t.startsWith('thk_') && t.length === 68);
        if (tokens.length === 0) {
          return jsonResponse({ success: true, thoughts: [] }, 200, corsHeaders);
        }

        if (tokens.length > 50) {
          return jsonResponse({ error: 'Too many tokens requested: Maximum is 50.' }, 400, corsHeaders);
        }

        // Hash each token with SHA-256 for private database lookup
        const tokenHashes = await Promise.all(tokens.map(t => sha256Hex(t)));
        const placeholders = tokenHashes.map(() => '?').join(', ');
        const query = `SELECT id, text, nickname, color, created_at FROM guestbook_thoughts WHERE token_hash IN (${placeholders}) ORDER BY id DESC`;

        const { results } = await env.DB.prepare(query).bind(...tokenHashes).all();
        return jsonResponse({ success: true, thoughts: results || [] }, 200, corsHeaders);
      }

      // 2b. GET /api/thoughts/my (Single thought retrieval via Authorization header for backward-compat)
      if (request.method === 'GET' && path === '/api/thoughts/my') {
        const token = extractToken(request);
        if (!token) {
          return jsonResponse({ error: 'Missing token in Authorization header.' }, 401, corsHeaders);
        }

        const tokenHash = await sha256Hex(token);
        const thought = await env.DB.prepare(
          'SELECT id, text, nickname, color, created_at FROM guestbook_thoughts WHERE token_hash = ?'
        ).bind(tokenHash).first();

        if (!thought) {
          return jsonResponse({ success: false, thought: null }, 404, corsHeaders);
        }

        return jsonResponse({ success: true, thought }, 200, corsHeaders);
      }

      // 3. POST /api/owner/login (Authenticate owner with durable brute-force protection)
      if (request.method === 'POST' && path === '/api/owner/login') {
        const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
        const rateCheck = await checkOwnerLoginRateLimit(env.DB, clientIp);
        if (!rateCheck.allowed) {
          return jsonResponse({
            error: `Too many failed login attempts. Locked for ${Math.ceil(rateCheck.remainingLockSeconds / 60)} minutes.`
          }, 429, corsHeaders);
        }

        const body = await request.json().catch(() => ({}));
        const { key } = body;

        if (!key || typeof key !== 'string' || !env.ADMIN_KEY) {
          await recordFailedOwnerLogin(env.DB, clientIp);
          return jsonResponse({ error: 'Invalid owner credentials.' }, 401, corsHeaders);
        }

        const keyOk = constantTimeCompare(key, env.ADMIN_KEY);
        if (!keyOk) {
          await recordFailedOwnerLogin(env.DB, clientIp);
          return jsonResponse({ error: 'Invalid owner credentials.' }, 401, corsHeaders);
        }

        // Authentication succeeded: clear failed attempts for this IP
        await clearOwnerLoginAttempts(env.DB, clientIp);

        // Issue 2-hour secure session token
        const sessionBytes = new Uint8Array(32);
        crypto.getRandomValues(sessionBytes);
        const sessionToken = 'adm_' + Array.from(sessionBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        const sessionHash = await sha256Hex(sessionToken);
        const expiresAt = Math.floor(Date.now() / 1000) + 7200; // 2 hours

        // Store ONLY SHA-256 hash in D1
        await env.DB.prepare(
          'INSERT INTO owner_sessions (session_hash, expires_at) VALUES (?, ?)'
        ).bind(sessionHash, expiresAt).run();

        return jsonResponse({
          success: true,
          session_token: sessionToken,
          expires_at: expiresAt
        }, 200, corsHeaders);
      }

      // 4. GET /api/owner/thoughts (List all thoughts for authenticated owner)
      if (request.method === 'GET' && path === '/api/owner/thoughts') {
        const sessionToken = extractToken(request);
        const isOwner = await verifyOwnerSession(env.DB, sessionToken);
        if (!isOwner) {
          return jsonResponse({ error: 'Unauthorized: Valid owner session required.' }, 401, corsHeaders);
        }

        const { results } = await env.DB.prepare(
          'SELECT id, text, nickname, color, created_at FROM guestbook_thoughts ORDER BY id DESC'
        ).all();

        return jsonResponse({ success: true, thoughts: results || [] }, 200, corsHeaders);
      }

      // 5. DELETE /api/owner/thoughts/:id (Owner delete submission)
      if (request.method === 'DELETE' && path.startsWith('/api/owner/thoughts/')) {
        const sessionToken = extractToken(request);
        const isOwner = await verifyOwnerSession(env.DB, sessionToken);
        if (!isOwner) {
          return jsonResponse({ error: 'Unauthorized: Valid owner session required.' }, 401, corsHeaders);
        }

        const id = parseInt(path.split('/').pop(), 10);
        if (isNaN(id) || id <= 0) {
          return jsonResponse({ error: 'Invalid thought ID.' }, 400, corsHeaders);
        }

        await env.DB.prepare('DELETE FROM guestbook_thoughts WHERE id = ?').bind(id).run();
        return jsonResponse({ success: true, deleted_id: id }, 200, corsHeaders);
      }

      // 6. POST /api/owner/logout (Owner logout)
      if (request.method === 'POST' && path === '/api/owner/logout') {
        const sessionToken = extractToken(request);
        if (sessionToken) {
          const sessionHash = await sha256Hex(sessionToken);
          await env.DB.prepare('DELETE FROM owner_sessions WHERE session_hash = ?').bind(sessionHash).run();
        }
        return jsonResponse({ success: true }, 200, corsHeaders);
      }

      return jsonResponse({ error: 'Endpoint not found.' }, 404, corsHeaders);

    } catch (err) {
      console.error('Worker error:', err);
      return jsonResponse({ error: 'Internal Server Error' }, 500, corsHeaders);
    }
  }
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...extraHeaders
    }
  });
}

function extractToken(request) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  return request.headers.get('X-Visitor-Token') || null;
}

async function sha256Hex(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeCompare(a, b) {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.byteLength !== bufB.byteLength) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < bufA.byteLength; i++) {
    mismatch |= bufA[i] ^ bufB[i];
  }
  return mismatch === 0;
}

/**
 * Atomic rate limiting for visitor submissions.
 * Uses SQLite ON CONFLICT with RETURNING to prevent race conditions during concurrent requests.
 */
async function checkSubmissionRateLimit(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const ipHash = await sha256Hex('visitor_' + clientIp);
  const windowSeconds = 600; // 10 minutes
  const maxSubmissions = 5;

  const stmt = db.prepare(`
    INSERT INTO rate_limits (ip_hash, count, reset_at)
    VALUES (?, 1, ?)
    ON CONFLICT(ip_hash) DO UPDATE SET
      count = CASE WHEN reset_at < ? THEN 1 ELSE count + 1 END,
      reset_at = CASE WHEN reset_at < ? THEN ? ELSE reset_at END
    RETURNING count, reset_at;
  `);

  const res = await stmt.bind(ipHash, now + windowSeconds, now, now, now + windowSeconds).first();
  if (!res) return false;
  return res.count <= maxSubmissions;
}

/**
 * Durable brute-force protection for owner login.
 * Tracks failed attempts server-side in owner_login_attempts table.
 */
async function checkOwnerLoginRateLimit(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const ipHash = await sha256Hex('owner_' + clientIp);

  const record = await db.prepare(
    'SELECT attempts, locked_until FROM owner_login_attempts WHERE ip_hash = ?'
  ).bind(ipHash).first();

  if (record && record.locked_until > now) {
    return { allowed: false, remainingLockSeconds: record.locked_until - now };
  }
  return { allowed: true };
}

async function recordFailedOwnerLogin(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const lockDuration = 900; // 15 minutes lockout after 5 consecutive failures
  const ipHash = await sha256Hex('owner_' + clientIp);

  const stmt = db.prepare(`
    INSERT INTO owner_login_attempts (ip_hash, attempts, locked_until)
    VALUES (?, 1, 0)
    ON CONFLICT(ip_hash) DO UPDATE SET
      attempts = CASE WHEN locked_until < ? AND locked_until > 0 THEN 1 ELSE attempts + 1 END,
      locked_until = CASE WHEN attempts + 1 >= 5 THEN ? ELSE 0 END
  `);

  await stmt.bind(ipHash, now, now + lockDuration).run();
}

async function clearOwnerLoginAttempts(db, clientIp) {
  const ipHash = await sha256Hex('owner_' + clientIp);
  await db.prepare('DELETE FROM owner_login_attempts WHERE ip_hash = ?').bind(ipHash).run();
}

/**
 * Validates owner session by hashing the presented token and checking expiration in D1.
 */
async function verifyOwnerSession(db, sessionToken) {
  if (!sessionToken || !sessionToken.startsWith('adm_') || sessionToken.length !== 68) return false;
  const sessionHash = await sha256Hex(sessionToken);
  const now = Math.floor(Date.now() / 1000);
  const session = await db.prepare(
    'SELECT session_hash FROM owner_sessions WHERE session_hash = ? AND expires_at > ?'
  ).bind(sessionHash, now).first();
  return !!session;
}
