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
    if (url.searchParams.has('token') || url.searchParams.has('visitor_token')) {
      return jsonResponse({
        error: 'Forbidden: Tokens must never be passed in URL query parameters. Use the Authorization header.'
      }, 400, corsHeaders);
    }

    try {
      // 1. POST /api/thoughts (Visitor submission)
      if (request.method === 'POST' && path === '/api/thoughts') {
        const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
        const rateLimitOk = await checkRateLimit(env.DB, clientIp);
        if (!rateLimitOk) {
          return jsonResponse({
            error: 'Rate limit exceeded. Please wait a few minutes before submitting another thought.'
          }, 429, corsHeaders);
        }

        const body = await request.json().catch(() => ({}));
        let { text, nickname, color } = body;

        if (!text || typeof text !== 'string' || text.trim().length === 0) {
          return jsonResponse({ error: 'Thought text cannot be empty.' }, 400, corsHeaders);
        }

        text = text.trim().slice(0, 280);
        nickname = (typeof nickname === 'string' && nickname.trim()) ? nickname.trim().slice(0, 32) : 'Anonymous';
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

        return jsonResponse({
          success: true,
          token: visitorToken,
          thought: {
            id: result.meta ? result.meta.last_row_id : null,
            text,
            nickname,
            color,
            created_at: new Date().toISOString()
          }
        }, 201, corsHeaders);
      }

      // 2. GET /api/thoughts/my (Retrieve visitor's own thought via header)
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

      // 3. POST /api/owner/login (Authenticate owner with ADMIN_KEY)
      if (request.method === 'POST' && path === '/api/owner/login') {
        const body = await request.json().catch(() => ({}));
        const { key } = body;

        if (!key || typeof key !== 'string' || !env.ADMIN_KEY) {
          return jsonResponse({ error: 'Invalid owner key.' }, 401, corsHeaders);
        }

        const keyOk = await constantTimeCompare(key, env.ADMIN_KEY);
        if (!keyOk) {
          return jsonResponse({ error: 'Invalid owner key.' }, 401, corsHeaders);
        }

        // Issue 2-hour secure session token
        const sessionBytes = new Uint8Array(32);
        crypto.getRandomValues(sessionBytes);
        const sessionToken = 'adm_' + Array.from(sessionBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        const expiresAt = Math.floor(Date.now() / 1000) + 7200; // 2 hours

        await env.DB.prepare(
          'INSERT INTO owner_sessions (session_id, expires_at) VALUES (?, ?)'
        ).bind(sessionToken, expiresAt).run();

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
          await env.DB.prepare('DELETE FROM owner_sessions WHERE session_id = ?').bind(sessionToken).run();
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

async function checkRateLimit(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const ipHash = await sha256Hex(clientIp);

  const record = await db.prepare(
    'SELECT count, reset_at FROM rate_limits WHERE ip_hash = ?'
  ).bind(ipHash).first();

  if (!record || record.reset_at < now) {
    // Reset window (10 minutes = 600 seconds)
    await db.prepare(
      'INSERT OR REPLACE INTO rate_limits (ip_hash, count, reset_at) VALUES (?, 1, ?)'
    ).bind(ipHash, now + 600).run();
    return true;
  }

  if (record.count >= 5) {
    return false;
  }

  await db.prepare(
    'UPDATE rate_limits SET count = count + 1 WHERE ip_hash = ?'
  ).bind(ipHash).run();
  return true;
}

async function verifyOwnerSession(db, sessionToken) {
  if (!sessionToken || !sessionToken.startsWith('adm_')) return false;
  const now = Math.floor(Date.now() / 1000);
  const session = await db.prepare(
    'SELECT session_id FROM owner_sessions WHERE session_id = ? AND expires_at > ?'
  ).bind(sessionToken, now).first();
  return !!session;
}
