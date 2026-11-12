/**
 * AlvirOS Anonymous Private Guestbook Backend
 * Cloudflare Worker + D1 Database
 */

export class PayloadTooLargeError extends Error {
  constructor(message = 'Payload Too Large: Maximum allowed size is 10KB.') {
    super(message);
    this.name = 'PayloadTooLargeError';
  }
}

export async function readSafeJson(request, maxBytes = 10240) {
  // 1. Check Content-Length header if present
  const clHeader = request.headers.get('Content-Length');
  if (clHeader !== null) {
    const cl = parseInt(clHeader, 10);
    if (!isNaN(cl) && cl > maxBytes) {
      throw new PayloadTooLargeError();
    }
  }

  // 2. Stream body and count bytes independently (handles missing/spoofed Content-Length)
  if (!request.body) {
    return null;
  }

  let totalBytes = 0;
  const chunks = [];

  if (typeof request.body.getReader === 'function') {
    const reader = request.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > maxBytes) {
          try { await reader.cancel(); } catch (_) {}
          throw new PayloadTooLargeError();
        }
        chunks.push(value);
      }
    } finally {
      try { reader.releaseLock(); } catch (_) {}
    }
  } else if (typeof request.arrayBuffer === 'function') {
    const buf = await request.arrayBuffer();
    if (buf.byteLength > maxBytes) {
      throw new PayloadTooLargeError();
    }
    chunks.push(new Uint8Array(buf));
    totalBytes = buf.byteLength;
  } else if (typeof request.text === 'function') {
    const text = await request.text();
    const encoder = new TextEncoder();
    const encoded = encoder.encode(text);
    if (encoded.byteLength > maxBytes) {
      throw new PayloadTooLargeError();
    }
    return JSON.parse(text);
  }

  if (chunks.length === 0) return null;

  const decoder = new TextDecoder('utf-8');
  let rawText = '';
  for (const chunk of chunks) {
    rawText += decoder.decode(chunk, { stream: true });
  }
  rawText += decoder.decode();

  if (!rawText.trim()) return null;
  return JSON.parse(rawText);
}

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

    // Top-level rejection for oversized request payloads if Content-Length specified
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > 10240) {
      return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
    }

    try {
      // 1. POST /api/thoughts (Visitor submission with atomic rate-limiting)
      if (request.method === 'POST' && path === '/api/thoughts') {
        const client = resolveClientIdentity(request);
        const rateLimitOk = await checkSubmissionRateLimit(env.DB, client.identity);
        if (!rateLimitOk) {
          return jsonResponse({
            error: 'Rate limit exceeded: Maximum 5 submissions per 10 minutes. Please try again later.'
          }, 429, corsHeaders);
        }

        let body;
        try {
          body = await readSafeJson(request, 10240);
        } catch (err) {
          if (err instanceof PayloadTooLargeError) {
            return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
          }
          return jsonResponse({ error: 'Invalid JSON request body.' }, 400, corsHeaders);
        }

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
        let body;
        try {
          body = await readSafeJson(request, 10240);
        } catch (err) {
          if (err instanceof PayloadTooLargeError) {
            return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
          }
          return jsonResponse({ error: 'Invalid JSON request body.' }, 400, corsHeaders);
        }

        // Support tokens from JSON body AND/OR Authorization headers
        const tokenSet = new Set();
        if (body && Array.isArray(body.tokens)) {
          for (const t of body.tokens) {
            if (typeof t === 'string') tokenSet.add(t.trim());
          }
        }

        const headerTokens = extractTokensFromHeader(request);
        for (const t of headerTokens) {
          tokenSet.add(t);
        }

        const tokens = Array.from(tokenSet).filter(t => t.startsWith('thk_') && t.length === 68);

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

      // 3. POST /api/owner/login (Authenticate owner with durable, concurrency-safe brute-force protection)
      if (request.method === 'POST' && path === '/api/owner/login') {
        const client = resolveClientIdentity(request);

        // Check if IP or client identity is currently locked out
        const lockStatus = await getOwnerLockStatus(env.DB, client.identity);
        if (lockStatus.locked) {
          return jsonResponse({
            error: `Too many failed login attempts. Locked for ${Math.ceil(lockStatus.remainingLockSeconds / 60)} minutes.`
          }, 429, {
            ...corsHeaders,
            'Retry-After': String(lockStatus.remainingLockSeconds)
          });
        }

        let body;
        try {
          body = await readSafeJson(request, 10240);
        } catch (err) {
          if (err instanceof PayloadTooLargeError) {
            return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
          }
          return jsonResponse({ error: 'Invalid JSON request body.' }, 400, corsHeaders);
        }

        const { key } = body || {};

        if (!key || typeof key !== 'string' || !env.ADMIN_KEY) {
          const failResult = await recordFailedOwnerLoginAtomic(env.DB, client.identity);
          if (failResult.locked) {
            return jsonResponse({
              error: `Too many failed login attempts. Locked for ${Math.ceil(failResult.remainingLockSeconds / 60)} minutes.`
            }, 429, {
              ...corsHeaders,
              'Retry-After': String(failResult.remainingLockSeconds)
            });
          }
          return jsonResponse({ error: 'Invalid owner credentials.' }, 401, corsHeaders);
        }

        const keyOk = constantTimeCompare(key, env.ADMIN_KEY);
        if (!keyOk) {
          const failResult = await recordFailedOwnerLoginAtomic(env.DB, client.identity);
          if (failResult.locked) {
            return jsonResponse({
              error: `Too many failed login attempts. Locked for ${Math.ceil(failResult.remainingLockSeconds / 60)} minutes.`
            }, 429, {
              ...corsHeaders,
              'Retry-After': String(failResult.remainingLockSeconds)
            });
          }
          return jsonResponse({ error: 'Invalid owner credentials.' }, 401, corsHeaders);
        }

        // Authentication succeeded: clear failed attempts for this client identity
        await clearOwnerLoginAttempts(env.DB, client.identity);

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

      // =====================================================================
      // STAGE 5.7: VISITOR IP TRACKING & ANONYMOUS ANALYTICS
      // =====================================================================

      // 7. POST /api/analytics/visit (Record visit: raw IP & decoupled anonymous visit)
      if (request.method === 'POST' && path === '/api/analytics/visit') {
        // Capture IP exclusively via Cloudflare's trusted CF-Connecting-IP.
        // Never fall back to 127.0.0.1 or accept spoofable headers (X-Forwarded-For, X-Real-IP).
        const client = resolveClientIdentity(request);

        if (client.hasTrustedIp && client.ip) {
          const rateLimitOk = await checkAnalyticsRateLimit(env.DB, client.identity);
          if (!rateLimitOk) {
            return jsonResponse({ error: 'Rate limit exceeded.' }, 429, corsHeaders);
          }
        }

        let body = {};
        try {
          body = await readSafeJson(request, 2048) || {};
        } catch (_) {}

        let aid = typeof body.aid === 'string' ? body.aid.trim().slice(0, 64) : '';
        if (!aid) {
          aid = 'aid_' + Math.random().toString(36).substring(2, 15);
        }

        let visitPath = typeof body.path === 'string' ? body.path.trim().slice(0, 128) : '/';
        if (!visitPath.startsWith('/')) visitPath = '/' + visitPath;

        const aidHash = await sha256Hex('aid_' + aid);

        // 1. Check if anonymous visitor has visited before (for unique vs returning metrics)
        const prev = await env.DB.prepare(
          'SELECT 1 FROM anonymous_visits WHERE visitor_aid_hash = ? LIMIT 1'
        ).bind(aidHash).first();
        const isReturning = prev ? 1 : 0;

        // 2. Insert into anonymous_visits (Decoupled: zero IP stored here)
        await env.DB.prepare(
          'INSERT INTO anonymous_visits (visitor_aid_hash, path, is_returning) VALUES (?, ?, ?)'
        ).bind(aidHash, visitPath, isReturning).run();

        // 3. Insert into visitor_ip_records ONLY if CF-Connecting-IP was present and valid
        // (User-Agent collection stopped completely per privacy hardening)
        if (client.hasTrustedIp && client.ip) {
          await env.DB.prepare(
            'INSERT INTO visitor_ip_records (ip, path) VALUES (?, ?)'
          ).bind(client.ip, visitPath).run();
        }

        return jsonResponse({ success: true, recorded: true, ip_stored: Boolean(client.ip) }, 200, corsHeaders);
      }

      // 8. GET /api/owner/analytics (Aggregated anonymous stats for authenticated owner)
      if (request.method === 'GET' && path === '/api/owner/analytics') {
        const sessionToken = extractToken(request);
        const isOwner = await verifyOwnerSession(env.DB, sessionToken);
        if (!isOwner) {
          return jsonResponse({ error: 'Unauthorized: Valid owner session required.' }, 401, corsHeaders);
        }

        const totalRow = await env.DB.prepare('SELECT COUNT(*) as count FROM anonymous_visits').first();
        const uniqueRow = await env.DB.prepare('SELECT COUNT(DISTINCT visitor_aid_hash) as count FROM anonymous_visits').first();
        const returningRow = await env.DB.prepare('SELECT COUNT(DISTINCT visitor_aid_hash) as count FROM anonymous_visits WHERE is_returning = 1').first();
        const todayRow = await env.DB.prepare("SELECT COUNT(*) as count FROM anonymous_visits WHERE visit_date = strftime('%Y-%m-%d', 'now')").first();

        const trendsRes = await env.DB.prepare(
          "SELECT visit_date as date, COUNT(*) as visits, COUNT(DISTINCT visitor_aid_hash) as uniques FROM anonymous_visits GROUP BY visit_date ORDER BY visit_date DESC LIMIT 14"
        ).all();

        const pagesRes = await env.DB.prepare(
          "SELECT path, COUNT(*) as count FROM anonymous_visits GROUP BY path ORDER BY count DESC LIMIT 10"
        ).all();

        return jsonResponse({
          success: true,
          overview: {
            total_visits: totalRow ? totalRow.count : 0,
            estimated_unique_browsers: uniqueRow ? uniqueRow.count : 0,
            unique_visitors: uniqueRow ? uniqueRow.count : 0, // preserved for backward-compatibility
            returning_visitors: returningRow ? returningRow.count : 0,
            visits_today: todayRow ? todayRow.count : 0
          },
          daily_trends: trendsRes?.results || [],
          top_pages: pagesRes?.results || []
        }, 200, corsHeaders);
      }

      // 9. GET /api/owner/analytics/ips (Raw visitor IP records for authenticated owner only with pagination)
      if (request.method === 'GET' && path === '/api/owner/analytics/ips') {
        const sessionToken = extractToken(request);
        const isOwner = await verifyOwnerSession(env.DB, sessionToken);
        if (!isOwner) {
          return jsonResponse({ error: 'Unauthorized: Valid owner session required.' }, 401, corsHeaders);
        }

        let page = parseInt(url.searchParams.get('page') || '1', 10);
        if (isNaN(page) || page < 1) page = 1;

        let limit = parseInt(url.searchParams.get('limit') || '20', 10);
        if (isNaN(limit) || limit <= 0) limit = 20;
        if (limit > 100) limit = 100;

        const offset = (page - 1) * limit;

        const totalRow = await env.DB.prepare('SELECT COUNT(*) as total FROM visitor_ip_records').first();
        const total = totalRow ? Number(totalRow.total) : 0;
        const totalPages = Math.max(1, Math.ceil(total / limit));

        // Preserves all historical records indefinitely, excludes user_agent
        const { results } = await env.DB.prepare(
          'SELECT id, ip, path, created_at FROM visitor_ip_records ORDER BY id DESC LIMIT ? OFFSET ?'
        ).bind(limit, offset).all();

        return jsonResponse({
          success: true,
          records: results || [],
          pagination: {
            page,
            limit,
            total,
            total_pages: totalPages,
            has_next: page < totalPages,
            has_prev: page > 1
          }
        }, 200, corsHeaders);
      }

      // 10. POST /api/owner/analytics/delete (Owner-only manual deletion of IP records)
      if (request.method === 'POST' && (path === '/api/owner/analytics/delete' || path === '/api/owner/analytics/cleanup')) {
        const sessionToken = extractToken(request);
        const isOwner = await verifyOwnerSession(env.DB, sessionToken);
        if (!isOwner) {
          return jsonResponse({ error: 'Unauthorized: Valid owner session required.' }, 401, corsHeaders);
        }

        let body = {};
        try {
          body = await readSafeJson(request, 1024) || {};
        } catch (_) {}

        let result;
        if (body.all === true) {
          result = await env.DB.prepare('DELETE FROM visitor_ip_records').run();
        } else if (body.days) {
          const days = parseInt(body.days, 10);
          if (isNaN(days) || days < 1) {
            return jsonResponse({ error: 'Invalid days parameter.' }, 400, corsHeaders);
          }
          result = await env.DB.prepare(
            "DELETE FROM visitor_ip_records WHERE created_at < datetime('now', '-' || ? || ' days')"
          ).bind(days).run();
        } else {
          return jsonResponse({ error: 'Explicit deletion criteria required (e.g. { all: true } or { days: N }). Automatic deletion is disabled.' }, 400, corsHeaders);
        }

        const deleted = result.meta ? result.meta.changes : 0;
        return jsonResponse({ success: true, deleted, message: `Deleted ${deleted} visitor IP record(s).` }, 200, corsHeaders);
      }

      return jsonResponse({ error: 'Endpoint not found.' }, 404, corsHeaders);

    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        return jsonResponse({ error: 'Payload Too Large: Maximum allowed size is 10KB.' }, 413, corsHeaders);
      }
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

function extractTokensFromHeader(request) {
  const tokens = [];
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const raw = auth.slice(7).trim();
    for (const part of raw.split(',')) {
      const trimmed = part.trim();
      if (trimmed) tokens.push(trimmed);
    }
  }
  const xToken = request.headers.get('X-Visitor-Token');
  if (xToken) {
    for (const part of xToken.split(',')) {
      const trimmed = part.trim();
      if (trimmed) tokens.push(trimmed);
    }
  }
  return tokens;
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
 * Strict IP address validation for Cloudflare CF-Connecting-IP header.
 * Validates IPv4 and IPv6 formatting. Rejects malformed strings, hostnames, and injection attempts.
 */
function isValidIpAddress(ip) {
  if (typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  if (!trimmed) return false;

  // IPv4: 4 octets 0-255 separated by dots
  const ipv4Regex = /^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
  if (ipv4Regex.test(trimmed)) return true;

  // IPv6: standard 8-group or compressed with ::
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
  return ipv6Regex.test(trimmed);
}

/**
 * Resolves the client identity for rate-limiting, lockout, and tracking.
 * Extracts and strictly validates CF-Connecting-IP.
 * Never falls back to fabricated IPs like 127.0.0.1.
 * Missing or invalid IP headers return identity 'missing_ip_anonymous' so missing-header
 * requests cannot bypass rate-limiting or lockout protections.
 */
function resolveClientIdentity(request) {
  const rawIp = request.headers.get('CF-Connecting-IP');
  if (typeof rawIp === 'string' && isValidIpAddress(rawIp.trim())) {
    const ip = rawIp.trim();
    return { ip, identity: ip, hasTrustedIp: true };
  }
  return { ip: null, identity: 'missing_ip_anonymous', hasTrustedIp: false };
}

/**
 * Atomic rate limiting for analytics visits (max 30 pings per 10 minutes per IP).
 */
async function checkAnalyticsRateLimit(db, clientIp) {
  if (!clientIp) return true;
  const now = Math.floor(Date.now() / 1000);
  const ipHash = await sha256Hex('analytics_' + clientIp);
  const windowSeconds = 600; // 10 minutes
  const maxPings = 30;

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
  return res.count <= maxPings;
}

/**
 * Concurrency-safe lookup of current owner lockout status.
 */
async function getOwnerLockStatus(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const ipHash = await sha256Hex('owner_' + clientIp);

  const record = await db.prepare(
    'SELECT attempts, locked_until FROM owner_login_attempts WHERE ip_hash = ?'
  ).bind(ipHash).first();

  if (record && record.locked_until > now) {
    return { locked: true, remainingLockSeconds: record.locked_until - now };
  }
  return { locked: false, remainingLockSeconds: 0 };
}

/**
 * Concurrency-safe atomic accounting for failed owner login attempts.
 * Uses SQLite ON CONFLICT ... DO UPDATE ... RETURNING to ensure concurrent
 * requests cannot bypass the 5-attempt threshold.
 */
async function recordFailedOwnerLoginAtomic(db, clientIp) {
  const now = Math.floor(Date.now() / 1000);
  const lockDuration = 900; // 15 minutes
  const ipHash = await sha256Hex('owner_' + clientIp);

  const stmt = db.prepare(`
    INSERT INTO owner_login_attempts (ip_hash, attempts, locked_until)
    VALUES (?, 1, 0)
    ON CONFLICT(ip_hash) DO UPDATE SET
      attempts = CASE
        WHEN locked_until > 0 AND locked_until <= ? THEN 1
        WHEN locked_until > ? THEN attempts
        ELSE attempts + 1
      END,
      locked_until = CASE
        WHEN locked_until > ? THEN locked_until
        WHEN (CASE WHEN locked_until > 0 AND locked_until <= ? THEN 1 ELSE attempts + 1 END) >= 5 THEN ?
        ELSE 0
      END
    RETURNING attempts, locked_until;
  `);

  const res = await stmt.bind(
    ipHash,
    now,
    now,
    now,
    now,
    now + lockDuration
  ).first();

  if (res && res.locked_until > now) {
    return { locked: true, remainingLockSeconds: res.locked_until - now, attempts: res.attempts };
  }
  return { locked: false, remainingLockSeconds: 0, attempts: res ? res.attempts : 1 };
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
