/**
 * AlvirOS Guestbook Test Suite
 * 
 * Includes:
 * 1. REAL SQLite / D1 Integration Tests (executes actual schema.sql and worker against native SQLite engine)
 * 2. MockD1 Unit Verification Tests (for headless environments without native SQLite)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import worker from './worker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper for assertions
let totalPassed = 0;
let totalFailed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  PASS: ${message}`);
    totalPassed++;
  } else {
    console.error(`  FAIL: ${message}`);
    totalFailed++;
    throw new Error(`Assertion failed: ${message}`);
  }
}

// ============================================================================
// PART 1: REAL SQLite / D1 INTEGRATION TEST HARNESS
// ============================================================================

let hasNativeSqlite = false;
let DatabaseSyncClass = null;

try {
  const sqliteModule = await import('node:sqlite');
  DatabaseSyncClass = sqliteModule.DatabaseSync;
  hasNativeSqlite = true;
} catch (e) {
  console.warn('Native node:sqlite not available. Integration tests will be skipped.');
}

class RealSQLiteD1Database {
  constructor(schemaSql) {
    this.sqlite = new DatabaseSyncClass(':memory:');
    if (schemaSql) {
      this.sqlite.exec(schemaSql);
    }
  }

  prepare(sql) {
    return new RealD1PreparedStatement(this.sqlite, sql);
  }

  async batch(statements) {
    this.sqlite.exec('BEGIN TRANSACTION;');
    try {
      const results = [];
      for (const stmt of statements) {
        results.push(await stmt.run());
      }
      this.sqlite.exec('COMMIT;');
      return results;
    } catch (err) {
      this.sqlite.exec('ROLLBACK;');
      throw err;
    }
  }

  async exec(sql) {
    this.sqlite.exec(sql);
  }
}

class RealD1PreparedStatement {
  constructor(sqlite, sql, params = []) {
    this.sqlite = sqlite;
    this.sql = sql;
    this.params = params;
  }

  bind(...params) {
    return new RealD1PreparedStatement(this.sqlite, this.sql, params);
  }

  async first() {
    const stmt = this.sqlite.prepare(this.sql);
    const row = stmt.get(...this.params);
    return row !== undefined ? row : null;
  }

  async all() {
    const stmt = this.sqlite.prepare(this.sql);
    const rows = stmt.all(...this.params);
    return { results: rows || [], success: true };
  }

  async run() {
    const stmt = this.sqlite.prepare(this.sql);
    const info = stmt.run(...this.params);
    return {
      success: true,
      meta: {
        changes: info ? info.changes : 0,
        last_row_id: info ? Number(info.lastInsertRowid) : null
      }
    };
  }
}

// ============================================================================
// PART 2: MOCK D1 DATABASE (For lightweight unit testing)
// ============================================================================

class MockD1Database {
  constructor() {
    this.thoughts = [];
    this.sessions = new Map();
    this.loginAttempts = new Map();
    this.rateLimits = new Map();
    this.nextId = 1;
  }

  prepare(sql) {
    return new MockPreparedStatement(this, sql);
  }
}

class MockPreparedStatement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...params) {
    return new MockPreparedStatement(this.db, this.sql, params);
  }

  async run() {
    const sql = this.sql.trim();
    if (sql.startsWith('INSERT INTO guestbook_thoughts')) {
      const [tokenHash, text, nickname, color] = this.params;
      const id = this.db.nextId++;
      this.db.thoughts.push({ id, token_hash: tokenHash, text, nickname, color, created_at: new Date().toISOString() });
      return { success: true, meta: { last_row_id: id, changes: 1 } };
    }
    if (sql.startsWith('INSERT INTO owner_sessions')) {
      const [sessionHash, expiresAt] = this.params;
      this.db.sessions.set(sessionHash, { session_hash: sessionHash, expires_at: expiresAt });
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.startsWith('DELETE FROM owner_sessions')) {
      const [sessionHash] = this.params;
      this.db.sessions.delete(sessionHash);
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.startsWith('DELETE FROM guestbook_thoughts')) {
      const [id] = this.params;
      this.db.thoughts = this.db.thoughts.filter(t => t.id !== id);
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.startsWith('DELETE FROM owner_login_attempts')) {
      const [ipHash] = this.params;
      this.db.loginAttempts.delete(ipHash);
      return { success: true, meta: { changes: 1 } };
    }
    return { success: true, meta: { changes: 0 } };
  }

  async first() {
    const sql = this.sql.trim();
    if (sql.includes('FROM rate_limits') || sql.startsWith('INSERT INTO rate_limits')) {
      const [ipHash, resetAt, now1, now2, newResetAt] = this.params;
      const now = now1;
      let rec = this.db.rateLimits.get(ipHash);
      if (!rec || rec.reset_at < now) {
        rec = { count: 1, reset_at: resetAt };
      } else {
        rec.count += 1;
      }
      this.db.rateLimits.set(ipHash, rec);
      return { count: rec.count, reset_at: rec.reset_at };
    }
    if (sql.startsWith('INSERT INTO owner_login_attempts')) {
      const [ipHash, now1, now2, now3, now4, lockedUntilVal] = this.params;
      const now = now1;
      let rec = this.db.loginAttempts.get(ipHash);
      if (!rec) {
        rec = { attempts: 1, locked_until: 0 };
      } else if (rec.locked_until > 0 && rec.locked_until <= now) {
        rec = { attempts: 1, locked_until: 0 };
      } else if (rec.locked_until > now) {
        // already locked
      } else {
        rec.attempts += 1;
        if (rec.attempts >= 5) {
          rec.locked_until = lockedUntilVal;
        }
      }
      this.db.loginAttempts.set(ipHash, rec);
      return { attempts: rec.attempts, locked_until: rec.locked_until };
    }
    if (sql.startsWith('SELECT attempts, locked_until FROM owner_login_attempts')) {
      const [ipHash] = this.params;
      return this.db.loginAttempts.get(ipHash) || null;
    }
    if (sql.startsWith('SELECT session_hash FROM owner_sessions')) {
      const [sessionHash, now] = this.params;
      const rec = this.db.sessions.get(sessionHash);
      if (rec && rec.expires_at > now) return rec;
      return null;
    }
    if (sql.startsWith('SELECT id, text, nickname, color, created_at FROM guestbook_thoughts WHERE token_hash = ?')) {
      const [tokenHash] = this.params;
      return this.db.thoughts.find(t => t.token_hash === tokenHash) || null;
    }
    return null;
  }

  async all() {
    const sql = this.sql.trim();
    if (sql.includes('WHERE token_hash IN')) {
      const hashes = this.params;
      const matched = this.db.thoughts.filter(t => hashes.includes(t.token_hash));
      return { results: matched, success: true };
    }
    if (sql.startsWith('SELECT id, text, nickname, color, created_at FROM guestbook_thoughts ORDER BY id DESC')) {
      return { results: [...this.db.thoughts].reverse(), success: true };
    }
    return { results: [], success: true };
  }
}

// ============================================================================
// TEST SUITE EXECUTION
// ============================================================================

async function runRealIntegrationTests() {
  console.log('\n======================================================');
  console.log('SUITE 1: REAL SQLITE / D1 INTEGRATION TESTS');
  console.log('Executes actual backend/schema.sql & native SQLite queries');
  console.log('======================================================\n');

  const schemaPath = path.join(__dirname, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  const realDb = new RealSQLiteD1Database(schemaSql);

  const env = {
    DB: realDb,
    ADMIN_KEY: 'correct_owner_secret_password_12345',
    ALLOWED_ORIGIN: '*'
  };

  // 1. Query parameter token rejection
  {
    const req = new Request('http://localhost/api/thoughts/my?token=thk_1234', { method: 'GET' });
    const res = await worker.fetch(req, env);
    assert(res.status === 400, 'Real D1: Query param token rejected with HTTP 400');
  }

  // 2. Body size enforcement independent of Content-Length
  {
    // A. Explicit Content-Length > 10KB
    const bigData = JSON.stringify({ text: 'A'.repeat(10500) });
    const reqA = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(bigData.length) },
      body: bigData
    });
    const resA = await worker.fetch(reqA, env);
    assert(resA.status === 413, 'Real D1: Explicit Content-Length > 10KB rejected with HTTP 413');

    // B. Missing Content-Length with oversized streamed body (>10KB)
    // Create a ReadableStream without setting Content-Length
    const bigStream = new ReadableStream({
      start(controller) {
        const chunk = new TextEncoder().encode('{"text":"' + 'X'.repeat(12000) + '"}');
        controller.enqueue(chunk);
        controller.close();
      }
    });
    const reqB = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }, // No Content-Length
      body: bigStream,
      duplex: 'half'
    });
    const resB = await worker.fetch(reqB, env);
    assert(resB.status === 413, 'Real D1: Missing Content-Length with oversized streamed body rejected with HTTP 413');

    // C. Incorrect/Spoofed Content-Length (Content-Length: 50, but body is 15KB)
    const spoofedStream = new ReadableStream({
      start(controller) {
        const chunk = new TextEncoder().encode('{"text":"' + 'Y'.repeat(15000) + '"}');
        controller.enqueue(chunk);
        controller.close();
      }
    });
    const reqC = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '50' }, // Spoofed small length
      body: spoofedStream,
      duplex: 'half'
    });
    const resC = await worker.fetch(reqC, env);
    assert(resC.status === 413, 'Real D1: Spoofed Content-Length with oversized body rejected with HTTP 413');

    // D. Safe size streamed body (<10KB) succeeds
    const safeData = JSON.stringify({ text: 'Valid stream thought', nickname: 'Streamer' });
    const safeStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(safeData));
        controller.close();
      }
    });
    const reqD = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: safeStream,
      duplex: 'half'
    });
    const resD = await worker.fetch(reqD, env);
    assert(resD.status === 201, 'Real D1: Safe streamed body without Content-Length accepted with HTTP 201');
  }

  // 3. Visitor Token Creation & SQLite Storage Verification
  let visitorAToken1, visitorAToken2, visitorBToken;
  {
    // Visitor A submission 1
    const req1 = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.1' },
      body: JSON.stringify({ text: 'Visitor A Thought 1', nickname: 'Alice', color: 'peach' })
    });
    const res1 = await worker.fetch(req1, env);
    const data1 = await res1.json();
    assert(res1.status === 201, 'Real D1: Visitor A first submission succeeds (HTTP 201)');
    assert(typeof data1.token === 'string' && data1.token.startsWith('thk_') && data1.token.length === 68,
      'Real D1: Visitor receives unguessable 32-byte crypto token');
    visitorAToken1 = data1.token;

    // Direct SQLite check: Token hash only, raw token NOT in DB
    const thoughts = realDb.sqlite.prepare('SELECT id, token_hash, text FROM guestbook_thoughts WHERE id = ?').get(data1.thought.id);
    assert(thoughts !== undefined, 'Real D1: Thought inserted into real SQLite table');
    assert(thoughts.token_hash.length === 64 && !thoughts.token_hash.includes('thk_'),
      'Real D1: Real SQLite stores 64-char SHA-256 token hash (never raw token)');

    // Visitor A submission 2 (Multiple thoughts)
    const req2 = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.1' },
      body: JSON.stringify({ text: 'Visitor A Thought 2', nickname: 'Alice', color: 'sky' })
    });
    const res2 = await worker.fetch(req2, env);
    const data2 = await res2.json();
    assert(res2.status === 201, 'Real D1: Visitor A can submit second thought (HTTP 201)');
    visitorAToken2 = data2.token;
    assert(visitorAToken1 !== visitorAToken2, 'Real D1: Each thought receives a distinct cryptographically random token');

    // Visitor B submission
    const reqB = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.2' },
      body: JSON.stringify({ text: 'Visitor B Private Thought', nickname: 'Bob', color: 'mint' })
    });
    const resB = await worker.fetch(reqB, env);
    const dataB = await resB.json();
    assert(resB.status === 201, 'Real D1: Visitor B submission succeeds (HTTP 201)');
    visitorBToken = dataB.token;
  }

  // 4. Multi-Thought Visitor Retrieval & Isolation
  {
    // A. Retrieval via POST body
    const reqA = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: [visitorAToken1, visitorAToken2] })
    });
    const resA = await worker.fetch(reqA, env);
    const dataA = await resA.json();
    assert(resA.status === 200, 'Real D1: Visitor A retrieves collection via POST body (HTTP 200)');
    assert(dataA.thoughts.length === 2, 'Real D1: Both Visitor A thoughts returned from SQLite');
    const hasVisitorBThought = dataA.thoughts.some(t => t.text.includes('Visitor B'));
    assert(!hasVisitorBThought, 'Real D1: Visitor Isolation - Visitor B thought NOT visible to Visitor A');

    // B. Retrieval via Authorization header (single & comma-separated)
    const reqHeader = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${visitorAToken1}, ${visitorAToken2}` }
    });
    const resHeader = await worker.fetch(reqHeader, env);
    const dataHeader = await resHeader.json();
    assert(resHeader.status === 200 && dataHeader.thoughts.length === 2,
      'Real D1: Retrieval via Authorization Bearer comma-separated tokens succeeds');

    // C. Single thought backward-compatible GET /api/thoughts/my
    const reqSingle = new Request('http://localhost/api/thoughts/my', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${visitorBToken}` }
    });
    const resSingle = await worker.fetch(reqSingle, env);
    const dataSingle = await resSingle.json();
    assert(resSingle.status === 200 && dataSingle.thought.text.includes('Visitor B'),
      'Real D1: Single-thought GET /api/thoughts/my with Authorization Bearer header succeeds');
  }

  // 5. Concurrency-Safe Owner Login Brute-Force Protection
  {
    const attackerIp = '203.0.113.99';

    // Fire 10 CONCURRENT failed login requests simultaneously against real SQLite
    const failedPromises = Array.from({ length: 10 }, (_, i) => {
      const req = new Request('http://localhost/api/owner/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': attackerIp },
        body: JSON.stringify({ key: `wrong_attempt_${i}` })
      });
      return worker.fetch(req, env);
    });

    const failedResponses = await Promise.all(failedPromises);
    const statusCodes = failedResponses.map(r => r.status);
    const count401 = statusCodes.filter(s => s === 401).length;
    const count429 = statusCodes.filter(s => s === 429).length;

    assert(count401 === 4, `Real D1 Concurrency: Exactly 4 requests receive HTTP 401 (got ${count401})`);
    assert(count429 === 6, `Real D1 Concurrency: Exactly 6 requests locked out with HTTP 429 (got ${count429})`);

    // Verify lockout record in real SQLite
    const lockoutRow = realDb.sqlite.prepare('SELECT attempts, locked_until FROM owner_login_attempts').get();
    assert(lockoutRow && lockoutRow.attempts >= 5 && lockoutRow.locked_until > 0,
      'Real D1: owner_login_attempts table in SQLite reflects active lockout');

    // Subsequent single request is locked out
    const followUpReq = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': attackerIp },
      body: JSON.stringify({ key: 'wrong_key_again' })
    });
    const followUpRes = await worker.fetch(followUpReq, env);
    assert(followUpRes.status === 429, 'Real D1: Subsequent request rejected with HTTP 429 while locked');

    // Test lockout expiration recovery
    // Fast-forward locked_until to past in SQLite
    realDb.sqlite.prepare('UPDATE owner_login_attempts SET locked_until = 100').run();
    const afterExpireReq = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': attackerIp },
      body: JSON.stringify({ key: 'wrong_after_expiration' })
    });
    const afterExpireRes = await worker.fetch(afterExpireReq, env);
    assert(afterExpireRes.status === 401, 'Real D1: After lockout expiration, request returns 401 and counter resets');

    // Test successful authentication clears failed attempts
    const validLoginReq = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': attackerIp },
      body: JSON.stringify({ key: env.ADMIN_KEY })
    });
    const validLoginRes = await worker.fetch(validLoginReq, env);
    const validLoginData = await validLoginRes.json();
    assert(validLoginRes.status === 200, 'Real D1: Valid owner login succeeds with HTTP 200');
    assert(typeof validLoginData.session_token === 'string' && validLoginData.session_token.startsWith('adm_'),
      'Real D1: Admin session token issued');

    // Verify failed-attempt record was cleared from SQLite
    const clearedRow = realDb.sqlite.prepare('SELECT attempts FROM owner_login_attempts').get();
    assert(!clearedRow, 'Real D1: Successful login completely cleared owner_login_attempts row in SQLite');

    // Verify owner session token is HASHED in SQLite
    const sessionInDb = realDb.sqlite.prepare('SELECT session_hash FROM owner_sessions').get();
    assert(sessionInDb && sessionInDb.session_hash.length === 64 && !sessionInDb.session_hash.includes('adm_'),
      'Real D1: owner_sessions stores only SHA-256 session_hash (never raw session token)');

    // Authenticated owner can list all thoughts
    const ownerListReq = new Request('http://localhost/api/owner/thoughts', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${validLoginData.session_token}` }
    });
    const ownerListRes = await worker.fetch(ownerListReq, env);
    const ownerListData = await ownerListRes.json();
    assert(ownerListRes.status === 200 && ownerListData.thoughts.length === 4,
      'Real D1: Authenticated owner can list all thoughts (including both visitors)');

    // Authenticated owner can delete thought
    const thoughtToDelete = ownerListData.thoughts[0].id;
    const deleteReq = new Request(`http://localhost/api/owner/thoughts/${thoughtToDelete}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${validLoginData.session_token}` }
    });
    const deleteRes = await worker.fetch(deleteReq, env);
    assert(deleteRes.status === 200, 'Real D1: Owner can delete thought via SQLite');

    // Owner logout
    const logoutReq = new Request('http://localhost/api/owner/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${validLoginData.session_token}` }
    });
    const logoutRes = await worker.fetch(logoutReq, env);
    assert(logoutRes.status === 200, 'Real D1: Owner logout returns HTTP 200');

    // Logged-out session rejected
    const expiredListRes = await worker.fetch(ownerListReq, env);
    assert(expiredListRes.status === 401, 'Real D1: Logged-out session rejected with HTTP 401');
  }

  // 6. Real Concurrent Submission Rate Limiting (SQLite Atomic Upsert)
  {
    const rateLimitIp = '192.0.2.77';

    // Fire 10 CONCURRENT submissions from the same IP at the exact same time
    const concurrentSubmissions = Array.from({ length: 10 }, (_, i) => {
      const req = new Request('http://localhost/api/thoughts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': rateLimitIp },
        body: JSON.stringify({ text: `Concurrent thought #${i}` })
      });
      return worker.fetch(req, env);
    });

    const results = await Promise.all(concurrentSubmissions);
    const statuses = results.map(r => r.status);
    const count201 = statuses.filter(s => s === 201).length;
    const count429 = statuses.filter(s => s === 429).length;

    assert(count201 === 5, `Real D1 Concurrency: Exactly 5 concurrent submissions allowed (got ${count201})`);
    assert(count429 === 5, `Real D1 Concurrency: Exactly 5 concurrent submissions rate-limited with HTTP 429 (got ${count429})`);
  }

  // 7. Stage 5.7 & 5.7.1: Real SQLite Visitor IP Tracking, Anonymous Analytics & Privacy Hardening
  {
    console.log('\n--- Running Stage 5.7.1 Analytics & IP Hardening Integration Tests ---');
    const realIp = '198.51.100.42';
    const fakeIp = '10.0.0.99';
    const visitorAid = 'aid_test_visitor_alpha_99';

    // 7a. Visit recording & CF-Connecting-IP capture (User-Agent excluded, spoofed headers ignored)
    const visitReq1 = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': realIp,
        'X-Forwarded-For': fakeIp,
        'X-Real-IP': fakeIp,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AlvirOSTestBrowser'
      },
      body: JSON.stringify({ aid: visitorAid, path: '/portfolio' })
    });
    const visitRes1 = await worker.fetch(visitReq1, env);
    assert(visitRes1.status === 200, 'Real D1 Analytics: Visit with CF-Connecting-IP accepted (HTTP 200)');
    const visitJson1 = await visitRes1.json();
    assert(visitJson1.ip_stored === true, 'Real D1 Analytics: Valid CF-Connecting-IP triggers ip_stored: true');

    // Verify raw IP record in SQLite
    const ipRecord = realDb.sqlite.prepare('SELECT ip, path, created_at FROM visitor_ip_records WHERE ip = ?').get(realIp);
    assert(ipRecord && ipRecord.ip === realIp && ipRecord.path === '/portfolio',
      'Real D1 Analytics: Captured CF-Connecting-IP stored in visitor_ip_records');

    // Verify user_agent column does NOT exist in visitor_ip_records schema
    const ipColumns = realDb.sqlite.prepare("PRAGMA table_info(visitor_ip_records)").all().map(c => c.name);
    assert(!ipColumns.includes('user_agent'),
      'Real D1 Analytics: user_agent column completely removed from visitor_ip_records schema');

    // Verify spoofed IP was NOT stored
    const fakeRecord = realDb.sqlite.prepare('SELECT id FROM visitor_ip_records WHERE ip = ?').get(fakeIp);
    assert(!fakeRecord, 'Real D1 Analytics: Spoofed IP headers (X-Forwarded-For/X-Real-IP) cannot override CF-Connecting-IP');

    // Verify raw IP record contains ZERO thoughts or visitor tokens
    assert(!ipColumns.includes('token_hash') && !ipColumns.includes('text'),
      'Real D1 Analytics: visitor_ip_records has zero guestbook columns (strict data decoupling)');

    // Verify anonymous visit in SQLite
    const anonVisit1 = realDb.sqlite.prepare('SELECT is_returning, path FROM anonymous_visits WHERE path = ?').get('/portfolio');
    assert(anonVisit1 && anonVisit1.is_returning === 0,
      'Real D1 Analytics: First visit correctly recorded as non-returning (is_returning = 0)');

    // Verify anonymous visit table has ZERO IP addresses
    const anonColumns = realDb.sqlite.prepare("PRAGMA table_info(anonymous_visits)").all().map(c => c.name);
    assert(!anonColumns.includes('ip') && !anonColumns.includes('client_ip'),
      'Real D1 Analytics: anonymous_visits table has zero IP address columns');

    // 7b. Missing and invalid IP headers testing (Must NEVER store fake 127.0.0.1)
    const countBeforeMissing = realDb.sqlite.prepare('SELECT COUNT(*) as c FROM visitor_ip_records').get().c;

    // Missing CF-Connecting-IP entirely
    const missingIpReq = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ aid: 'aid_missing_ip_user', path: '/contact' })
    });
    const missingIpRes = await worker.fetch(missingIpReq, env);
    const missingJson = await missingIpRes.json();
    assert(missingIpRes.status === 200, 'Real D1 Analytics: Visit without CF-Connecting-IP accepted (HTTP 200)');
    assert(missingJson.ip_stored === false, 'Real D1 Analytics: Missing CF-Connecting-IP skips IP storage (ip_stored: false)');

    const countAfterMissing = realDb.sqlite.prepare('SELECT COUNT(*) as c FROM visitor_ip_records').get().c;
    assert(countBeforeMissing === countAfterMissing,
      'Real D1 Analytics: Missing CF-Connecting-IP creates zero records in visitor_ip_records');

    const fakeLocalhost = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '127.0.0.1'").get();
    assert(!fakeLocalhost, 'Real D1 Analytics: Never use 127.0.0.1 fallback when IP header is missing');

    // Invalid IP header format
    const invalidIpReq = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': 'malformed.ip.value.999'
      },
      body: JSON.stringify({ aid: 'aid_invalid_ip_user', path: '/' })
    });
    const invalidIpRes = await worker.fetch(invalidIpReq, env);
    const invalidJson = await invalidIpRes.json();
    assert(invalidJson.ip_stored === false, 'Real D1 Analytics: Invalid IP format skips IP storage');

    // Spoofed-only headers (no CF-Connecting-IP, but X-Forwarded-For present)
    const spoofedOnlyReq = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.99',
        'X-Real-IP': '203.0.113.99'
      },
      body: JSON.stringify({ aid: 'aid_spoofed_user', path: '/' })
    });
    const spoofedOnlyRes = await worker.fetch(spoofedOnlyReq, env);
    const spoofedJson = await spoofedOnlyRes.json();
    assert(spoofedJson.ip_stored === false,
      'Real D1 Analytics: Spoofed X-Forwarded-For cannot substitute for missing CF-Connecting-IP');
    const spoofedInDb = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '203.0.113.99'").get();
    assert(!spoofedInDb, 'Real D1 Analytics: Spoofed IP without CF-Connecting-IP was NOT stored');

    // 7c. Returning visitor detection with same AID
    const visitReq2 = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '198.51.100.99', // Different IP, same AID
      },
      body: JSON.stringify({ aid: visitorAid, path: '/about' })
    });
    const visitRes2 = await worker.fetch(visitReq2, env);
    assert(visitRes2.status === 200, 'Real D1 Analytics: Second visit with same AID accepted (HTTP 200)');

    const anonVisit2 = realDb.sqlite.prepare('SELECT is_returning, path FROM anonymous_visits WHERE path = ?').get('/about');
    assert(anonVisit2 && anonVisit2.is_returning === 1,
      'Real D1 Analytics: Subsequent visit with same AID correctly marked as returning (is_returning = 1)');

    // 7d. Non-guestbook visitor tracking
    const thoughtsCountBefore = realDb.sqlite.prepare('SELECT COUNT(*) as c FROM guestbook_thoughts').get().c;
    const lurkerAid = 'aid_lurker_visitor_no_thoughts';
    const lurkerReq = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.88' },
      body: JSON.stringify({ aid: lurkerAid, path: '/' })
    });
    await worker.fetch(lurkerReq, env);
    const thoughtsCountAfter = realDb.sqlite.prepare('SELECT COUNT(*) as c FROM guestbook_thoughts').get().c;
    assert(thoughtsCountBefore === thoughtsCountAfter,
      'Real D1 Analytics: Visitors who never submit thoughts are recorded in analytics without touching guestbook');

    // 7e. Unauthorized owner access protections
    const unauthAnalyticsReq = new Request('http://localhost/api/owner/analytics', { method: 'GET' });
    const unauthAnalyticsRes = await worker.fetch(unauthAnalyticsReq, env);
    assert(unauthAnalyticsRes.status === 401,
      'Real D1 Analytics: Unauthorized access to /api/owner/analytics rejected with HTTP 401');

    const unauthIpsReq = new Request('http://localhost/api/owner/analytics/ips', { method: 'GET' });
    const unauthIpsRes = await worker.fetch(unauthIpsReq, env);
    assert(unauthIpsRes.status === 401,
      'Real D1 Analytics: Unauthorized access to /api/owner/analytics/ips rejected with HTTP 401');

    const unauthDeleteReq = new Request('http://localhost/api/owner/analytics/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ all: true })
    });
    const unauthDeleteRes = await worker.fetch(unauthDeleteReq, env);
    assert(unauthDeleteRes.status === 401,
      'Real D1 Analytics: Unauthorized deletion request rejected with HTTP 401');

    // 7f. Authenticated owner analytics retrieval & metric clarification
    const ownerLoginReq = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: env.ADMIN_KEY })
    });
    const ownerLoginRes = await worker.fetch(ownerLoginReq, env);
    const ownerSessionToken = (await ownerLoginRes.json()).session_token;

    const authAnalyticsReq = new Request('http://localhost/api/owner/analytics', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${ownerSessionToken}` }
    });
    const authAnalyticsRes = await worker.fetch(authAnalyticsReq, env);
    const analyticsData = await authAnalyticsRes.json();

    assert(authAnalyticsRes.status === 200 && analyticsData.success === true,
      'Real D1 Analytics: Authenticated owner retrieves aggregated analytics (HTTP 200)');
    assert(analyticsData.overview && analyticsData.overview.total_visits >= 3,
      'Real D1 Analytics: Aggregated overview correctly calculates total visits');
    assert(analyticsData.overview.estimated_unique_browsers !== undefined,
      'Real D1 Analytics: Dashboard metric Estimated Unique Browsers is present');
    assert(analyticsData.overview.estimated_unique_browsers >= 2,
      'Real D1 Analytics: Aggregated overview correctly calculates unique browsers');

    // Verify aggregated analytics JSON contains ZERO IP addresses
    const analyticsJsonStr = JSON.stringify(analyticsData);
    assert(!analyticsJsonStr.includes('198.51.100') && !analyticsJsonStr.includes('203.0.113'),
      'Real D1 Analytics: Aggregated analytics response contains ZERO IP addresses');

    // 7g. Indefinite historical IP records preservation (No automatic 30-day deletion)
    // Insert simulated 120-day-old and 45-day-old records directly into SQLite
    realDb.sqlite.exec(`
      INSERT INTO visitor_ip_records (ip, path, created_at)
      VALUES ('192.0.2.120', '/ancient-page', datetime('now', '-120 days')),
             ('192.0.2.45', '/older-page', datetime('now', '-45 days'));
    `);

    // Perform multiple ordinary analytics visits and owner requests
    const regularVisitReq = new Request('http://localhost/api/analytics/visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.77' },
      body: JSON.stringify({ aid: 'aid_normal_routine_visitor', path: '/' })
    });
    await worker.fetch(regularVisitReq, env);
    await worker.fetch(new Request('http://localhost/api/owner/analytics', {
      headers: { 'Authorization': `Bearer ${ownerSessionToken}` }
    }), env);

    // Verify historical records remain intact indefinitely
    const ancientRecord = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '192.0.2.120'").get();
    const olderRecord = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '192.0.2.45'").get();
    assert(ancientRecord && olderRecord,
      'Real D1 Analytics: Historical IP records preserved indefinitely; ordinary requests never auto-delete');

    // Authenticated owner raw IP records retrieval includes older records
    const authIpsReq = new Request('http://localhost/api/owner/analytics/ips?limit=50', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${ownerSessionToken}` }
    });
    const authIpsRes = await worker.fetch(authIpsReq, env);
    const ipsData = await authIpsRes.json();
    assert(authIpsRes.status === 200 && Array.isArray(ipsData.records),
      'Real D1 Analytics: Authenticated owner can query raw IP records via /api/owner/analytics/ips');
    assert(ipsData.records.some(r => r.ip === '192.0.2.120'),
      'Real D1 Analytics: Historical 120-day-old record displayed in owner IP history');
    assert(!ipsData.records.some(r => r.user_agent !== undefined),
      'Real D1 Analytics: IP records response strictly excludes user_agent');

    // 7h. Manual deletion requires explicit criteria (Automatic/empty deletion rejected)
    const emptyDeleteReq = new Request('http://localhost/api/owner/analytics/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${ownerSessionToken}` },
      body: JSON.stringify({})
    });
    const emptyDeleteRes = await worker.fetch(emptyDeleteReq, env);
    assert(emptyDeleteRes.status === 400,
      'Real D1 Analytics: Manual deletion without explicit criteria rejected with HTTP 400');

    // Explicit manual owner deletion of records older than 90 days
    const scopedDeleteReq = new Request('http://localhost/api/owner/analytics/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${ownerSessionToken}` },
      body: JSON.stringify({ days: 90 })
    });
    const scopedDeleteRes = await worker.fetch(scopedDeleteReq, env);
    const scopedJson = await scopedDeleteRes.json();
    assert(scopedDeleteRes.status === 200 && scopedJson.deleted >= 1,
      'Real D1 Analytics: Explicit owner deletion with days parameter succeeds');

    const ancientAfterDelete = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '192.0.2.120'").get();
    assert(!ancientAfterDelete, 'Real D1 Analytics: Explicitly deleted 120-day-old record purged');

    const olderStillExists = realDb.sqlite.prepare("SELECT id FROM visitor_ip_records WHERE ip = '192.0.2.45'").get();
    assert(olderStillExists, 'Real D1 Analytics: 45-day-old record preserved when deleting >90 days');

    // 7i. Migration Verification Test (0002_remove_user_agent.sql)
    // Create simulated legacy table with user_agent, populate with rows, run migration, verify schema and data
    realDb.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS legacy_test_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        path TEXT NOT NULL DEFAULT '/',
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO legacy_test_ips (ip, path, user_agent) VALUES ('198.51.100.1', '/page1', 'OldAgent/1.0');
    `);
    const fs = await import('fs');
    const path = await import('path');
    const migrationSql = fs.readFileSync(path.join(__dirname, 'migrations', '0002_remove_user_agent.sql'), 'utf-8');
    // Adapt table name for isolated test
    const testMigrationSql = migrationSql
      .replace(/visitor_ip_records_dg_tmp/g, 'legacy_test_ips_tmp')
      .replace(/visitor_ip_records/g, 'legacy_test_ips')
      .replace(/idx_visitor_ip_created_at/g, 'idx_legacy_test_ips_created_at');
    realDb.sqlite.exec(testMigrationSql);

    const migratedCols = realDb.sqlite.prepare("PRAGMA table_info(legacy_test_ips)").all().map(c => c.name);
    assert(!migratedCols.includes('user_agent'), 'Real D1 Analytics: Migration safely removes user_agent column');
    const migratedRow = realDb.sqlite.prepare("SELECT ip, path FROM legacy_test_ips WHERE ip = '198.51.100.1'").get();
    assert(migratedRow && migratedRow.path === '/page1', 'Real D1 Analytics: Migration preserves all historical rows and paths');

    // 7j. Analytics rate limiting (30 pings per 10 minutes)
    const floodIp = '203.0.113.199';
    let hitRateLimit = false;
    for (let i = 0; i < 32; i++) {
      const floodReq = new Request('http://localhost/api/analytics/visit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': floodIp },
        body: JSON.stringify({ aid: `aid_flood_${i}`, path: '/' })
      });
      const floodRes = await worker.fetch(floodReq, env);
      if (floodRes.status === 429) {
        hitRateLimit = true;
        break;
      }
    }
    assert(hitRateLimit, 'Real D1 Analytics: Rapid analytics pings from same IP rate-limited with HTTP 429');
  }

  // 8. PR #25 Final Review: Fabricated IP Elimination & Owner IP History Pagination
  {
    console.log('\n--- Running PR #25 Review Corrections: IP Fallback & Pagination Tests ---');

    // 8a. Rate Limiting on POST /api/thoughts with missing CF-Connecting-IP
    // Verify that missing header uses 'missing_ip_anonymous' identity, is rate limited, and NEVER uses 127.0.0.1
    let missingHeaderRateLimited = false;
    for (let i = 0; i < 7; i++) {
      const thoughtReq = new Request('http://localhost/api/thoughts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: `Missing IP thought ${i}`, nickname: 'Anon' })
      });
      const thoughtRes = await worker.fetch(thoughtReq, env);
      if (thoughtRes.status === 429) {
        missingHeaderRateLimited = true;
        break;
      }
    }
    assert(missingHeaderRateLimited,
      'PR #25 Rate Limit: Requests with missing CF-Connecting-IP are rate-limited on missing_ip_anonymous bucket');

    // Confirm that 127.0.0.1 was NEVER hashed or stored for missing-IP requests
    const encoder = new TextEncoder();
    const hash127Buf = await crypto.subtle.digest('SHA-256', encoder.encode('visitor_127.0.0.1'));
    const hash127Hex = Array.from(new Uint8Array(hash127Buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const fake127RateLimit = realDb.sqlite.prepare('SELECT ip_hash FROM rate_limits WHERE ip_hash = ?').get(hash127Hex);
    assert(!fake127RateLimit,
      'PR #25 Rate Limit: 127.0.0.1 is NEVER used as fallback or stored in rate_limits');

    // Verify valid CF-Connecting-IP is not blocked by the anonymous bucket
    const validIpSubmission = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '198.51.100.201'
      },
      body: JSON.stringify({ text: 'Valid IP thought', nickname: 'Alice' })
    });
    const validIpRes = await worker.fetch(validIpSubmission, env);
    assert(validIpRes.status === 201,
      'PR #25 Rate Limit: Valid CF-Connecting-IP request succeeds independently of missing_ip_anonymous bucket');

    // 8b. Owner Login Brute-Force Lockout with missing CF-Connecting-IP
    // Send 5 failed attempts without CF-Connecting-IP
    let missingIpLockout = false;
    for (let i = 0; i < 6; i++) {
      const loginReq = new Request('http://localhost/api/owner/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: 'wrong_secret_attempt' })
      });
      const loginRes = await worker.fetch(loginReq, env);
      if (loginRes.status === 429) {
        missingIpLockout = true;
        break;
      }
    }
    assert(missingIpLockout,
      'PR #25 Lockout: Owner login with missing CF-Connecting-IP locks out after failed attempts on missing_ip_anonymous');

    // Confirm that 127.0.0.1 was NEVER hashed or stored in owner_login_attempts
    const hashOwner127Buf = await crypto.subtle.digest('SHA-256', encoder.encode('owner_127.0.0.1'));
    const hashOwner127Hex = Array.from(new Uint8Array(hashOwner127Buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const fakeOwner127 = realDb.sqlite.prepare('SELECT ip_hash FROM owner_login_attempts WHERE ip_hash = ?').get(hashOwner127Hex);
    assert(!fakeOwner127,
      'PR #25 Lockout: 127.0.0.1 is NEVER used as fallback or stored in owner_login_attempts');

    // Verify valid CF-Connecting-IP can still log in if credentials are correct
    const validIpLogin = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '198.51.100.202'
      },
      body: JSON.stringify({ key: env.ADMIN_KEY })
    });
    const validLoginRes = await worker.fetch(validIpLogin, env);
    assert(validLoginRes.status === 200,
      'PR #25 Lockout: Valid CF-Connecting-IP owner login succeeds independently of anonymous lockout');
    const validSessionToken = (await validLoginRes.json()).session_token;

    // 8c. IP History Pagination (GET /api/owner/analytics/ips)
    // Clear and insert exactly 45 deterministic records
    realDb.sqlite.exec('DELETE FROM visitor_ip_records');
    for (let i = 1; i <= 45; i++) {
      realDb.sqlite.prepare(
        "INSERT INTO visitor_ip_records (id, ip, path, created_at) VALUES (?, ?, ?, datetime('now', ?))"
      ).run(i, `198.51.100.${i}`, `/page-${i}`, `-${45 - i} minutes`);
    }

    // Page 1 with limit=20
    const p1Req = new Request('http://localhost/api/owner/analytics/ips?page=1&limit=20', {
      headers: { 'Authorization': `Bearer ${validSessionToken}` }
    });
    const p1Res = await worker.fetch(p1Req, env);
    const p1Data = await p1Res.json();
    assert(p1Res.status === 200 && p1Data.success === true, 'PR #25 Pagination: Page 1 request succeeds (HTTP 200)');
    assert(p1Data.records.length === 20, 'PR #25 Pagination: Page 1 returns exactly 20 records');
    assert(p1Data.pagination.page === 1, 'PR #25 Pagination: Page 1 pagination.page === 1');
    assert(p1Data.pagination.limit === 20, 'PR #25 Pagination: Page 1 pagination.limit === 20');
    assert(p1Data.pagination.total === 45, 'PR #25 Pagination: Page 1 pagination.total === 45');
    assert(p1Data.pagination.total_pages === 3, 'PR #25 Pagination: Page 1 pagination.total_pages === 3');
    assert(p1Data.pagination.has_next === true, 'PR #25 Pagination: Page 1 has_next === true');
    assert(p1Data.pagination.has_prev === false, 'PR #25 Pagination: Page 1 has_prev === false');
    assert(p1Data.records[0].id === 45 && p1Data.records[19].id === 26,
      'PR #25 Pagination: Page 1 correctly ordered id DESC (45 down to 26)');

    // Page 2 with limit=20
    const p2Req = new Request('http://localhost/api/owner/analytics/ips?page=2&limit=20', {
      headers: { 'Authorization': `Bearer ${validSessionToken}` }
    });
    const p2Res = await worker.fetch(p2Req, env);
    const p2Data = await p2Res.json();
    assert(p2Data.records.length === 20, 'PR #25 Pagination: Page 2 returns exactly 20 records');
    assert(p2Data.pagination.page === 2, 'PR #25 Pagination: Page 2 pagination.page === 2');
    assert(p2Data.pagination.has_next === true, 'PR #25 Pagination: Page 2 has_next === true');
    assert(p2Data.pagination.has_prev === true, 'PR #25 Pagination: Page 2 has_prev === true');
    assert(p2Data.records[0].id === 25 && p2Data.records[19].id === 6,
      'PR #25 Pagination: Page 2 correctly ordered id DESC (25 down to 6)');

    // Page 3 with limit=20
    const p3Req = new Request('http://localhost/api/owner/analytics/ips?page=3&limit=20', {
      headers: { 'Authorization': `Bearer ${validSessionToken}` }
    });
    const p3Res = await worker.fetch(p3Req, env);
    const p3Data = await p3Res.json();
    assert(p3Data.records.length === 5, 'PR #25 Pagination: Page 3 returns remaining 5 records');
    assert(p3Data.pagination.page === 3, 'PR #25 Pagination: Page 3 pagination.page === 3');
    assert(p3Data.pagination.has_next === false, 'PR #25 Pagination: Page 3 has_next === false');
    assert(p3Data.pagination.has_prev === true, 'PR #25 Pagination: Page 3 has_prev === true');
    assert(p3Data.records[0].id === 5 && p3Data.records[4].id === 1,
      'PR #25 Pagination: Page 3 correctly ordered id DESC (5 down to 1)');

    // Bounds checking: limit > 100 clamped to 100, page < 1 clamped to 1
    const clampReq = new Request('http://localhost/api/owner/analytics/ips?page=0&limit=999', {
      headers: { 'Authorization': `Bearer ${validSessionToken}` }
    });
    const clampRes = await worker.fetch(clampReq, env);
    const clampData = await clampRes.json();
    assert(clampData.pagination.page === 1, 'PR #25 Pagination: page <= 0 safely clamped to 1');
    assert(clampData.pagination.limit === 100, 'PR #25 Pagination: limit > 100 safely clamped to 100');
    assert(clampData.records.length === 45, 'PR #25 Pagination: Returns all 45 records within clamped limit of 100');
  }
}

// ============================================================================
// SUITE 2: LIGHTWEIGHT MOCK UNIT TESTS
// ============================================================================

async function runMockUnitTests() {
  console.log('\n======================================================');
  console.log('SUITE 2: LIGHTWEIGHT MOCK UNIT TESTS');
  console.log('Fast, dependency-free logical unit tests using MockD1');
  console.log('======================================================\n');

  const mockDb = new MockD1Database();
  const env = {
    DB: mockDb,
    ADMIN_KEY: 'mock_admin_secret_key',
    ALLOWED_ORIGIN: '*'
  };

  // Mock Unit Test 1: Query param rejection
  {
    const req = new Request('http://localhost/api/thoughts/my?token=test', { method: 'GET' });
    const res = await worker.fetch(req, env);
    assert(res.status === 400, 'Mock Unit: Query param token rejected with HTTP 400');
  }

  // Mock Unit Test 2: Payload > 10KB rejected
  {
    const big = JSON.stringify({ text: 'M'.repeat(11000) });
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Length': String(big.length) },
      body: big
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 413, 'Mock Unit: Oversized payload rejected with HTTP 413');
  }

  // Mock Unit Test 3: Empty thought rejected
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: '   ' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 400, 'Mock Unit: Empty thought rejected with HTTP 400');
  }

  // Mock Unit Test 4: Successful submission & token generation
  let token1;
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'Mock thought 1', nickname: 'MockUser' })
    });
    const res = await worker.fetch(req, env);
    const data = await res.json();
    assert(res.status === 201, 'Mock Unit: Submission succeeds with HTTP 201');
    assert(typeof data.token === 'string' && data.token.startsWith('thk_'), 'Mock Unit: Crypto token returned');
    token1 = data.token;
  }

  // Mock Unit Test 5: Multi-thought retrieval
  {
    const req = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: [token1] })
    });
    const res = await worker.fetch(req, env);
    const data = await res.json();
    assert(res.status === 200 && data.thoughts.length === 1, 'Mock Unit: Multi-thought retrieval succeeds');
  }

  // Mock Unit Test 6: Invalid owner login
  {
    const req = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'wrong_key' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 401, 'Mock Unit: Invalid credentials return HTTP 401');
  }

  // Mock Unit Test 7: Valid owner login
  let sessionToken;
  {
    const req = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: env.ADMIN_KEY })
    });
    const res = await worker.fetch(req, env);
    const data = await res.json();
    assert(res.status === 200 && data.session_token.startsWith('adm_'), 'Mock Unit: Valid owner login succeeds');
    sessionToken = data.session_token;
  }

  // Mock Unit Test 8: Owner list & logout
  {
    const listReq = new Request('http://localhost/api/owner/thoughts', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const listRes = await worker.fetch(listReq, env);
    assert(listRes.status === 200, 'Mock Unit: Owner thought retrieval succeeds');

    const logoutReq = new Request('http://localhost/api/owner/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const logoutRes = await worker.fetch(logoutReq, env);
    assert(logoutRes.status === 200, 'Mock Unit: Owner logout succeeds');
  }
}

// ============================================================================
// MAIN RUNNER
// ============================================================================

async function main() {
  console.log('Starting AlvirOS Guestbook Verification...\n');

  if (hasNativeSqlite) {
    await runRealIntegrationTests();
  }

  await runMockUnitTests();

  console.log('\n======================================================');
  console.log(`TEST SUMMARY: ${totalPassed} passed, ${totalFailed} failed.`);
  console.log('======================================================\n');

  if (totalFailed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Test execution failed with error:', err);
  process.exit(1);
});
