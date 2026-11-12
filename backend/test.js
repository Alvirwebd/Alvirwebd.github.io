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
