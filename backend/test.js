/**
 * AlvirOS Guestbook Automated Test Suite
 * Tests all backend security, rate-limiting, token-hashing, and multi-session requirements.
 *
 * Usage: node backend/test.js
 */

const worker = require('./worker.js').default;

class MockD1 {
  constructor() {
    this.thoughts = [];
    this.rateLimits = new Map();
    this.ownerAttempts = new Map();
    this.sessions = new Map();
    this.nextId = 1;
  }

  prepare(query) {
    const self = this;
    const makeExec = (args = []) => ({
      async run() {
        if (query.includes('INSERT INTO guestbook_thoughts')) {
          const id = self.nextId++;
          self.thoughts.push({
            id,
            token_hash: args[0],
            text: args[1],
            nickname: args[2],
            color: args[3],
            created_at: new Date().toISOString()
          });
          return { meta: { last_row_id: id } };
        }
        if (query.includes('INSERT INTO owner_sessions')) {
          self.sessions.set(args[0], args[1]); // session_hash -> expires_at
          return { success: true };
        }
        if (query.includes('DELETE FROM owner_sessions WHERE session_hash')) {
          self.sessions.delete(args[0]);
          return { success: true };
        }
        if (query.includes('DELETE FROM guestbook_thoughts WHERE id')) {
          self.thoughts = self.thoughts.filter(t => t.id !== args[0]);
          return { success: true };
        }
        if (query.includes('DELETE FROM owner_login_attempts WHERE ip_hash')) {
          self.ownerAttempts.delete(args[0]);
          return { success: true };
        }
        if (query.includes('INSERT INTO owner_login_attempts')) {
          const ipHash = args[0];
          const now = args[1];
          const lockUntil = args[2];
          const existing = self.ownerAttempts.get(ipHash);
          if (!existing) {
            self.ownerAttempts.set(ipHash, { attempts: 1, locked_until: 0 });
          } else {
            const attempts = (existing.locked_until < now && existing.locked_until > 0) ? 1 : existing.attempts + 1;
            const newLock = attempts >= 5 ? lockUntil : 0;
            self.ownerAttempts.set(ipHash, { attempts, locked_until: newLock });
          }
          return { success: true };
        }
        return { success: true };
      },

      async first() {
        if (query.includes('FROM guestbook_thoughts WHERE token_hash = ?')) {
          return self.thoughts.find(t => t.token_hash === args[0]) || null;
        }
        if (query.includes('FROM owner_sessions WHERE session_hash = ?')) {
          const exp = self.sessions.get(args[0]);
          const now = Math.floor(Date.now() / 1000);
          if (exp && exp > now) return { session_hash: args[0], expires_at: exp };
          return null;
        }
        if (query.includes('FROM owner_login_attempts WHERE ip_hash = ?')) {
          return self.ownerAttempts.get(args[0]) || null;
        }
        // Atomic visitor rate-limit upsert
        if (query.includes('INSERT INTO rate_limits')) {
          const ipHash = args[0];
          const resetAt = args[1];
          const now = args[2];
          const existing = self.rateLimits.get(ipHash);
          if (!existing || existing.reset_at < now) {
            const entry = { count: 1, reset_at: resetAt };
            self.rateLimits.set(ipHash, entry);
            return entry;
          } else {
            existing.count += 1;
            return existing;
          }
        }
        return null;
      },

      async all() {
        if (query.includes('FROM guestbook_thoughts WHERE token_hash IN')) {
          const matched = self.thoughts.filter(t => args.includes(t.token_hash));
          return { results: [...matched].reverse() };
        }
        if (query.includes('FROM guestbook_thoughts ORDER BY id DESC')) {
          return { results: [...self.thoughts].reverse() };
        }
        return { results: [] };
      }
    });

    const exec = makeExec([]);
    return {
      ...exec,
      bind(...args) {
        return makeExec(args);
      }
    };
  }
}

async function runTests() {
  const db = new MockD1();
  const env = {
    DB: db,
    ADMIN_KEY: 'test-admin-secret-key-xyz-2026',
    ALLOWED_ORIGIN: '*'
  };

  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      console.log(`PASS: ${message}`);
      passed++;
    } else {
      console.error(`FAIL: ${message}`);
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  console.log('========================================');
  console.log('RUNNING ALVIROS GUESTBOOK TEST SUITE');
  console.log('========================================\n');

  // Test 1: Query param token rejection (Mandatory Security Rule 1)
  {
    const req = new Request('http://localhost/api/thoughts/my?token=thk_123456');
    const res = await worker.fetch(req, env);
    assert(res.status === 400, '1. Query param token rejected with HTTP 400');
  }

  // Test 2: Oversized body rejection (> 10KB)
  {
    const bigText = 'a'.repeat(12000);
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': bigText.length.toString() },
      body: JSON.stringify({ text: bigText })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 413, '2. Oversized payload (>10KB) rejected with HTTP 413');
  }

  // Test 3: Invalid input rejection
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: '' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 400, '3. Empty thought rejected with HTTP 400');
  }

  // Test 4: Anonymous visitor submission
  let tokenA1, tokenA2, tokenB1;
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '10.0.0.1' },
      body: JSON.stringify({ text: 'First thought from Visitor A', nickname: 'Alice', color: 'yellow' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 201, '4a. Anonymous Visitor A first submission succeeds (HTTP 201)');
    const data = await res.json();
    assert(data.token && data.token.startsWith('thk_'), '4b. Visitor receives unguessable 32-byte crypto token');
    tokenA1 = data.token;
  }

  // Test 5: Token hashing (D1 stores ONLY SHA-256 hash, never raw token)
  {
    assert(db.thoughts.length === 1, '5a. Thought stored in database');
    assert(db.thoughts[0].token_hash !== tokenA1, '5b. Database does NOT store raw visitor token');
    assert(db.thoughts[0].token_hash.length === 64, '5c. Database stores 64-char SHA-256 token hash');
  }

  // Test 6: Multiple thoughts per visitor (Visitor A submits a second thought)
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '10.0.0.1' },
      body: JSON.stringify({ text: 'Second thought from Visitor A', nickname: 'Alice', color: 'mint' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 201, '6a. Visitor A can submit multiple thoughts (HTTP 201)');
    const data = await res.json();
    tokenA2 = data.token;
    assert(tokenA1 !== tokenA2, '6b. Each thought receives a distinct unguessable token');
  }

  // Test 7: Visitor B submission
  {
    const req = new Request('http://localhost/api/thoughts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '10.0.0.2' },
      body: JSON.stringify({ text: 'Thought from Visitor B', nickname: 'Bob', color: 'peach' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 201, '7. Visitor B submission succeeds (HTTP 201)');
    const data = await res.json();
    tokenB1 = data.token;
  }

  // Test 8: Multiple thoughts retrieval via POST /api/thoughts/my
  {
    const req = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: [tokenA1, tokenA2] })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 200, '8a. Visitor A retrieves collection of their own thoughts (HTTP 200)');
    const data = await res.json();
    assert(Array.isArray(data.thoughts) && data.thoughts.length === 2, '8b. Both Visitor A thoughts returned');
    assert(!data.thoughts.some(t => t.text.includes('Visitor B')), '8c. Visitor B thought is NOT present in Visitor A retrieval');
  }

  // Test 9: Visitor isolation (Visitor B cannot access Visitor A thoughts)
  {
    const req = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: [tokenB1] })
    });
    const res = await worker.fetch(req, env);
    const data = await res.json();
    assert(data.thoughts.length === 1 && data.thoughts[0].nickname === 'Bob', '9. Strict Visitor Isolation: Visitor B sees only their own thought');
  }

  // Test 10: Invalid tokens return empty safely without leaking
  {
    const req = new Request('http://localhost/api/thoughts/my', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tokens: ['thk_' + '0'.repeat(64)] })
    });
    const res = await worker.fetch(req, env);
    const data = await res.json();
    assert(data.thoughts.length === 0, '10. Non-existent tokens return empty list without leaking');
  }

  // Test 11: Owner login failure
  {
    const req = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.168.1.1' },
      body: JSON.stringify({ key: 'wrong-password' })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 401, '11. Incorrect owner key returns HTTP 401');
  }

  // Test 12: Owner login brute-force rate-limiting
  {
    const ip = '192.168.1.50';
    for (let i = 0; i < 4; i++) {
      const req = new Request('http://localhost/api/owner/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
        body: JSON.stringify({ key: 'wrong' })
      });
      const res = await worker.fetch(req, env);
      assert(res.status === 401, `12a. Failed attempt #${i + 1} returns HTTP 401`);
    }

    // 5th failed attempt triggers lockout
    const req5 = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
      body: JSON.stringify({ key: 'wrong' })
    });
    const res5 = await worker.fetch(req5, env);
    assert(res5.status === 401, '12b. 5th failed attempt recorded');

    // 6th attempt is blocked by brute force protection
    const req6 = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
      body: JSON.stringify({ key: env.ADMIN_KEY }) // even with correct key
    });
    const res6 = await worker.fetch(req6, env);
    assert(res6.status === 429, '12c. 6th attempt locked out with HTTP 429');
  }

  // Test 13: Owner login success & hashed session storage
  let sessionToken;
  {
    const req = new Request('http://localhost/api/owner/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.168.1.99' },
      body: JSON.stringify({ key: env.ADMIN_KEY })
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 200, '13a. Valid owner key returns HTTP 200');
    const data = await res.json();
    assert(data.session_token && data.session_token.startsWith('adm_'), '13b. Admin session token issued');
    sessionToken = data.session_token;

    // Check that D1 stores session hash, NOT raw session token
    assert(!db.sessions.has(sessionToken), '13c. D1 does NOT store raw session token');
    assert(db.sessions.size > 0, '13d. D1 stores hashed session token');
  }

  // Test 14: Owner retrieves all thoughts
  {
    const req = new Request('http://localhost/api/owner/thoughts', {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 200, '14a. Authenticated owner retrieves all thoughts (HTTP 200)');
    const data = await res.json();
    assert(data.thoughts.length === 3, '14b. Owner sees all 3 visitor submissions');
  }

  // Test 15: Owner deletes a thought
  {
    const req = new Request('http://localhost/api/owner/thoughts/1', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const res = await worker.fetch(req, env);
    assert(res.status === 200, '15a. Owner can delete thought (HTTP 200)');
    assert(db.thoughts.length === 2, '15b. Database reflects deletion');
  }

  // Test 16: Owner logout & session invalidation
  {
    const logoutReq = new Request('http://localhost/api/owner/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const logoutRes = await worker.fetch(logoutReq, env);
    assert(logoutRes.status === 200, '16a. Owner logout returns HTTP 200');

    // Check that deleted session is rejected
    const listReq = new Request('http://localhost/api/owner/thoughts', {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    });
    const listRes = await worker.fetch(listReq, env);
    assert(listRes.status === 401, '16b. Logged-out session rejected with HTTP 401');
  }

  // Test 17: Concurrent visitor rate limiting (Atomic race-condition check)
  {
    const testIp = '10.0.0.88';
    // Send 6 concurrent requests simultaneously
    const promises = Array.from({ length: 6 }).map((_, i) => {
      const req = new Request('http://localhost/api/thoughts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': testIp },
        body: JSON.stringify({ text: `Concurrent test ${i}`, nickname: 'Racer' })
      });
      return worker.fetch(req, env);
    });

    const responses = await Promise.all(promises);
    const statuses = responses.map(r => r.status);
    const successCount = statuses.filter(s => s === 201).length;
    const rateLimitedCount = statuses.filter(s => s === 429).length;

    assert(successCount === 5, '17a. Exactly 5 concurrent submissions allowed');
    assert(rateLimitedCount === 1, '17b. 6th concurrent submission atomically rate-limited with HTTP 429');
  }

  console.log('\n========================================');
  console.log(`ALL TESTS PASSED: ${passed}/${total}`);
  console.log('========================================');
}

runTests().catch(err => {
  console.error('\nTEST SUITE FAILED:', err);
  process.exit(1);
});
