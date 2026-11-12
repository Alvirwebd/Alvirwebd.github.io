-- D1 Schema for AlvirOS Anonymous Private Guestbook

CREATE TABLE IF NOT EXISTS guestbook_thoughts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  text TEXT NOT NULL,
  nickname TEXT NOT NULL DEFAULT 'Anonymous',
  color TEXT NOT NULL DEFAULT 'yellow',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_thoughts_token_hash ON guestbook_thoughts(token_hash);

-- Persistent IP Rate Limiting for visitor submissions (5 per 10 minutes)
CREATE TABLE IF NOT EXISTS rate_limits (
  ip_hash TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 1,
  reset_at INTEGER NOT NULL
);

-- Brute-Force Rate Limiting for owner authentication (5 failed attempts per 15 minutes)
CREATE TABLE IF NOT EXISTS owner_login_attempts (
  ip_hash TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 1,
  locked_until INTEGER NOT NULL DEFAULT 0
);

-- Short-lived authenticated owner sessions (Stored as SHA-256 hashes only)
CREATE TABLE IF NOT EXISTS owner_sessions (
  session_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
