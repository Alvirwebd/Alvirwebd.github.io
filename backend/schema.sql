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

-- ============================================================================
-- STAGE 5.7: VISITOR IP TRACKING & ANONYMOUS ANALYTICS
-- ============================================================================

-- Raw Visitor IP Records (30-day default retention, owner-only access)
CREATE TABLE IF NOT EXISTS visitor_ip_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '/',
  user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_visitor_ip_created_at ON visitor_ip_records(created_at);

-- Anonymous Visitor Analytics (Decoupled from IPs, privacy-friendly unique visitor tracking)
CREATE TABLE IF NOT EXISTS anonymous_visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor_aid_hash TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '/',
  is_returning INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  visit_date TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_anon_visits_date ON anonymous_visits(visit_date);
CREATE INDEX IF NOT EXISTS idx_anon_visits_aid_hash ON anonymous_visits(visitor_aid_hash);
