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

-- Persistent IP Rate Limiting (5 submissions per 10 minutes)
CREATE TABLE IF NOT EXISTS rate_limits (
  ip_hash TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 1,
  reset_at INTEGER NOT NULL
);

-- Short-lived authenticated owner sessions
CREATE TABLE IF NOT EXISTS owner_sessions (
  session_id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
