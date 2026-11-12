-- ============================================================================
-- Migration: 0002_remove_user_agent.sql
-- Removes user_agent column from visitor_ip_records
-- Preserves all historical IP records, timestamps, and paths
-- ============================================================================

-- Step 1: Create new visitor_ip_records table without user_agent column
CREATE TABLE IF NOT EXISTS visitor_ip_records_dg_tmp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '/',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Step 2: Copy existing historical data safely (excluding user_agent)
INSERT INTO visitor_ip_records_dg_tmp (id, ip, path, created_at)
SELECT id, ip, path, created_at FROM visitor_ip_records;

-- Step 3: Drop original table
DROP TABLE visitor_ip_records;

-- Step 4: Rename temporary table to canonical table name
ALTER TABLE visitor_ip_records_dg_tmp RENAME TO visitor_ip_records;

-- Step 5: Recreate index on created_at
CREATE INDEX IF NOT EXISTS idx_visitor_ip_created_at ON visitor_ip_records(created_at);
