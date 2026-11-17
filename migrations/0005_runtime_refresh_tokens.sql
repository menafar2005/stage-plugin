-- Refresh tokens get their own table (one row per issued token, history kept), instead of a column on runtime_sessions.
-- Exactly one 'active' token per session (partial unique index). On every refresh the active row becomes 'rotated'
-- (its ciphertext wiped) and the replacement is inserted, in the same atomic D1 batch as the session update.
-- When a session ends, its active token becomes 'ended' (ciphertext wiped, status_reason = why).
CREATE TABLE IF NOT EXISTS runtime_refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,          -- runtime_sessions.id
  user_id TEXT,
  biz_domain_id TEXT,
  runtime_id TEXT,
  refresh_token_encrypted TEXT,         -- AES-GCM base64(iv || ciphertext); NULL once rotated/ended
  expires_at INTEGER NOT NULL,          -- unix seconds: absolute session end (refreshTokenExpiresAt), never extended
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'ended')),
  status_reason TEXT,                   -- e.g. REFRESH_TOKEN_EXPIRED, INSTALLATION_ACCESS_DENIED, REFRESH_OUTCOME_UNKNOWN
  replaced_by_id INTEGER,               -- the token issued in exchange for this one
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rotated_at INTEGER                    -- unix seconds
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_refresh_tokens_one_active ON runtime_refresh_tokens (session_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_runtime_refresh_tokens_session ON runtime_refresh_tokens (session_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_refresh_tokens_expires ON runtime_refresh_tokens (expires_at);

-- Move the tokens stored by migration 0002's column into the new table, then clear the old column (kept, unused).
INSERT INTO runtime_refresh_tokens (session_id, user_id, biz_domain_id, runtime_id, refresh_token_encrypted, expires_at, status)
  SELECT id, user_id, biz_domain_id, runtime_id, refresh_token_encrypted, COALESCE(refresh_token_expires_at, expires_at), 'active'
  FROM runtime_sessions
  WHERE refresh_token_encrypted IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM runtime_refresh_tokens t WHERE t.session_id = runtime_sessions.id AND t.status = 'active');
UPDATE runtime_sessions SET refresh_token_encrypted = NULL WHERE refresh_token_encrypted IS NOT NULL;
