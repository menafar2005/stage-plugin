-- Refreshable runtime sessions (marketplace POST /api/v1/runtime/refresh).
-- Additive only: existing rows keep their data. Rows from before this migration have no refresh token, so the app
-- answers them with "launch again" instead of refreshing.
--
-- Tokens are stored AES-GCM encrypted (src/crypto.ts, ENCRYPTION_KEY), server-side only. The cookie still carries
-- only a random session id; session_id_hash (SHA-256 of it) stays the lookup key.
ALTER TABLE runtime_sessions ADD COLUMN access_token_encrypted TEXT;     -- base64(iv || ciphertext)
ALTER TABLE runtime_sessions ADD COLUMN access_token_expires_at INTEGER; -- unix seconds, from expiresInSeconds
ALTER TABLE runtime_sessions ADD COLUMN refresh_token_encrypted TEXT;    -- one-time; replaced on every refresh
ALTER TABLE runtime_sessions ADD COLUMN refresh_token_expires_at INTEGER; -- unix seconds, absolute end (refreshTokenExpiresAt), never extended
ALTER TABLE runtime_sessions ADD COLUMN context_json TEXT;               -- full Runtime Context, as received
ALTER TABLE runtime_sessions ADD COLUMN launch_code_hash TEXT;           -- SHA-256 of the launchCode that started the run (iframe reloads)
ALTER TABLE runtime_sessions ADD COLUMN status TEXT NOT NULL DEFAULT 'active'; -- active | reauth_required | expired | revoked | unavailable
ALTER TABLE runtime_sessions ADD COLUMN status_reason TEXT;              -- marketplace error.code or internal reason
ALTER TABLE runtime_sessions ADD COLUMN version INTEGER NOT NULL DEFAULT 0; -- compare-and-swap counter, +1 per token change
ALTER TABLE runtime_sessions ADD COLUMN refresh_lease_id TEXT;           -- holder of the single in-flight refresh
ALTER TABLE runtime_sessions ADD COLUMN refresh_lease_until INTEGER;     -- unix seconds; lease (or cool-down) end
ALTER TABLE runtime_sessions ADD COLUMN refresh_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runtime_sessions ADD COLUMN last_refreshed_at INTEGER;

-- expires_at keeps meaning "row may be deleted after this" (daily cron). For old rows it was the JWT expiry;
-- copy it into the new explicit column.
UPDATE runtime_sessions SET access_token_expires_at = expires_at WHERE access_token_expires_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_runtime_sessions_status_expires ON runtime_sessions (status, expires_at);
