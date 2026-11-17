-- New install contract: POST {MARKETPLACE_URL}/install/auth/token returns only {"api_key", "scope"}.
-- installation_id, app_public_id, installed_at and scopes are no longer returned: existing values are kept as they
-- are and new rows leave them NULL (nothing is invented). api_key goes into the existing api_key_encrypted column.
ALTER TABLE installations ADD COLUMN scope TEXT;                -- raw `scope` string, e.g. "full api access"
ALTER TABLE installations ADD COLUMN installed_by_user_id TEXT; -- first part of the callback code, stored only after the marketplace accepted it
