-- Read-only check: prints only COUNTS of rows that may still hold secrets, never a value.
-- (One SELECT per check: D1 limits the number of terms in a compound SELECT.)
--   npx wrangler d1 execute stage-plugin-db --remote --file scripts/check-legacy-secrets.sql
SELECT 'external_api_calls: unscrubbed legacy rows' AS check_name, COUNT(*) AS row_count
  FROM external_api_calls WHERE redaction_version IS NULL AND legacy_scrubbed_at IS NULL;
SELECT 'external_api_calls: JWT-looking text' AS check_name, COUNT(*) AS row_count FROM external_api_calls
  WHERE (COALESCE(request_url, '') || COALESCE(request_headers, '') || COALESCE(request_body, '') || COALESCE(response_headers, '')
     || COALESCE(response_body, '') || COALESCE(error_message, '')) LIKE '%eyJ%';
SELECT 'external_api_calls: unmasked apikey in URL' AS check_name, COUNT(*) AS row_count FROM external_api_calls
  WHERE request_url LIKE '%apikey=%' AND request_url NOT LIKE '%apikey=[REDACTED]%';
SELECT 'rate_limits: JWT-looking query/headers' AS check_name, COUNT(*) AS row_count FROM rate_limits
  WHERE request_query LIKE '%eyJ%' OR request_headers LIKE '%eyJ%';
SELECT 'extension_events: JWT-looking payload' AS check_name, COUNT(*) AS row_count FROM extension_events WHERE payload LIKE '%eyJ%';
SELECT 'runtime_sessions: rows without refresh token (need a new launch)' AS check_name, COUNT(*) AS row_count
  FROM runtime_sessions WHERE refresh_token_encrypted IS NULL;
