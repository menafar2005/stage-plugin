-- external_api_calls: columns for redacted logging + one-time scrub of rows written before redaction.
-- Up to commit 0f335a2 this table was written unredacted (client secret, launchCodes, Runtime Tokens, ?apikey=).
-- That code is still what runs on stage-plugin until this version is deployed, so stage-plugin-db may hold such rows.
-- New rows carry redaction_version = 2 and error_code / trace_id in their own columns.
-- The UPDATE below is the same SQL as scripts/scrub-legacy-api-logs.sql. Run that script again AFTER deploying:
-- the previous Worker version may write unredacted rows between this migration and the deploy.
-- D1 Time Travel history and earlier Workers Logs are not touched by this (see README, Old logs).
ALTER TABLE external_api_calls ADD COLUMN error_code TEXT;
ALTER TABLE external_api_calls ADD COLUMN trace_id TEXT;
ALTER TABLE external_api_calls ADD COLUMN redaction_version INTEGER; -- NULL = written by old code (possibly unredacted)
ALTER TABLE external_api_calls ADD COLUMN legacy_scrubbed_at TEXT;
CREATE INDEX IF NOT EXISTS idx_external_api_calls_redaction ON external_api_calls (redaction_version, legacy_scrubbed_at);

UPDATE external_api_calls SET
  error_code = COALESCE(error_code, CASE WHEN json_valid(response_body) THEN COALESCE(
    json_extract(response_body, '$.error.code'),
    CASE WHEN json_type(response_body, '$.error') = 'text' THEN json_extract(response_body, '$.error') END,
    json_extract(response_body, '$.Response.Error.Code')) END),
  trace_id = COALESCE(trace_id, CASE WHEN json_valid(response_body) THEN COALESCE(
    json_extract(response_body, '$.meta.traceId'), json_extract(response_body, '$.Response.Meta.TraceId')) END),
  request_url = CASE WHEN instr(request_url, '?') > 0 THEN substr(request_url, 1, instr(request_url, '?') - 1) || '?[REDACTED_LEGACY]' ELSE request_url END,
  request_headers = CASE WHEN request_headers IS NULL THEN NULL ELSE '[REDACTED_LEGACY]' END,
  request_body = CASE WHEN request_body IS NULL THEN NULL ELSE '[REDACTED_LEGACY]' END,
  response_headers = CASE WHEN response_headers IS NULL THEN NULL ELSE '[REDACTED_LEGACY]' END,
  response_body = CASE
    WHEN response_body IS NULL THEN NULL
    WHEN json_valid(response_body) THEN json_object(
      'legacyRedacted', json('true'),
      'succeeded', COALESCE(json_extract(response_body, '$.succeeded'), json_extract(response_body, '$.Response.Succeeded')),
      'error', json_object('code', COALESCE(
        json_extract(response_body, '$.error.code'),
        CASE WHEN json_type(response_body, '$.error') = 'text' THEN json_extract(response_body, '$.error') END,
        json_extract(response_body, '$.Response.Error.Code'))),
      'meta', json_object('traceId', COALESCE(json_extract(response_body, '$.meta.traceId'), json_extract(response_body, '$.Response.Meta.TraceId'))))
    ELSE '[REDACTED_LEGACY]' END,
  error_message = CASE WHEN error_message IS NULL THEN NULL ELSE '[REDACTED_LEGACY]' END,
  legacy_scrubbed_at = CURRENT_TIMESTAMP
WHERE redaction_version IS NULL AND legacy_scrubbed_at IS NULL;
