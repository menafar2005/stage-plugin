-- Re-runnable scrub of external_api_calls rows written before redaction (redaction_version IS NULL).
-- Keeps: service, URL path, method, status, timings, success, error_name, error.code and traceId.
-- Removes: query strings, headers, request/response bodies and error messages (they may hold the client secret,
-- install codes, launchCodes, Runtime/refresh tokens or api keys). Selects and prints no values. Rows written by
-- the current code (redaction_version >= 2) are never touched, so it is safe to run again at any time.
--   npx wrangler d1 execute stage-plugin-db --remote --file scripts/scrub-legacy-api-logs.sql
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
