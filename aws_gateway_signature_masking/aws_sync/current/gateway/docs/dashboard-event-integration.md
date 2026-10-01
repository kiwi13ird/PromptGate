# Gateway → Dashboard Event integration

## Scope

The baseline Gateway is `/home/ubuntu/llm-gateway/gateway.py`. The active
`llm-gateway.service` still runs `/home/ubuntu/llm_gateway_addon.py` on port
8080 and is intentionally unchanged.

```text
Client / Extension
  → gateway.py
  → ChatGPT prompt extraction
  → Detection POST /detect
  → decision.action
  → BLOCK / ALLOW / ALLOW_DEGRADED
  → canonical metadata-only Event mapper
  → best-effort Dashboard sender
```

Dashboard delivery never changes the Detection decision or Gateway
enforcement result.

## Detection contract observed by the Gateway

Request fields:

```text
request_id
normalized_text
source.service
source.endpoint
```

Response fields consumed by `detection_client.py`:

```text
blocked, reason, request_id, decided_by
doc_id, doc_span, input_span, score, pii_hits
hash_status, signature_status, total_ms
decision.action, decision.reason_code, decision.user_message, decision.http_status
```

The current timeout remains 0.5 seconds. Connection, HTTP and JSON decode
errors keep the existing provisional fail-open behavior and return
`action=allow_degraded`.

## Client identity

The Gateway reads and strips these internal headers before upstream forwarding:

```text
x-llmsgw-client-id
x-llmsgw-tenant-id
x-llmsgw-extension-version
```

`clientId` uses the client header when present. The explicit fallback is
`unknown-client`; client IP is not redefined as a client ID. `tenantId` is
included when present. Extension version remains internal because canonical v1
does not define a field for it.

## requestId and eventId

- `requestId`: the UUID already created for the intercepted LLM request and
  shared with Detection.
- `eventId`: a separate `evt-<UUID4>` created only when a Dashboard Security
  Event is safely built.

## Mapper behavior

Confirmed mappings:

| Runtime value | Canonical value |
| --- | --- |
| `decision.action=block` | `finalAction=BLOCK` |
| `decision.action=allow` | `finalAction=ALLOW` |
| `allow_degraded` | `finalAction=ALLOW`, `detectionOutcome=UNAVAILABLE`, `degraded=true`, `degradedReason=UNREACHABLE`, `failurePolicy=FAIL_OPEN` |
| ChatGPT service | `targetLlm=ChatGPT` |
| request host/path | `host` / `endpoint` |
| blocked HTTP response | `enforcement.applied=true`, actual `httpStatus` |

`recommendedAction` is omitted. The Detection action is the actual enforcement
instruction, not a separately confirmed recommendation.

Regular ALLOW Events are disabled by default. They can be enabled with
`DASHBOARD_REPORT_ALLOW_EVENTS=true`, but the mapper still does not invent a
`NO_MATCH` outcome.

Signature results currently lack canonical `category` and `ruleId`, so the
Event contains confirmed enforcement metadata but no synthetic Detection item.

## WindowHash safety gate

The current response exposes `decided_by=windowhash`, `score`, `doc_id`,
`input_span`, `doc_span`, `hash_status` and `decision.*`. It does not establish:

- whether score means coverage;
- the score range or threshold;
- span units;
- inclusive/exclusive end semantics;
- detector/ruleset/model version.

Therefore a WindowHash result is not converted to canonical v1. Delivery is
skipped with the metadata-only warning:

```text
Dashboard event skipped: unresolved WindowHash score/span semantics
```

## Sender configuration

```text
DASHBOARD_EVENT_URL=https://.../api/events/ingest
DASHBOARD_INGEST_TOKEN=<secret>
DASHBOARD_EVENT_TIMEOUT=0.3
DASHBOARD_REPORT_ALLOW_EVENTS=false
```

If URL or token is absent, integration is disabled and Gateway enforcement is
unchanged. Delivery performs one synchronous best-effort POST. Errors are
caught internally and logs contain only event ID, request ID, action and error
type. Tokens and Event bodies are never logged.

TODO: Dashboard delivery retry/backoff and queue/async delivery require a team
decision. The short synchronous timeout can still add up to that amount of
Gateway latency.

## Metadata-only boundary

Dashboard Events never include raw prompt, normalized text, request body,
Cookie, Authorization, credentials, PII values, document contents, digests,
MinHash signatures, fingerprints, embeddings or the raw Detection response.

Gateway console logging was also changed to output prompt length and decision
metadata rather than prompt/Event/Detection object contents.

## Candidate non-production run

After setting only the desired test environment variables, the candidate can
be run manually on the currently unused 8081 port:

```bash
cd /home/ubuntu/llm-gateway
.venv/bin/mitmdump --listen-port 8081 --set block_global=false -s gateway.py
```

This command is documentation only. The integration work does not start it or
modify the active 8080 systemd service.

## Remaining decisions

- WindowHash score/span/threshold semantics
- detector/ruleset/model versions
- official production fail-open/fail-closed policy
- NO_MATCH Event storage policy
- production Dashboard URL, TLS and credential rotation
- retry/backoff or queue delivery
- Gemini/Claude Detection
- file-upload blocking
- whether Signature adds category/rule metadata to its response
