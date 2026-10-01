# Gateway 8081 non-production test runbook

This runbook tests `/home/ubuntu/llm-gateway/gateway.py` without changing,
restarting, or replacing the operating `llm-gateway.service` on port 8080.
The fake receiver is only a Gateway sender test tool; it is not a Dashboard
backend. Never put a production token in the example file or command history.

## Confirmed runtime configuration

- Gateway form: mitmdump addon (`-s gateway.py`), not a standalone server.
- Detection: `http://10.0.3.168:8000/detect`, hard-coded in `gateway.py`.
- Detection request timeout: 0.5 seconds in the current code.
- Detection failure policy: `allow_degraded` (fail-open).
- Dashboard variables:
  - `DASHBOARD_EVENT_URL`
  - `DASHBOARD_INGEST_TOKEN`
  - `DASHBOARD_EVENT_TIMEOUT` (default 0.3 seconds)
  - `DASHBOARD_REPORT_ALLOW_EVENTS` (default false)

No confirmed Detection health endpoint is encoded in the project, so the
procedure below performs a TCP connection check only and sends no prompt.

## 1. Capture the operating-service state

```bash
systemctl show llm-gateway.service \
  -p ActiveState -p SubState -p MainPID -p ExecStart
systemctl cat llm-gateway.service
ss -lntp | grep -E ':(8080|8081|19100)\b' || true
```

Do not continue on 8081 if it is occupied. Choose another unused port and use
that same port in every later command. Do not stop the owner of the port.

## 2. Run the readiness check

```bash
cd /home/ubuntu/llm-gateway
bash scripts/check-gateway-test-readiness.sh
```

## 3. Start the fake Dashboard receiver (terminal A)

```bash
cd /home/ubuntu/llm-gateway
export FAKE_DASHBOARD_TOKEN='replace-with-a-test-only-token'
export FAKE_DASHBOARD_MODE='success'
bash scripts/start-test-dashboard.sh
```

Modes: `success` returns 201, `error` returns 500, and `delay` waits for
`FAKE_DASHBOARD_DELAY_SECONDS` before returning 201.

## 4. Start the test Gateway (terminal B)

```bash
cd /home/ubuntu/llm-gateway
export DASHBOARD_EVENT_URL='http://127.0.0.1:19100/api/events/ingest'
export DASHBOARD_INGEST_TOKEN='replace-with-the-same-test-only-token'
export DASHBOARD_EVENT_TIMEOUT='0.3'
export DASHBOARD_REPORT_ALLOW_EVENTS='false'
.venv/bin/mitmdump \
  --listen-port 8081 \
  --set block_global=false \
  -s /home/ubuntu/llm-gateway/gateway.py
```

This is foreground-only. Stop it with Ctrl+C after the test. It does not
modify systemd.

## 5. Verify the listener and a harmless proxy path (terminal C)

```bash
ss -lntp | grep -E ':(8080|8081|19100)\b'
curl --fail --show-error --silent \
  --noproxy '' \
  --proxy http://127.0.0.1:8081 \
  http://127.0.0.1:19100/healthz
```

The second command contains no LLM prompt. It only confirms that the 8081
proxy can pass a local health request to the fake receiver.

## 6. Check Detection connectivity without a prompt

```bash
cd /home/ubuntu/llm-gateway
.venv/bin/python - <<'PY'
import socket
with socket.create_connection(("10.0.3.168", 8000), timeout=1.0):
    print("[PASS] Detection TCP reachable: 10.0.3.168:8000")
PY
```

Do not POST to `/detect` merely for a health check.

## 7. Exercise Dashboard delivery without an LLM request

These commands send one synthetic metadata-only event. They test the sender,
not the Detection-to-Gateway BLOCK E2E path.

```bash
cd /home/ubuntu/llm-gateway
.venv/bin/python scripts/dashboard_delivery_smoke.py --expect sent
```

For 500, restart terminal A with `FAKE_DASHBOARD_MODE=error`, keep terminal B
unchanged, then run:

```bash
.venv/bin/python scripts/dashboard_delivery_smoke.py --expect failed
```

For timeout, restart terminal A as follows and use a shorter sender timeout:

```bash
export FAKE_DASHBOARD_MODE='delay'
export FAKE_DASHBOARD_DELAY_SECONDS='1.0'
bash scripts/start-test-dashboard.sh
```

```bash
export DASHBOARD_EVENT_TIMEOUT='0.05'
.venv/bin/python scripts/dashboard_delivery_smoke.py --expect failed
```

Dashboard-disabled behavior needs no receiver:

```bash
env -u DASHBOARD_EVENT_URL -u DASHBOARD_INGEST_TOKEN \
  .venv/bin/python scripts/dashboard_delivery_smoke.py --expect disabled
```

## 8. Review safe output

Allowed fake-receiver log fields are `eventId`, `requestId`, `action`, and
`targetLlm`. The output must not contain raw prompt, `normalized_text`, Cookie,
Authorization, credentials, a full Detection response, or a full LLM request
body. Run the fixture-based tests:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

WindowHash remains a safe skip until its score and span semantics are agreed.
Do not alter the mapper to force an Event.

## 9. Stop tests and verify the operating service

Press Ctrl+C in terminal B, then terminal A. Do not use kill, sudo changes, or
systemd commands. Verify the original service again:

```bash
systemctl show llm-gateway.service \
  -p ActiveState -p SubState -p MainPID -p ExecStart
systemctl cat llm-gateway.service
ss -lntp | grep -E ':(8080|8081|19100)\b' || true
```

Expected final state: only the original port 8080 Gateway remains, its MainPID
is unchanged, and the unit's ExecStart is unchanged.
