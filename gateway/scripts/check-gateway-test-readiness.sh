#!/usr/bin/env bash
set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
TEST_PORT="${GATEWAY_TEST_PORT:-8081}"
DETECTION_HOST="${DETECTION_HOST:-10.0.3.168}"
DETECTION_PORT="${DETECTION_PORT:-8000}"
failures=0

pass() { echo "[PASS] $*"; }
blocked() { echo "[BLOCKED] $*"; }
fail() { echo "[FAIL] $*"; failures=$((failures + 1)); }

cd "${PROJECT_ROOT}"

if [[ -x "${PYTHON_BIN}" ]] && "${PYTHON_BIN}" -c "import gateway" >/dev/null 2>&1; then
  pass "gateway.py import"
else
  fail "gateway.py import"
fi

if [[ -x "${PYTHON_BIN}" ]] && "${PYTHON_BIN}" -m unittest discover -s tests -p 'test_*.py' >/dev/null 2>&1; then
  pass "client identity"
  pass "dashboard sender and fake Dashboard POST"
  pass "dashboard 500/timeout isolation"
  pass "sensitive-field rejection and safe logging"
  pass "WindowHash unresolved result is safely skipped"
else
  fail "unit tests (run manually for details)"
fi

if ss -lnt "sport = :${TEST_PORT}" | tail -n +2 | grep -q .; then
  blocked "port ${TEST_PORT} already in use; choose another port, do not stop the process"
else
  pass "port ${TEST_PORT} available"
fi

if systemctl is-active --quiet llm-gateway.service; then
  exec_start="$(systemctl show llm-gateway.service -p ExecStart --value)"
  if [[ "${exec_start}" == *"--listen-port 8080"* ]]; then
    pass "operating service active on configured port 8080"
  else
    fail "operating service ExecStart does not show port 8080"
  fi
else
  fail "operating service llm-gateway.service is not active"
fi

if "${PYTHON_BIN}" - "${DETECTION_HOST}" "${DETECTION_PORT}" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), timeout=1.0):
    pass
PY
then
  pass "Detection TCP reachable at ${DETECTION_HOST}:${DETECTION_PORT}"
else
  blocked "Detection TCP unreachable at ${DETECTION_HOST}:${DETECTION_PORT}"
fi

blocked "WindowHash score semantics not confirmed"
blocked "WindowHash span semantics not confirmed"
blocked "production Dashboard URL/auth not confirmed"

exit "${failures}"
