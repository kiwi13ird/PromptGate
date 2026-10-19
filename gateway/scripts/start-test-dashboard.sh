#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${FAKE_DASHBOARD_PORT:-19100}"
MODE="${FAKE_DASHBOARD_MODE:-success}"
DELAY_SECONDS="${FAKE_DASHBOARD_DELAY_SECONDS:-1.0}"
PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"

if [[ -z "${FAKE_DASHBOARD_TOKEN:-}" ]]; then
  echo "[BLOCKED] FAKE_DASHBOARD_TOKEN is required (use a test-only value)."
  exit 2
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "[BLOCKED] Python not found: ${PYTHON_BIN}"
  exit 2
fi

if ss -lnt "sport = :${PORT}" | tail -n +2 | grep -q .; then
  echo "[BLOCKED] Port ${PORT} is already in use. No process was stopped."
  exit 2
fi

cd "${PROJECT_ROOT}"
exec "${PYTHON_BIN}" tests/fake_dashboard_receiver.py \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --mode "${MODE}" \
  --delay-seconds "${DELAY_SECONDS}"
