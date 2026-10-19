#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd -- "$PROJECT_DIR/.." && pwd -P)"
source "$PROJECT_DIR/gateway/install_helpers.sh"

TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT

SOURCE="$TEST_DIR/llm_gateway_addon.py"
DESTINATION="$TEST_DIR/different.py"
SYMLINK="$TEST_DIR/same-through-symlink.py"

touch "$SOURCE" "$DESTINATION"
ln -s "$SOURCE" "$SYMLINK"

same_real_path "$SOURCE" "$SOURCE"
same_real_path "$SOURCE" "$SYMLINK"
if same_real_path "$SOURCE" "$DESTINATION"; then
  echo "different paths were incorrectly treated as the same file" >&2
  exit 1
fi

echo "PASS: gateway installer real-path comparison"
