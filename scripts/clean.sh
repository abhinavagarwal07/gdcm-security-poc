#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ ! -f "$ROOT/.gdcm-security-poc-root" ]]; then
  echo "refusing cleanup: package marker is missing" >&2
  exit 1
fi

rm -rf -- \
  "$ROOT/_build" \
  "$ROOT/_generated" \
  "$ROOT/_runs" \
  "$ROOT/_work" \
  "$ROOT/generators/__pycache__" \
  "$ROOT/scripts/__pycache__"
echo "removed package-owned generated directories"
