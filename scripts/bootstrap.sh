#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../manifest/targets.env
source "$ROOT/manifest/targets.env"

TARGET=${1:-}
case "$TARGET" in
  vulnerable) REV=$VULNERABLE_REV ;;
  master) REV=$MASTER_REV ;;
  fixed)
    REV=${FIXED_REV:-}
    if [[ -z "$REV" ]]; then
      echo "fixed target is unset; populate FIXED_REV after review" >&2
      exit 2
    fi
    ;;
  *)
    echo "usage: $0 {vulnerable|master|fixed}" >&2
    exit 2
    ;;
esac

SOURCE_URL=${GDCM_SOURCE_REPO:-https://github.com/malaterre/GDCM.git}
MIRROR="$ROOT/_work/upstream"
SOURCE="$ROOT/_work/source-$TARGET"
mkdir -p "$ROOT/_work"

if [[ ! -d "$MIRROR/.git" ]]; then
  git clone --no-checkout "$SOURCE_URL" "$MIRROR"
fi

if ! git -C "$MIRROR" cat-file -e "$REV^{commit}" 2>/dev/null; then
  git -C "$MIRROR" fetch --no-tags origin "$REV"
fi

if [[ -e "$SOURCE" ]]; then
  ACTUAL=$(git -C "$SOURCE" rev-parse HEAD)
  if [[ "$ACTUAL" != "$REV" ]]; then
    echo "$SOURCE exists at $ACTUAL, expected $REV; run scripts/clean.sh first" >&2
    exit 1
  fi
else
  git -C "$MIRROR" worktree add --detach "$SOURCE" "$REV"
fi

ACTUAL=$(git -C "$SOURCE" rev-parse HEAD)
[[ "$ACTUAL" == "$REV" ]] || {
  echo "revision verification failed: expected $REV, got $ACTUAL" >&2
  exit 1
}

python3 "$ROOT/scripts/make-controls.py"
printf 'prepared %s at %s\n' "$TARGET" "$ACTUAL"
