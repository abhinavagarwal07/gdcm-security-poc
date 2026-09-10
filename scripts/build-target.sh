#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET=${1:-}
SANITIZER=${2:-}
PROFILE=${3:-debug}

usage() { echo "usage: $0 {vulnerable|master|fixed} {asan|ubsan|none} [debug|release]" >&2; exit 2; }
case "$TARGET" in vulnerable|master|fixed) ;; *) usage ;; esac
case "$SANITIZER" in asan|ubsan|none) ;; *) usage ;; esac
case "$PROFILE" in debug|release) ;; *) usage ;; esac

"$ROOT/scripts/bootstrap.sh" "$TARGET"

SOURCE="$ROOT/_work/source-$TARGET"
STEM="$TARGET-$SANITIZER-$PROFILE"
GDCM_BUILD="$ROOT/_build/$STEM-gdcm"
HARNESS_BUILD="$ROOT/_build/$STEM-harness"
JOBS=${JOBS:-2}

case "$SANITIZER" in
  asan) SAN_FLAG=address ;;
  ubsan) SAN_FLAG=undefined ;;
  none) SAN_FLAG= ;;
esac

# The release profile compiles with -O2 -DNDEBUG so that the reported defects are
# demonstrated with GDCM's gdcm_debug_assert()s elided, matching distribution builds.
if [[ "$PROFILE" == debug ]]; then
  CMAKE_BUILD_TYPE=Debug
  PROFILE_FLAGS="-g"
else
  CMAKE_BUILD_TYPE=RelWithDebInfo
  PROFILE_FLAGS="-O2 -g -DNDEBUG"
fi

if [[ -n "$SAN_FLAG" ]]; then
  SAN_OPT="-fsanitize=$SAN_FLAG"
else
  SAN_OPT=
fi
FLAGS="$SAN_OPT -fno-omit-frame-pointer $PROFILE_FLAGS"

CC=${CC:-clang} CXX=${CXX:-clang++} cmake -S "$SOURCE" -B "$GDCM_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
  -DCMAKE_C_FLAGS="$FLAGS" \
  -DCMAKE_CXX_FLAGS="$FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SAN_OPT" \
  -DCMAKE_SHARED_LINKER_FLAGS="$SAN_OPT" \
  -DGDCM_BUILD_APPLICATIONS=ON \
  -DGDCM_BUILD_SHARED_LIBS=ON \
  -DGDCM_BUILD_TESTING=OFF \
  -DGDCM_BUILD_EXAMPLES=OFF \
  -DGDCM_BUILD_NETWORK=OFF \
  -DGDCM_SUPPORT_BROKEN_IMPLEMENTATION=ON \
  -DGDCM_USE_SYSTEM_OPENJPEG=OFF

cmake --build "$GDCM_BUILD" --parallel "$JOBS"

CC=${CC:-clang} CXX=${CXX:-clang++} cmake -S "$ROOT" -B "$HARNESS_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
  -DCMAKE_CXX_FLAGS="$PROFILE_FLAGS" \
  -DGDCM_DIR="$GDCM_BUILD" \
  -DREPRO_SANITIZER="$SANITIZER"
cmake --build "$HARNESS_BUILD" --parallel "$JOBS"

# Provenance: every run summary embeds this record, so archived evidence is
# self-describing without trusting the surrounding prose.
python3 - "$GDCM_BUILD/build-info.json" <<PY
import json, subprocess, sys, platform
def cmd(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True).stdout.strip().splitlines()[0]
    except Exception:
        return "unknown"
json.dump({
    "target": "$TARGET",
    "sanitizer": "$SANITIZER",
    "profile": "$PROFILE",
    "cmake_build_type": "$CMAKE_BUILD_TYPE",
    "compile_flags": "$FLAGS",
    "revision": cmd("git", "-C", "$SOURCE", "rev-parse", "HEAD"),
    "revision_subject": cmd("git", "-C", "$SOURCE", "log", "-1", "--format=%s"),
    "compiler": cmd("${CXX:-clang++}", "--version"),
    "cmake": cmd("cmake", "--version"),
    "platform": platform.platform(),
    "machine": platform.machine(),
}, open(sys.argv[1], "w"), indent=2)
PY

printf 'built %s (%s)\n' "$STEM" "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["revision"])' "$GDCM_BUILD/build-info.json")"
