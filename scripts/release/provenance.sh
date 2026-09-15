#!/usr/bin/env sh
# Emit a JSON provenance record for the workspace.
#
# Usage: sh scripts/release/provenance.sh [OUT_PATH]
#   Writes to stdout when OUT_PATH is omitted or "-".
#
# Fields: sourceCommit, tree, cargoLockSha256, dirty. Missing git metadata is
# reported as null rather than failing. No credentials are read or printed.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

OUT="${1:-}"

SOURCE_COMMIT=""
TREE=""
DIRTY="null"

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  SOURCE_COMMIT=$(git rev-parse HEAD 2>/dev/null || printf '')
  TREE=$(git rev-parse 'HEAD^{tree}' 2>/dev/null || printf '')
  if [ -n "$(git status --porcelain 2>/dev/null || printf '')" ]; then
    DIRTY="true"
  else
    DIRTY="false"
  fi
fi

CARGO_LOCK_SHA256=""
if [ -f Cargo.lock ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    CARGO_LOCK_SHA256=$(sha256sum Cargo.lock | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    CARGO_LOCK_SHA256=$(shasum -a 256 Cargo.lock | awk '{print $1}')
  fi
fi

json_or_null() {
  if [ -n "$1" ]; then
    printf '"%s"' "$1"
  else
    printf 'null'
  fi
}

emit() {
  printf '{\n'
  printf '  "sourceCommit": %s,\n' "$(json_or_null "$SOURCE_COMMIT")"
  printf '  "tree": %s,\n' "$(json_or_null "$TREE")"
  printf '  "cargoLockSha256": %s,\n' "$(json_or_null "$CARGO_LOCK_SHA256")"
  printf '  "dirty": %s\n' "$DIRTY"
  printf '}\n'
}

if [ -z "$OUT" ] || [ "$OUT" = "-" ]; then
  emit
else
  mkdir -p -- "$(dirname -- "$OUT")"
  emit > "$OUT"
  printf 'provenance.sh: wrote %s\n' "$OUT" >&2
fi
