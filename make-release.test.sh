#!/usr/bin/env bash
# Does make-release.sh's freshness gate MEASURE anything before it prints [ok]?
#
# WHY THIS FILE EXISTS
# --------------------
# `RB2-1` found the gate reporting success against a search root that did not exist: find
# complained to stderr, stderr went to /dev/null, the empty result read as "no source is
# newer". The fix checked that the roots EXIST. `RAB3-B4` then found the fix one level above
# its own last sentence — "a gate that measures nothing must not print [ok]" — because a root
# can exist and hold no file the `-name` allowlist recognises. Driven at HEAD:
#
#     root MISSING                        -> rc=1  (the fix works)
#     root EXISTS, holds no matching file -> rc=0  (the gate passed having measured nothing)
#
# The same defect, in the same function, in the diff that fixed it. This file pins the
# CONTRACT (something was measured) rather than the mechanism (the roots exist), because the
# mechanism is what drifted.
#
# The real function is extracted from make-release.sh, never copied: a copy passes while the
# original rots (`P8`). Needs no tag, no build, no network.
set -u
SRC="${SRC:-$(dirname "$0")/make-release.sh}"
pass=0; fail=0

BODY="$(sed -n '/^require_not_older_than_sources() {$/,/^}$/p' "$SRC")"
if [[ -z "$BODY" ]]; then
  echo "FAIL: require_not_older_than_sources() not found in $SRC — nothing was tested"
  exit 1
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

gate() { # binary roots...
  bash -c '
    set -uo pipefail
    fail() { echo "error: $*" >&2; exit 1; }
    '"$BODY"'
    require_not_older_than_sources "$@"
  ' _ "$@" 2>&1
}
run() { # description want_rc binary roots...
  local desc="$1" want="$2"; shift 2
  local out rc
  out="$(gate "$@")"; rc=$?
  if [[ "$rc" == "$want" ]]; then
    pass=$((pass+1)); printf '  ok    %-52s rc=%s\n' "$desc" "$rc"
  else
    fail=$((fail+1)); printf '  FAIL  %-52s rc=%s want=%s\n        %s\n' "$desc" "$rc" "$want" "$out"
  fi
}

# Ordered in time on purpose: `find -newer` is strictly-newer and mtimes here have
# sub-second resolution, so "the source is older than the binary" has to be MADE true.
mkdir -p "$TMP/src-ok" "$TMP/src-empty" "$TMP/src-empty2" "$TMP/src-newer"
: > "$TMP/src-ok/lib.rs"                       # (1) source
touch "$TMP/src-empty/notes.md"                # exists, holds nothing the gate calls source
touch "$TMP/src-empty2/README"
sleep 1
BIN="$TMP/husk-slurm-broker-x86_64"; : > "$BIN"; chmod 755 "$BIN"   # (2) built after it
sleep 1
: > "$TMP/src-newer/lib.rs"                    # (3) edited after the build

echo "-- the two cases that already worked, so the fix cannot be a regression --"
run "a root that does not exist is refused"          1 "$BIN" "$TMP/src-ok" "$TMP/nope"
run "a source newer than the binary is refused"      1 "$BIN" "$TMP/src-newer"

echo "-- RAB3-B4: a root that exists but holds no source must not report [ok] --"
run "root present, zero matching files"              1 "$BIN" "$TMP/src-empty"
run "two roots that exist and hold no source between them" 1 "$BIN" "$TMP/src-empty" "$TMP/src-empty2"

echo "-- and the gate must still PASS a real tree, or the fix is an operator DoS --"
run "a root with source, none newer"                 0 "$BIN" "$TMP/src-ok"
run "the real repo roots make-release.sh passes"     0 "$BIN" \
    "$(dirname "$0")/slurm-broker/broker/src" "$(dirname "$0")/seccomp-wrapper/src"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
