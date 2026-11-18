#!/usr/bin/env bash
# Does install-husk.sh's closing summary describe THIS MACHINE, or this RUN?
#
# WHY THIS FILE EXISTS
# --------------------
# `RAB3-B1`. The summary printed
#
#     husk              — INSTALLED BUT NOT RUNNABLE: husk-slurm-wrapper is missing
#
# in the one case where the wrapper IS present: a failed `build-release.sh` over a previous
# install. Twelve lines above, the [error] block had correctly named the path where that
# wrapper still sits and warned that husk would keep brokering with the older binaries. The
# operator reads the closing block, concludes husk is dead, and never looks for the stale
# deploy — a confident wrong remediation invited by a false attribution (`P11`), shipped in
# the commit whose subject was that the transcript must not lie.
#
# The cause was one variable answering the wrong question: `HUSK_SLURM_INSTALLED` means "did
# THIS RUN install it" and the sentence asserted "is one PRESENT". So the fix is not a
# sentence, it is the rule that every line here is a stat, and this file is what keeps it
# one: it extracts the REAL function from install-husk.sh (never a copy — a copy drifts and
# then tests itself, `P8`) and drives it through the machine states.
#
# Needs no cluster, no broker, no $HOME, and installs nothing.
set -u
SRC="${SRC:-$(dirname "$0")/install-husk.sh}"
pass=0; fail=0

# Extract the subject. If the function is renamed or inlined again this yields nothing and
# every case fails loudly, which is the intended answer: a harness that cannot find its
# subject must not report success (`P7`, and it is the same defect as `RAB3-B4` next door).
#
# The `^` anchors are load-bearing for the second subject below: `husk_slurm_seed` has to be
# defined at COLUMN ZERO, i.e. at the top level of the script. That is exactly what `B7-5`
# was — the same two assignments, nested two spaces in, inside the branch that runs only
# when the broker binaries were built. Move them back in there and this extraction returns
# nothing and the run aborts.
extract() { sed -n "/^$1() {/,/^}\$/p" "$SRC"; }

BODY="$(extract husk_layer_summary)"
if [[ -z "$BODY" ]]; then
  echo "FAIL: husk_layer_summary() not found in $SRC — nothing was tested"
  exit 1
fi
# Joined with real newlines: `$(…)$(…)` strips the trailing one and welds `}` to the next
# `name() {`, which bash reports as a syntax error 40 lines from the mistake.
SEEDFNS="$(extract husk_slurm_seed)
$(extract husk_write_config)
$(extract husk_config_in_effect)"
for fn in husk_slurm_seed husk_write_config husk_config_in_effect; do
  [[ -n "$(extract "$fn")" ]] || { echo "FAIL: $fn() not found at top level in $SRC"; exit 1; }
done

# One scenario: run the real function under a controlled machine state and return its text.
# `bwrap` presence is controlled through PATH (the function's only external command), the
# rest through the paths it stats. bash is invoked by ABSOLUTE path because the scenario
# owns PATH.
#
# Empty output is a HARD FAILURE and not a scenario. `check_lacks` on an empty string passes
# — five of these assertions are "must not say X", and every one of them would have reported
# ok against a function that never ran. That is the same defect as `RAB3-B4` and the same
# shape as the bug this file exists for, one level in (`P10`: know what your harness cannot
# see).
BASH_BIN="$(command -v bash)"
summary() { # bwrap_on_path installed prefix apply seccomp
  local bwrap="$1" installed="$2" prefix="$3" apply="$4" seccomp="$5" out
  local pathdir="$TMP/nopath"
  [[ "$bwrap" == yes ]] && pathdir="$TMP/withbwrap"
  out="$(PATH="$pathdir" \
    HUSK_SLURM_INSTALLED="$installed" PREFIX="$prefix" \
    APPLY_SECCOMP_DEST="$apply" SECCOMP_WRAPPER_DEST="$seccomp" \
    "$BASH_BIN" -c "set -uo pipefail; $BODY; husk_layer_summary")"
  if [[ -z "$out" ]]; then
    echo "FATAL: husk_layer_summary produced nothing; every \"must not say\" below would" >&2
    echo "       have passed vacuously. The extraction or the function is broken." >&2
    exit 1
  fi
  printf '%s\n' "$out"
}

check_has() { # description text needle
  if grep -qF -- "$3" <<<"$2"; then
    pass=$((pass+1)); printf '  ok    %s\n' "$1"
  else
    fail=$((fail+1)); printf '  FAIL  %s\n        wanted: %s\n        got:\n%s\n' "$1" "$3" "$2"
  fi
}
check_lacks() { # description text needle
  if grep -qF -- "$3" <<<"$2"; then
    fail=$((fail+1)); printf '  FAIL  %s\n        must NOT say: %s\n        got:\n%s\n' "$1" "$3" "$2"
  else
    pass=$((pass+1)); printf '  ok    %s\n' "$1"
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/nopath" "$TMP/withbwrap"
# A stub bwrap, so "is bwrap on PATH" is a property of the scenario and not of this laptop.
printf '#!/bin/sh\nexit 0\n' > "$TMP/withbwrap/bwrap"; chmod 755 "$TMP/withbwrap/bwrap"

PFX="$TMP/prefix"; mkdir -p "$PFX/bin" "$PFX/lib/husk"
present() { printf '#!/bin/sh\nexit 0\n' > "$1"; chmod 755 "$1"; }
present "$PFX/bin/seccomp-wrapper"
present "$PFX/lib/husk/apply-seccomp"
SECC="$PFX/bin/seccomp-wrapper"; APPL="$PFX/lib/husk/apply-seccomp"

echo "-- 1. this run installed the broker pair: the ordinary success --"
present "$PFX/bin/husk-slurm-wrapper"
t="$(summary yes 1 "$PFX" "$APPL" "$SECC")"
check_has   "says ready"            "$t" "Sandbox ready. Active layers:"
check_has   "brokering announced"   "$t" "+ SLURM job brokering"
check_lacks "does not cry missing"  "$t" "husk-slurm-wrapper is missing"

echo "-- 2. THE BUG: broker build failed, a PREVIOUS install is still deployed --"
# `HUSK_SLURM_INSTALLED=0` (this run installed nothing) but the wrapper IS on disk.
t="$(summary yes 0 "$PFX" "$APPL" "$SECC")"
check_lacks "must not claim the wrapper is missing — it is right there" \
            "$t" "husk-slurm-wrapper is missing"
check_has   "names the state the [error] above warned about" \
            "$t" "STILL RUNNING A PREVIOUS INSTALL"
check_lacks "and the header must not say ready on a run that exits 1" \
            "$t" "Sandbox ready"
check_has   "header agrees with the exit status"  "$t" "Install INCOMPLETE"

echo "-- 3. broker build failed on a FRESH machine: the message that was always right --"
rm -f "$PFX/bin/husk-slurm-wrapper"
t="$(summary yes 0 "$PFX" "$APPL" "$SECC")"
check_has   "still says missing when it IS missing" "$t" "husk-slurm-wrapper is missing"
check_lacks "and does not claim a previous install" "$t" "STILL RUNNING A PREVIOUS INSTALL"

echo "-- 4. the same confusion in the other three lines (the CLASS, not the sentence) --"
t="$(summary no 1 "$PFX" "$APPL" "$SECC")"
check_has   "bwrap absent from PATH is reported, not asserted" "$t" "bwrap             — NOT ON PATH"
t="$(summary yes 1 "$PFX" "$APPL" "$PFX/bin/deleted-by-hand")"
check_has   "a deleted seccomp-wrapper is reported"  "$t" "seccomp-wrapper   — MISSING at"
check_lacks "…and not asserted as an active layer"   "$t" "seccomp-wrapper   — broad syscall deny-list"
t="$(summary yes 1 "$PFX" "" "$SECC")"
check_lacks "apply-seccomp is silent when unsupported-arch left it unset" "$t" "apply-seccomp"

# ── `B7-5`: does a seed flag reach the file it seeds? ─────────────────────────────────────
#
# `./install-husk.sh --slurm-account acctA --slurm-partition partA` on a machine where
# `build-release.sh` had not been run wrote `{"accounts": [], "partitions": []}`, called it
# `[ok]`, and never named either flag. The two resolutions lived inside the
# broker-binaries-exist branch; the seeder that reads them lives outside it.
#
# THE FALSE FRIEND, and it is the whole reason this section is shaped the way it is: a test
# that exports `SLURM_ACCOUNT` and calls the writer PASSES AGAINST THE SHIPPED BUG. The bug
# is that nothing in that scenario ever set `SLURM_ACCOUNT`. So this drives the real
# `husk_slurm_seed` from the variables the ARGUMENT PARSER sets — `*_ARG` — and never sets
# the resolved names itself. It also never runs the broker branch, which is the scenario.
seed() {  # account_arg partition_arg -> the file's content, as the file reports it
  local out="$TMP/cfg-$RANDOM.json" out_text
  out_text="$(SLURM_ACCOUNT_ARG="$1" SLURM_PARTITION_ARG="$2" \
  HUSK_SLURM_ACCOUNT="" HUSK_SLURM_PARTITION="" \
    "$BASH_BIN" -c "set -uo pipefail
                    $SEEDFNS
                    husk_slurm_seed
                    husk_write_config '$out'
                    husk_config_in_effect '$out'
                    stat -c %a '$out'")"
  # Same rule as summary() above, for the same reason: three of the assertions below are
  # "must not say X", and empty output satisfies every one of them (`P10`).
  if [[ -z "$out_text" ]]; then
    echo "FATAL: the extracted seed/write/report functions produced nothing." >&2
    exit 1
  fi
  printf '%s\n' "$out_text"
}

echo "-- 5. B7-5: the seed flags reach the config file with no broker branch in sight --"
t="$(seed acctA partA)"
check_has   "the account the operator passed is IN THE FILE" "$t" "accounts    acctA"
check_has   "and the partition"                              "$t" "partitions  partA"
check_lacks "not the empty file that shipped"                "$t" "accounts    (none)"
check_has   "still 0600"                                     "$t" "600"

echo "-- 6. …and the list form, and the empty form, still behave --"
t="$(seed 'acctA, acctB' 'gpu-part,pp-part')"
check_has   "comma list, whitespace trimmed"                 "$t" "accounts    acctA, acctB"
check_has   "both partitions"                                "$t" "partitions  gpu-part, pp-part"
t="$(seed '' '')"
check_has   "no flags is still an empty set, honestly named" "$t" "accounts    (none)"
check_has   "…and uenvs was never seeded by a flag at all"   "$t" "uenvs       (none)"

echo "-- 7. a value the hand-rolled JSON could not escape --"
# Found by the read-back, not by reading the emitter: the printf version wrote
# {"accounts": ["a"b"]} and husk refuses to start on that.
t="$(seed 'a"b' 'p')"
check_has   "the quote survives into the file as data"      "$t" 'accounts    a"b'
check_lacks "…and the file is not unparseable JSON"          "$t" "(unreadable:"

# ── `G-1`: does the installer's seccomp-wrapper probe DIAGNOSE, or guess? ─────────────────
#
# `d73072c` gave seccomp-wrapper a fatal startup assert: a deny-list name that resolves to
# nothing now refuses to run and names the name. This probe is that assert's ONLY
# operator-facing appearance, and it was
#
#     "$SECCOMP_WRAPPER_DEST" --profile=login /bin/true >/dev/null 2>&1
#
# so the wrapper's diagnosis went to /dev/null and the operator was told the wrapper "does not
# understand --profile" — of a wrapper that understands it perfectly — and then told to run
# `make`, which runs no tests and does not write the file this installer reads. A wrong
# diagnosis plus an impossible remedy is `P11` twice over, and the loop is closed: the operator
# does what they are told, gets the identical binary, and sees the identical error.
#
# THE FALSE FRIEND: asserting the probe "fails on a broken wrapper". It did fail, with exit 1,
# on every scenario below — the exit status was never the defect. The oracle has to be the
# TEXT, and specifically whether the wrapper's OWN words survive into it.
CAPFN="$(extract husk_seccomp_capability_check)"
[[ -n "$CAPFN" ]] || { echo "FAIL: husk_seccomp_capability_check() not found at top level in $SRC"; exit 1; }

stub() {  # <path> <kind>
  case "$2" in
    good)   cat > "$1" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in --*) shift;; *) break;; esac; done
exec "$@"
EOF
            ;;
    old)    cat > "$1" <<'EOF'
#!/bin/sh
case "$1" in --*) echo "seccomp_wrapper: exec '$1' failed" >&2; exit 1;; esac
exec "$@"
EOF
            ;;
    assert) cat > "$1" <<'EOF'
#!/bin/sh
echo "seccomp_wrapper: 1 name(s) in BLOCKED_SYSCALLS are not syscall names this libseccomp knows:" >&2
echo "seccomp_wrapper:     io_uring_setup" >&2
exit 1
EOF
            ;;
    mute)   printf '#!/bin/sh\nexit 3\n' > "$1" ;;
  esac
  chmod 755 "$1"
}

capcheck() {  # <kind> -> "rc=<n>" followed by the transcript. Never empty (`P10`).
  local w="$TMP/stub-wrapper" out rc=0
  stub "$w" "$1"
  out="$("$BASH_BIN" -c "set -uo pipefail; $CAPFN
                         husk_seccomp_capability_check '$w' 'REBUILD-COMMAND-HERE'" 2>&1)" || rc=$?
  printf 'rc=%s\n%s\n' "$rc" "$out"
}

echo "-- 8. G-1: a wrapper that WORKS is accepted quietly --"
t="$(capcheck good)"
check_has   "exit 0"                                     "$t" "rc=0"
check_lacks "and says nothing alarming"                  "$t" "[error]"

echo "-- 9. G-1: a wrapper that predates --profile is still named correctly --"
t="$(capcheck old)"
check_has   "exit 1"                                     "$t" "rc=1"
check_has   "the skew diagnosis survives"                "$t" "does not understand --profile"
check_has   "…and the wrapper's own words are shown now" "$t" "exec '--profile=login' failed"
check_has   "…with a remedy"                             "$t" "REBUILD-COMMAND-HERE"
check_lacks "…and it is not confused with a startup failure" "$t" "refuses to START"

echo "-- 10. G-1 THE BUG: the fatal deny-list assert, diagnosed instead of guessed --"
t="$(capcheck assert)"
check_has   "exit 1"                                     "$t" "rc=1"
check_has   "THE WRAPPER'S OWN DIAGNOSIS, which >/dev/null 2>&1 discarded" \
                                                         "$t" "io_uring_setup"
check_lacks "and NOT the misdiagnosis this replaces"     "$t" "does not understand --profile"
check_has   "named as what it is"                        "$t" "refuses to START"
check_has   "…and why a bare make cannot help: it runs no tests" "$t" "runs no tests"
check_has   "…and writes a name this installer never reads" "$t" 'seccomp-wrapper-$(uname -m)'

echo "-- 11. G-1: a wrapper that fails SILENTLY is not silently misdescribed either --"
t="$(capcheck mute)"
check_has   "exit 1"                                     "$t" "rc=1"
check_has   "the exit status is quoted"                  "$t" "it exited 3"
check_has   "…and the silence is named"                  "$t" "said nothing at all"

echo "-- 12. G-1: the remedy the CALL SITE names must be the one that builds what is read --"
# The message above is generic; the actual command comes from the call site, and that is where
# `make -C .../seccomp-wrapper` used to be. Lexical, because the call site is not a function.
callsite="$(grep -A2 'husk_seccomp_capability_check "\$SECCOMP_WRAPPER_DEST"' "$SRC")"
check_has   "the call site offers build_and_test.sh"     "$callsite" "build_and_test.sh"
check_lacks "…and not the make that rebuilds an unread file" "$callsite" "make -C"

echo "-- 13. the uninstall banner asks for the managed-key list instead of restating it --"
MERGE_PY="$(dirname "$SRC")/scripts/merge-claude-settings.py"
banner="$(sed -n '/Uninstall mode/,/Press Enter/p' "$SRC")"
check_has   "the banner derives the list"                "$banner" "--managed-keys"
check_lacks "…rather than hardcoding the three names"    "$banner" "enableAllProjectMcpServers / sandbox / permissions"
check_has   "…and the merge script answers that question" \
            "$(python3 "$MERGE_PY" --managed-keys)" "enableAllProjectMcpServers / sandbox / permissions"

# ── --prefix: where the install goes, and what may refuse it ──────────────────────────────
# The REAL functions, extracted by name, driven against a throwaway $HOME. Each scenario is a
# machine state (record present or not, an older install at ~/.local or not) and one command
# line. Node-local roots are passed in, because on a Linux test host mktemp lives under /tmp —
# the one directory the production list has to refuse.
PFX_FNS=""
for fn in husk_canon husk_path_within husk_installed_at husk_settings_prefix husk_prefix_others_can_write husk_prefix_validate \
          husk_prefix_choose husk_prefix_for_uninstall husk_write_prefix_record; do
  body="$(extract "$fn")"
  [[ -n "$body" ]] || { echo "FAIL: $fn() not found at top level in $SRC — nothing was tested"; exit 1; }
  PFX_FNS+="$body"$'\n'
done
HELPER="$(cd "$(dirname "$SRC")" && pwd)/slurm-broker/husk-prefix.sh"   # absolute: scenarios cd
[[ -f "$HELPER" ]] || { echo "FAIL: $HELPER not found — nothing was tested"; exit 1; }
check_eq() { # description want got
  if [[ "$3" == "$2" ]]; then pass=$((pass+1)); printf '  ok    %s\n' "$1"
  else fail=$((fail+1)); printf '  FAIL  %s\n        want: %s\n        got:  %s\n' "$1" "$2" "$3"; fi
}
canon() { python3 -c 'import os,sys;print(os.path.realpath(os.path.expanduser(sys.argv[1])))' "$1"; }

# <fn> <home> <tree> <given> <arg> [node-local root...] -> rc=, prefix=, from=, then the transcript
pfx() {
  local fn="$1" home="$2" tree="$3"; shift 3
  HOME="$home" SCRIPT_DIR_EARLY="$tree" "$BASH_BIN" -c '
    set -uo pipefail; . "$1"; eval "$2"; fn="$3"; shift 3
    given="$1" arg="$2"; shift 2
    HUSK_NODE_LOCAL_ROOTS=("$@")
    rc=0; out="$("$fn" "$given" "$arg")" || rc=$?
    printf "rc=%s\nprefix=%s\nfrom=%s\n%s\n" "$rc" "${PREFIX:-}" "${PREFIX_FROM:-}" "$out"
    # husk_prefix_choose sets PREFIX in a subshell above; ask again to READ it.
    [ "$rc" = 0 ] && { "$fn" "$given" "$arg" >/dev/null; printf "PREFIX=%s\nFROM=%s\n" "$PREFIX" "$PREFIX_FROM"; }
  ' _ "$HELPER" "$PFX_FNS" "$fn" "$@"
}
choose()    { pfx husk_prefix_choose "$@"; }
uninstall() { pfx husk_prefix_for_uninstall "$@"; }

H="$TMP/home1"; TREE="$TMP/husk-tree"; mkdir -p "$H" "$TREE" "$TMP/opt" "$TMP/nodelocal"
REC="$H/.husk/install-prefix"
NL="$TMP/nodelocal"

echo "-- 14. --prefix: no flag, no record — the default, spelled as it always was --"
t="$(choose "$H" "$TREE" 0 "" "$NL")"
check_has   "accepted"                                   "$t" "rc=0"
check_has   "PREFIX is the literal \$HOME/.local"        "$t" "PREFIX=$H/.local"
check_has   "…and says it is the default"                "$t" "FROM=the default"

echo "-- 15. --prefix DIR is canonicalised, and ~ is expanded when the shell did not --"
t="$(choose "$H" "$TREE" 1 "$TMP/opt/./a/" "$NL")"
check_has   "canonical absolute path"                    "$t" "PREFIX=$(canon "$TMP/opt/a")"
check_has   "…attributed to the flag"                    "$t" "FROM=--prefix"
t="$(choose "$H" "$TREE" 1 "~/tools/husk" "$NL")"
check_has   "a literal ~ (zsh --prefix=~/x) lands under HOME" "$t" "PREFIX=$(canon "$H/tools/husk")"
t="$(cd "$TMP/opt" && choose "$H" "$TREE" 1 "rel/husk" "$NL")"
check_has   "a relative path is resolved against the cwd" "$t" "PREFIX=$(canon "$TMP/opt/rel/husk")"
t="$(choose "$H" "$TREE" 1 "$H/.local" "$NL")"
check_has   "--prefix ~/.local IS the default, spelled the default way" "$t" "PREFIX=$H/.local"

echo "-- 16. --prefix values husk could install into but not run from are refused --"
for bad in "$TMP/opt/a:b" "$TMP/opt/a b" "$TMP/opt/a*" "$TMP/opt/a[1]" "$TMP/opt/a\$x"; do
  t="$(choose "$H" "$TREE" 1 "$bad" "$NL")"
  check_has "refused: '${bad##*/}'"                      "$t" "rc=1"
  check_has "…naming the characters rule"                "$t" "contains characters husk will not install under"
done
t="$(choose "$H" "$TREE" 1 "$TMP/opt/a"$'\n'"b" "$NL")"
check_has   "refused: an embedded newline"               "$t" "rc=1"
t="$(choose "$H" "$TREE" 1 "$NL/husk" "$NL")"
check_has   "refused: under a node-local root"           "$t" "rc=1"
check_has   "…saying compute nodes cannot see it"        "$t" "local to each node"
t="$(choose "$H" "$TREE" 1 "$NL" "$NL")"
check_has   "refused: the node-local root itself"        "$t" "local to each node"
t="$(choose "$H" "$TREE" 1 "$TREE/install" "$NL")"
check_has   "refused: inside the tree being installed from" "$t" "inside the husk tree"
t="$(choose "$H" "$TREE" 1 "" "$NL")"
check_has   "refused: --prefix with no directory"        "$t" "--prefix needs a directory"
check_has   "…rather than quietly meaning the default"   "$t" "rc=1"
check_has   "the production list names the four node-local roots" \
            "$(grep '^HUSK_NODE_LOCAL_ROOTS=' "$SRC")" "(/tmp /var/tmp /dev/shm /run)"

echo "-- 16b. REVIEW FINDING: a prefix other users can write is WARNED about, not refused --"
H6="$TMP/home6"; mkdir -p "$H6" "$TMP/shared/proj" "$TMP/mine"
chmod 775 "$TMP/shared"; chmod 755 "$TMP/shared/proj" "$TMP/mine"
t="$(choose "$H6" "$TREE" 1 "$TMP/shared/proj/husk" "$NL")"
check_has   "accepted"                                   "$t" "rc=0"
check_has   "…with a warning"                            "$t" "other users can write here"
check_has   "…naming the writable ANCESTOR, not only the prefix" "$t" "$(canon "$TMP/shared")"
t="$(choose "$H6" "$TREE" 1 "$TMP/mine/husk" "$NL")"
check_lacks "a directory only the operator can write is silent" "$t" "other users can write"
chmod 1777 "$TMP/shared"
t="$(choose "$H6" "$TREE" 1 "$TMP/shared/proj/husk" "$NL")"
check_lacks "a sticky world-writable parent cannot have entries replaced" "$t" "other users can write"
chmod 755 "$TMP/shared"

echo "-- 16c. REVIEW FINDING: a following flag is never a flag's value --"
# `--prefix --uninstall` used to eat `--uninstall` as the directory, so the uninstall never
# ran, and `--slurm-partition --gpu-part` would have recorded a partition no cluster has.
# The REAL parse loop, evaluated against argv — not a copy (`P8`) — so the guard cannot
# drift from the flags it guards. Removing the guard is the acceptance criterion (`P9`):
# point SRC at a copy with the `husk_flag_value` calls reverted and this section goes red.
PARSE_SRC="$(sed -n '/^_args=()$/,/^set -- /p' "$SRC")"
[[ -n "$PARSE_SRC" ]] || { echo "FAIL: the argument loop was not found in $SRC"; exit 1; }
[[ -n "$(extract husk_flag_value)" ]] || { echo "FAIL: husk_flag_value() not found in $SRC"; exit 1; }
parse() { "$BASH_BIN" -c 'set -euo pipefail; PREFIX_ARG= PREFIX_ARG_GIVEN=0 SLURM_PARTITION_ARG= SLURM_ACCOUNT_ARG=; '"$PARSE_SRC"'
    printf "prefix=%s|given=%s|part=%s|acct=%s|rest=%s\n" \
      "$PREFIX_ARG" "$PREFIX_ARG_GIVEN" "$SLURM_PARTITION_ARG" "$SLURM_ACCOUNT_ARG" "$*"' _ "$@"; }
t="$(parse --prefix --uninstall)"
check_eq "--prefix does not eat the command that follows it" \
          "prefix=|given=1|part=|acct=|rest=--uninstall" "$t"
t="$(parse --prefix "$TMP/opt/a" --uninstall)"
check_eq "…and a real value still parses, later args intact" \
          "prefix=$TMP/opt/a|given=1|part=|acct=|rest=--uninstall" "$t"
t="$(parse --slurm-partition --uninstall)"
check_eq "--slurm-partition does not eat --uninstall either" \
          "prefix=|given=0|part=|acct=|rest=--uninstall" "$t"
t="$(parse --slurm-partition gpu-part,pp-part --slurm-account proj --uninstall)"
check_eq "…the seed flags keep their real values" \
          "prefix=|given=0|part=gpu-part,pp-part|acct=proj|rest=--uninstall" "$t"
t="$(parse --prefix=-x --uninstall)"
check_eq "the = form still passes a value that begins with -" \
          "prefix=-x|given=1|part=|acct=|rest=--uninstall" "$t"
t="$(parse --prefix)"
check_eq "a missing value is still given-but-empty, refused later" \
          "prefix=|given=1|part=|acct=|rest=" "$t"
t="$(parse --prefix '' --uninstall)"
check_eq "an explicit empty value still lands as given-but-empty" \
          "prefix=|given=1|part=|acct=|rest=--uninstall" "$t"

echo "-- 17. the record makes the prefix a property of the machine --"
HOME="$H" "$BASH_BIN" -c ". '$HELPER'; $(extract husk_write_prefix_record); husk_write_prefix_record '$TMP/opt/a'"
check_eq    "the record holds the prefix, one line"      "$TMP/opt/a" "$(cat "$REC")"
check_eq    "…and no temp file is left beside it"        "install-prefix" "$(ls "$H/.husk")"
t="$(choose "$H" "$TREE" 0 "" "$NL")"
check_has   "an upgrade with no flag reuses the recorded prefix" "$t" "PREFIX=$(canon "$TMP/opt/a")"
check_has   "…and says where it came from"               "$t" "FROM=recorded in $REC"
t="$(choose "$H" "$TREE" 1 "$TMP/opt/a/" "$NL")"
check_has   "the same prefix spelled differently is not a move" "$t" "rc=0"

echo "-- 18. a --prefix that MOVES the install is refused until it is uninstalled --"
t="$(choose "$H" "$TREE" 1 "$TMP/opt/b" "$NL")"
check_has   "refused"                                    "$t" "rc=1"
check_has   "…naming both prefixes"                      "$t" "already installed under $TMP/opt/a"
check_has   "…and the command that unblocks it"          "$t" "--uninstall"
t="$(choose "$H" "$TREE" 1 "$H/.local" "$NL")"
check_has   "moving back to the default is a move too"   "$t" "rc=1"
t="$(choose "$H" "$TREE" 1 "$TMP/opt/b:c" "$NL")"
check_has   "a bad --prefix is reported as BAD before it is reported as a move" \
            "$t" "contains characters"
check_lacks "…so nobody uninstalls to make room for a prefix that would be refused" \
            "$t" "already installed under"

echo "-- 19. an install made before the record existed is found at ~/.local --"
H2="$TMP/home2"; mkdir -p "$H2/.local/lib/husk"
: > "$H2/.local/lib/husk/uninstall-manifest.json"
t="$(choose "$H2" "$TREE" 1 "$TMP/opt/c" "$NL")"
check_has   "a --prefix elsewhere is a move, and refused" "$t" "already installed under $H2/.local"
t="$(choose "$H2" "$TREE" 0 "" "$NL")"
check_has   "…while a plain re-install upgrades it in place" "$t" "PREFIX=$H2/.local"

echo "-- 19b. REVIEW FINDING: a lost record is not a lost install — the policy in force says where --"
# Without this, deleting ~/.husk (or a record that never got written) plus a --prefix elsewhere
# writes a SECOND manifest that records husk's own settings as the operator's.
H5="$TMP/home5"; mkdir -p "$H5/.claude"
printf '{"sandbox": {"seccomp": {"applyPath": "%s/lib/husk/apply-seccomp"}}}\n' "$TMP/opt/e" \
  > "$H5/.claude/settings.json"
t="$(choose "$H5" "$TREE" 1 "$TMP/opt/f" "$NL")"
check_has   "a --prefix elsewhere is refused as a move"  "$t" "already installed under $TMP/opt/e"
t="$(choose "$H5" "$TREE" 0 "" "$NL")"
check_has   "a plain re-install upgrades the witnessed install in place" "$t" "PREFIX=$(canon "$TMP/opt/e")"
check_has   "…and says how it knew"                      "$t" "sandbox.seccomp.applyPath"
t="$(uninstall "$H5" "$TREE" 0 "")"
check_has   "--uninstall finds it the same way"          "$t" "PREFIX=$TMP/opt/e"
printf '{"sandbox": {"seccomp": {"applyPath": "/opt/other/apply-seccomp"}}}\n' > "$H5/.claude/settings.json"
t="$(choose "$H5" "$TREE" 0 "" "$NL")"
check_has   "an applyPath not in husk's layout is not a witness" "$t" "PREFIX=$H5/.local"

echo "-- 20. a record that does not name a directory is a refusal, not a guess --"
H3="$TMP/home3"; mkdir -p "$H3/.husk"; echo "relative/path" > "$H3/.husk/install-prefix"
t="$(choose "$H3" "$TREE" 0 "" "$NL")"
check_has   "install refuses"                            "$t" "rc=1"
check_has   "…naming the file"                           "$t" "$H3/.husk/install-prefix exists but"
t="$(uninstall "$H3" "$TREE" 0 "")"
check_has   "uninstall refuses without --prefix"         "$t" "rc=1"
t="$(uninstall "$H3" "$TREE" 1 "$TMP/opt/a")"
check_has   "…and --prefix is how to name it"            "$t" "PREFIX=$(canon "$TMP/opt/a")"

echo "-- 21. --uninstall FOLLOWS the record --"
t="$(uninstall "$H" "$TREE" 0 "")"
check_has   "the recorded prefix, with no flag"          "$t" "PREFIX=$TMP/opt/a"
t="$(uninstall "$H" "$TREE" 1 "$TMP/opt/b")"
check_has   "a --prefix that disagrees with the record is refused" "$t" "rc=1"
check_has   "…saying which install it would remove"      "$t" "recorded as installed under $TMP/opt/a"
H4="$TMP/home4"; mkdir -p "$H4"
t="$(uninstall "$H4" "$TREE" 0 "")"
check_has   "no record: the default"                     "$t" "PREFIX=$H4/.local"
t="$(uninstall "$H4" "$TREE" 1 "$TMP/opt/d")"
check_has   "no record: --prefix names a lost install"   "$t" "PREFIX=$(canon "$TMP/opt/d")"
banner="$(sed -n '/Uninstall mode/,/^fi$/p' "$SRC")"
check_has   "the record is deleted by the uninstall"     "$banner" 'rm -f "$PREFIX_RECORD"'

echo "-- 22. the launcher runs the seccomp-wrapper INSTALLED BESIDE IT, not PATH's --"
# A decoy earlier on PATH is the old ~/.local install beside a --prefix one. The fake
# husk-slurm-wrapper prints the argv it was handed, which is the object the launcher chose.
LAUNCHER_SRC="$(sed -n "/<<'LAUNCHER'\$/,/^LAUNCHER\$/p" "$SRC" | sed '1d;$d')"
[[ -n "$LAUNCHER_SRC" ]] || { echo "FAIL: the launcher heredoc was not found in $SRC"; exit 1; }
LP="$TMP/lprefix"; mkdir -p "$LP/bin" "$TMP/decoy"
printf '%s\n' "$LAUNCHER_SRC" > "$LP/bin/husk"; chmod 755 "$LP/bin/husk"
printf '#!/bin/sh\nfor a in "$@"; do printf "arg=%%s\\n" "$a"; done\n' > "$LP/bin/husk-slurm-wrapper"
chmod 755 "$LP/bin/husk-slurm-wrapper"
present "$LP/bin/seccomp-wrapper"; present "$TMP/decoy/seccomp-wrapper"; present "$TMP/decoy/claude"
t="$(HOME="$H4" PATH="$TMP/decoy:/usr/bin:/bin" "$LP/bin/husk" --resume 2>&1)"
check_has   "the agent command is the sibling, by absolute path" \
            "$t" "arg=$(canon "$LP/bin")/seccomp-wrapper"
check_lacks "…never the bare name PATH would resolve"   "$t" "arg=seccomp-wrapper"
check_has   "…and the operator's own arguments still arrive" "$t" "arg=--resume"
rm -f "$LP/bin/seccomp-wrapper"
t="$(HOME="$H4" PATH="$TMP/decoy:/usr/bin:/bin" "$LP/bin/husk" 2>&1)"; rc=$?
check_eq    "a missing sibling is a refusal"             1 "$rc"
check_has   "…that says what is missing and where"       "$t" "expected at: $(canon "$LP/bin")/seccomp-wrapper"
check_lacks "…and does not fall back to the decoy"       "$t" "arg="

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
