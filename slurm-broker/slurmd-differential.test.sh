#!/usr/bin/env bash
# Exercise `slurmd-differential.sh` and its grader END TO END, offline, with no cluster.
#
# What this can establish: the harness parses its own corpus, submits the right invocations,
# scans one directory per case, writes an artefact the grader accepts, refuses to run in a
# husk session, refuses a corpus larger than `--max-jobs`, and reaches every one of its own
# "I measured nothing" states. What it cannot establish: anything at all about slurmd. The
# `sbatch` on PATH here is `slurmd-differential-fixture/sbatch`, whose substitution model is
# a COPY of what the operator measured by hand, so it agrees with those measurements by
# construction.
#
#   ./slurmd-differential.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export PATH="$HERE/slurmd-differential-fixture:$PATH"
export HUSKDIFF_FIXTURE_STATE="$WORK/state"
export USER="${USER:-tester}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected ${3@Q}, got ${2@Q}"; fi; }

echo "== slurmd-differential.sh, offline =="

# ── syntax ──────────────────────────────────────────────────────────────────────────────
for f in "$HERE/slurmd-differential.sh" "$HERE/slurmd-differential-fixture/sbatch"; do
  if bash -n "$f"; then ok "bash -n $(basename "$f")"; else bad "bash -n $(basename "$f")"; fi
done

# ── it refuses to run inside a husk session ─────────────────────────────────────────────
# `query-parity-probe.sh` reported `all 147 allowed query options exist here` against husk's
# stub. This is the check that stops the same thing happening here, and it is checked rather
# than trusted.
out=$(HUSK_SLURM_SPOOL=/tmp/whatever "$HERE/slurmd-differential.sh" \
        --account a --partition p --base "$WORK/x" 2>&1); rc=$?
check "refuses inside a husk session (exit 2)" "$rc" 2
case "$out" in *"husk session detected"*) ok "…and says which variable gave it away" ;;
               *) bad "…and says which variable gave it away" "$out" ;; esac

# ── --partition is required; --account is NOT ───────────────────────────────────────────
# This test asserted the opposite until 2026-09-01, pinning a precondition whose stated reason
# ("Santis/Balfrin both require one") was false of Balfrin: ~/.husk/config.json ships
# `accounts: []` and every job in that day's bring-up submitted without one. A site that DOES
# require an account refuses every submission, and that is caught by the getopt canary — which
# is where "everything was refused" belongs (`B8-1`), rather than by a precondition asserting a
# fact about two named clusters. The contract is now: run without one, say so, let the canary
# stop the run if the site disagrees.
out=$("$HERE/slurmd-differential.sh" --partition p --base "$WORK/x" --dry-run 2>&1); rc=$?
check "accepts no --account (does not refuse)" "$([ "$rc" = 2 ] && echo 2 || echo 0)" 0
case "$out" in *"no --account given"*) ok "…and says it is submitting without one" ;;
               *) bad "…and says it is submitting without one" "$out" ;; esac
out=$("$HERE/slurmd-differential.sh" --account a --base "$WORK/x" 2>&1); rc=$?
check "refuses with no --partition (exit 2)" "$rc" 2

# ── it refuses rather than truncating a corpus over --max-jobs ──────────────────────────
out=$("$HERE/slurmd-differential.sh" --account a --partition p --base "$WORK/x" --max-jobs 3 2>&1); rc=$?
check "refuses a corpus over --max-jobs (exit 2)" "$rc" 2
case "$out" in *"REFUSING rather than truncating"*) ok "…and says why truncating would be worse" ;;
               *) bad "…and says why truncating would be worse" "$out" ;; esac

# ── dry run ─────────────────────────────────────────────────────────────────────────────
out=$("$HERE/slurmd-differential.sh" --account acct01 --partition debug \
        --base "$WORK/dry" --out "$WORK/dry.artefact" --dry-run 2>&1); rc=$?
check "dry run exits 0" "$rc" 0
if grep -q $'^END\tdry-run$' "$WORK/dry.artefact"; then
  ok "dry run marks its artefact as measuring nothing"
else
  bad "dry run marks its artefact as measuring nothing" "$(tail -1 "$WORK/dry.artefact")"
fi
n=$(grep -c $'^ARGV\t' "$WORK/dry.artefact")
if [ "$n" -gt 100 ]; then ok "dry run still records every invocation ($n argv lines)";
else bad "dry run still records every invocation" "only $n"; fi

# ── the real thing, against the fixture ─────────────────────────────────────────────────
run_model() {
  local model="$1" base="$WORK/$1"
  HUSKDIFF_FIXTURE_MODEL="$model" HUSKDIFF_FIXTURE_STATE="$base/state" \
    "$HERE/slurmd-differential.sh" --account acct01 --partition debug \
      --base "$base" --out "$base.artefact" >"$base.log" 2>&1
  echo $?
}
mkdir -p "$WORK/measured" "$WORK/stepid"
rc=$(run_model measured)
check "a full fixture run exits 0" "$rc" 0
for want in 'HUSKDIFF	1' 'CONTROL	literal_control_file	PASS' 'END	ok'; do
  if grep -qF "$want" "$WORK/measured.artefact"; then ok "artefact carries ${want//	/ }";
  else bad "artefact carries ${want//	/ }"; fi
done
# The `RA-2` shape, present in the artefact as a plain recorded filename.
if grep -qE $'^FILE\tj03-o\tprobe-A[0-9]+-a4294967294-sbatch\\.log' "$WORK/measured.artefact"; then
  ok "the %A case recorded the name slurmd opened"
else
  bad "the %A case recorded the name slurmd opened" "$(grep -P '^FILE\tj03-o' "$WORK/measured.artefact")"
fi
# An artefact must never claim a case it did not scan.
cases=$(grep -c $'^CASE\t' "$WORK/measured.artefact")
files=$(grep -c $'^FILES\t' "$WORK/measured.artefact")
check "every CASE has a FILES summary" "$cases" "$files"

# ── the cluster script cleans up after itself ───────────────────────────────────────────
left=$(find "$WORK/measured" -maxdepth 1 -name 'slurmd-diff-*' -print 2>/dev/null | wc -l)
check "the working tree is removed (artefact is not)" "$left" 0
if [ -s "$WORK/measured.artefact" ]; then ok "…and the artefact survives"; else bad "…and the artefact survives"; fi

# ── the instrument can report NOT MEASURED ──────────────────────────────────────────────
# An sbatch that refuses everything the way a wrong account does. `B8-1` is this exact state
# reported as "husk and Slurm agree on every spelling probed".
mkdir -p "$WORK/refuser"
cat > "$WORK/refuser/sbatch" <<'REFUSER'
#!/bin/sh
case "$1" in
  --version) echo "slurm 23.02.7"; exit 0 ;;
esac
for a in "$@"; do
  case "$a" in --husk-differential-canary) echo "sbatch: unrecognized option '$a'" >&2; exit 1 ;; esac
done
echo "sbatch: error: Batch job submission failed: Invalid account or account/partition combination specified" >&2
exit 1
REFUSER
cat > "$WORK/refuser/squeue" <<'Q'
#!/bin/sh
exit 0
Q
chmod +x "$WORK/refuser/sbatch" "$WORK/refuser/squeue"
out=$(PATH="$WORK/refuser:$PATH" "$HERE/slurmd-differential.sh" --account bad --partition bad \
        --base "$WORK/ref" --out "$WORK/ref.artefact" 2>&1); rc=$?
check "an sbatch that refuses everything gives exit 3, not 0" "$rc" 3
case "$out" in *"NOT MEASURED"*) ok "…and says NOT MEASURED in those words" ;;
               *) bad "…and says NOT MEASURED in those words" "$out" ;; esac
if grep -q $'^JOB\tj00\t-\tREFUSED' "$WORK/ref.artefact"; then
  ok "…and each refusal is recorded as data, not skipped"
else
  bad "…and each refusal is recorded as data, not skipped" "$(grep -P '^JOB' "$WORK/ref.artefact" | head -2)"
fi

# ── a stub that is not an option parser is caught ───────────────────────────────────────
# `B8-2`: six executables reproducing husk's stub verified 147 options against nothing.
mkdir -p "$WORK/stub"
cat > "$WORK/stub/sbatch" <<'STUB'
#!/bin/sh
echo "sbatch-stub.py: error: HUSK_SLURM_SPOOL is not set, so there is no broker to talk to." >&2
exit 1
STUB
cat > "$WORK/stub/squeue" <<'Q'
#!/bin/sh
exit 0
Q
chmod +x "$WORK/stub/sbatch" "$WORK/stub/squeue"
out=$(PATH="$WORK/stub:$PATH" "$HERE/slurmd-differential.sh" --account a --partition p \
        --base "$WORK/stub-run" --out "$WORK/stub.artefact" 2>&1); rc=$?
check "husk's stub on PATH gives exit 3, not 0" "$rc" 3
if grep -q $'^CONTROL\tsbatch_getopt_canary\tFAIL' "$WORK/stub.artefact"; then
  ok "…and the artefact records the canary failure for the grader to re-decide"
else
  bad "…and the artefact records the canary failure" "$(grep -P '^CONTROL' "$WORK/stub.artefact")"
fi

# ── the grader, on the artefacts this run just produced ─────────────────────────────────
if command -v cargo >/dev/null 2>&1; then
  echo
  echo "== the grader, on the artefact this run just produced =="
  # A fresh artefact, not the committed fixture: this is the link between the two halves.
  if HUSK_DIFFERENTIAL_ARTEFACT="$WORK/measured.artefact" \
     cargo test --offline --manifest-path "$HERE/broker/Cargo.toml" \
       slurmd_differential -- --nocapture >"$WORK/grade.log" 2>&1; then
    ok "cargo test slurmd_differential passes on a freshly produced artefact"
  else
    bad "cargo test slurmd_differential on a freshly produced artefact" "see $WORK/grade.log"
    tail -30 "$WORK/grade.log"
  fi
  # …and it must REFUSE the one that measured nothing.
  if HUSK_DIFFERENTIAL_ARTEFACT="$WORK/stub.artefact" \
     cargo test --offline --manifest-path "$HERE/broker/Cargo.toml" \
       slurmd_differential::tests::a_named_artefact >"$WORK/grade-stub.log" 2>&1; then
    bad "the grader must REFUSE an artefact whose canary failed" "it passed"
  else
    ok "the grader refuses an artefact whose canary failed"
  fi
else
  echo "  SKIP  cargo is not on PATH, so the grader half was not exercised"
  FAIL=$((FAIL + 1))
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: $PASS checks passed."
  echo "        This exercised the HARNESS. The sbatch it ran against is a fixture whose"
  echo "        substitution model is a copy of measurements taken by hand, so none of it is"
  echo "        evidence about any cluster."
  exit 0
fi
echo "RESULT: $FAIL of $((PASS + FAIL)) checks failed."
exit 1
