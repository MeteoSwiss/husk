#!/usr/bin/env bash
# When a live job does not come back, is that evidence about husk — or no evidence at all?
#
# WHY THIS FILE EXISTS
# --------------------
# Santis, 2026-09-01. `selftest.sh --full` reported `pass=64 fail=2 skip=3 arms=69` against
# Balfrin's 94/0/0/0. Both FAILs read "no job output … (job never ran, or --output not
# honoured) [PENDING|0:0]": two probe jobs were still queued when the 300s wait expired.
# `wait_for_job` fell through on timeout without saying so, the caller read a missing output
# file as a failed cage, and the `return` took 26 downstream arms — the whole FS cage, the
# whole network cage, PID isolation, MUNGE masking — out of the report with them.
#
# The first fix was worse than the bug: it made that case a SKIP, and since SKIP does not
# gate the run, a cluster too busy to schedule husk's probe would have exited 0 having
# measured none of the containment claim. So there are two rules here, and this file exists
# because neither is expressible in the Rust suite (`C2`: the suite pins the predicate, not
# the wiring) and neither can be exercised without a scheduler:
#
#   1. WHOSE FAULT IS IT.  PENDING is the cluster's and must not be a FAIL. RUNNING-and-hung
#      is husk's — a wedged bwrap, a Lustre metadata stall, a relay that never returns — and
#      must not be a SKIP. The first version collapsed them.
#   2. A RUN THAT MEASURED NOTHING IS NOT GREEN.  Unmeasured arms leave no FAIL behind, so
#      the run must carry its own witness (`UNMEASURED`, exit 3) rather than relying on a
#      human to notice `arms=` is 69 instead of 94 — a number whose correct value differs
#      per cluster and so cannot be diffed mechanically.
#
# It extracts the REAL functions from selftest.sh (never a copy — a copy drifts and then
# tests itself, `P8`) and drives them against a stubbed scheduler.
#
# Needs no cluster, no SLURM, no broker, and submits nothing.
set -u
SRC="${SRC:-$(dirname "$0")/selftest.sh}"
pass=0; fail=0
ok(){ pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
no(){ fail=$((fail+1)); printf '  FAIL %s\n     %s\n' "$1" "$2"; }
eq(){ [ "$2" = "$3" ] && ok "$1" || no "$1" "got [$2] want [$3]"; }

RIG="$(mktemp -d)"; trap 'rm -rf "$RIG"' EXIT
mkdir -p "$RIG/bin"

# ---- a scheduler that answers however the case needs -------------------------------
cat > "$RIG/bin/squeue" <<'EOF'
#!/bin/bash
fmt=""; jid=""
while [ $# -gt 0 ]; do case "$1" in -o|--format) fmt="$2"; shift 2;; -j) jid="$2"; shift 2;; *) shift;; esac; done
case "${STUB_MODE:-}" in
  gone)    exit 0 ;;
  pending) T=PENDING; RSN=Resources ; ST=PD ;;
  running) T=RUNNING; RSN=None      ; ST=R  ;;
  compl)   T=COMPLETING; RSN=None   ; ST=CG ;;
  badcon)  T=PENDING; RSN=BadConstraints; ST=PD ;;
  nofmt)   [ -n "$fmt" ] && exit 1; T=PENDING; RSN=Resources; ST=PD ;;
  *) exit 0 ;;
esac
if [ -n "$fmt" ]; then out="${fmt//%T/$T}"; out="${out//%r/$RSN}"; echo "$out"
else echo "$jid debug probe u $ST 0:00 1 ($RSN)"; fi
EOF
cat > "$RIG/bin/sacct" <<'EOF'
#!/bin/bash
case "${STUB_MODE:-}" in pending|badcon|nofmt) echo "PENDING|0:0";; running|compl) echo "RUNNING|0:0";; *) echo "COMPLETED|0:0";; esac
EOF
printf '#!/bin/bash\nexit 0\n' > "$RIG/bin/scancel"
chmod +x "$RIG/bin"/*
export PATH="$RIG/bin:$PATH"

# ---- extract the subject ------------------------------------------------------------
# If a function is renamed or inlined, this yields nothing and every case below fails
# loudly. A harness that cannot find its subject must not report success (`P7`).
sed -n '/^JOB_WAIT_SECONDS=/,/^}/p; /^queue_reason() {/,/^}/p; /^probe_arm_ids() {/,/^}/p' "$SRC" > "$RIG/fns.sh"
for fn in wait_for_job queue_reason probe_arm_ids; do
  grep -q "^$fn() {" "$RIG/fns.sh" || { echo "FATAL: $fn not found in $SRC"; exit 127; }
done
# shellcheck disable=SC1090
source "$RIG/fns.sh"
JOB_WAIT_SECONDS=2   # the real 300s is not a property under test

echo "-- 1. whose fault is it: the three outcomes must stay three --"
w(){ export STUB_MODE="$1"; wait_for_job 42; echo $?; }
eq "a terminal job is measured (rc 0)"                       "$(w gone)"    0
eq "PENDING never started - the cluster's, not husk's (rc 1)" "$(w pending)" 1
eq "RUNNING and hung IS husk's - a wedged cage (rc 2)"        "$(w running)" 2
eq "COMPLETING and stuck is husk's too (rc 2)"                "$(w compl)"   2
eq "PENDING for a reason husk caused is still rc 1"           "$(w badcon)"  1

echo "-- 2. an unreadable state is the LOUD branch, never the quiet one --"
# A SLURM that rejects -o must not make a queued job look terminal: that would restore the
# exact silence this file exists to prevent.
eq "job present but state unreadable -> rc 2, not 0"          "$(w nofmt)"   2

echo "-- 3. the message diagnoses itself --"
export STUB_MODE=badcon
eq "a husk-caused hold names its reason" "$(queue_reason 42)" " [PENDING/BadConstraints]"
export STUB_MODE=pending
eq "a busy cluster names its reason"     "$(queue_reason 42)" " [PENDING/Resources]"
export STUB_MODE=nofmt
eq "no -o support falls back to sacct"   "$(queue_reason 42)" " [PENDING/0:0]"
export STUB_MODE=gone
eq "a job squeue has forgotten still resolves" "$(queue_reason 42)" " [COMPLETED/0:0]"
export STUB_MODE=badcon
( set -u; queue_reason 42 >/dev/null ) && ok "queue_reason returns 0 (its value is a string)" \
  || no "queue_reason returns 0 (its value is a string)" "nonzero rc traps the next caller"

echo "-- 4. the arms a probe would have emitted are read out of the probe, not re-typed --"
# This is what keeps a never-run job from deleting 26 claims from the report silently. It
# is derived from PROBE_BODY (`P8`), so reformatting those RESULT lines breaks it HERE
# rather than on a cluster six weeks from now.
BSTART="$(grep -n "^    PROBE_BODY='#\!/bin/bash" "$SRC" | cut -d: -f1)"
BEND="$(grep -n 'PROBE_BODY="\${PROBE_BODY//__WORKDIR__' "$SRC" | cut -d: -f1)"
if [ -n "$BSTART" ] && [ -n "$BEND" ]; then
  ids="$(probe_arm_ids "$(sed -n "${BSTART},${BEND}p" "$SRC")")"
  n="$(printf '%s\n' "$ids" | grep -c .)"
  [ "$n" -ge 20 ] && ok "PROBE_BODY yields its arm ids (found $n)" \
                  || no "PROBE_BODY yields its arm ids" "found only $n - has the RESULT format changed?"
  for want in fs.users net.allowlist pid.isolated cred.munge; do
    printf '%s\n' "$ids" | grep -q " $want\$" && ok "…including $want" \
      || no "…including $want" "absent; the extraction regex no longer matches the body"
  done
  printf '%s\n' "$ids" | grep -qE '^(containment|functional) ' \
    && ok "…each carrying its tier, so the SKIP lands in the right one" \
    || no "…each carrying its tier" "tier column missing"
else
  no "PROBE_BODY located" "anchors not found in $SRC"
fi

echo "-- 5. the run's own witness: green requires measured --"
# Read from the source rather than executed: reaching this path for real needs a scheduler.
tail30="$(tail -30 "$SRC")"
case "$tail30" in
  *'if [ "$UNMEASURED" -gt 0 ]; then exit 3; fi'*) ok "an unmeasured run exits 3, not 0" ;;
  *) no "an unmeasured run exits 3, not 0" "the exit gate does not consult UNMEASURED" ;;
esac
case "$(grep -c 'UNMEASURED=$((UNMEASURED+1))' "$SRC")" in
  0) no "every not-measured path raises the witness" "no path increments UNMEASURED" ;;
  *) ok "every not-measured path raises the witness ($(grep -c 'UNMEASURED=$((UNMEASURED+1))' "$SRC") sites)" ;;
esac
grep -q 'UNMEASURED:-0' "$SRC" && ok "cleanup keeps the evidence an unmeasured run needs" \
  || no "cleanup keeps the evidence an unmeasured run needs" "cleanup only consults FAIL"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
