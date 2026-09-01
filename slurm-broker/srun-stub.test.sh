#!/usr/bin/env bash
# Does the srun stub fail loudly when the step broker is not there?
#
# WHY THIS FILE EXISTS
# --------------------
# The stub has exactly one wait and it is unbounded — correctly, because a step legitimately
# runs for hours. But that single wait used to answer two different questions at once: "has
# anyone picked this up" (seconds) and "has the step finished" (hours). With no way to
# separate them, a broker that was never running looked exactly like a long simulation.
#
# Balfrin, 2026-08-06: an empty `.claude/settings.json` stopped the step broker from starting.
# srun then hung to the walltime in five or six jobs, across four nodes and rank counts
# 2/8/64/128, producing NO output on any channel. The reason was in husk's job log the whole
# time. Cost: one afternoon.
#
# Case 1 is that incident. Case 2 is the half a per-request ack would have missed: a broker
# that dies AFTER picking the request up. Case 3 is the one that must not regress — a broker
# that is alive and working must be waited for indefinitely, because killing a six-hour
# simulation on a wall clock is worse than the bug this fixes.
#
# Runs anywhere with python3; no cluster, no SLURM, no broker binary.
set -u
STUB="${STUB:-$(dirname "$0")/srun-stub.py}"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0

check() { # name expect_rc pattern
  local name="$1" want="$2" pat="$3" rc out
  out=$(cat "$T/out" 2>/dev/null); rc=$(cat "$T/rc" 2>/dev/null)
  # An empty pattern means "rc is the whole assertion" — `grep -q ""` returns 1 on empty
  # input, so testing for it would fail the case that produces no output by design.
  if [ "$rc" = "$want" ] && { [ -z "$pat" ] || printf '%s' "$out" | grep -q "$pat"; }; then
    pass=$((pass+1)); printf '  ok    %-46s rc=%s\n' "$name" "$rc"
  else
    fail=$((fail+1)); printf '  FAIL  %-46s rc=%s (want %s), output:\n' "$name" "${rc:-none}" "$want"
    printf '%s\n' "$out" | sed 's/^/          /'
  fi
}

run_stub() { # spool timeout_secs
  local spool="$1" limit="$2"
  ( HUSK_STEP_SPOOL="$spool" \
    HUSK_HEARTBEAT_FIRST_WAIT=1 HUSK_HEARTBEAT_STALE_AFTER=2 \
    timeout "$limit" python3 "$STUB" -n 1 /bin/true > "$T/out" 2>&1
    echo $? > "$T/rc" )
}

echo "-- 1. the broker never started (the Balfrin case) --"
mkdir -p "$T/s1"; run_stub "$T/s1" 15
check "no broker: fails, does not hang" 1 "step broker is not running"

echo "-- 2. the broker died after picking the request up --"
mkdir -p "$T/s2"; echo "$(( $(date +%s) - 600 ))" > "$T/s2/broker.alive"
run_stub "$T/s2" 15
check "stale heartbeat: fails, does not hang" 1 "stopped responding"

echo "-- 3. a live broker must still be waited for, however long it takes --"
mkdir -p "$T/s3"
( for _ in $(seq 1 40); do date +%s > "$T/s3/broker.alive"; sleep 0.2; done ) &
beater=$!
run_stub "$T/s3" 4          # times out at 4s => still waiting => correct
kill "$beater" 2>/dev/null
check "live broker: keeps waiting (124=timeout)" 124 ""

echo "-- 4. the answer must be the answer to the question this stub asked --"
# Pure function, extracted from the shipped file — no spool, no broker. `version` had four
# writers and one reader (`policy.rs:101`); `id` had none, because both stubs paired request
# to response by the filename THEY constructed. Neither check may be fatal: a response means
# the step has already run, and refusing here would throw away its exit status.
mism=$(python3 - "$STUB" <<'PYM'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
ok = {"version": m.PROTOCOL_VERSION, "id": "req-1", "status": "ok", "exit_code": 0}
print("match:", len(m.response_mismatch(ok, "req-1")))
print("skew:", "protocol version" in (m.response_mismatch(dict(ok, version=99), "req-1") or [""])[0])
print("other:", "names request" in (m.response_mismatch(dict(ok, id="req-2"), "req-1") or [""])[0])
PYM
)
for want in "match: 0" "skew: True" "other: True"; do
  if printf '%s\n' "$mism" | grep -qx "$want"; then
    pass=$((pass+1)); printf '  ok    %-46s %s\n' "response check" "$want"
  else
    fail=$((fail+1)); printf '  FAIL  response check: wanted %s, got:\n%s\n' "$want" "$mism"
  fi
done

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
