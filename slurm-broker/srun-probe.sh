#!/bin/bash
# srun-probe.sh — first bring-up job for the husk STEP pair (Chapter 1).
#
# Submit it the way the agent would, through the broker's stub:
#   sbatch --partition=<site> srun-probe.sh
#
# What it exercises, which hello.sh does not: the job calls `srun`. Inside the cage
# that is not the real srun but husk's stub, bound over it by the job guard. The stub
# writes a request to the step-spool; the step-broker — running OUTSIDE the cage but
# inside this allocation, so it still holds MUNGE and a route to the daemons — validates
# it against the step allowlist, wraps the command in the rank cage, and runs the real
# srun. Every rank slurmstepd launches is therefore itself sandboxed.
#
# No #SBATCH --partition (site-specific, and the broker forces it) and no #SBATCH
# --nodes (the cage profile forces --nodes=1; asking for more is rejected by design).
#
#SBATCH --ntasks=2
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-srun-probe
set -u

echo "job  : running on $(hostname)"
echo "spool: ${HUSK_STEP_SPOOL:-<UNSET — the guard did not bootstrap the step pair>}"
echo "srun : $(command -v srun || echo '<not on PATH>')"
echo "--- step checks ---"

# 1) The plain case: one rank, one command. This is the whole of Chapter 1 working.
if out=$(srun -n1 hostname 2>&1); then
  echo "step : OK — srun -n1 hostname -> $out"
else
  rc=$?
  echo "step : FAILED (rc=$rc)"
  echo "       $out"
  echo "       If this says 'no step spool configured', the stub is bound but the guard"
  echo "       did not export HUSK_STEP_SPOOL. If it says the step was rejected, the"
  echo "       message is from the step allowlist and says which option to drop."
  echo "       Otherwise see this job's husk log: ${HUSK_JOB_LOG:-~/.husk/log/job-<jobid>.log}"
fi

# 2) The step must be CAGED too, not merely launched. A rank that can read other
# users' homes would mean the per-task wrapper is not being applied.
if out=$(srun -n1 sh -c 'ls -A /users 2>/dev/null | wc -l' 2>&1); then
  if [ "${out##*$'\n'}" -gt 2 ] 2>/dev/null; then
    echo "cage : /users shows $out entries INSIDE the step — rank NOT sandboxed!"
  else
    echo "cage : homes hidden inside the step (/users has $out entries) [expect]"
  fi
else
  echo "cage : could not run the containment check inside a step ($out)"
fi

# 2b) Ranks must share ONE pid namespace: they can see each other (which is what Cross
# Memory Attach needs, and what MPI needs) and nothing else on the node. Per-rank
# `--unshare-pid` would give each its own namespace, unable to name its peers — the
# sibling-user-namespace failure that killed ICON, one layer down. So this checks BOTH
# halves: the node is hidden, and a peer is not.
if out=$(srun -n2 sh -c 'ls /proc | grep -c "^[0-9]"' 2>&1); then
  hi=$(printf '%s\n' "$out" | sort -n | tail -1)
  if [ "${hi:-999}" -gt 50 ] 2>/dev/null; then
    echo "pidns: a rank sees $hi processes — it is in the HOST pid namespace, not the job's"
  else
    echo "pidns: ranks see only their own namespace (max $hi pids) [expect]"
  fi
else
  echo "pidns: could not count processes inside a step ($out)"
fi
# The other half: two tasks of ONE step must see each other, or MPI has no peers to attach
# to. Each task holds a MARKER process alive and counts how many markers it can see.
#
# The marker has to outlive the count, which the first version got wrong: it ran `sleep 1`
# in the FOREGROUND and then counted processes named sleep — by which time its own sleep had
# exited and there was nothing to find. Both tasks counted 0 and the arm reported "ranks are
# in SEPARATE pid namespaces, MPI cannot attach" on a Balfrin run where cma.peers had just
# proved the opposite (2026-08-01). A probe that measures the wrong instant is worse than no
# probe: it accuses the system of the failure it was written to detect.
#
# So: background a marker, wait long enough for BOTH tasks to have started theirs, count,
# then kill it. One task alone counts 1 (its own); two sharing a namespace count 2.
PEER_SCRIPT='sleep 8 & m=$!
sleep 2
n=0; for p in /proc/[0-9]*; do case $(cat $p/comm 2>/dev/null) in sleep) n=$((n+1));; esac; done
echo $n
kill $m 2>/dev/null'
if out=$(srun -n2 sh -c "$PEER_SCRIPT" 2>&1); then
  lo=$(printf '%s\n' "$out" | grep -E '^[0-9]+$' | sort -n | head -1)
  if [ "${lo:-x}" = x ]; then
    echo "pidns: peer check inconclusive - no count came back: $(printf '%s' "$out" | tr '\n' ' ' | head -c 100)"
  elif [ "$lo" -ge 2 ]; then
    echo "pidns: ranks can see each other ($lo markers) — CMA has someone to attach to [expect]"
  elif [ "$lo" -eq 1 ]; then
    echo "pidns: peers invisible - each rank saw only its own marker, so ranks are in SEPARATE pid namespaces and MPI will fail"
  else
    # Zero means not even our OWN marker was there, so the probe measured the wrong instant.
    # That is a fault in this script, not in husk, and must not be reported as a breach.
    echo "pidns: peer check inconclusive - a rank could not see even its own marker (probe timing)"
  fi
else
  echo "pidns: could not run the peer-visibility check ($out)"
fi

# 2c) EGRESS INSIDE A RANK. The job cage and a rank cage are separate bwrap namespaces and
# bwrap mounts do NOT propagate, so a rank cannot inherit the job cage socat: it must bind
# its own. That was wrong until 2026-08-02 — ranks were handed a path to the job cage
# placeholder, which is an EMPTY file in a rank namespace, so every rank ran with no egress
# and said nothing about it. net.live never caught it because it tests the JOB cage.
# Three observations, cheapest first, so a failure says WHICH half broke.
# NO APOSTROPHES BELOW - single-quoted probe body.
if [ -z "${HUSK_NET_SOCK:-}" ]; then
  echo "rnet : no egress configured for this job - skipped (set sandbox.network.allowedDomains to exercise it)"
else
  RANK_NET='s=$([ -x /tmp/husk-socat ] && echo yes || echo no)
p=${HTTP_PROXY:-unset}
r=$(timeout 3 bash -c ": < /dev/tcp/127.0.0.1/3128" 2>/dev/null && echo up || echo down)
echo "socat=$s proxy=$p relay=$r"'
  if out=$(srun -n1 bash -c "$RANK_NET" 2>&1 | tail -1); then
    case "$out" in
      *"socat=yes"*"relay=up"*)
        echo "rnet : a rank has socat and its relay is listening [$out] [expect]" ;;
      *"socat=no"*)
        echo "rnet : a rank has NO socat in its cage [$out] - the rank never binds one, so it has no egress" ;;
      *"relay=down"*)
        echo "rnet : a rank has socat but nothing is listening on 127.0.0.1:3128 [$out] - the relay did not start" ;;
      *)
        echo "rnet : unexpected answer from the rank [$out]" ;;
    esac
  else
    echo "rnet : could not run the rank egress check ($out)"
  fi
fi

# 3) An option that runs code outside the per-task wrap must be REFUSED, with a
# reason. This is the step allowlist doing its job; a silent success here would
# mean a job can escape the rank cage.
# Check the MESSAGE, not just the exit status. The real srun ACCEPTS --task-prolog and
# then fails because the prolog does not exist — a status-only check reports "refused"
# for that too, so it would pass with no husk in the path at all. (Balfrin 2026-07-30:
# an uncaged control run printed [expect] here, which is what caught it.) Husk's
# rejection is identifiable: the step allowlist says "not permitted here".
if deny_out=$(srun --task-prolog=/tmp/nope -n1 true 2>&1); then
  echo "deny : --task-prolog ACCEPTED — the step allowlist is not being applied!"
elif printf '%s' "$deny_out" | grep -q "not permitted here"; then
  echo "deny : --task-prolog refused by the step allowlist [expect]"
else
  echo "deny : --task-prolog failed, but NOT via husk — so this is the real srun and the"
  echo "       stub is not bound. First line: $(printf '%s' "$deny_out" | head -1)"
fi

# 3b) MULTI-RANK IN ONE STEP — the actual MPI shape, as opposed to several separate
# steps. slurmstepd launches N tasks, each of which must land inside its own rank cage.
if multi=$(srun -n2 hostname 2>&1); then
  n=$(printf '%s\n' "$multi" | grep -c .)
  if [ "$n" -eq 2 ]; then
    echo "rank2: OK — 2 ranks in ONE step, both launched ($(printf '%s' "$multi" | tr '\n' ' '))"
  else
    echo "rank2: got $n line(s) from srun -n2, expected 2: $(printf '%s' "$multi" | tr '\n' ' ')"
  fi
else
  echo "rank2: FAILED — srun -n2 did not run: $(printf '%s' "$multi" | head -2 | tr '\n' ' ')"
fi

# 3c) ...and those ranks must SHARE memory. This is the one thing the rank cage does
# specially: a per-task `--tmpfs /dev/shm` would give every rank its own empty shared
# memory namespace, which HANGS same-node MPI (probe runs 8-9, with and without the
# netns). So rank 0 writes into /dev/shm and rank 1 must be able to read it.
SHM_SCRIPT='f=/dev/shm/husk-shm-probe-$SLURM_JOB_ID
if [ "${SLURM_PROCID:-0}" = 0 ]; then echo SHARED > "$f"; sleep 3
else sleep 1; cat "$f" 2>&1 || echo MISSING; fi'
if shm=$(srun -n2 sh -c "$SHM_SCRIPT" 2>&1); then
  if printf '%s' "$shm" | grep -q SHARED; then
    echo "shm  : OK — rank 1 read what rank 0 wrote to /dev/shm [expect]"
  else
    echo "shm  : ranks do NOT share /dev/shm — same-node MPI will hang. Saw: $(printf '%s' "$shm" | tr '\n' ' ' | head -c 120)"
  fi
else
  echo "shm  : could not run the shared-memory check: $(printf '%s' "$shm" | head -2 | tr '\n' ' ')"
fi

# 3d) ENVIRONMENT. A brokered srun breaks the chain by which a run script's `export`
# reaches its ranks — the script runs inside the cage, the real srun outside it — so the
# broker carries the delta across as bwrap --setenv pairs. Without this, a script like
#   export OMP_NUM_THREADS=4
#   srun ./solver
# runs with different settings than it asked for, and says nothing about it.
# NB the name must not start with a RESERVED prefix (SLURM_/SBATCH_/PMI_/PALS_/HUSK_) —
# those are deliberately never carried, and an earlier version of this check used
# HUSK_ENV_PROBE and so tested the one name guaranteed to fail.
export PROBE_ENV_CARRIED=carried
if envq=$(srun -n1 sh -c 'echo "${PROBE_ENV_CARRIED:-MISSING}"' 2>&1); then
  case "$envq" in
    *carried*) echo "env  : the script's exported variable reached the rank [expect]" ;;
    *MISSING*) echo "env  : exported variable did NOT reach the rank — a run script's settings"
               echo "       are silently dropped (broker env forwarding not working)" ;;
    *)         echo "env  : unexpected answer from the rank: $(printf '%s' "$envq" | tr '\n' ' ' | head -c 80)" ;;
  esac
else
  echo "env  : could not run the environment check: $(printf '%s' "$envq" | head -2 | tr '\n' ' ')"
fi

# NOTE for 3e/3f: these are NEGATIVE checks, and they also pass when NOTHING is being
# forwarded at all. They only mean something if `env` above passed — read them together.
#
# 3e) ...but scheduler-owned names must NOT be carried. They are inputs to srun's own
# option handling: a forwarded SLURM_NTASKS would contradict the validated --ntasks, and
# bwrap applies --setenv last, so it would win. The rank must see SLURM's value, not the
# one this script set.
export SLURM_NTASKS=99
if sq=$(srun -n1 sh -c 'echo "ntasks=${SLURM_NTASKS:-unset}"' 2>&1); then
  case "$sq" in
    *ntasks=99*) echo "envx : SLURM_NTASKS=99 LEAKED into the rank — scheduler-owned names are"
                 echo "       being forwarded, which can contradict the validated options!" ;;
    *ntasks=*)   echo "envx : SLURM_NTASKS not overridable from the job script [expect]" ;;
    *)           echo "envx : unexpected answer: $(printf '%s' "$sq" | tr '\n' ' ' | head -c 80)" ;;
  esac
else
  echo "envx : could not run the reserved-name check: $(printf '%s' "$sq" | head -2 | tr '\n' ' ')"
fi
unset SLURM_NTASKS

# 3f) ...and neither is husk's OWN namespace. HUSK_STEP_SPOOL tells a stub where to send
# its requests, so a rank able to set it could redirect its own brokering. Our control
# plane is no more forwardable than the scheduler's.
export HUSK_ENV_PROBE=leaked
if hq=$(srun -n1 sh -c 'echo "husk=${HUSK_ENV_PROBE:-unset}"' 2>&1); then
  case "$hq" in
    *husk=leaked*) echo "envh : HUSK_* LEAKED into the rank — a rank could redirect its own"
                   echo "       brokering by setting HUSK_STEP_SPOOL!" ;;
    *husk=*)       echo "envh : husk's own namespace not settable from the job script [expect]" ;;
    *)             echo "envh : unexpected answer: $(printf '%s' "$hq" | tr '\n' ' ' | head -c 80)" ;;
  esac
else
  echo "envh : could not run the husk-namespace check: $(printf '%s' "$hq" | head -2 | tr '\n' ' ')"
fi
unset HUSK_ENV_PROBE

# 4) Concurrency. CAREFUL WHAT THIS MEASURES. Two plain `srun` steps serialise even
# with NO husk in the path: without --overlap a step takes exclusive claim on the
# allocation's CPUs, so the second waits for resources. That is SLURM's accounting, not
# the broker's. (Balfrin 2026-07-30: an UNCAGED run of this probe serialised too, which
# is what caught the earlier version of this check blaming the broker.)
#
# So ask the question that is actually about husk: with --overlap and enough tasks
# allocated, do steps run at the same time? If THAT serialises, the step-broker is the
# suspect. The job requests --ntasks=2 so there is room for two.
t0=$SECONDS
srun --overlap -n1 sleep 3 & p1=$!
srun --overlap -n1 sleep 3 & p2=$!
wait "$p1" "$p2" 2>/dev/null
el=$(( SECONDS - t0 ))
if [ "$el" -lt 5 ]; then
  echo "conc : ${el}s for 2x 3s overlapping steps — the broker runs steps concurrently [expect]"
else
  echo "conc : ${el}s for 2x 3s OVERLAPPING steps — steps serialised even with --overlap."
  echo "       That points at the step-broker (it spawns and polls, so it should not"
  echo "       block); see ${HUSK_JOB_LOG:-~/.husk/log/job-<jobid>.log}."
fi

# 4b) For contrast, the same thing WITHOUT --overlap. Serialising here is normal and
# expected — it is recorded so the two numbers are never confused again.
t0=$SECONDS
srun -n1 sleep 3 & p3=$!
srun -n1 sleep 3 & p4=$!
wait "$p3" "$p4" 2>/dev/null
echo "conc-: $(( SECONDS - t0 ))s for the same steps WITHOUT --overlap (serialising here is SLURM, not husk)"

echo "done."
