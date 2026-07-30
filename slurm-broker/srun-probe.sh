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
  echo "       Otherwise see .husk-step-spool-*/step-broker.log next to this job."
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
export HUSK_ENV_PROBE=carried
if envq=$(srun -n1 sh -c 'echo "${HUSK_ENV_PROBE:-MISSING}"' 2>&1); then
  case "$envq" in
    *carried*) echo "env  : the script's exported variable reached the rank [expect]" ;;
    *MISSING*) echo "env  : exported variable did NOT reach the rank — a run script's settings"
               echo "       are silently dropped (broker env forwarding not working)" ;;
    *)         echo "env  : unexpected answer from the rank: $(printf '%s' "$envq" | tr '\n' ' ' | head -c 80)" ;;
  esac
else
  echo "env  : could not run the environment check: $(printf '%s' "$envq" | head -2 | tr '\n' ' ')"
fi

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
  echo "       block); see .husk-step-spool-*/step-broker.log."
fi

# 4b) For contrast, the same thing WITHOUT --overlap. Serialising here is normal and
# expected — it is recorded so the two numbers are never confused again.
t0=$SECONDS
srun -n1 sleep 3 & p3=$!
srun -n1 sleep 3 & p4=$!
wait "$p3" "$p4" 2>/dev/null
echo "conc-: $(( SECONDS - t0 ))s for the same steps WITHOUT --overlap (serialising here is SLURM, not husk)"

echo "done."
