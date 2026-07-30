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
#SBATCH --ntasks=1
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
if srun --task-prolog=/tmp/nope -n1 true 2>/dev/null; then
  echo "deny : --task-prolog ACCEPTED — the step allowlist is not being applied!"
else
  echo "deny : --task-prolog refused [expect]"
fi

# 4) Concurrency: steps must overlap, or a job that launches several at once
# deadlocks. Two 3s steps started together should finish in ~3s, not ~6s.
t0=$SECONDS
srun -n1 sleep 3 & p1=$!
srun -n1 sleep 3 & p2=$!
wait "$p1" "$p2" 2>/dev/null
el=$(( SECONDS - t0 ))
if [ "$el" -lt 5 ]; then
  echo "conc : ${el}s for 2x 3s steps — steps overlap [expect]"
else
  echo "conc : ${el}s for 2x 3s steps — steps SERIALISED (a long step will block others)"
fi

echo "done."
