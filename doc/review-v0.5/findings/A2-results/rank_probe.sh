#!/bin/sh
echo "=== COMPUTE-CAGE (guard) VIEW ==="
echo "host=$(hostname); uid=$(id -u)"
echo "srun-bin:"; ls -la /usr/bin/srun 2>&1; printf 'magic='; head -c4 /usr/bin/srun 2>/dev/null | cat -v; echo
echo "HUSK_STEP_SPOOL=[${HUSK_STEP_SPOOL-<unset>}]"
echo "compute-cage LD_PRELOAD=[${LD_PRELOAD-<unset>}]  LD_LIBRARY_PATH=[${LD_LIBRARY_PATH-<unset>}]"
# --- A2 payloads: exec-relevant env, exported into the job env before srun ---
export HUSKREV_CANARY=husk-review-a2env-rank
export LD_PRELOAD=/nonexistent/husk-review-a2env-preload.so
export LD_LIBRARY_PATH=/nonexistent/husk-review-a2env-libpath
export PYTHONPATH=/nonexistent/husk-review-a2env-py
echo "=== SRUN into rank cage (n=1) ==="
srun -n1 "$1" rank-srun-arg 2>"$2.srunerr"
echo "srun-exit=$?"
echo "=== srun STDERR (trusted-side srun/sh/bwrap complaints, e.g. preload errors) ==="
cat "$2.srunerr" 2>/dev/null
echo "=== COMPUTE-CAGE END ==="
