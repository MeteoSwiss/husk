#!/bin/sh
export LD_PRELOAD=/nonexistent/husk-review-a2env-preload.so
echo "== srun /bin/true (rank=1 dyn exec; stub launch=env+python) =="
srun -n1 /bin/true 2>"$1.true.err"; echo "true-exit=$?"
echo "ld.so errors (true):"; grep -c 'cannot be preloaded' "$1.true.err"
echo "== srun hostname =="
srun -n1 hostname 2>"$1.host.err" >/dev/null; echo "host-exit=$?"
echo "ld.so errors (hostname):"; grep -c 'cannot be preloaded' "$1.host.err"
echo "== unique error lines (true) =="; sort -u "$1.true.err"
