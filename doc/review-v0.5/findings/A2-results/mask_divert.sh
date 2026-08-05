#!/bin/sh
echo "== BODY: attempt munge divert via job-made symlink =="
mkdir -p /tmp/husk-review-a2env-maskdir 2>&1
echo "/run writable? test:"; ( : > /run/husk-review-a2env-runtest 2>&1 ) && echo "  /run IS writable" || echo "  /run not writable"
echo "before: readlink-f /run/munge = [$(readlink -f /run/munge)]"
echo "attempt replace /run/munge with symlink -> /tmp/husk-review-a2env-maskdir:"
rm -rf /run/munge 2>&1 && echo "  rm /run/munge ok" || echo "  rm /run/munge FAILED"
ln -s /tmp/husk-review-a2env-maskdir /run/munge 2>&1 && echo "  symlink created" || echo "  symlink FAILED"
echo "after: readlink-f /run/munge = [$(readlink -f /run/munge)]"
echo "after: readlink-f /var/run/munge = [$(readlink -f /var/run/munge)]"
echo "== BODY: srun into rank to observe mask placement =="
srun -n1 "$1" 2>"$2.srunerr"
echo "srun-exit=$?"
echo "== srun stderr (trusted rank-wrapper sh / bwrap) =="; cat "$2.srunerr" 2>/dev/null
echo "== BODY END =="
