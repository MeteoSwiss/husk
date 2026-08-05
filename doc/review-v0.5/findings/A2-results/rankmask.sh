#!/bin/sh
echo "== RANK: munge/mask view =="
echo "rank uid=$(id -u) host=$(hostname)"
echo "ls /run/munge:"; ls -la /run/munge 2>&1
echo "readlink-f /run/munge: [$(readlink -f /run/munge 2>&1)]"
echo "mountinfo munge/mask lines:"; grep -iE 'munge|husk-review-a2env-maskdir' /proc/self/mountinfo 2>&1 || echo "(no munge/maskdir mount line)"
echo "tmpfs mounts total:"; grep -c tmpfs /proc/self/mountinfo 2>&1
echo "== RANK END =="
