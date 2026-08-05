#!/bin/sh
echo "=== SRUN STUB SOURCE (in-job /usr/bin/srun) ==="
cat /usr/bin/srun 2>&1
echo "=== END SRUN STUB ==="
echo
echo "=== MUNGE readlink recon (the ★ target) ==="
for p in /run/munge /var/run/munge /run/munge/munge.socket.2 /var/run; do
  echo "--- $p ---"
  ls -lad "$p" 2>&1
  echo "readlink-f: [$(readlink -f "$p" 2>&1)]"
done
echo "--- can I create /run/munge (is /run writable)? ---"
( : > /run/munge/husk-review-a2env-probe 2>&1 ) && echo "WROTE /run/munge (UNEXPECTED)" || echo "cannot write /run/munge (expected)"
( ln -s /tmp/x /run/munge/husk-review-a2env-link 2>&1 ) && echo "SYMLINK created in /run/munge (UNEXPECTED)" || echo "cannot symlink in /run/munge (expected)"
echo "--- can the job make a bind mount (needs CAP_SYS_ADMIN)? ---"
echo "CapEff=$(grep CapEff /proc/self/status)"
( mkdir -p "$HOME/hr_mnt" 2>/dev/null; mount --bind /tmp /run/munge 2>&1 ) && echo "MOUNT OK (UNEXPECTED)" || echo "mount --bind denied (expected)"
( unshare -m true 2>&1 ) && echo "unshare -m OK" || echo "unshare -m denied"
echo "=== END MUNGE recon ==="
