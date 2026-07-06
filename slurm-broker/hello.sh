#!/bin/bash
# hello.sh — minimal 1-node bring-up job for the husk SLURM broker.
#
# Submit it the way the agent would, through the broker's stub:
#   sbatch --partition=<site> hello.sh
# The broker FORCES the site partition (HUSK_SLURM_PARTITION) and -o/-e/-D/--export
# to safe values, and prepends the compute-side re-sandbox guard. This body then
# runs INSIDE that cage, so the checks below report whether containment held.
# No #SBATCH --partition here: the broker forces it, and it is site-specific
# (Balfrin preemptible, Santis debug), so pinning one would break a direct submit.
#
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:02:00
#SBATCH --job-name=husk-bringup
set -u

echo "host : $(hostname)"          # proves the job reached a compute node
echo "user : $(whoami)"
echo "--- containment checks (each should print [expect] when sandboxed) ---"

# 1) network: --unshare-net should leave only loopback + no external route.
if timeout 5 bash -c ': < /dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "net  : EXTERNAL REACHABLE — NOT sandboxed!"
else
  echo "net  : external blocked [expect]"
fi

# 2) filesystem: other users' homes + your own secrets must be hidden. NOTE:
# --tmpfs /users leaves an EMPTY /users that `ls` still succeeds on, so test the
# CONTENT (entry count + a real secret), not merely whether the dir lists.
n=$(ls -A /users 2>/dev/null | wc -l)
if ls "$HOME/.ssh" >/dev/null 2>&1; then
  echo "fs   : \$HOME/.ssh READABLE — NOT sandboxed!"
elif [ "$n" -gt 2 ]; then
  echo "fs   : /users shows $n entries — other homes visible, NOT sandboxed"
else
  echo "fs   : homes hidden (/users has $n entries) [expect]"
fi

echo "done."
