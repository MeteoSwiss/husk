#!/bin/bash
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-review-A4-hb
# A3-lead: can a RANK in the compute cage defeat husk's .git/hooks tmpfs mask and write
# into the HOST hooks dir (auto-exec)? Tests direct removal and parent-rename bypass.
# Empty non-hook markers only; restores .git and cleans up.
WR="${HUSK_WRITABLE:-$PWD}"; JID="${SLURM_JOB_ID:-nojob}"
REPORT="$WR/husk-review-A4-hookbypass-$JID.txt"
{
  echo "CAGE host=$(hostname) jid=$JID"
  echo "=== mask state (compute cage) ==="
  grep -E "/A4/\.(git/hooks|git/config|idea|vscode|claude)" /proc/self/mountinfo 2>/dev/null | sed 's/ - .*//'
  echo "=== positive control: write into masked .git/hooks (expect tmpfs throwaway, not host) ==="
  ( : > "$WR/.git/hooks/husk-review-A4-maskcontrol-$JID" ) 2>&1 && echo "  wrote into .git/hooks (tmpfs)" || echo "  blocked"
  echo "  fstype at .git/hooks: $(stat -f -c %T "$WR/.git/hooks" 2>&1)"
  echo "=== bypass A: direct rmdir .git/hooks ==="
  rmdir "$WR/.git/hooks" 2>&1 && echo "  rmdir SUCCEEDED (mask not a mountpoint?)" || echo "  rmdir blocked (expected)"
  echo "=== bypass B: rename parent .git -> .gitX, does the child mask follow? ==="
  if mv "$WR/.git" "$WR/.gitX" 2>&1; then
    echo "  renamed .git -> .gitX"
    if grep -qE "/A4/\.gitX/hooks" /proc/self/mountinfo 2>/dev/null; then
      echo "  MASK FOLLOWED rename (.gitX/hooks still masked) -> bypass FAILED (defended)"
    else
      echo "  MASK DID NOT FOLLOW -> .gitX/hooks may be the unmasked HOST dir"
      echo "  fstype at .gitX/hooks: $(stat -f -c %T "$WR/.gitX/hooks" 2>&1)"
      if ( : > "$WR/.gitX/hooks/husk-review-A4-hookreach-$JID" ) 2>&1; then
        echo "  *** HOST WRITE OK (FAIL-OPEN): $WR/.gitX/hooks/husk-review-A4-hookreach-$JID ***"
      else
        echo "  host write failed"
      fi
    fi
    mv "$WR/.gitX" "$WR/.git" 2>&1 && echo "  renamed back .gitX -> .git" || echo "  RENAME-BACK FAILED (.gitX left)"
  else
    echo "  rename of .git failed"
  fi
  echo "=== cleanup any marker that reached a real host path ==="
  rm -f "$WR/.git/hooks/husk-review-A4-hookreach-$JID" "$WR/.gitX/hooks/husk-review-A4-hookreach-$JID" 2>/dev/null
  echo "=== final .git/hooks listing ==="; ls -la "$WR/.git/hooks/" 2>&1
  echo DONE
} > "$REPORT" 2>&1
cat "$REPORT"
