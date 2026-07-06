#!/usr/bin/env bash
# verify-uenv-export.sh — does the compute-node uenv mount survive a tight --export?
#
# The broker will force a locked-down --export on submissions. But the uenv SPANK
# plugin mounts on the compute node based on the UENV_MOUNT_LIST *env var*
# (init_post_opt_remote reads it, ignoring the propagated --uenv option). So a
# blanket --export=NONE may strip it and leave the job with no software stack.
# This submits the SAME tiny probe job three ways and reports which one mounts:
#
#   A  --export=NONE                          (does the --uenv option alone suffice?)
#   C  --export=<UENV_*/SLURM_UENV* allowlist> (does the planned allowlist work?)
#   B  --export=ALL                           (control — should always mount)
#
# All three pass --uenv=<session label> explicitly, because uenv disables
# sbatch-from-a-uenv-session unless --uenv is given.
#
# Run from a NORMAL shell INSIDE a uenv session (i.e. after `uenv start …`),
# NOT inside husk. No sandbox/broker involved — pure platform probe.
#
# Config via env: PARTITION (default preemptible), ACCOUNT (optional),
#                 LABEL (default $UENV_LABEL), TIMELIMIT (default 00:02:00).
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"; exit 0
fi

die() { echo "error: $*" >&2; exit 1; }
command -v sbatch >/dev/null 2>&1 || die "sbatch not on PATH (load SLURM first)."

PARTITION="${PARTITION:-preemptible}"
ACCOUNT="${ACCOUNT:-}"
TIMELIMIT="${TIMELIMIT:-00:02:00}"
# What to pass to --uenv. Prefer a label, but UENV_MOUNT_LIST (file:mount-point
# pairs) is itself a valid --uenv argument and is always present in a session,
# so fall back to it (handles uenv versions that don't export UENV_LABEL).
LABEL="${LABEL:-${UENV_LABEL:-${UENV_MOUNT_LIST:-}}}"

[[ -n "${UENV_MOUNT_LIST:-}" ]] || die "not in a uenv session (UENV_MOUNT_LIST unset). Run 'uenv start …' first."
[[ -n "$LABEL" ]] || die "could not determine a --uenv argument. Set LABEL=… and re-run."

echo "uenv (--uenv arg)  : $LABEL"
echo "UENV_MOUNT_LIST    : $UENV_MOUNT_LIST"
echo "UENV_VIEW          : ${UENV_VIEW:-<unset>}"
echo "Partition          : $PARTITION${ACCOUNT:+   Account: $ACCOUNT}"
echo

# ── the probe job: report whether a squashfs (uenv) is mounted on the node ──────
PROBE="$PWD/.uenv-export-probe.$$.sh"
cat > "$PROBE" <<'EOF'
#!/bin/bash
echo "host=$(hostname)"
echo "UENV_MOUNT_LIST=${UENV_MOUNT_LIST:-<unset>}"
echo "UENV_VIEW=${UENV_VIEW:-<unset>}"
if grep -qi squashfs /proc/mounts; then
  echo "RESULT=MOUNTED"
  grep -i squashfs /proc/mounts | sed 's/^/  mount: /'
else
  echo "RESULT=NOT-MOUNTED"
fi
ls -d /user-environment /user-tools 2>/dev/null | sed 's/^/  exists: /' || true
EOF
chmod +x "$PROBE"
trap 'rm -f "$PROBE"' EXIT

submit() {  # $1=TAG ; rest=extra sbatch args
  local tag="$1"; shift
  sbatch --parsable \
    --partition="$PARTITION" ${ACCOUNT:+--account="$ACCOUNT"} \
    --time="$TIMELIMIT" --nodes=1 --ntasks=1 \
    --job-name="uenvtest-$tag" \
    --output="$PWD/uenv-export-test.${tag}.%j.out" \
    --uenv="$LABEL" \
    "$@" "$PROBE"
}

echo "==> Submitting 3 probe jobs..."
A=$(submit A --export=NONE)
C=$(submit C --export=UENV_MOUNT_LIST,UENV_VIEW,UENV_REPO,UENV_LABEL,SLURM_UENV,SLURM_UENV_VIEW,SLURM_UENV_REPO)
B=$(submit B --export=ALL)
echo "  A (--export=NONE)       job $A"
echo "  C (--export=allowlist)  job $C"
echo "  B (--export=ALL)        job $B"
echo

echo "==> Waiting for the jobs to finish (Ctrl-C to stop; outputs are in uenv-export-test.*.out)..."
for _ in $(seq 1 120); do
  left=$(squeue -h -j "$A,$B,$C" 2>/dev/null | wc -l || echo 0)
  [[ "$left" -eq 0 ]] && break
  sleep 5
done
echo

for pair in "A:$A:--export=NONE" "C:$C:--export=allowlist" "B:$B:--export=ALL"; do
  tag="${pair%%:*}"; rest="${pair#*:}"; id="${rest%%:*}"; desc="${rest#*:}"
  f="$PWD/uenv-export-test.${tag}.${id}.out"
  echo "######## $tag  (job $id, $desc) ########"
  if [[ -f "$f" ]]; then cat "$f"; else echo "(no output yet — job may still be queued; check $f later)"; fi
  echo
done

cat <<EOF
── how to read it ──────────────────────────────────────────────────────────────
  B (--export=ALL)  should say RESULT=MOUNTED — confirms the session + --uenv work.
  A (--export=NONE):
     MOUNTED      -> the --uenv option alone suffices; the broker can use --export=NONE.
     NOT-MOUNTED  -> the env var must be carried; --export=NONE is too tight.
  C (--export=allowlist):
     MOUNTED      -> our planned allowlist export works (carry UENV_*/SLURM_UENV*).
     NOT-MOUNTED  -> the allowlist is missing a var the plugin needs (widen it).
Clean up when done:  rm -f uenv-export-test.*.out
EOF
