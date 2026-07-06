#!/usr/bin/env bash
# test-dryrun.sh — end-to-end smoke test of the broker in --dry-run against the
# Python stub. No SLURM involved: the broker prints the sbatch argv it WOULD run
# and stages the wrapped script. Run after `cargo build`.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STUB="$HERE/../sbatch-stub.py"
BIN="$HERE/target/debug/husk-slurm-broker"
[[ -x "$BIN" ]] || { echo "build first:  (cd '$HERE' && cargo build)"; exit 1; }

SP="$(mktemp -d)"
export HUSK_SLURM_SPOOL="$SP" HUSK_SLURM_TIMEOUT=15
printf '#!/bin/bash\n#SBATCH --nodes=2 --time=00:10:00\nsrun hostname\n' > "$SP/job.sh"

echo "== starting broker (dry-run), spool=$SP =="
"$BIN" --dry-run --poll-ms 100 &
BROKER=$!
trap 'kill "$BROKER" 2>/dev/null; rm -rf "$SP"' EXIT
sleep 0.5

echo; echo "== case 1: valid submission (--partition=preemptible) =="
( cd "$SP" && python3 "$STUB" --partition=preemptible job.sh 42 )

echo; echo "== case 2: missing partition (expect a teaching rejection) =="
( cd "$SP" && python3 "$STUB" job.sh ) || true

echo; echo "== case 3: wrong partition (expect rejection) =="
( cd "$SP" && python3 "$STUB" --partition=normal job.sh ) || true

echo; echo "done."
