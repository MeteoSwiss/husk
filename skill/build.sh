#!/usr/bin/env bash
# Regenerate the option-contract section of SKILL.md from the broker's REGISTRY.
#
# WHY THIS IS GENERATED
# ---------------------
# The skill tells an agent which sbatch options husk forces, passes through, drops and
# refuses. The registry decides that. Two statements of one contract drift (`P8`), and this
# one drifts in the direction that hurts: every friction report so far has been about exactly
# this table — an option silently dropped, an option refused without a reason — so a stale
# copy actively misleads the party the skill exists to help.
#
# Regenerating is one command; reviewing is a diff. Run it whenever REGISTRY changes.
#
#   skill/build.sh          # rewrite the generated block
#   skill/build.sh --check  # fail if it is out of date (for CI)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$HERE/SKILL.md"
BROKER="${HUSK_BROKER:-$HERE/../slurm-broker/broker/target/debug/husk-slurm-broker}"

if [ ! -x "$BROKER" ]; then
    echo "build.sh: no broker binary at $BROKER" >&2
    echo "build.sh: build it first (cargo build --manifest-path slurm-broker/broker/Cargo.toml)" >&2
    echo "build.sh: or point HUSK_BROKER at one" >&2
    exit 2
fi

BEGIN='<!-- BEGIN GENERATED: husk-slurm-broker --print-option-contract -->'
END='<!-- END GENERATED -->'
NOTE='<!-- Regenerate with skill/build.sh — do not edit by hand. -->'

grep -qF "$BEGIN" "$SKILL" || { echo "build.sh: no BEGIN marker in $SKILL" >&2; exit 2; }
grep -qF "$END"   "$SKILL" || { echo "build.sh: no END marker in $SKILL" >&2;   exit 2; }

tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
{
    sed -n "1,/$(printf '%s' "$BEGIN" | sed 's/[][\.*^$/]/\\&/g')/p" "$SKILL"
    printf '%s\n\n' "$NOTE"
    "$BROKER" --print-option-contract
    printf '\n'
    sed -n "/$(printf '%s' "$END" | sed 's/[][\.*^$/]/\\&/g')/,\$p" "$SKILL"
} > "$tmp"

if [ "${1:-}" = "--check" ]; then
    if cmp -s "$tmp" "$SKILL"; then
        echo "build.sh: SKILL.md option contract is up to date"
        exit 0
    fi
    echo "build.sh: SKILL.md is STALE — the registry changed and the skill did not." >&2
    echo "build.sh: run skill/build.sh to regenerate. Diff:" >&2
    diff -u "$SKILL" "$tmp" >&2 || true
    exit 1
fi

cp "$tmp" "$SKILL"
echo "build.sh: regenerated the option contract in $SKILL"
