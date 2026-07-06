#!/usr/bin/env bash
# verify-sbatch-inheritance.sh — v0.2.2 SLURM-broker GATE TEST.
#
# Question this answers: when the Claude Code agent runs a bash command, claude
# spins up its own inner bwrap mount namespace per command. Does that inner
# bwrap INHERIT a bind-mount we place over sbatch in an OUTER namespace, before
# claude ever starts?
#
#   PASS  -> the agent's sbatch resolves to OUR stub. The outer-wrapper
#            injection works; the broker can be built on it.
#   FAIL  -> the agent sees the REAL sbatch. claude re-sourced it from a path
#            our outer mount missed; find a different injection point first.
#
# It also incidentally proves claude's inner bwrap can start AT ALL while nested
# inside our outer user namespace — CSCS userns-nesting limits would surface here.
#
# Run on a CSCS login node (Balfrin / Santis), signed in to Claude, and NOT from
# inside an existing husk session. Costs one short headless agent turn.
#
# Usage:
#   ./verify-sbatch-inheritance.sh           headless auto-test + verdict
#   ./verify-sbatch-inheritance.sh --manual  print the interactive command only
#
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

die() { echo "error: $*" >&2; exit 1; }

command -v husk >/dev/null 2>&1 \
  || die "husk not on PATH (install it / add ~/.local/bin to PATH first)."
command -v unshare >/dev/null 2>&1 || die "unshare (util-linux) not found."

REAL_SBATCH="$(type -P sbatch || true)"
[[ -n "$REAL_SBATCH" ]] \
  || die "sbatch not on PATH. Load the SLURM module first, then re-run."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
MARKER="SBATCH_STUB_REACHED_$$_${RANDOM}"

# The stub that stands in for sbatch inside the namespace. It ignores its args
# and prints an unmistakable marker so we can tell it apart from real sbatch.
FAKE="$WORK/fake-sbatch"
cat > "$FAKE" <<EOF
#!/bin/sh
echo "$MARKER"
EOF
chmod +x "$FAKE"

echo "Real sbatch:  $REAL_SBATCH"
echo "Stub:         $FAKE  (prints $MARKER)"
echo

# ── manual mode: just print the interactive command ───────────────────────────
if [[ "${1:-}" == "--manual" ]]; then
  cat <<EOF
Run this, then inside the agent ask it to run:  sbatch --version

  unshare -rm bash -c '
    mount --make-rprivate / 2>/dev/null
    mount --bind "$FAKE" "$REAL_SBATCH"
    exec husk'

How to read the agent's output:
  - prints $MARKER   -> PASS (inner bwrap inherited the stub)
  - prints "slurm <version>"                  -> FAIL (agent saw the real sbatch)
  - bwrap / namespace error                   -> nesting failed under outer userns
EOF
  exit 0
fi

# ── headless mode: drive one agent turn and grade it ──────────────────────────
RUNNER="$WORK/runner.sh"
cat > "$RUNNER" <<EOF
#!/bin/bash
mount --make-rprivate / 2>/dev/null || true
mount --bind "$FAKE" "$REAL_SBATCH" || { echo "__MOUNT_FAILED__"; exit 3; }
exec husk -p 'Use the Bash tool to run exactly:  sbatch --version 2>&1  — then reply with ONLY that command'"'"'s raw output and nothing else.'
EOF
chmod +x "$RUNNER"

echo "==> Running one headless agent turn under the outer bind-mount..."
OUT="$(unshare -rm "$RUNNER" 2>&1)" || true

echo "──────── agent / sandbox output ────────"
echo "$OUT"
echo "────────────────────────────────────────"
echo

if   grep -q "__MOUNT_FAILED__" <<<"$OUT"; then
  echo "VERDICT: ERROR — could not bind-mount over $REAL_SBATCH."
  echo "         The outer user+mount namespace or the bind itself failed; the"
  echo "         injection mechanism can't even be set up. Investigate first."
elif grep -q "$MARKER" <<<"$OUT"; then
  echo "VERDICT: PASS ✅ — the agent's inner bwrap inherited our stub."
  echo "         The outer-wrapper injection works. Build the broker on it."
elif grep -qiE 'slurm[ -]?[0-9]' <<<"$OUT"; then
  echo "VERDICT: FAIL ❌ — the agent saw the REAL sbatch."
  echo "         claude's inner bwrap re-sourced sbatch from a path our outer mount"
  echo "         missed. Do NOT build on this; find another injection point first."
elif grep -qiE 'bwrap|namespace|clone3?\(|Operation not permitted|user namespace' <<<"$OUT"; then
  echo "VERDICT: INCONCLUSIVE — claude's inner sandbox likely failed to start nested"
  echo "         inside our outer userns. If CSCS limits userns nesting, the"
  echo "         outer-wrapper trick is blocked; read the error above."
else
  echo "VERDICT: INCONCLUSIVE — the agent may not have run the command verbatim, hit"
  echo "         a permission prompt, or sbatch wasn't found. Inspect the output above,"
  echo "         or re-run with --manual to drive it interactively."
fi
