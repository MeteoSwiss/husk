#!/usr/bin/env bash
# discover-writable-spool.sh — v0.2.2 SLURM-broker: find a safe spool location.
#
# The in-sandbox sbatch stub must DROP a request file somewhere the
# out-of-sandbox broker can READ it. That location must be BOTH:
#   (1) writable from inside the agent's per-bash-command bwrap, AND
#   (2) shared with the host — i.e. the file the agent writes is the same inode
#       the broker sees outside, and it survives the bwrap teardown.
# A private writable /tmp (per-command tmpfs) satisfies (1) but NOT (2): the
# broker never sees it. This test checks BOTH for a menu of candidate dirs.
#
# Method: one headless agent turn writes a marker file into each candidate dir
# (probing #1 from the inside); afterwards this script checks, on the real
# filesystem, which markers actually appeared (probing #2 from the outside).
# A dir that is writable AND whose marker shows up outside = a usable spool.
#
# Run on a CSCS login node, signed in to Claude, NOT inside an existing
# husk session. Costs one short headless agent turn. Writes throwaway
# marker files into the candidate dirs and cleans up the ones it can see.
#
# Usage:
#   ./discover-writable-spool.sh           headless auto-test + verdict
#   ./discover-writable-spool.sh --manual  print the command to run by hand
#
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

die() { echo "error: $*" >&2; exit 1; }
command -v husk >/dev/null 2>&1 \
  || die "husk not on PATH (install it / add ~/.local/bin to PATH first)."

SUFFIX="$$_${RANDOM}"
TOKEN="SPOOLPROBE_${SUFFIX}"
echo "Probe id ${SUFFIX}  (markers: .slmprobe.${SUFFIX}, manifest: .slmprobe-results.${SUFFIX})"
echo

# The probe command runs INSIDE the agent's bash. $PWD/$HOME/$XDG_RUNTIME_DIR/
# id -u must expand THERE, so they stay literal here (quoted heredoc, no
# expansion); only the two placeholders are filled in by us.
#
# It writes a RESULTS MANIFEST (OK/RO + absolute path per candidate) into the
# project dir, which is reliably writable+shared. We grade from that file on the
# real filesystem afterwards, so it does NOT matter how the agent reformats its
# chat reply (tables / summaries / dropped filenames have burned us before).
read -r -d '' CMD <<'EOF' || true
m="$PWD/.slmprobe-results.__SUFFIX__"; : > "$m" 2>/dev/null || true
for d in "$PWD" /tmp /dev/shm "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$HOME"; do
  f="$d/.slmprobe.__SUFFIX__"
  if ( printf '%s\n' '__TOKEN__' > "$f" ) 2>/dev/null; then s=OK; else s=RO; fi
  echo "$s $f"; echo "$s $f" >> "$m"
done
echo "manifest: $m"
EOF
CMD="${CMD//__SUFFIX__/$SUFFIX}"
CMD="${CMD//__TOKEN__/$TOKEN}"

PROMPT="I'm building husk's SLURM broker and need you to ACTUALLY RUN a small filesystem write test with the Bash tool. Please do not simulate, predict, or summarize it without running it — I am going to read the files it creates to verify, so a described-but-not-executed answer is worse than useless.

It is benign: for each of a few standard locations (the project dir, /tmp, /dev/shm, the runtime dir, and \$HOME) it tries to create ONE small marker file and records OK (write succeeded) or RO (refused). It reads no existing data and deletes nothing. RO results for some paths are expected and wanted.

Run exactly this with the Bash tool:

${CMD}

Then reply with BOTH:
  (1) an explicit statement that you actually executed it (not simulated), and
  (2) the verbatim contents of the manifest it wrote — i.e. run and paste:
      cat \"\$PWD/.slmprobe-results.${SUFFIX}\""

# ── manual mode ───────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--manual" ]]; then
  cat <<EOF
Start an interactive session:   husk
Then paste this prompt to the agent:

----------------------------------------------------------------------
${PROMPT}
----------------------------------------------------------------------

The probe writes a manifest into the project dir. Afterwards, from a NORMAL
shell (outside the sandbox), inspect it and check each "OK" path on the real fs:
  cat .slmprobe-results.${SUFFIX}        # OK/RO + absolute path per candidate
  - an OK path that EXISTS on the real fs   -> writable AND shared = usable spool
  - an OK path that is MISSING              -> writable but private = NOT usable
  - RO lines are read-only inside the sandbox
Clean up:
  rm -f .slmprobe.${SUFFIX} .slmprobe-results.${SUFFIX} \\
        /dev/shm/.slmprobe.${SUFFIX} "\$HOME/.slmprobe.${SUFFIX}"
EOF
  exit 0
fi

# ── headless mode ─────────────────────────────────────────────────────────────
echo "==> Probing candidate spool locations via one headless agent turn..."
OUT="$(husk -p "$PROMPT" 2>&1)" || true

echo "──────── agent / sandbox output (context only) ────────"
echo "$OUT"
echo "───────────────────────────────────────────────────────"
echo

# Grade from the manifest on the REAL filesystem — independent of how the agent
# worded its chat reply.
MANIFEST="$PWD/.slmprobe-results.${SUFFIX}"
if [[ ! -f "$MANIFEST" ]]; then
  echo "VERDICT: INCONCLUSIVE — results manifest not found at:"
  echo "           $MANIFEST"
  echo "         Either the agent didn't run the probe, or it ran from a different"
  echo "         cwd. Re-run, or use --manual and inspect the marker files by hand."
  exit 0
fi

echo "Results (writable INSIDE + visible OUTSIDE = usable spool):"
echo
USABLE=()
while read -r status path; do
  [[ -n "$path" ]] || continue
  dir="${path%/*}/"
  if [[ "$status" == "OK" ]]; then
    if [[ -f "$path" ]] && grep -q "$TOKEN" "$path" 2>/dev/null; then
      printf '  ✅ writable + SHARED    %s\n' "$dir"; USABLE+=("$dir"); rm -f "$path"
    else
      printf '  ⚠️  writable but PRIVATE %s   (ephemeral inside the sandbox — broker cannot read it)\n' "$dir"
    fi
  else
    printf '  🔒 read-only            %s\n' "$dir"
  fi
done < "$MANIFEST"
rm -f "$MANIFEST"
echo

# ── recommendation ────────────────────────────────────────────────────────────
if [[ ${#USABLE[@]} -eq 0 ]]; then
  echo "VERDICT: no writable+shared location found by default. Every writable spot is"
  echo "         private/ephemeral. The spool then needs a sandbox-config writable-root"
  echo "         (settings.json) — a separate step; confirm the shipped binary honors it."
  exit 0
fi

# Prefer a dedicated location outside the project dir and outside home.
PICK=""
for d in "${USABLE[@]}"; do
  case "$d" in
    "$PWD"/*|"$PWD"/) : ;;          # inside the project
    "$HOME"/*|"$HOME"/) : ;;        # inside home
    *) PICK="$d"; break ;;
  esac
done

echo "VERDICT: PASS — usable spool location(s) found."
if [[ -n "$PICK" ]]; then
  echo "         Recommend a dedicated per-session dir under: ${PICK}"
  echo "         (outside the project — clean and safe by construction)."
else
  echo "         Only the project dir (cwd) is writable+shared. Use a dedicated"
  echo "         subdir there, or relocate it outside the project with the outer"
  echo "         wrapper's bind-into-cwd trick (real dir lives elsewhere, bind-"
  echo "         mounted under cwd so it's writable inside but stored off-project)."
fi
