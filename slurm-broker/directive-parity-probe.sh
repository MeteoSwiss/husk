#!/usr/bin/env bash
# directive-parity-probe.sh — what spellings of `#SBATCH` does THIS site's Slurm honour?
#
# WHY THIS EXISTS  — REWRITTEN 2026-08-05; the old rationale was inverted, see below
# ------------------------------------------------------------------------------------
# This probe used to say: husk "submits the script body VERBATIM", so two parsers read one
# file and a spelling husk cannot see is a spelling slurmd honours ungated. **Both halves
# of that stopped being true**, in opposite directions, and the verdict logic followed the
# old model. Do not trust an older copy of this file.
#
# What is true now:
#
#  1. **The body never reaches slurmd.** Since Fix 1 husk submits its OWN script on
#     sbatch's stdin; the agent's body travels separately as a data file, run by an
#     interpreter husk names inside the cage. No `#SBATCH` line in it is ever parsed by
#     slurmd. So a directive husk fails to see is INERT, not smuggled.
#  2. **husk re-emits.** Since `da7a6e6` husk interprets the body's directives and puts the
#     whole resource family onto the real command line itself, merged with the CLI.
#
# So this is no longer a probe about GATING. It is a probe about FIDELITY: husk is now the
# only thing standing between what a script says and what runs, and it should honour the
# same lines the author's `sbatch` would. That question has two directions, and BOTH are
# findings now:
#
#   BLIND  — Slurm honours a spelling husk cannot see.
#            husk silently drops a directive the author expected to take effect. This is
#            exactly the `da7a6e6` outage: `#SBATCH --ntasks=64` got one task, SLURM_NTASKS
#            came back empty, and nothing said husk had dropped anything. Silent, and on
#            the normal path for every real run script.
#
#   EAGER  — husk reads a line Slurm would have ignored.
#            husk then re-emits it, so a line that would have been dead ON THIS SITE becomes
#            live. **This class did not exist before husk started re-emitting** — under the
#            old verbatim model, reading more than slurmd only cost false rejections. It is
#            the direction the old version of this file explicitly dismissed as harmless.
#
# husk's parser, in full, as of 2026-08-05:
#   - the scan covers the HEADER ONLY: the leading run of blank and `#` lines, ending at the
#     first command (A3 — a heredoc that GENERATES a job script carries directives that are
#     data for a different submission)
#   - a directive must start at COLUMN 0 with the exact bytes `#SBATCH`; case-sensitive, and
#     an indented one is not a directive
#   - values are tokenised with quote handling: `'` and `"` group and are stripped, an
#     unquoted `#` at a token boundary starts a comment, an unterminated quote is an error
#   - no continuation-line (`\` at end of line) handling
#
# HOW IT ASKS
# -----------
# Each variant sets `--job-name` to a unique canary and is submitted HELD, so nothing ever
# runs and no allocation is consumed. `scontrol show job` then reports whether Slurm took
# the name. Every job is cancelled again before the script exits.
#
# RUN IT OUTSIDE husk, on a login node — it must measure the REAL sbatch, not the stub.
#
#   ./directive-parity-probe.sh [--partition NAME]
#
# Any line marked BLIND or EAGER is a finding — see the two directions above.
set -uo pipefail

PART=""
while [ $# -gt 0 ]; do
  case "$1" in
    --partition) PART="${2:-}"; shift 2 ;;
    --partition=*) PART="${1#*=}"; shift ;;
    -h|--help) sed -n '2,57p' "$0"; exit 0 ;;
    *) echo "unknown argument '$1' (try --help)" >&2; exit 2 ;;
  esac
done

command -v sbatch >/dev/null 2>&1 || { echo "no sbatch on PATH — run this on a login node" >&2; exit 1; }
if [ -z "$PART" ]; then
  PART="${HUSK_SLURM_PARTITION:-}"
  for cfg in "$HOME/.local/lib/husk/slurm-partition"; do
    [ -z "$PART" ] && [ -r "$cfg" ] && PART="$(head -n1 "$cfg" | tr -d '[:space:]')"
  done
fi
[ -n "$PART" ] || { echo "need --partition NAME (no HUSK_SLURM_PARTITION or install record found)" >&2; exit 2; }

# Refuse to run through husk's stub: it would measure husk, not Slurm.
if [ -n "${HUSK_SLURM_SPOOL:-}" ]; then
  echo "HUSK_SLURM_SPOOL is set, so sbatch here is husk's stub. This probe must" >&2
  echo "measure the REAL slurmd parser — run it outside a husk session." >&2
  exit 2
fi

WORK="$(mktemp -d)"
JOBS=""
cleanup() {
  for j in $JOBS; do scancel "$j" >/dev/null 2>&1; done
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== #SBATCH directive parity probe =="
echo "host      : $(hostname)"
echo "partition : $PART   (jobs are submitted HELD and cancelled; nothing runs)"
echo "sbatch    : $(command -v sbatch)  [$(sbatch --version 2>/dev/null)]"
echo

# husk_sees: does husk's parser recognise this line as a directive?
# Kept as data next to each variant rather than recomputed, so the table states husk's
# behaviour explicitly and a reader can check it against sbatch.rs by eye.
#
# THREE OF THESE WERE WRONG until 2026-08-05, because the column was written against the
# whole-file scan and never revisited when the scan narrowed to the header (A3):
# `leading_space` and `leading_tab` are NOT seen (column 0 is required), and `after_code`
# is NOT seen (the header ends at the first command). A stale column silently mislabels
# every verdict computed from it — the probe would have called a real BLIND case "ok".
#
# `line_continuation` puts the canary on the CONTINUED line, so the result discriminates:
# if this site honours `\` continuation the name is taken, otherwise the second line is not
# a directive at all. husk does not honour continuations — worse, the trailing `\` becomes a
# stray token and husk REJECTS the submission. If Slurm honours it here, that is a BLIND
# finding AND a false reject, which is two bugs in one line.
#
# No single-quoted variant: VARIANTS is itself a single-quoted string, and the escaping
# needed to embed one would obscure the table it exists to make readable. The quote path is
# covered by unit tests in sbatch.rs; what needs the CLUSTER is what Slurm honours.
#
# variant|husk_sees|description|the directive line(s), %CANARY% substituted
VARIANTS='
canonical|yes|the control: plain #SBATCH, first line|#SBATCH --job-name=%CANARY%
lowercase|no|#sbatch in lower case|#sbatch --job-name=%CANARY%
mixedcase|no|#SBatch in mixed case|#SBatch --job-name=%CANARY%
leading_space|no|one leading space before #SBATCH| #SBATCH --job-name=%CANARY%
leading_tab|no|a leading tab before #SBATCH|\t#SBATCH --job-name=%CANARY%
no_space|yes|no space between #SBATCH and the option|#SBATCH--job-name=%CANARY%
tab_sep|yes|a tab between #SBATCH and the option|#SBATCH\t--job-name=%CANARY%
separated|yes|separated value form (--job-name X)|#SBATCH --job-name %CANARY%
quoted|yes|a quoted value|#SBATCH --job-name="%CANARY%"
trailing_comment|yes|a trailing comment after the value|#SBATCH --job-name=%CANARY% # note
line_continuation|no|the option is on a backslash-continued line|#SBATCH --time=00:02:00 \\\n   --job-name=%CANARY%
after_code|no|a directive AFTER the first executable line|echo start\n#SBATCH --job-name=%CANARY%
after_blank_and_comment|yes|after blank lines and plain comments (still before code)|\n# a comment\n\n#SBATCH --job-name=%CANARY%
'

printf '%-26s %-10s %-9s %-9s %s\n' VARIANT HUSK-SEES SLURM SVERDICT DESCRIPTION
printf '%-26s %-10s %-9s %-9s %s\n' "-----" "---------" "-----" "--------" "-----------"

FINDINGS=0
i=0
while IFS='|' read -r name husk_sees desc line; do
  [ -z "$name" ] && continue
  i=$((i + 1))
  canary="HUSKPAR${i}$$"
  script="$WORK/$name.sh"
  {
    echo "#!/bin/bash"
    # shellcheck disable=SC2059
    printf "${line//%CANARY%/$canary}\n"
    echo "true"
  } > "$script"

  jid="$(sbatch --hold --partition="$PART" --time=00:01:00 --output=/dev/null \
                --parsable "$script" 2>"$WORK/$name.err")"
  jid="${jid%%;*}"
  if [ -z "$jid" ]; then
    printf '%-26s %-10s %-9s %-9s %s\n' "$name" "$husk_sees" "refused" "-" \
      "sbatch refused: $(head -c 60 "$WORK/$name.err" | tr '\n' ' ')"
    continue
  fi
  JOBS="$JOBS $jid"
  got="$(scontrol show job "$jid" 2>/dev/null | tr ' ' '\n' | sed -n 's/^JobName=//p' | head -1)"
  if [ "$got" = "$canary" ]; then
    slurm=honoured
  else
    slurm=ignored
  fi

  # BOTH directions are findings now. See the header: husk is the only reader of these
  # lines that still matters, so any disagreement with the author's sbatch changes what
  # their job does.
  verdict=ok
  if [ "$slurm" = honoured ] && [ "$husk_sees" = no ]; then
    verdict=BLIND        # husk silently drops a directive the author expected to apply
    FINDINGS=$((FINDINGS + 1))
  elif [ "$slurm" = ignored ] && [ "$husk_sees" = yes ]; then
    verdict=EAGER        # husk re-emits a line this site's sbatch would have ignored
    FINDINGS=$((FINDINGS + 1))
  fi
  printf '%-26s %-10s %-9s %-9s %s\n' "$name" "$husk_sees" "$slurm" "$verdict" "$desc"
done <<EOF
$(printf '%s' "$VARIANTS")
EOF

echo
if [ "$FINDINGS" -gt 0 ]; then
  echo "RESULT: $FINDINGS spelling(s) where husk and this site's Slurm disagree."
  echo
  echo "  BLIND — Slurm honours it, husk cannot see it. husk drops the directive SILENTLY."
  echo "          This is the da7a6e6 shape: '#SBATCH --ntasks=64' got one task and nothing"
  echo "          anywhere said husk had dropped it. Fix by widening husk's parser."
  echo
  echo "  EAGER — husk reads it, Slurm ignores it. Because husk RE-EMITS onto the real"
  echo "          command line, a line that is dead on this site becomes live. Fix by"
  echo "          narrowing husk's parser to match, or by accepting it deliberately and"
  echo "          writing down why."
  echo
  echo "Neither is an escape: the body no longer reaches slurmd, so husk's parse decides"
  echo "everything. That is exactly why fidelity is now the property that matters."
  exit 1
fi
echo "RESULT: husk's parser and this site's Slurm agree on every spelling probed."
