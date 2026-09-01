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
#
# EXIT CODES — three, because a probe needs to be able to say "I did not measure".
#   0  every variant was measured and husk agrees with this site's Slurm on all of them
#   1  measured, and there are findings (BLIND and/or EAGER); see the table
#   2  declined to run (no sbatch, no partition, HUSK_SLURM_SPOOL set)
#   3  RAN BUT MEASURED NOTHING — the instrument is not in a state to answer
#
# Exit 3 exists because of `B8-1`. Put an `sbatch` on PATH that refuses every submission the
# way a wrong account does, and every one of the 13 variants printed `refused`, the loop
# `continue`d without touching FINDINGS, and this script's own conclusion was
# "husk's parser and this site's Slurm agree on every spelling probed", exit 0 — which
# `selftest.sh` rendered as a PASS reading "no #SBATCH spelling is honoured by slurmd that
# husk's parser cannot see". Thirteen of thirteen unmeasured, reported as settled. It is run
# on exactly the occasions where the environment is least settled: a new site, a new
# partition, a new account.
#
# The other direction was measured too, and it is worse than a false green: a `scontrol`
# that cannot reach the controller makes every variant read `ignored`, which flips the
# CONTROL to EAGER and produces "husk re-emits 7 lines Slurm would have ignored — narrow
# husk's parser". An unattributed failure inviting a confident, wrong and expensive
# remediation (`P11`). Both are caught by the same two assertions below: count the refusals,
# and require the control to come back `honoured`.
set -uo pipefail

PART=""
while [ $# -gt 0 ]; do
  case "$1" in
    --partition) PART="${2:-}"; shift 2 ;;
    --partition=*) PART="${1#*=}"; shift ;;
    -h|--help) sed -n '2,79p' "$0"; exit 0 ;;
    *) echo "unknown argument '$1' (try --help)" >&2; exit 2 ;;
  esac
done

# exit 2, not 1: "I declined to run" is not "I found a divergence". `selftest.sh` maps 1 to a
# FAIL that quotes a BLIND/EAGER count, and there is none.
command -v sbatch >/dev/null 2>&1 || { echo "no sbatch on PATH — run this on a login node" >&2; exit 2; }
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
REFUSED=0        # variants sbatch would not accept at all — these measured NOTHING
MEASURED=0       # variants that produced a real honoured/ignored answer
CONTROL=""       # what Slurm did with the plain, first-line, canonical directive
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
    REFUSED=$((REFUSED + 1))
    REFUSE_WHY="$(head -c 90 "$WORK/$name.err" | tr '\n' ' ')"
    printf '%-26s %-10s %-9s %-9s %s\n' "$name" "$husk_sees" "refused" "-" \
      "sbatch refused: $REFUSE_WHY"
    continue
  fi
  JOBS="$JOBS $jid"
  got="$(scontrol show job "$jid" 2>/dev/null | tr ' ' '\n' | sed -n 's/^JobName=//p' | head -1)"
  if [ "$got" = "$canary" ]; then
    slurm=honoured
  else
    slurm=ignored
  fi
  MEASURED=$((MEASURED + 1))
  [ "$name" = canonical ] && CONTROL="$slurm"

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
# ── IS THIS INSTRUMENT MEASURING? Ask before reporting a verdict. ────────────────────────
# `:122` has labelled the first variant "the control" since the file was written, and its
# result was computed into $slurm and then used only to decide BLIND/EAGER. Nothing asserted
# that it came back `honoured` — which is precisely what a control is for. `C4`: the comment
# named the thing and no code read it.
if [ "$MEASURED" -eq 0 ]; then
    echo "RESULT: NOT MEASURED — none of the $i variants produced an answer."
    echo "  $REFUSED of $i were refused by sbatch before any parsing happened. The last"
    echo "  refusal was: ${REFUSE_WHY:-<no stderr>}"
    echo
    echo "  This is an instrument state, not a finding about husk: a wrong --partition, an"
    echo "  expired account or a full QoS refuses every submission, and every variant then"
    echo "  looks identical. Fix the submission first and re-run; do NOT read this as parity."
    exit 3
fi
if [ "$REFUSED" -gt 0 ]; then
    echo "RESULT: NOT MEASURED — $REFUSED of $i variants were refused by sbatch."
    echo "  Only $MEASURED were actually put to this site's Slurm, so the table below is"
    echo "  partial and its silence about the other $REFUSED is not agreement."
    echo "  Last refusal: ${REFUSE_WHY:-<no stderr>}"
    exit 3
fi
if [ "$CONTROL" != honoured ]; then
    echo "RESULT: NOT MEASURED — the control did not behave like a control."
    echo "  'canonical' is a plain \`#SBATCH --job-name=...\` on the first line of the script."
    echo "  This site's Slurm reported it as '${CONTROL:-<never ran>}', not 'honoured'."
    echo
    echo "  Every verdict in the table is computed from the same scontrol read, so if that"
    echo "  read is not working NOTHING here is a finding — and the failure is asymmetric:"
    echo "  an unanswering scontrol makes every variant read 'ignored', which turns the"
    echo "  control itself into an EAGER row and invites narrowing husk's parser to match a"
    echo "  Slurm that was never asked. Check scontrol reaches slurmctld, then re-run."
    exit 3
fi

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
echo "RESULT: $MEASURED of $i spellings measured against this site's Slurm (control honoured);"
echo "        husk's parser agrees with all $MEASURED."
