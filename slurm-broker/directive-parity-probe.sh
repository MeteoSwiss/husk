#!/usr/bin/env bash
# directive-parity-probe.sh — what spellings of `#SBATCH` does THIS site's Slurm honour?
#
# WHY THIS EXISTS
# ---------------
# husk gates a job's `#SBATCH` directives with its own parser (`sbatch::sbatch_directives`
# / `body_reject_reason`), then submits the script body VERBATIM. So two parsers read one
# file: husk's decides what is ALLOWED, slurmd's decides what is HONOURED.
#
# For the Forced/dominated family (--partition, --nodes, --export, --output, --error,
# --chdir, --uenv, --view) that is safe whatever the parsers do: husk emits its own value
# unconditionally on the real command line, and sbatch precedence is
# `command line > environment > #SBATCH`. A directive husk mis-reads cannot win.
#
# For everything else — --array, --dependency, --signal, --gres, --ntasks, hetjob — the
# body is the ONLY channel: husk validates but does not re-emit them, so they take effect
# through slurmd's own parse. There, a line husk's parser fails to see is a line husk
# neither rejects nor overrides, and Slurm honours an option husk never approved.
#
# husk's parser, in full (it is eight lines):
#   - a directive is any line whose LEADING WHITESPACE-TRIMMED form starts with `#SBATCH`
#   - CASE-SENSITIVE
#   - scanned over the WHOLE FILE, with no stop at the first executable line
#   - split on whitespace, with no quote or continuation handling
#
# `man sbatch` says Slurm stops at the first non-comment, non-whitespace line — so husk
# already sees MORE than Slurm there, which costs false rejections, not safety. The
# dangerous direction is the other one, and it is site- and version-specific. Hence: ask.
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
# Any line marked DIVERGES is a finding: Slurm honoured a spelling husk does not
# recognise, so that spelling is an ungated channel for every non-forced option.
set -uo pipefail

PART=""
while [ $# -gt 0 ]; do
  case "$1" in
    --partition) PART="${2:-}"; shift 2 ;;
    --partition=*) PART="${1#*=}"; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
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
#   yes = trimmed line starts with the exact bytes "#SBATCH"
# Kept as data next to each variant rather than recomputed, so the table states husk's
# behaviour explicitly and a reader can check it against sbatch.rs by eye.
#
# variant|husk_sees|description|the directive line(s), %CANARY% substituted
VARIANTS='
canonical|yes|the control: plain #SBATCH, first line|#SBATCH --job-name=%CANARY%
lowercase|no|#sbatch in lower case|#sbatch --job-name=%CANARY%
mixedcase|no|#SBatch in mixed case|#SBatch --job-name=%CANARY%
leading_space|yes|one leading space before #SBATCH| #SBATCH --job-name=%CANARY%
leading_tab|yes|a leading tab before #SBATCH|\t#SBATCH --job-name=%CANARY%
no_space|yes|no space between #SBATCH and the option|#SBATCH--job-name=%CANARY%
tab_sep|yes|a tab between #SBATCH and the option|#SBATCH\t--job-name=%CANARY%
separated|yes|separated value form (--job-name X)|#SBATCH --job-name %CANARY%
quoted|yes|a quoted value|#SBATCH --job-name="%CANARY%"
trailing_comment|yes|a trailing comment after the value|#SBATCH --job-name=%CANARY% # note
after_code|yes|a directive AFTER the first executable line|echo start\n#SBATCH --job-name=%CANARY%
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

  # The finding: Slurm took a spelling husk does not recognise. husk then neither
  # rejects nor overrides that line, so every non-forced option is reachable through it.
  verdict=ok
  if [ "$slurm" = honoured ] && [ "$husk_sees" = no ]; then
    verdict=DIVERGES
    FINDINGS=$((FINDINGS + 1))
  fi
  printf '%-26s %-10s %-9s %-9s %s\n' "$name" "$husk_sees" "$slurm" "$verdict" "$desc"
done <<EOF
$(printf '%s' "$VARIANTS")
EOF

echo
if [ "$FINDINGS" -gt 0 ]; then
  echo "RESULT: $FINDINGS spelling(s) are honoured by Slurm but invisible to husk's parser."
  echo "Each is an ungated channel for any option husk does not force on the command line"
  echo "(--array, --dependency, --signal, --gres, --ntasks, hetjob ...)."
  exit 1
fi
echo "RESULT: no spelling was honoured by Slurm that husk's parser cannot see."
echo "Note the converse is expected and harmless: husk scans the whole file while sbatch"
echo "stops at the first executable line, so husk sees MORE. That costs false rejections."
