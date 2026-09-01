#!/usr/bin/env bash
# slurmd-differential.sh — what does THIS site's slurmd actually do with a `%` specifier?
#
# WHY THIS EXISTS
# ---------------------------------------------------------------------------------------
# `B1-1`/`RA-2` were not drift between two parts of husk. They were drift between husk and
# an EXTERNAL program husk models: `settings::OUTPUT_SPECIFIERS` says what husk believes
# slurmd substitutes for `%j %A %a %N %n %t %s %u`, and the compute-node guard re-derives
# the filename slurmd will open so it can `lstat` the leaf. When the model is wrong the
# guard checks a file that does not exist and every leaf control runs on the wrong path —
# measured on Santis 2026-08-31, `--output=probe-A%A-a%a-s%s.log` on a non-array job:
# slurmd opened `probe-A837636-a4294967294-sbatch.log` while husk named
# `probe-A-a-sbatch.log`.
#
# No type and no proof reaches that. `const fn` validation makes the table well-formed;
# codegen makes the guard agree with the table; neither can make the TABLE agree with
# slurmd. Only a measurement can, and this is the instrument that takes it.
#
# WHAT THIS SCRIPT DOES, AND THE ONE THING IT DOES NOT
# ---------------------------------------------------------------------------------------
# It submits a bounded set of trivial jobs whose `--output`/`--error` patterns are the
# corpus, records **what slurmd did** — the exact argv, the job id, the filenames that
# appeared, and the environment the batch step was handed — and writes ONE artefact.
#
# It does **not** decide whether husk is right. There is no exit code here that means
# "husk disagrees with slurmd", and there is no copy of husk's table in this file. The
# comparison happens offline, in `broker/src/slurmd_differential.rs`, against husk's own
# `OUTPUT_SPECIFIERS` and husk's own GENERATED guard shell. Keeping the cluster side dumb
# is the point:
#
#   * the operator runs it in one sitting with no agent on the machine, so it has to be
#     one self-contained script that needs no judgement while it runs;
#   * a recorder cannot produce a false green, because it produces no green at all;
#   * husk need not be installed — this measures slurmd, and a run that reaches husk's
#     stub is measuring husk's model of slurmd against husk's model of slurmd (`B8-2`).
#
# WHAT MAKES IT ABLE TO SAY "I MEASURED NOTHING" — the governing requirement
# ---------------------------------------------------------------------------------------
# Both sibling probes shipped a false green. `directive-parity-probe.sh` concluded "husk
# and Slurm agree on every spelling probed" against an `sbatch` that refused every
# submission (`B8-1`); `query-parity-probe.sh` reported "all 147 allowed query options
# exist here" against husk's own stub on `PATH` (`B8-2`). Both had the same shape: an
# ABSENCE OF EVIDENCE was rendered as agreement.
#
# Four controls answer that here, and every one of them is WRITTEN INTO THE ARTEFACT as a
# `CONTROL` record so the offline grader re-decides it rather than trusting this script:
#
#   sbatch_present          there is an `sbatch` on PATH at all
#   sbatch_getopt_canary    it complains about `--husk-differential-canary`. A real getopt
#                           binary does; husk's stub does not, nor does any shim. This is
#                           the check that distinguishes "sbatch" the name from sbatch the
#                           program (`B8-2`).
#   not_in_husk_session     no husk submission variable is set
#   literal_control_file    job `j00` asks for a filename with NO `%` in it and that exact
#                           name appeared. If the plainest possible case did not produce a
#                           file, then every ABSENT below is uninterpretable and nothing in
#                           this artefact is a finding about slurmd (`B8-1`, and
#                           directive-parity-probe's `CONTROL != honoured` arm).
#
# The grader REFUSES to report agreement for any artefact whose controls did not pass, and
# refuses one with no `END ok` line — a run killed halfway is not a partial measurement, it
# is no measurement.
#
# COST TO THE SHARED SCHEDULER — state it, do not discover it (`P16`)
# ---------------------------------------------------------------------------------------
# 16 jobs, one node each, `--time=00:01:00`, and the body writes one small file and exits,
# so the real occupancy is a few seconds per job. One of them is a 2-task array. That is
# the whole cost, it is bounded by `--max-jobs` (default 20; the script REFUSES rather than
# truncates), and `--only` runs a named subset. `--dry-run` submits nothing and prints
# every invocation.
#
# A job array cannot carry more than one case, and it is worth saying why rather than
# leaving it as an omission: `--output` is a property of the SUBMISSION, not of the task.
# Every task of an array shares one pattern, so an array replicates a case instead of
# adding one — and the only thing it varies is `%a`, which is precisely the value the
# non-array cases need held still. So arrays are used here for exactly one thing, `j04`,
# where varying `%a` IS the measurement. Two cases per job is the real ceiling, because a
# submission has exactly two output-pattern options: `--output` and `--error`.
#
# USAGE
# ---------------------------------------------------------------------------------------
#   ./slurmd-differential.sh --account ACCT --partition PART [options]
#
#     --account NAME       required (or $HUSK_SLURM_ACCOUNT, or the install record)
#     --partition NAME     required (or $HUSK_SLURM_PARTITION, or the install record)
#                          Santis wants `debug`; Balfrin differs — ask the site, do not
#                          guess, because a wrong partition refuses every job and that is
#                          exactly the state `B8-1` mistook for agreement.
#     --base DIR           where to work. Default "$SCRATCH/claude-scratch-space".
#     --out FILE           artefact path. Default <base>/slurmd-differential-<host>-<ts>.artefact
#     --max-jobs N         refuse to run if the corpus needs more than N jobs (default 20)
#     --only TAG[,TAG...]  run only these jobs (j00 is always included as the control)
#     --wait-seconds N     how long to wait for every job to leave the queue (default 900)
#     --poll N             seconds between queue polls (default 10)
#     --keep               keep the working tree for forensics (default: remove it)
#     --dry-run            print the invocations, submit nothing, write a dry-run artefact
#     -h, --help
#
# Then bring the artefact back and grade it offline, with the repo and no cluster:
#
#   HUSK_DIFFERENTIAL_ARTEFACT=/path/to/artefact \
#     cargo test --manifest-path slurm-broker/broker/Cargo.toml \
#                slurmd_differential -- --nocapture
#
# EXIT CODES — and note which one is missing.
#   0  it ran, every control passed, the artefact is written
#   2  it declined to run (no sbatch, no account/partition, a husk session, corpus > max)
#   3  it ran but MEASURED NOTHING — a control failed; the artefact says so and the grader
#      will refuse it
#   There is deliberately no exit code meaning "husk and slurmd disagree". This script does
#   not know husk's table and must never appear to have an opinion about it.
set -uo pipefail

TAB=$(printf '\t')
ACCOUNT=""; PARTITION=""; BASE=""; ART=""; MAXJOBS=20; ONLY=""
WAITS=900; POLL=10; KEEP=0; DRYRUN=0

die2() { printf '%s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --account)      ACCOUNT="${2:-}"; shift 2 ;;
    --account=*)    ACCOUNT="${1#*=}"; shift ;;
    --partition)    PARTITION="${2:-}"; shift 2 ;;
    --partition=*)  PARTITION="${1#*=}"; shift ;;
    --base)         BASE="${2:-}"; shift 2 ;;
    --base=*)       BASE="${1#*=}"; shift ;;
    --out)          ART="${2:-}"; shift 2 ;;
    --out=*)        ART="${1#*=}"; shift ;;
    --max-jobs)     MAXJOBS="${2:-}"; shift 2 ;;
    --max-jobs=*)   MAXJOBS="${1#*=}"; shift ;;
    --only)         ONLY="${2:-}"; shift 2 ;;
    --only=*)       ONLY="${1#*=}"; shift ;;
    --wait-seconds) WAITS="${2:-}"; shift 2 ;;
    --wait-seconds=*) WAITS="${1#*=}"; shift ;;
    --poll)         POLL="${2:-}"; shift 2 ;;
    --poll=*)       POLL="${1#*=}"; shift ;;
    --keep)         KEEP=1; shift ;;
    --dry-run)      DRYRUN=1; shift ;;
    -h|--help)      sed -n '2,110p' "$0"; exit 0 ;;
    *)              die2 "unknown argument '$1' (try --help)" ;;
  esac
done

case "$MAXJOBS" in ''|*[!0-9]*) die2 "--max-jobs wants a number, got '$MAXJOBS'" ;; esac
case "$WAITS"   in ''|*[!0-9]*) die2 "--wait-seconds wants a number, got '$WAITS'" ;; esac
case "$POLL"    in ''|*[!0-9]*) die2 "--poll wants a number, got '$POLL'" ;; esac

# -- Refuse to run inside a husk session ------------------------------------------------
#
# `query-parity-probe.sh` produced `all 147 allowed query options exist here` against
# husk's stub, and the login cage shadows the SLURM verbs BY BIND MOUNT — so a reviewer
# running from inside a session has husk's `sbatch` on PATH under its real name. Two
# independent checks, because each catches what the other misses: the environment says a
# broker is there, the canary says the binary is not SLURM.
HUSKVARS=""
for v in HUSK_SLURM_SPOOL HUSK_SLURM_ACCOUNT HUSK_SLURM_PARTITION HUSK_SESSION_LOG \
         HUSK_LOG HUSK_NET_SOCK HUSK_TOOLS HUSK_WRITABLE HUSK_STEP_SPOOL HUSK_RESANDBOXED; do
  eval "val=\${$v:-}"
  [ -n "$val" ] && HUSKVARS="$HUSKVARS $v"
done
if [ -n "$HUSKVARS" ]; then
  printf '%s\n' "husk session detected ($HUSKVARS)." >&2
  printf '%s\n' "The sbatch on PATH here is husk's stub, so this would measure husk's model of" >&2
  printf '%s\n' "slurmd against husk's model of slurmd. Run it OUTSIDE husk, on a login node." >&2
  exit 2
fi

command -v sbatch >/dev/null 2>&1 || die2 "no sbatch on PATH — run this on a login node"
SBATCH_PATH=$(command -v sbatch)

# The getopt canary. This is the one check that tells a real option parser from a program
# that merely has the right name (`B8-2`). `--husk-differential-canary` is not an option of
# any SLURM tool and never will be.
CANARY_OUT=$(timeout 15 sbatch --husk-differential-canary </dev/null 2>&1)
CANARY_OK=0
case "$CANARY_OUT" in
  *"unrecognized option"*|*"Unrecognized option"*|*"invalid option"*|*"illegal option"*) CANARY_OK=1 ;;
esac

SBATCH_VERSION=$(timeout 15 sbatch --version </dev/null 2>&1 | head -1)

# -- account / partition ----------------------------------------------------------------
ACCT_SRC="--account"; PART_SRC="--partition"
if [ -z "$ACCOUNT" ]; then
  ACCOUNT="${HUSK_SLURM_ACCOUNT:-}"; ACCT_SRC="HUSK_SLURM_ACCOUNT"
  if [ -z "$ACCOUNT" ] && [ -r "$HOME/.local/lib/husk/slurm-account" ]; then
    ACCOUNT="$(head -n1 "$HOME/.local/lib/husk/slurm-account" | tr -d '[:space:]')"
    ACCT_SRC="$HOME/.local/lib/husk/slurm-account"
  fi
fi
if [ -z "$PARTITION" ]; then
  PARTITION="${HUSK_SLURM_PARTITION:-}"; PART_SRC="HUSK_SLURM_PARTITION"
  if [ -z "$PARTITION" ] && [ -r "$HOME/.local/lib/husk/slurm-partition" ]; then
    PARTITION="$(head -n1 "$HOME/.local/lib/husk/slurm-partition" | cut -d, -f1 | tr -d '[:space:]')"
    PART_SRC="$HOME/.local/lib/husk/slurm-partition"
  fi
fi
# Both are REQUIRED and neither is guessed. A wrong one refuses every submission, which is
# the exact state `B8-1` reported as agreement — so it must be a loud refusal here, before
# anything is submitted, and not a default.
# --account is NOT required, and the claim that it was is one this harness had no measurement
# for. Balfrin does not need one: `~/.husk/config.json` ships `accounts: []`, install-husk.sh
# says "fine where the site does not require one (Balfrin)", and every job in the 2026-09-01
# bring-up submitted without it. Santis DOES — its cli_filter answers "you must specify a
# project account". A site that needs one and does not get one refuses EVERY submission, which
# is exactly the state `B8-1` reported as agreement — so it is caught where that belongs, by
# the getopt canary before any case is recorded, rather than by a precondition asserting a fact
# about two named clusters that was true of one.
if [ -z "$ACCOUNT" ]; then
  printf '%s\n' \
    "note: no --account given; submitting without one." \
    "      Correct where the site does not require an account (Balfrin: ~/.husk/config.json" \
    "      ships accounts: []). Where it does (Santis), EVERY submission will be refused and" \
    "      the control canary stops the run before a single case is recorded." >&2
fi
[ -n "$PARTITION" ] || die2 "need --partition NAME (Santis wants 'debug'; Balfrin differs — ask the site)"

# -- working tree -----------------------------------------------------------------------
# `$SCRATCH/claude-scratch-space`, never /tmp: HPC /tmp is shared, small and reaped.
if [ -z "$BASE" ]; then
  [ -n "${SCRATCH:-}" ] || die2 "\$SCRATCH is not set and no --base DIR was given. Do not use /tmp on these machines."
  BASE="$SCRATCH/claude-scratch-space"
fi
mkdir -p "$BASE" || die2 "cannot create $BASE"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
HOSTN=$(hostname -s 2>/dev/null || hostname)
RUN="$BASE/slurmd-diff-$HOSTN-$STAMP-$$"
[ -n "$ART" ] || ART="$BASE/slurmd-differential-$HOSTN-$STAMP.artefact"
mkdir -p "$RUN/cases" "$RUN/records" "$RUN/bin" "$RUN/scripts" "$RUN/err" \
  || die2 "cannot create the working tree under $RUN"

# -- the recorder -----------------------------------------------------------------------
#
# Every job runs this and nothing else. It is deliberately trivial — one small write and
# exit — but it is NOT `true`, and the reason matters: husk's guard expands `%A` from
# `SLURM_ARRAY_JOB_ID`, `%s` from `SLURM_STEP_ID` and so on, so without the environment
# the batch step was handed, the offline grader would have to GUESS what husk would have
# computed. Guessing husk's side is how you grade your model of husk against your model of
# slurmd. It also answers `ROADMAP` probe `P2` — whether `SLURM_NODEID`, `SLURM_LOCALID`
# and `SLURM_STEP_ID` are set at all, which the reference table still records as UNMEASURED.
#
# It records facts and no conclusions. `${v+set}` (no colon) distinguishes UNSET from
# set-and-empty, because husk's `${VAR:-}` and its `[ -n "${VAR:-}" ]` presence guard treat
# those two the same and the grader must be able to see which one it saw.
cat > "$RUN/bin/husk-diff-record.sh" <<'RECORDER'
#!/bin/sh
# Written by slurmd-differential.sh. Records the environment slurmd handed this step.
set -u
d="$HUSKDIFF_RECORDS"
key="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-nojobid}}"
task="${SLURM_ARRAY_TASK_ID:-none}"
f="$d/${SLURM_JOB_ID:-nojobid}.${task}.rec"
{
  printf 'KEY\t%s\t%s\n' "$key" "$task"
  printf 'PWD\t%s\n' "$(pwd)"
  for v in SLURM_JOB_ID SLURM_ARRAY_JOB_ID SLURM_ARRAY_TASK_ID SLURMD_NODENAME \
           SLURM_NODEID SLURM_LOCALID SLURM_STEP_ID USER SLURM_JOB_NAME; do
    if eval "[ \"\${${v}+set}\" = set ]"; then
      eval "printf 'ENV\t%s\tSET\t%s\n' \"\$v\" \"\${$v}\""
    else
      printf 'ENV\t%s\tUNSET\n' "$v"
    fi
  done
} > "$f"
# One line to each stream, so an output file that exists is also a file slurmstepd wrote
# to — "created but empty" and "never opened" are then distinguishable.
echo "husk-differential: batch step ran"
echo "husk-differential: batch step ran" >&2
RECORDER
chmod +x "$RUN/bin/husk-diff-record.sh"

# -- the corpus -------------------------------------------------------------------------
#
# Generated from the shape of husk's grammar, not from hand-chosen examples: every
# specifier `OUTPUT_SPECIFIERS` accepts, every one it names as refused, the escape `%%`,
# the two `requires` specifiers with and without `--array`, a `%` in a DIRECTORY component,
# and specifiers husk has never heard of. The round's bugs were all in the gaps between
# hand-chosen cases.
#
# THREE ROWS ARE KNOWN-ANSWER CONTROLS. The operator has already run these by hand and the
# answers are in the round-3 record, so the first real run carries its own calibration —
# and a harness whose known answers come out wrong is telling you about the harness, not
# about slurmd. This file does NOT state the expected answers; the grader holds them, with
# provenance, because a recorder that knows the answer can be tuned until it agrees.
#
#   j03  probe-A%A-a%a-s%s.log        Santis 2026-08-31 (RA §6)
#   j06  jprobe-%J.log                Santis 2026-08-31 (RA §8)
#   j11  --chdir=<dir>/chd%x          Santis 2026-08-31 (RA §7) — is --chdir literal, and
#                                     where does the DEFAULT output land?
#
# tag|where|extra sbatch args (@CASEDIR@ = this job's output case dir)|--output|--error|why
#   where: cli = both patterns on the command line
#          dir = both patterns as #SBATCH directives in the submitted script
#          none = neither is given; slurmd composes its own default
CORPUS='
j00|cli|-|ctrl-literal.log|ctrl-literal.err|THE CONTROL: no % anywhere. If this name does not appear, nothing else here is readable
j01|cli|-|%j|x%jy.err|a specifier alone, and one adjacent to literals on both sides
j02|cli|-|all_j-%j_A-%A_a-%a_N-%N_n-%n_t-%t_s-%s_u-%u.log|def_n-%n_t-%t_s-%s.err|every specifier husk accepts, at once (ROADMAP probe P2)
j03|cli|-|probe-A%A-a%a-s%s.log|errA-%A.err|KNOWN ANSWER: the RA-2 divergence, non-array
j04|cli|--array=0-1|arr_A-%A_a-%a_j-%j_s-%s.log|arr_a-%a.err|the same specifiers WITH --array, which is the case they exist for
j05|cli|-|pct%%pct.log|pct%%j.err|the escape %%, and a specifier immediately after one
j06|cli|-|jprobe-%J.log|errJ-%J.err|KNOWN ANSWER: %J, which husk refuses as unmeasured
j07|cli|--job-name=huskdiffx|x-%x.log|x-%x-%j.err|%x, which husk refuses because slurmd expands it after husk confined the path
j08|cli|-|q-%q.log|Z-%Z.err|specifiers no SLURM version defines: literal, error, or something else?
j09|cli|-|trail%|lead%.err|a dangling % at end of name, and a % in front of a non-letter
j10|cli|--job-name=huskdiffd|%x/out-%j.log|%j/err.err|D2-7: a % in a DIRECTORY component of an explicit --output
j11|none|--chdir=@CASEDIR@/chd%x --job-name=huskdiffc|-|-|KNOWN ANSWER: is --chdir literal, and which directory holds the DEFAULT output
j12|dir|-|d_all_j-%j_A-%A_a-%a_N-%N_n-%n_t-%t_s-%s_u-%u.log|d_x%jy.err|the same as j02 but as #SBATCH directives
j13|dir|-|d_probe-A%A-a%a-s%s.log|d_errA-%A.err|the RA-2 divergence as a directive
j14|dir|-|d_pct%%pct.log|d_pct%%j.err|the escape %% as a directive
j15|dir|-|d_jprobe-%J.log|d_q-%q.err|%J and an unknown specifier as directives
'

# -- artefact ---------------------------------------------------------------------------
: > "$ART" || die2 "cannot write the artefact at $ART"
rec() {
  local line="$1"; shift
  local a
  for a in "$@"; do line="$line$TAB$a"; done
  printf '%s\n' "$line" >> "$ART"
}
# Free text (stderr, versions) is flattened: a newline or tab in a value would corrupt the
# record format. Filenames are NEVER flattened — see `record_files`.
flat() { printf '%s' "$1" | tr '\n\t' '  ' | cut -c1-400; }

rec "HUSKDIFF" "1"
rec "META" "generated"       "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
rec "META" "host"            "$(hostname)"
rec "META" "source"          "$([ "$DRYRUN" -eq 1 ] && echo dry-run || echo cluster)"
rec "META" "sbatch_path"     "$SBATCH_PATH"
rec "META" "sbatch_version"  "$(flat "$SBATCH_VERSION")"
rec "META" "account"         "$ACCOUNT"
rec "META" "account_source"  "$ACCT_SRC"
rec "META" "partition"       "$PARTITION"
rec "META" "partition_source" "$PART_SRC"
rec "META" "rundir"          "$RUN"
rec "META" "uname"           "$(flat "$(uname -sr)")"

rec "CONTROL" "sbatch_present" "PASS" "$SBATCH_PATH"
if [ "$CANARY_OK" -eq 1 ]; then
  rec "CONTROL" "sbatch_getopt_canary" "PASS" "$(flat "$CANARY_OUT")"
else
  rec "CONTROL" "sbatch_getopt_canary" "FAIL" "$(flat "${CANARY_OUT:-<no output>}")"
fi
rec "CONTROL" "not_in_husk_session" "PASS" "no husk submission variable is set"

# -- select the jobs --------------------------------------------------------------------
SELECTED=""
NJOBS=0
while IFS='|' read -r tag where extra outp errp why; do
  [ -z "$tag" ] && continue
  if [ -n "$ONLY" ] && [ "$tag" != j00 ]; then
    case ",$ONLY," in *",$tag,"*) : ;; *) continue ;; esac
  fi
  SELECTED="$SELECTED $tag"
  NJOBS=$((NJOBS + 1))
done <<EOF
$(printf '%s' "$CORPUS")
EOF

if [ "$NJOBS" -gt "$MAXJOBS" ]; then
  printf '%s\n' "the corpus needs $NJOBS jobs and --max-jobs is $MAXJOBS." >&2
  printf '%s\n' "REFUSING rather than truncating: a silently shortened corpus reports the cases it" >&2
  printf '%s\n' "skipped as nothing at all. Raise --max-jobs, or name a subset with --only." >&2
  exit 2
fi

echo "== slurmd % specifier differential =="
echo "host       : $(hostname)"
echo "sbatch     : $SBATCH_PATH  [$SBATCH_VERSION]"
echo "account    : $ACCOUNT   (from $ACCT_SRC)"
echo "partition  : $PARTITION   (from $PART_SRC)"
echo "workdir    : $RUN"
echo "artefact   : $ART"
echo "jobs       : $NJOBS, one node each, --time=00:01:00, body writes one small file and exits"
echo "             (one of them is a 2-task array; that is the whole cost to the scheduler)"
[ "$DRYRUN" -eq 1 ] && echo "MODE       : DRY RUN — nothing will be submitted"
echo
if [ "$CANARY_OK" -ne 1 ]; then
  echo "WARNING: the sbatch on PATH did not complain about a bogus option. That is what husk's"
  echo "         stub and any shim do. Continuing so the artefact records it, but the grader"
  echo "         will refuse this run."
  echo
fi

# -- submit -----------------------------------------------------------------------------
IDS=""
declare -A JOBID_OF
# case id -> the one directory that case's file may appear in. The SCAN iterates this, not
# the corpus, so "one FILES record per CASE record" holds by construction: `j11` declares an
# output case and no error case, and a scan driven by the corpus emitted a `FILES` line for
# a directory no `CASE` line mentions.
declare -A CASEDIR_OF
printf '%-6s %-8s %-12s %s\n' TAG WHERE JOBID NOTE
printf '%-6s %-8s %-12s %s\n' "---" "-----" "-----" "----"

while IFS='|' read -r tag where extra outp errp why; do
  [ -z "$tag" ] && continue
  case " $SELECTED " in *" $tag "*) : ;; *) continue ;; esac

  odir="$RUN/cases/$tag-o"
  edir="$RUN/cases/$tag-e"
  mkdir -p "$odir" "$edir"

  args=( --partition="$PARTITION" --time=00:01:00
         --nodes=1 --ntasks=1 --parsable )
  [ -n "$ACCOUNT" ] && args=( --account="$ACCOUNT" "${args[@]}" )
  arrayval="ABSENT"; jobname="ABSENT"
  if [ "$extra" != "-" ]; then
    for e in $extra; do
      e="${e//@CASEDIR@/$odir}"
      args+=( "$e" )
      case "$e" in
        --array=*)    arrayval="${e#*=}" ;;
        --job-name=*) jobname="${e#*=}" ;;
      esac
    done
  fi

  ocase=""; ecase=""
  case "$where" in
    cli)
      [ "$outp" != "-" ] && { args+=( --output="$odir/$outp" ); ocase="$tag-o"; }
      [ "$errp" != "-" ] && { args+=( --error="$edir/$errp" );  ecase="$tag-e"; }
      args+=( --wrap="$RUN/bin/husk-diff-record.sh" )
      ;;
    dir)
      s="$RUN/scripts/$tag.sh"
      {
        echo "#!/bin/bash"
        [ "$outp" != "-" ] && echo "#SBATCH --output=$odir/$outp"
        [ "$errp" != "-" ] && echo "#SBATCH --error=$edir/$errp"
        echo "exec \"$RUN/bin/husk-diff-record.sh\""
      } > "$s"
      chmod +x "$s"
      [ "$outp" != "-" ] && ocase="$tag-o"
      [ "$errp" != "-" ] && ecase="$tag-e"
      args+=( "$s" )
      ;;
    none)
      # No pattern at all: slurmd composes its own default, relative to the working
      # directory. `j11` pre-creates the LITERAL `chd%x` directory only — so if a
      # job-name-named directory appears instead, slurmd both expanded `--chdir` and
      # created the directory, and the artefact shows which.
      mkdir -p "$odir/chd%x"
      args+=( --wrap="$RUN/bin/husk-diff-record.sh" )
      ocase="$tag-o"
      ;;
    *) die2 "corpus row $tag has an unknown 'where' value '$where'" ;;
  esac

  # Record the invocation ARGUMENT BY ARGUMENT. One line per argument, because an argv
  # flattened onto one line stops being the exact invocation the moment a value has a
  # space in it, and "the exact sbatch invocation" is half of what this artefact is for.
  for c in $ocase $ecase; do
    i=0
    rec "ARGV" "$c" "$i" "sbatch"
    for a in "${args[@]}"; do i=$((i + 1)); rec "ARGV" "$c" "$i" "$a"; done
  done
  if [ -n "$ocase" ]; then
    CASEDIR_OF[$ocase]="$odir"
    rec "CASE" "$tag" "$ocase" "output" "$where" "$([ "$outp" = "-" ] && echo "<default>" || echo "$outp")" "$odir"
    rec "OPT"  "$ocase" "array"   "$arrayval"
    rec "OPT"  "$ocase" "jobname" "$jobname"
    rec "NOTE" "$ocase" "$why"
  fi
  if [ -n "$ecase" ]; then
    CASEDIR_OF[$ecase]="$edir"
    rec "CASE" "$tag" "$ecase" "error" "$where" "$errp" "$edir"
    rec "OPT"  "$ecase" "array"   "$arrayval"
    rec "OPT"  "$ecase" "jobname" "$jobname"
    rec "NOTE" "$ecase" "$why"
  fi

  if [ "$DRYRUN" -eq 1 ]; then
    printf '%-6s %-8s %-12s %s\n' "$tag" "$where" "(dry-run)" "$why"
    printf '  sbatch'; for a in "${args[@]}"; do printf ' %q' "$a"; done; printf '\n'
    continue
  fi

  errf="$RUN/err/$tag.err"
  jid=$(HUSKDIFF_RECORDS="$RUN/records" sbatch "${args[@]}" 2>"$errf")
  rc=$?
  jid="${jid%%;*}"
  jid="$(printf '%s' "$jid" | tr -d '[:space:]')"
  errtxt="$(flat "$(cat "$errf")")"
  if [ "$rc" -ne 0 ] || [ -z "$jid" ]; then
    # A refusal is DATA, not a skip. `B8-1` skipped these and then concluded agreement.
    rec "JOB" "$tag" "-" "REFUSED" "rc=$rc ${errtxt:-<no stderr>}"
    printf '%-6s %-8s %-12s %s\n' "$tag" "$where" "REFUSED" "${errtxt:-<no stderr>}"
    continue
  fi
  # No trailing empty field: every record's arity says what it carries, and a line ending
  # in a separator is a field that exists and is empty rather than one that is absent.
  if [ -n "$errtxt" ]; then
    rec "JOB" "$tag" "$jid" "SUBMITTED" "$errtxt"
  else
    rec "JOB" "$tag" "$jid" "SUBMITTED"
  fi
  JOBID_OF[$tag]="$jid"
  IDS="${IDS:+$IDS,}$jid"
  printf '%-6s %-8s %-12s %s\n' "$tag" "$where" "$jid" "$why"
done <<EOF
$(printf '%s' "$CORPUS")
EOF

if [ "$DRYRUN" -eq 1 ]; then
  rec "END" "dry-run"
  echo
  echo "DRY RUN: nothing was submitted. The artefact at $ART records the invocations and"
  echo "carries END dry-run, which the grader refuses — a dry run measures nothing."
  [ "$KEEP" -eq 1 ] || rm -rf -- "$RUN"
  exit 0
fi

# -- wait -------------------------------------------------------------------------------
echo
if [ -z "$IDS" ]; then
  rec "CONTROL" "literal_control_file" "FAIL" "no job was accepted, so nothing ran"
  rec "CONTROL" "all_jobs_terminal" "FAIL" "no job was submitted"
  rec "END" "ok"
  echo "RESULT: NOT MEASURED — sbatch accepted no job at all."
  echo "  Every row above says REFUSED. That is an instrument state, not a finding: a wrong"
  echo "  --account or --partition refuses every submission identically (B8-1). The artefact"
  echo "  records each refusal and the grader will refuse to read it as agreement."
  [ "$KEEP" -eq 1 ] || rm -rf -- "$RUN"
  exit 3
fi

echo "waiting for $(printf '%s' "$IDS" | tr ',' '\n' | grep -c .) job(s) to leave the queue (up to ${WAITS}s)..."
deadline=$(( $(date +%s) + WAITS ))
WAIT_STATE="done"
while :; do
  qerr="$RUN/err/squeue.err"
  left=$(squeue -h -j "$IDS" -o '%i' 2>"$qerr")
  qrc=$?
  if [ "$qrc" -ne 0 ]; then
    # SLURM answers "Invalid job id specified" once every id has been purged from the
    # queue — that is completion, not a failure. Anything else is a real failure and must
    # be recorded rather than swallowed: `2>/dev/null || true` here is how a broken
    # scontrol turned every variant into a finding in the sibling probe (P11).
    if grep -q "Invalid job id" "$qerr"; then
      break
    fi
    rec "CONTROL" "queue_readable" "FAIL" "$(flat "$(cat "$qerr")")"
    WAIT_STATE="squeue-failed"
    break
  fi
  left="$(printf '%s' "$left" | tr -d '[:space:]')"
  [ -z "$left" ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then WAIT_STATE="timeout"; break; fi
  sleep "$POLL"
done
rec "CONTROL" "all_jobs_terminal" "$([ "$WAIT_STATE" = done ] && echo PASS || echo FAIL)" "$WAIT_STATE"

# Final state per job, from sacct where it exists and scontrol otherwise. Recorded, never
# interpreted: a FAILED job whose output file still appeared is a perfectly good
# measurement of what slurmd named, and a COMPLETED job with no file is a finding.
for tag in $SELECTED; do
  jid="${JOBID_OF[$tag]:-}"
  [ -z "$jid" ] && continue
  st=""
  if command -v sacct >/dev/null 2>&1; then
    st=$(sacct -n -X -j "$jid" -o State%30 2>"$RUN/err/sacct.$tag.err" | head -1 | tr -d '[:space:]')
  fi
  if [ -z "$st" ]; then
    st=$(scontrol show job "$jid" 2>"$RUN/err/scontrol.$tag.err" | tr ' ' '\n' \
         | sed -n 's/^JobState=//p' | head -1)
  fi
  rec "JOBSTATE" "$tag" "$jid" "${st:-UNKNOWN}"
done

# -- scan -------------------------------------------------------------------------------
#
# One directory per case, so "the filename that actually appeared" needs no matching and
# no guessing: it is the content of that directory. Nothing else writes there. An empty
# directory is recorded as `FILES <case> 0` — an absence, explicitly, which the grader
# reports as NOT MEASURED and never as agreement.
record_files() {
  local case_id="$1" dir="$2" n=0
  local list="$RUN/err/$case_id.list"
  find "$dir" -mindepth 1 -print > "$list" 2>"$RUN/err/$case_id.finderr"
  local frc=$?
  if [ "$frc" -ne 0 ]; then
    rec "FILES" "$case_id" "ERROR" "$(flat "$(cat "$RUN/err/$case_id.finderr")")"
    return
  fi
  local p rel ty sz
  while IFS= read -r p; do
    rel="${p#"$dir"/}"
    if   [ -h "$p" ]; then ty=symlink; sz=0
    elif [ -d "$p" ]; then ty=dir;     sz=0
    elif [ -f "$p" ]; then ty=file;    sz=$(wc -c < "$p" | tr -d '[:space:]')
    else                   ty=other;   sz=0
    fi
    # A name holding a tab or a newline would corrupt this record format. Recorded as
    # UNPARSEABLE with its byte length rather than silently mangled — the grader then says
    # NOT MEASURED for the case instead of comparing a name that is not the one on disk.
    case "$rel" in
      *"$TAB"*|*"
"*) rec "FILE" "$case_id" "UNPARSEABLE" "$ty" "${#rel}" ;;
      *)  rec "FILE" "$case_id" "$rel" "$ty" "$sz"
          [ "$ty" = file ] && n=$((n + 1)) ;;
    esac
  done < "$list"
  rec "FILES" "$case_id" "$n"
}

for case_id in "${!CASEDIR_OF[@]}"; do
  record_files "$case_id" "${CASEDIR_OF[$case_id]}"
done

# The recorded environments, one block per (job, array task).
for f in "$RUN"/records/*.rec; do
  [ -e "$f" ] || continue
  key=""; task=""
  while IFS="$TAB" read -r kind a b c; do
    case "$kind" in
      KEY) key="$a"; task="$b" ;;
      PWD) rec "PWD" "$key" "$task" "$a" ;;
      ENV) if [ "$b" = SET ]; then
             rec "ENV" "$key" "$task" "$a" "$b" "${c:-}"
           else
             rec "ENV" "$key" "$task" "$a" "$b"
           fi ;;
    esac
  done < "$f"
done

# -- the control that decides whether any of this is readable ---------------------------
CTRL_FOUND=""
if [ -d "$RUN/cases/j00-o" ]; then
  CTRL_FOUND=$(find "$RUN/cases/j00-o" -mindepth 1 -name 'ctrl-literal.log' -print | head -1)
fi
if [ -n "$CTRL_FOUND" ]; then
  rec "CONTROL" "literal_control_file" "PASS" "ctrl-literal.log"
else
  rec "CONTROL" "literal_control_file" "FAIL" "j00 asked for a name with no % in it and it did not appear"
fi
rec "END" "ok"

# -- cleanup ----------------------------------------------------------------------------
# The artefact lives outside the working tree, so the tree goes. Guarded on the path shape
# because this is an `rm -rf` on a computed path.
if [ "$KEEP" -eq 1 ]; then
  echo
  echo "kept the working tree at $RUN (--keep)"
else
  case "$RUN" in
    */slurmd-diff-*-*) rm -rf -- "$RUN" ;;
    *) echo "refusing to remove '$RUN' — it does not look like a run directory this script made" >&2 ;;
  esac
fi

# -- what this script is allowed to say -------------------------------------------------
echo
echo "artefact: $ART"
echo
if [ -n "$CTRL_FOUND" ] && [ "$CANARY_OK" -eq 1 ] && [ "$WAIT_STATE" = done ]; then
  echo "RESULT: RECORDED. $NJOBS jobs, every control passed."
  echo
  echo "This script has NOT compared anything against husk and has no opinion about whether"
  echo "husk's table is right. Grade the artefact offline, with the repo:"
  echo
  echo "  HUSK_DIFFERENTIAL_ARTEFACT=$ART \\"
  echo "    cargo test --manifest-path slurm-broker/broker/Cargo.toml \\"
  echo "               slurmd_differential -- --nocapture"
  exit 0
fi
echo "RESULT: NOT MEASURED — a control did not pass."
[ "$CANARY_OK" -eq 1 ]      || echo "  * the sbatch on PATH did not complain about a bogus option (not a getopt binary)"
[ -n "$CTRL_FOUND" ]        || echo "  * j00's literal, %-free filename did not appear, so no ABSENT below means anything"
[ "$WAIT_STATE" = done ]    || echo "  * jobs did not all leave the queue ($WAIT_STATE); files may still be arriving"
echo
echo "  The artefact is still written, with those failures recorded, and the grader will"
echo "  refuse to read it as agreement. Fix the instrument and re-run; do NOT read the"
echo "  absence of a file as slurmd declining to create one."
exit 3
