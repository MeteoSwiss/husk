#!/bin/bash
# --- injected by husk-slurm-broker: re-exec once inside the compute-side sandbox ---
# The agent's script, as DATA. Set before the branch because both halves need it: the
# in-cage half execs it, the outer half removes it. One origin for the path, so the two
# cannot drift - the cleanup set has already been wrong once, and every file the guard is
# responsible for must be named exactly once.
_husk_body='/work/.husk-body-t.sh'
if [ -z "${_HUSK_RESANDBOXED:-}" ]; then
export _HUSK_RESANDBOXED=1
# EVERY HUSK_ NAME THIS GUARD EXPORTS, CLEARED BEFORE ANYTHING SETS IT. `K-1`.
#
# `spool.rs` forwards the `HUSK_` prefix from the submitting shell, so each of these
# names arrives in the job environment already carrying whatever was in the login
# session. `B4-3` was that channel used against the egress pair: with HUSK_NET_SOCK and
# HUSK_SOCAT set in the launching shell, a job with NO allowlist reached the step broker
# with egress_decided=true and bound another session's proxy socket into a rank.
#
# step.rs answers that by CHECKING the inherited pair against this job. This line answers
# it by removing the inheritance: after it, the only writer of these five names is the
# guard, so "the guard builds this once and exports it, so there is a single origin" is
# true by construction rather than by argument (`P2` - the confined side supplies neither
# its own boundary nor its own record; the submitting shell is not the confined side, but
# it is not husk either). The step-broker check STAYS: it is what makes an in-cage or
# nested husk unable to mint a pair, and it is the half that holds if this guard is ever
# not the process that starts the step broker.
#
# HUSK_STEP_SPOOL and HUSK_WRITABLE are here for a reason the finding did not name:
# neither is exported on every branch. The guard only exports HUSK_STEP_SPOOL when the
# spool is usable, so on the branch where the spool is REFUSED a leaked value survived
# into the cage and the in-cage srun stub would have written its requests to a directory
# the login shell chose; and HUSK_WRITABLE is what the banner tells the agent it may
# write, so an inherited one is a LOGIN session's answer to a COMPUTE question. Same
# channel, three variables over (`fix the sibling in the same pass`).
#
# `every_husk_name_the_guard_exports_is_cleared_first` reads the emitted script and fails
# if a fifth name is exported without joining this line - an enumeration that asserts
# itself rather than a comment asking to be maintained (`P8`).
unset HUSK_NET_SOCK HUSK_SOCAT HUSK_STEP_SPOOL HUSK_JOB_LOG HUSK_WRITABLE
# An ARRAY, not a string. A string of pre-quoted arguments expanded unquoted gets
# word-split but NOT quote-removed, so bwrap would receive a path with literal quotes
# in it - which is exactly how the srun bind below took every job down once.
#
# THE MUNGE MASK, AND IT REFUSES ON THE SAME INPUT THE RANK REFUSES ON (`K-2`).
# profile.rs names this mount as the load-bearing control for the only shipped profile,
# and it is enforced in TWO places - here for the job cage, and rank.rs for each rank,
# because bwrap mount namespaces do not propagate. Fix K made the rank refuse when the
# mask cannot be applied and left this half at a bare `[ -d ] || continue`, so the SAME
# node configuration produced a refusal there and a silently unmasked job cage here. Two
# enforcers of one control, giving opposite answers, and the operator meets the confusing
# half first: a job that runs (with the real /run/munge visible to the body - AV8) until
# it calls srun.
#
# So: same split as rank.rs. ABSENT is not a failure and must stay a silent skip - there
# is no credential socket to hide and `--tmpfs` on an absent DEST is what took the whole
# cage down twice. PRESENT-BUT-UNMASKABLE is a failure of the control, and the job does
# not start.
#
# WHERE THE TWO LEGITIMATELY DIFFER, and why this half does not simply copy that one: a
# path resolving through WHITESPACE is unmaskable in a rank (it builds `$_m` by string
# concatenation and expands it unquoted) and perfectly maskable here (`_husk_extra` is a
# bash array, so one word stays one word - measured). Refusing here would be husk denying
# a job whose cage it can actually build, which is the operator-aimed denial of service
# this round shipped three times. It ANNOUNCES instead: the job is caged, and every srun
# in it will refuse, said once at job start rather than discovered per rank (`P13`).
_husk_extra=()
_husk_seen=
_husk_mwhy=
_husk_mspace=
for _d in /run/munge /var/run/munge; do
if [ ! -d "$_d" ]; then
[ -e "$_d" ] || continue
_husk_mwhy="$_d exists but is not a directory, so a tmpfs cannot be mounted over it"
break
fi
_r=$(readlink -f "$_d" 2>/dev/null || echo "$_d")
case "$_r" in
"")
_husk_mwhy="$_d resolves to an empty path, so husk has no name to mount over"
break
;;
*[[:space:]]*) [ -n "$_husk_mspace" ] || _husk_mspace="$_d -> $_r" ;;
esac
case " $_husk_seen " in *" $_r "*) continue ;; esac
_husk_seen="$_husk_seen $_r"
_husk_extra+=(--tmpfs "$_r")
done
if [ -n "$_husk_mwhy" ]; then
echo "husk: cannot mask this node's credential socket directory - $_husk_mwhy." >&2
echo "husk: Refusing to run this job. That mask is what keeps the MUNGE socket" >&2
echo "husk: out of the cage, and without it a job can authenticate to SLURM and" >&2
echo "husk: submit work husk never sees. Nothing your job did causes this - it is" >&2
echo "husk: how this node is configured, so report the path above to your site." >&2
echo "husk: The body has NOT run." >&2
exit 1
fi
if [ -n "$_husk_mspace" ]; then
echo "husk: this node's credential socket directory resolves through whitespace:" >&2
echo "husk:   $_husk_mspace" >&2
echo "husk: the job cage masks it correctly, so THIS job is confined - but every" >&2
echo "husk: srun step in it will refuse to start, because a rank cannot pass that" >&2
echo "husk: path to bwrap as one word. Nothing your job did causes this; report the" >&2
echo "husk: path above to your site." >&2
fi
# Bootstrap the step pair: an UN-CAGED step-broker (it needs MUNGE and the daemon
# route, which is exactly what the cage removes) plus the in-cage srun stub bound over
# the real srun. Everything is conditional on the pieces existing HERE, on this node:
# the broker resolved these paths on the login node, and a bwrap bind whose source is
# missing kills the cage outright. If any of it is absent the job still runs - srun
# simply is not brokered, and fails in the cage for want of a route, which is the
# status quo. The stub is convenience, not containment.
# The job spool. Hoisted OUT of the step-pair block below: it holds the step spool AND
# the egress socket, and a job with no srun stub must still be able to have a network.
# Coupling egress to the stub would have made an inactive step pair silently mean no
# network either.
# ONE definition of "is this still the directory husk made?", used at EVERY place in this
# guard that deletes inside a directory whose PARENT somebody else can write. It existed
# once, inline on /dev/shm, under a comment naming "a deletion primitive" - and the step
# spool, whose parent is the workdir the cage binds WRITABLE, never got it (`RDF-D-1`).
#
# `mkdir -p` over a SYMLINK TO A DIRECTORY returns 0. `[ -d ]` follows it. `rm -f`'s globs
# resolve through it. So the confined side points this name at any directory the user can
# write, and husk's own cleanup deletes `out-*`, `err-*` and `.*.tmp` there, as the real
# user, OUTSIDE the cage - then echoes `ls -A` of it to the job's stderr, which is a file
# the agent reads. No race is needed. `P15`: a control names a target; check that the name
# resolves to the object you meant.
_husk_ours() {
[ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ]
}
_husk_spool='/work/project'"/.husk-step-spool-${SLURM_JOB_ID:-nojob}"
mkdir -p "$_husk_spool" 2>/dev/null
if _husk_ours "$_husk_spool"; then
:
elif [ -e "$_husk_spool" ] || [ -L "$_husk_spool" ]; then
# CHECKED AT CREATION, not only at cleanup. The step-broker runs UNCAGED and writes
# out-<id>/err-<id> - files whose CONTENT is the step's own output - into this
# directory, so a name pre-planted before the job started is an out-of-cage WRITE
# primitive as well as a delete one. Refusing costs this job its srun brokering and
# nothing else: the spool is not on the egress path (the socket moved to node-local
# /tmp), the body still runs, and an unusable spool has always meant exactly this.
echo "husk: NOT using $_husk_spool as this job's step spool - something is already" >&2
echo "husk: at that name, and it is a symlink or not a directory you own. husk creates" >&2
echo "husk: this directory itself and will not write into, or delete inside, a name" >&2
echo "husk: something else chose. srun is NOT brokered in this job; the job still runs." >&2
echo "husk: Remove or rename that path and resubmit." >&2
_husk_spool=
else
# This used to be a bare `|| _husk_spool=`, and it was SILENT: with the stub, the broker
# and srun all present, the step-pair block's `else` never fires, so a job whose spool
# could not be created got no step broker, no bound stub and NO MESSAGE on any channel
# (`P7`).
echo "husk: could not create $_husk_spool, so srun is NOT brokered in this job. The" >&2
echo "husk: job still runs; a real srun inside the cage will fail for want of a route." >&2
_husk_spool=
fi
# Hoisted with the spool, and for the same reason: BOTH the egress proxy and the
# step-broker are started from it, and the proxy now starts first. Leaving this in the
# step-pair block below made the proxy line expand to an EMPTY command - the guard said
# only "line 43: : command not found", no proxy ever ran, and three network arms failed
# for a reason none of them could see (Balfrin 4987657).
_husk_broker='<HUSK_BROKER>'
# Where husk's own record of this job goes, and it is deliberately NOT the spool.
# The spool sits inside the workdir, which the cage binds WRITABLE, so a log kept there
# is one the job can truncate, rewrite or plant lines in - the audited party must not be
# able to author the audit trail. $HOME is tmpfs-masked inside the cage, so this file is
# out of the job's reach entirely; it is read from the login node, where husk was
# launched. One file per job, named by job id, so there is no question which run it is.
#
# The step-broker and the egress proxy BOTH append here. They are two trusted processes
# with one story to tell about one job, they prefix their lines distinctly, and one place
# to look beats two.
_husk_log=/dev/stderr
if [ -n "${HOME:-}" ] && mkdir -p "$HOME/.husk/log" 2>/dev/null; then
_husk_log="$HOME/.husk/log/job-${SLURM_JOB_ID:-nojob}.log"
echo "husk: job ${SLURM_JOB_ID:-nojob} on $(hostname 2>/dev/null || echo '?') started $(date -u +%Y%m%d-%H%M%SZ 2>/dev/null) in '/work/project'" \
>>"$_husk_log" 2>/dev/null || _husk_log=/dev/stderr
fi
if [ "$_husk_log" = /dev/stderr ]; then
# Logging is diagnostics, not the boundary, so a home it cannot write must never abort
# a job. Merge into the job's stderr and SAY the record is no longer out of reach.
echo "husk: $HOME/.husk/log is not writable from this node, so husk's log for this" >&2
echo "husk: job is merged into the job's own stderr instead of kept outside it." >&2
fi
export HUSK_JOB_LOG="$_husk_log"
  # --- husk: stdout/stderr must resolve INSIDE the writable set (A1) ---
  # `/proc/$$/fd`, never `/proc/self/fd`: this runs inside `$(...)`, and a command
  # substitution is a FORKED subshell whose OWN stdout is the substitution pipe. `self`
  # therefore reports `pipe:[…]` for every job — the check would have looked present,
  # passed its tests, and enforced nothing. `$$` stays the invoking shell's pid in a
  # subshell, so it names the descriptor slurmd actually handed us.
  _husk_fd_outside() {
    _husk_fd_p=$(readlink "/proc/$$/fd/$1" 2>/dev/null) || return 1
    case "$_husk_fd_p" in
      /*) ;;
      *) return 1 ;;
    esac
    _husk_fd_p=${_husk_fd_p% (deleted)}
    [ -f "$_husk_fd_p" ] || return 1
    for _husk_fd_r in '/work/project' '/scratch/shared'; do
      _husk_fd_c=$(readlink -f "$_husk_fd_r" 2>/dev/null || echo "$_husk_fd_r")
      case "$_husk_fd_p" in
        "$_husk_fd_c"|"$_husk_fd_c"/*) return 1 ;;
      esac
    done
    return 0
  }
  _husk_fd_checked=
  for _husk_fd in 1 2; do
    _husk_fd_t=$(readlink "/proc/$$/fd/$_husk_fd" 2>/dev/null || true)
    case "$_husk_fd_t" in /*) [ -f "${_husk_fd_t% (deleted)}" ] && _husk_fd_checked=1 ;; esac
    _husk_fd_outside "$_husk_fd" || continue
    {
      echo "husk: ================== JOB REFUSED =================="
      echo "husk: file descriptor $_husk_fd of this job resolves to"
      echo "husk:   $_husk_fd_p"
      echo "husk: which is OUTSIDE the set this job may write:"
      echo "husk:   '/work/project' '/scratch/shared'"
      echo "husk: husk confines --output/--error when the job is SUBMITTED. A path that"
      echo "husk: was inside the set then and outside it now was replaced in between -"
      echo "husk: a symlink swapped in while the job sat pending, which is the one thing"
      echo "husk: a submit-time check cannot catch. SLURM opens these files as you and"
      echo "husk: OUTSIDE the sandbox, so husk refuses the job instead."
      echo "husk: The agent's body has NOT been run: nothing it controls was written"
      echo "husk: there, and --open-mode=append means nothing was truncated either."
      echo "husk:   job  : ${SLURM_JOB_ID:-nojob}"
      echo "husk:   node : $(hostname 2>/dev/null || echo '?')"
      echo "husk: ================================================="
    } >>"$_husk_log" 2>/dev/null
    exit 1
  done
  if [ -z "$_husk_fd_checked" ]; then
    echo "husk: stdout/stderr are not regular files on this node, so husk could not \
verify where its output lands; --output confinement rests on the submit-time check alone." \
      >>"$_husk_log" 2>/dev/null
  fi
  # --- husk: the --output/--error paths husk emitted must still be safe (A1-F1) ---
  _husk_name_bad() {
    # $1 = the emitted value; may carry SLURM % specifiers in the LEAF only.
    _husk_nv=$1
    _husk_nd=${_husk_nv%/*}
    _husk_nl=${_husk_nv##*/}
    _husk_nwhy=
    # The comment above says the leaf is the ONLY place a % may appear, so check it
    # rather than assume it (RA-9). `readlink -f` would resolve the LITERAL name, which
    # exists inside the set, and every check below would pass on the wrong directory.
    case "$_husk_nd" in
      *%*) _husk_nwhy='its directory holds a % specifier, which husk does not expand, so this is not the directory SLURM will open under'; return 0 ;;
    esac
    _husk_nrd=$(readlink -f "$_husk_nd" 2>/dev/null || echo "$_husk_nd")
    _husk_nin=
    for _husk_nr in '/work/project' '/scratch/shared'; do
      _husk_nrc=$(readlink -f "$_husk_nr" 2>/dev/null || echo "$_husk_nr")
      case "$_husk_nrd" in "$_husk_nrc"|"$_husk_nrc"/*) _husk_nin=1 ;; esac
    done
    # directory resolved OUTSIDE the set -> bad
    [ -n "$_husk_nin" ] || { _husk_nwhy='its directory resolves outside the writable set'; return 0; }
    # Expand the specifiers SLURM will, so the leaf can be named and lstat'd. Bash
    # parameter substitution, no external command and no regex - the guard already
    # requires bash (it uses arrays), and a sed here is exactly the kind of generated
    # shell that has shipped literal quotes before.
    #
    # These lines are GENERATED from settings::OUTPUT_SPECIFIERS, which is the same table
    # the submit-time validator accepts from. They were hand-written beside it until B1-1,
    # and the two drifted by two entries.
    case "$_husk_nl" in *'%j'*) [ -n "${SLURM_JOB_ID:-}" ] || { _husk_nwhy='%j needs SLURM_JOB_ID, which is not set on this node, so husk cannot name the file SLURM will open'; return 0; } ;; esac
    _husk_nl=${_husk_nl//'%j'/${SLURM_JOB_ID:-}}
    case "$_husk_nl" in *'%A'*) [ -n "${SLURM_ARRAY_JOB_ID:-}" ] || { _husk_nwhy='%A needs SLURM_ARRAY_JOB_ID, which is not set on this node, so husk cannot name the file SLURM will open'; return 0; } ;; esac
    _husk_nl=${_husk_nl//'%A'/${SLURM_ARRAY_JOB_ID:-}}
    case "$_husk_nl" in *'%a'*) [ -n "${SLURM_ARRAY_TASK_ID:-}" ] || { _husk_nwhy='%a needs SLURM_ARRAY_TASK_ID, which is not set on this node, so husk cannot name the file SLURM will open'; return 0; } ;; esac
    _husk_nl=${_husk_nl//'%a'/${SLURM_ARRAY_TASK_ID:-}}
    case "$_husk_nl" in *'%N'*) [ -n "${SLURMD_NODENAME:-}" ] || { _husk_nwhy='%N needs SLURMD_NODENAME, which is not set on this node, so husk cannot name the file SLURM will open'; return 0; } ;; esac
    _husk_nl=${_husk_nl//'%N'/${SLURMD_NODENAME:-}}
    _husk_nl=${_husk_nl//'%n'/${SLURM_NODEID:-0}}
    _husk_nl=${_husk_nl//'%t'/${SLURM_LOCALID:-0}}
    _husk_nl=${_husk_nl//'%s'/${SLURM_STEP_ID:-batch}}
    case "$_husk_nl" in *'%u'*) [ -n "${USER:-}" ] || { _husk_nwhy='%u needs USER, which is not set on this node, so husk cannot name the file SLURM will open'; return 0; } ;; esac
    _husk_nl=${_husk_nl//'%u'/${USER:-}}
    case "$_husk_nl" in
      # FAIL CLOSED. A leaf that still holds a % after every substitution is one husk
      # cannot name, so it is one husk cannot check - and an unverified path is not a safe
      # path. This branch used to `return 1` (= not bad) and set _husk_name_unverified,
      # which the caller consumed on the NEXT iteration and used to skip a genuine
      # refusal: an unexpandable --output silently disarmed the --error check (B1-1).
      # There is no excuse variable any more, and no branch that lets a path through
      # because husk could not look at it.
      *%*) _husk_nwhy='a % specifier survived expansion, so husk cannot name the file SLURM will open'; return 0 ;;
      # …and a / in a substituted value does not merely make the leaf unnameable, it
      # MOVES it: USER=../outside/x with --output=%u.log lands outside the writable
      # set, past a containment check that already ran on the directory (RA-1).
      */*) _husk_nwhy='an expanded value contains a /, so the leaf is not in the directory husk confined'; return 0 ;;
    esac
    # N1: a symlink leaf is caught, but a HARD LINK is a regular file, so `-h` is false and
    # the fd check reports the in-set name the fd was opened by, not the inode's other name.
    # A rank could hard-link the emitted leaf to an inode outside the set and defeat BOTH
    # checks. husk's leaf is a unique `slurm-%j.out`, so it is created fresh with one link;
    # a link count above one means the name was pre-planted to alias another path -> bad.
    _husk_leaf="$_husk_nrd/$_husk_nl"
    # leaf is a symlink -> bad
    [ -h "$_husk_leaf" ] && { _husk_nwhy='its final component is a symlink'; return 0; }
    if [ -e "$_husk_leaf" ]; then
      _husk_nlinks=$(stat -c %h "$_husk_leaf" 2>/dev/null || echo 1)
      # a hard link aliasing another path -> bad
      [ "$_husk_nlinks" -gt 1 ] 2>/dev/null && { _husk_nwhy='its final component has more than one hard link, so it aliases another path'; return 0; }
    fi
    return 1
  }
  for _husk_np in '/work/project/slurm-%j.out' '/work/project/slurm-%j.err'; do
    [ -n "$_husk_np" ] || continue
    if _husk_name_bad "$_husk_np"; then
      {
        echo "husk: ================== JOB REFUSED =================="
        echo "husk: husk cannot show that an emitted output path is safe on this node:"
        echo "husk:   $_husk_np"
        echo "husk:   why  : ${_husk_nwhy:-it could not be verified}"
        echo "husk: SLURM opens --output/--error as you and OUTSIDE the sandbox, so husk"
        echo "husk: refuses a path it cannot confine OR cannot name. The body has NOT run,"
        echo "husk: and --open-mode=append means nothing was truncated."
        echo "husk: a directory or leaf swapped to a symlink after submission is the case the"
        echo "husk: submit-time check cannot catch, and is what this guard exists for. an"
        echo "husk: unexpandable % is refused at SUBMIT time, so meeting one HERE means the"
        echo "husk: guard and the validator have drifted - report it rather than retrying."
        echo "husk:   job  : ${SLURM_JOB_ID:-nojob}"
        echo "husk:   node : $(hostname 2>/dev/null || echo '?')"
        echo "husk: ================================================="
      } >>"$_husk_log" 2>/dev/null
      exit 1
    fi
  done
  _husk_step_pid=
_husk_stub='<HUSK_STUB>'
_husk_real_srun=$(command -v srun 2>/dev/null || true)
if [ -r "$_husk_stub" ] && [ -x "$_husk_broker" ] && [ -n "$_husk_real_srun" ]; then
if [ -n "$_husk_spool" ]; then
export HUSK_STEP_SPOOL="$_husk_spool"
"$_husk_broker" --step-broker --spool "$_husk_spool" --workdir '/work/project' \
>>"$_husk_log" 2>&1 &
_husk_step_pid=$!
# CONFIRM IT CAME UP. The step broker fails CLOSED on settings it cannot parse and
# exits(2) - which is correct. But it was started in the background and nothing ever
# checked, so that exit was invisible: the stub still got bound over srun, every srun
# wrote a request no one would ever answer, and the job hung to its walltime with no
# output on any channel anyone was reading. The reason sat in husk's own job log, two
# clear sentences, where neither the agent nor the operator was looking.
#
# That is not fail-closed. It is fail-silent, and it is the worst shape available: the
# safe decision was taken and then hidden. It cost an afternoon of ghost-hunting across
# four nodes and four rank counts (2026-08-06), and the trigger was a human saving an
# empty .claude/settings.json in vim - about as ordinary as a mistake gets.
#
# Settings resolution happens before the watch loop, so a broker that is gone by now
# refused to start. `kill -0` is NOT enough: bash has not reaped it, so a dead child is
# a zombie and `kill -0` succeeds. Read the actual state instead.
sleep 1
_husk_step_state=$(sed -n 's/^State:[[:space:]]*\([A-Z]\).*/\1/p' \
"/proc/$_husk_step_pid/status" 2>/dev/null)
case "${_husk_step_state:-gone}" in
Z|gone)
echo "husk: the step broker refused to start, so srun cannot work in this job." >&2
echo "husk: failing the job now, rather than letting every srun hang silently" >&2
echo "husk: until the walltime expires. The reason it refused:" >&2
if [ -f "$_husk_log" ]; then
sed -n 's/^husk: /husk:     /p' "$_husk_log" 2>/dev/null | tail -n 4 >&2
else
echo "husk:     (see the step broker's output above)" >&2
fi
exit 1
;;
esac
_husk_extra+=(--ro-bind "$_husk_stub" "$_husk_real_srun")
fi
else
# SAY SO. Continuing is the right call - the stub is convenience, not containment -
# but doing it silently means a job where srun is NOT brokered looks exactly like one
# where it is, until srun fails inside the cage with a scheduler error about an
# expired allocation. That is what a real srun does with MUNGE masked and no route,
# and diagnosing it from the message alone costs a bring-up round (2026-07-31).
echo "husk: srun is NOT brokered in this job - the step pair is inactive" >&2
echo "husk:   stub=$_husk_stub" >&2
echo "husk:   broker=$_husk_broker" >&2
echo "husk:   srun=${_husk_real_srun:-<not found on this node>}" >&2
echo "husk:   a real srun in the cage cannot reach slurmctld; run husk from its" >&2
echo "husk:   installed prefix so <prefix>/lib/husk/srun-stub.py resolves" >&2
fi
# Catch the signal SLURM ends a job with, for TWO reasons.
#
# 1. Without a trap an untrapped SIGTERM kills this shell outright, so NONE of the
#    cleanup below runs - the step-broker, the proxy, the socket dir and the step spool
#    all leak on every preempted job. bash defers a trap until the foreground command
#    finishes, and that command has been signalled too, so the handler runs right after
#    the cage exits and the normal path continues.
# 2. It is how the job learns its output is PARTIAL. See the message below.
_husk_signalled=
trap '_husk_signalled=SIGTERM' TERM
trap '_husk_signalled=SIGINT' INT
  # --- husk: remember which mask targets do not exist yet (A4-S3) ---
_husk_masks=('/work/project/.Rprofile' '/work/project/.Renviron' '/work/project/.claude' '/work/project/.vscode' '/work/project/.idea' '/work/project/.git' '/work/project/.hg')
_husk_made=(); _husk_madedir=()
for _m in "${_husk_masks[@]}"; do
  [ -e "$_m" ] || _husk_made+=("$_m")
  _d=$(dirname "$_m" 2>/dev/null) || _d=
  [ -z "$_d" ] || [ -e "$_d" ] || _husk_madedir+=("$_d")
done
seccomp-wrapper --profile=single-node bwrap '--die-with-parent' '--ro-bind' '/' '/' '--dev' '/dev' '--proc' '/proc' '--tmpfs' '/tmp' '--tmpfs' '/dev/shm' '--unshare-pid' '--dev-bind-try' '/dev/nvidiactl' '/dev/nvidiactl' '--dev-bind-try' '/dev/nvidia-uvm' '/dev/nvidia-uvm' '--dev-bind-try' '/dev/nvidia-uvm-tools' '/dev/nvidia-uvm-tools' '--dev-bind-try' '/dev/nvidia-caps' '/dev/nvidia-caps' '--dev-bind-try' '/dev/gdrdrv' '/dev/gdrdrv' '--dev-bind-try' '/dev/nvidia0' '/dev/nvidia0' '--dev-bind-try' '/dev/nvidia1' '/dev/nvidia1' '--dev-bind-try' '/dev/nvidia2' '/dev/nvidia2' '--dev-bind-try' '/dev/nvidia3' '/dev/nvidia3' '--dev-bind-try' '/dev/nvidia4' '/dev/nvidia4' '--dev-bind-try' '/dev/nvidia5' '/dev/nvidia5' '--dev-bind-try' '/dev/nvidia6' '/dev/nvidia6' '--dev-bind-try' '/dev/nvidia7' '/dev/nvidia7' '--dev-bind-try' '/dev/nvidia-nvswitchctl' '/dev/nvidia-nvswitchctl' '--dev-bind-try' '/dev/nvidia-nvswitch0' '/dev/nvidia-nvswitch0' '--dev-bind-try' '/dev/nvidia-nvswitch1' '/dev/nvidia-nvswitch1' '--dev-bind-try' '/dev/nvidia-nvswitch2' '/dev/nvidia-nvswitch2' '--dev-bind-try' '/dev/nvidia-nvswitch3' '/dev/nvidia-nvswitch3' '--dev-bind-try' '/dev/kfd' '/dev/kfd' '--tmpfs' '/users' '--bind' '/work/project' '/work/project' '--tmpfs' '/work/project/.claude' '--tmpfs' '/work/project/.vscode' '--tmpfs' '/work/project/.idea' '--tmpfs' '/work/project/.git' '--tmpfs' '/work/project/.hg' '--ro-bind-try' '/work/project/.mcp.json' '/work/project/.mcp.json' '--ro-bind-try' '/dev/null' '/work/project/.Rprofile' '--ro-bind-try' '/dev/null' '/work/project/.Renviron' '--unshare-net' ${_husk_extra[@]+"${_husk_extra[@]}"} -- /bin/bash "$0" "$@"
_husk_rc=$?
  # --- husk: reclaim the mount points husk itself created (A4-S3) ---
  # Only paths recorded as ABSENT above, and only while still empty: a file
  # the project shipped was bound over, never created, and is not ours.
  # Every path SAYS what happened to it. The spool cleanup below learned this
  # the expensive way — a failure with no branch leaked a spool per job, in
  # silence. A reclaim that quietly keeps a file is the same shape (P7).
  _husk_kept=0
  for _m in ${_husk_made[@]+"${_husk_made[@]}"}; do
    if [ -d "$_m" ]; then rmdir "$_m" 2>/dev/null || _husk_kept=$((_husk_kept+1))
    elif [ -f "$_m" ] && [ ! -s "$_m" ]; then rm -f "$_m" 2>/dev/null || _husk_kept=$((_husk_kept+1))
    elif [ -e "$_m" ]; then _husk_kept=$((_husk_kept+1)); fi
  done
  if [ "$_husk_kept" -gt 0 ]; then
    echo "husk: kept $_husk_kept mask mount-point(s) - not empty, or not removable." >&2
    echo "husk: husk creates these to mask a file the job must not write; one that" >&2
    echo "husk: gained content is NOT deleted. Remove it yourself if it is not yours." >&2
  fi
  # rmdir, never rm -r: a directory that gained real content keeps it and
  # stays — the safe outcome. Files are listed before dirs, so a reclaimed
  # mask leaves its parent empty in time for this pass.
  for _d in ${_husk_madedir[@]+"${_husk_madedir[@]}"}; do
    rmdir "$_d" 2>/dev/null
  done
# The step-broker holds the credentials the job must not have, so it dies WITH the job.
# It also sets PR_SET_PDEATHSIG, so this is the belt to that pair of braces.
[ -n "$_husk_step_pid" ] && kill "$_husk_step_pid" 2>/dev/null
# The egress proxy holds the one route out of this job, so it dies WITH the job for the
# same reason the step-broker does. It sets PR_SET_PDEATHSIG too; this is the belt.
[ -n "${_husk_net_pid:-}" ] && kill "$_husk_net_pid" 2>/dev/null
# --- husk: cleanup ---
# ...and the node-local directory its socket lived in. Same rule as the step spool:
# by name, then rmdir, so anything else in there keeps the directory instead of being
# deleted. /tmp is node-local, so this is the only chance to clean it up.
if [ -n "${_husk_net_dir:-}" ] && _husk_ours "$_husk_net_dir"; then
rm -f "$_husk_net_dir/net.sock" 2>/dev/null
rmdir "$_husk_net_dir" 2>/dev/null
fi
# --- husk: remove the step spool ---
# Per-JOB and worthless the moment the job ends, but it is created in the user's working
# directory, so one left behind per job turns an active project into a litter tray. It is
# now unconditional: the record worth keeping is $_husk_log, which is not in here.
#
# Removed by name and then rmdir, never `rm -rf`: this runs with the user's rights in a
# directory the JOB can write, so a recursive delete would be a deletion primitive aimed
# at whatever else ended up there. Anything unrecognised makes rmdir fail, the directory
# survives, and we say so - the safe outcome, out loud rather than silently.
#
# This list must cover every file the guard creates in the spool. When egress was added
# it did not: net.sock, socat and net-proxy.log were never removed, so rmdir failed and
# EVERY networked job leaked its spool, silently, because the failure had no branch that
# reported it. A test now derives the required names from the generated script.
# THE STAGED BODY IS NOT DELETED HERE, and that is the fix for a real defect.
#
# This used to say the body was owned by the guard - it must outlive submission but not
# outlive the job - and then rm -f it. The job is not the TASK. One submission
# is N array tasks, so N guards each reclaim the shared script: an --array=1-27 %6 run had
# tasks 1-6 succeed and 7-27 fail identically with No such file or directory, because the
# first wave finished and deleted what the rest were still going to read (2026-08-09).
# A REQUEUED job hits the same thing, and husk forces the preemptible partition, so that is
# the normal case rather than an edge one.
#
# The guard is simply the wrong owner: a per-task actor cannot release a per-submission
# resource, because nothing here knows whether another task is still queued. Ownership is
# the session's now, age-based, at the next husk start (see `bodies_to_prune`).
# The per-job /dev/shm directory the ranks create and share. It had no owner and no
# release on ANY path, not even the clean one: a step exited 0 and the directory stayed,
# RAM-backed, holding whatever MPI segments were in it, until something else on the node
# happened to clear it. rmdir, not rm -rf: this is /dev/shm, it is shared with every
# other user, and a recursive delete pointed at a path someone else may have created
# first is a deletion primitive. If it is not empty we leave it and say so.
_husk_shm="/dev/shm/husk-${SLURM_JOB_ID:-nojob}"
if _husk_ours "$_husk_shm"; then
rm -f "$_husk_shm"/* 2>/dev/null
rmdir "$_husk_shm" 2>/dev/null \
|| echo "husk: kept $_husk_shm - it is not empty" >>"$_husk_log" 2>/dev/null
fi
if [ -z "$_husk_spool" ]; then
# UNCONDITIONAL, and this is why: a job left a step spool behind with NO message
# anywhere, and the directory mtime proved this block had never run. Silence made
# "did not execute" and "executed and failed" indistinguishable, which cost a round
# of guessing. Every path through the cleanup says what it did.
echo "husk: no step spool to clean (spool=<empty>)" >>"$_husk_log" 2>/dev/null
elif _husk_ours "$_husk_spool"; then
# NOTE THE SHAPE: this line NAMES what it removes, so every artifact anyone adds to
# the spool must be added here too, or the rmdir below fails and the whole spool leaks.
# A cleanup that enumerates is a denylist. It cost three selftest failures the day the
# broker heartbeat arrived (2026-08-06), caught on hardware by the arm that exists for
# exactly this.
#
# GENERATED - every glob of it - from step::step_spool_globs(), so the shell cannot
# drift from the Rust, and a test writes one file per glob and RUNS this block to prove
# each glob works. It used to be two hand-written rm lines whose comment claimed they
# covered "the write-and-rename temp": true of the heartbeat's, which is deliberately
# named as a suffix of it, and false of the OTHER write-and-rename in this same
# directory. write_atomic names its temp with a LEADING DOT, no glob here began with
# one, and a shell glob does not match a leading dot - so one interrupted step response
# left .resp-<id>.json.tmp, the rmdir failed, and the job reported "it still holds"
# about a file husk had written itself.
rm -f "$_husk_spool"/req-*.json "$_husk_spool"/resp-*.json "$_husk_spool"/out-* "$_husk_spool"/err-* "$_husk_spool"/broker.alive* "$_husk_spool"/.*.tmp 2>/dev/null
if rmdir "$_husk_spool" 2>/dev/null; then
echo "husk: step spool removed" >>"$_husk_log" 2>/dev/null
else
_husk_left=$(ls -A "$_husk_spool" 2>/dev/null | tr '\n' ' ')
echo "husk: kept $_husk_spool - it still holds: $_husk_left" >&2
echo "husk: kept $_husk_spool - it still holds: $_husk_left" >>"$_husk_log" 2>/dev/null
fi
elif [ ! -e "$_husk_spool" ] && [ ! -L "$_husk_spool" ]; then
echo "husk: no step spool to clean ($_husk_spool is already gone)" >>"$_husk_log" 2>/dev/null
else
# REFUSED, and note what is NOT here: no `rm`, and no `ls -A`. Both halves of `RDF-D-1`
# were in this branch's predecessor - the deletion AND the listing of the target echoed
# onto the job's stderr, which lands in `--output`, which the agent reads. A cleanup
# that cannot prove what it is standing in tells you the name and nothing about the
# contents (`P2`: the confined side supplies neither its own boundary nor its own
# record).
#
# This is a leaked directory, never a failed job: the body has already run and exited.
echo "husk: NOT cleaning $_husk_spool - it is no longer a directory husk owns (a" >&2
echo "husk: symlink, or owned by somebody else). husk removes files BY NAME inside a" >&2
echo "husk: directory it created; it will not follow a name that now points somewhere" >&2
echo "husk: else, so nothing was deleted and nothing there was listed. The path is" >&2
echo "husk: yours to remove." >&2
echo "husk: NOT cleaning $_husk_spool - not a directory husk owns; nothing deleted" \
>>"$_husk_log" 2>/dev/null
fi
# PARTIAL OUTPUT IS THE FAILURE MODE THAT MATTERS HERE.
#
# husk forces every job onto one partition, and on a preemptible one any job from any
# other partition interrupts it - that is exactly what keeps an agent from ever blocking
# the machine. The cost of that cheap guarantee is this: an interrupted run leaves output
# behind. A model that does not checkpoint (ICON with lrestart = .FALSE.) leaves a
# directory that looks much like a finished run, and an agent reading it can report that
# the science ran. For a weather service that is a worse outcome than an escape.
#
# So say it, unmissably, in BOTH places someone looks: the job's own stderr and husk's
# job log. The exit status already differs (143), but the thing at risk is a reader
# looking at the OUTPUT DIRECTORY, who never sees an exit status.
#
# Deliberately NOT claiming "preempted": SLURM sends SIGTERM for preemption, for a
# wall-clock limit and for scancel alike, and they are indistinguishable from in here.
# Naming the wrong cause confidently is the mistake husk keeps having to fix - so state
# the fact (it ended early) and the consequence (the output is incomplete), which hold
# whichever it was.
if [ -n "$_husk_signalled" ] || [ "$_husk_rc" = 143 ] || [ "$_husk_rc" = 137 ]; then
{
echo "husk: =========================================================="
echo "husk: THIS JOB WAS TERMINATED EARLY - ITS OUTPUT IS INCOMPLETE"
echo "husk:   job        : ${SLURM_JOB_ID:-nojob}"
echo "husk:   ended by   : ${_husk_signalled:-signal} (exit $_husk_rc)"
echo "husk:   likely why : preemption, the partition wall limit, or scancel -"
echo "husk:                these are indistinguishable from inside the job."
echo "husk: Do NOT read the output directory as a completed run. A model that"
echo "husk: does not checkpoint (e.g. ICON with lrestart = .FALSE.) leaves files"
echo "husk: that look like a successful run. Check the job's state with"
echo "husk:   sacct -j ${SLURM_JOB_ID:-<jobid>} -o JobID,State,Elapsed,ExitCode"
echo "husk: before believing any result in it."
echo "husk: =========================================================="
} 2>&1 | tee -a "$_husk_log" >&2
fi
if [ "$_husk_rc" = 159 ]; then
echo "husk: job killed by SIGSYS - a syscall blocked by husk's seccomp-wrapper." >&2
echo "husk: strace will NOT tell you which one: ptrace is blocked too, so strace dies" >&2
echo "husk: the same way. Reproduce the command OUTSIDE husk instead --" >&2
echo "husk:   strace -f -o trace.log <your command>   # on the login node, no husk" >&2
echo "husk: -- and look for one of the calls husk blocks. Send us trace.log." >&2
echo "husk: Common causes: io_uring (libuv/CMake/node - husk now returns ENOSYS for" >&2
echo "husk: the probe, so this is no longer it), keyctl, bpf, perf_event_open." >&2
fi
# THE LAST LINE, on every path husk controls.
#
# Its ABSENCE is the diagnostic. A trapped signal gets the block above, which names sacct.
# But SIGKILL - the OOM killer, a cgroup limit, scancel -9 - cannot be trapped, so the job
# vanishes and husk writes nothing at all. An agent then cannot tell a husk refusal from
# the machine taking the job away, and the LETKF session burned a second 128-rank
# allocation on exactly that ambiguity: it read a silent death as a transient node fault
# and retried.
#
# So: if this line is in the job output, husk reached the end and the exit status is the
# workload own. If it is missing, the job was killed in a way nothing inside it could
# observe, and sacct is the only place the reason exists.
#
# ONE terse line, deliberately. The first version explained all of that here, on every
# job including every successful one, and a test caught it: husk must not comment on an
# ordinary failure or every failing job looks like a sandbox problem. The marker has to
# be PRESENT to make its absence mean something; it does not have to be loud. The
# explanation belongs in the skill, which is read once, not in every job output.
echo "husk: job guard finished (rc=$_husk_rc)" >&2
exit "$_husk_rc"
fi
export HUSK_WRITABLE='/work/project:/scratch/shared'
echo "husk: compute cage active - the filesystem is READ-ONLY except:" >&2
echo "husk:   /work/project  (project dir: where husk was launched)" >&2
echo "husk:   /scratch/shared" >&2
echo "husk: a write outside the list above fails with 'Read-only file" >&2
echo "husk: system' - that is husk, not the filesystem." >&2
echo "husk: reads are mostly unrestricted, with three deliberate gaps:" >&2
echo "husk:   home directories are hidden (they look EMPTY, not missing)," >&2
echo "husk:   configured denyRead paths are hidden the same way, and" >&2
echo "husk:   credential files read as empty or refuse with EACCES." >&2
echo "husk: If a file you expect is empty or absent, that may be husk" >&2
echo "husk: hiding it rather than the file being gone. Copy what the job" >&2
echo "husk: needs to the writable set above." >&2
echo "husk: masked (they read as empty or refuse - credential-named files and" >&2
echo "husk: auto-exec files husk protects, e.g. .git/hooks):" >&2
echo "husk:   /work/project/.Rprofile" >&2
echo "husk:   /work/project/.Renviron" >&2
echo "husk: this is a HEURISTIC on the file name and it can be wrong. If one of" >&2
echo "husk: those is not a secret, rename it or declare the real ones in" >&2
echo "husk: sandbox.credentials.files and they will be the only ones masked." >&2
echo "husk: this job HOLDS: nodes=${SLURM_JOB_NUM_NODES:-?} ntasks=${SLURM_NTASKS:-<unset>} cpus-per-task=${SLURM_CPUS_PER_TASK:-<unset>} cpus-on-node=${SLURM_CPUS_ON_NODE:-?}" >&2
echo "husk: if that is not what you asked for: husk forces --nodes=1, --export=ALL," >&2
echo "husk: --open-mode=append and the output paths, and resolves --partition," >&2
echo "husk: --account and --uenv against your operator's allowlists. Anything else" >&2
echo "husk: is passed through, so a mismatch there is upstream of husk." >&2
echo "husk: this job RUNS AS: partition=${SLURM_JOB_PARTITION:-?} account=${SLURM_JOB_ACCOUNT:-<none>}" >&2
echo "husk:   uenv=${UENV_MOUNT_LIST:-<none>} view=${UENV_VIEW:-<none>}" >&2
echo "husk: network: this job has NO outbound network. A connection that" >&2
echo "husk: hangs or refuses is husk, not the site. Fetch what the job needs" >&2
echo "husk: before submitting, into the writable set above." >&2
echo "husk: working inside husk? the 'husk' skill explains these rules," >&2
echo "husk: what is masked, and what to do when something is refused." >&2
echo "husk: husk's own log for this job: ${HUSK_JOB_LOG:-<merged into stderr>}" >&2
# --- hand off to the agent's script, inside the cage ---
exec /bin/bash "$_husk_body" "$@"
