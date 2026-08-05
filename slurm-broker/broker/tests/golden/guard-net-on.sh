#!/bin/bash
# --- injected by husk-slurm-broker: re-exec once inside the compute-side sandbox ---
# The agent's script, as DATA. Set before the branch because both halves need it: the
# in-cage half execs it, the outer half removes it. One origin for the path, so the two
# cannot drift - the cleanup set has already been wrong once, and every file the guard is
# responsible for must be named exactly once.
_husk_body='/work/.husk-body-t.sh'
if [ -z "${_HUSK_RESANDBOXED:-}" ]; then
export _HUSK_RESANDBOXED=1
# An ARRAY, not a string. A string of pre-quoted arguments expanded unquoted gets
# word-split but NOT quote-removed, so bwrap would receive a path with literal quotes
# in it - which is exactly how the srun bind below took every job down once.
_husk_extra=()
_husk_seen=
for _d in /run/munge /var/run/munge; do
[ -d "$_d" ] || continue
_r=$(readlink -f "$_d" 2>/dev/null || echo "$_d")
case " $_husk_seen " in *" $_r "*) continue ;; esac
_husk_seen="$_husk_seen $_r"
_husk_extra+=(--tmpfs "$_r")
done
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
_husk_spool='/work/project'"/.husk-step-spool-${SLURM_JOB_ID:-nojob}"
mkdir -p "$_husk_spool" 2>/dev/null || _husk_spool=
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
  # The relay needs socat INSIDE the cage, and husk's own socat lives at
  # <prefix>/bin/socat — under the user's HOME, which the cage tmpfs-masks. So bind it in,
  # read-only, over an empty file in the spool. A copy would also work and be simpler, but
  # the spool sits inside the WRITABLE workdir, so a copy is something the job could
  # overwrite before its own relay starts; a read-only bind is not. The bind goes into
  # _husk_extra, appended last, so it wins over the workdir bind — the same ordering the
  # MUNGE mask depends on.
  #
  # ALWAYS bind, wherever the binary came from. An earlier version used a socat found on
  # PATH as-is, on the assumption that anything on PATH is visible inside the cage. It is
  # not: this runs OUTSIDE the cage, --export=ALL carries the login PATH, so `command -v`
  # finds husk's OWN socat under /users — which the cage then masks. The relay silently
  # never started (Balfrin, twice). Binding unconditionally removes the reasoning: the
  # relay uses one known path that is visible by construction.
  _husk_socat=
  _husk_socat_src=$(command -v socat 2>/dev/null || true)
  [ -n "$_husk_socat_src" ] || _husk_socat_src='<HUSK_SOCAT>'
  if [ -x "$_husk_socat_src" ]; then
    # Bound to a path in the cage's OWN tmpfs, never over a file on the host. The previous
    # design created an empty placeholder in the step spool and bind-mounted socat over it,
    # which left a file that could not be removed: a dentry that is still a mountpoint
    # cannot be unlinked, so the cleanup rm failed with EBUSY (silently, under 2>/dev/null)
    # and every job that ran a step kept its spool. bwrap creates this mountpoint inside its
    # own namespace and it vanishes with the cage - nothing to clean up, so nothing to leak.
    _husk_socat=/tmp/husk-socat
    _husk_extra+=(--ro-bind "$_husk_socat_src" "$_husk_socat")
  fi
  if [ -n "$_husk_socat" ]; then
    # The HOST path, not the in-cage one: the step-broker hands this to each rank, and a
    # rank must bind it into its own cage (bwrap namespaces do not propagate).
    export HUSK_SOCAT="$_husk_socat_src"
  else
    echo "husk: no socat available, so this job gets no network." >&2
    echo "husk:   looked for '<HUSK_SOCAT>'" >&2
    echo "husk: the cage masks /users, so a socat in your home must be bound in, and the" >&2
    echo "husk: job spool was not usable here. Re-run install-husk.sh, or ask for socat" >&2
    echo "husk: system-wide on the compute nodes." >&2
  fi
  # Egress proxy: OUTSIDE the cage, holding the allowlist. It resolves the policy from the
  # settings files itself rather than being handed it, so what is in force never depends on
  # a string carried on a command line.
  #
  # Started BEFORE the step-broker on purpose: the step-broker inherits HUSK_NET_SOCK and
  # HUSK_SOCAT and passes them to each rank, so both have ONE origin instead of being
  # rebuilt from the job id in two places that could drift.
  # The socket does NOT live in the step spool, and cannot.
  #
  # A unix socket address must fit in sun_path - 108 bytes, fixed by the kernel, with no
  # way to ask for more. <workdir>/.husk-step-spool-<jobid>/net.sock spends ~34 of those
  # on the suffix alone, so the budget for the project path was ~73 bytes. A real Balfrin
  # project measured ~57: it worked, with under 20 to spare, and a project a couple of
  # directories deeper would have lost its network to a bare "AF_UNIX path too long".
  #
  # So: a short, node-local, per-job directory instead - created by `mktemp -d`, with a
  # RANDOM suffix, and that randomness is the point (O1).
  #
  # The name used to be exactly `/tmp/husk-<uid>-<jobid>`, and job ids are public in
  # squeue, so the path was predictable before it existed. `mkdir` + an ownership test
  # answers the CROSS-USER version of that (someone else's directory is not ours, so the
  # job gets no network) but NOT the same-uid version: a second session of the same user,
  # or an escaped agent, could pre-create the directory for a job id it expected, pass the
  # `-O` test - it really is that uid's directory - and still hold a handle on the path the
  # ranks later resolve. AF_UNIX connect needs only write permission on the socket, and
  # permission does not distinguish two sessions of one user; only NAMING does.
  #
  # `mktemp -d` closes it by construction: it creates the directory atomically at a name
  # nobody could have guessed, 0700, and fails rather than accepting one that exists. So
  # the directory is ours because we made it, not because it looked like ours. The proxy
  # still re-checks ownership and mode before binding - the shell only proposes - and the
  # socket is BIND-mounted into each cage, so a later swap of the host path cannot redirect
  # a job that has already resolved it. Cost: ~7 more bytes of the 108-byte sun_path
  # budget, out of the ~34 this layout spends.
  #
  # It is bound into the cage READ-ONLY. connect(2) works fine through a read-only bind
  # under --unshare-net - measured on 6.8, then confirmed on the kernel that matters when
  # net.live fetched through this socket on Balfrin (5.14.21, Cray Shasta, 2026-08-01).
  # The job then cannot delete or replace its own socket, which it could when the socket
  # sat in the writable spool.
  _husk_net_dir=$(mktemp -d "/tmp/husk-$(id -u 2>/dev/null || echo u)-${SLURM_JOB_ID:-nojob}-XXXXXX" 2>/dev/null || true)
  if [ -n "$_husk_net_dir" ] && [ -d "$_husk_net_dir" ] && [ -O "$_husk_net_dir" ]; then
    chmod 700 "$_husk_net_dir" 2>/dev/null
    rm -f "$_husk_net_dir/net.sock" 2>/dev/null
    _husk_net_sock="$_husk_net_dir/net.sock"
    # --workdir is where the proxy READS ITS ALLOWLIST FROM, so it must be the trusted
    # project dir and not "$PWD". $PWD here is the job's --chdir, which is confined to the
    # writable set but chosen by the agent within it — so the confined side got to pick
    # which settings files decided its own egress policy. The submit-time half already
    # resolved the allowlist from the project dir; the two halves disagreed, and main.rs
    # says out loud that the policy comes from "files the agent cannot write".
    "$_husk_broker" --net-proxy --socket "$_husk_net_sock" --workdir '/work/project' \
      >>"$_husk_log" 2>&1 &
    _husk_net_pid=$!
    export HUSK_NET_SOCK="$_husk_net_sock"
    # Bind the SOCKET, not its directory — and wait for the proxy to create it first.
    #
    # Binding the directory was the obvious move (the socket does not exist yet, and a
    # bwrap bind with a missing source kills the cage), but it makes the DIRECTORY a
    # mountpoint, and a dentry that is still a mountpoint cannot be unlinked or removed
    # while anything holds that mount. That is exactly what stranded the socat placeholder
    # in the step spool: the cleanup ran, the removal failed with EBUSY, and 2>/dev/null
    # hid it. A per-job directory on node-local /tmp that fails to rmdir accumulates on a
    # node that reboots rarely, which is the one thing node-local scratch must not do.
    #
    # So: bounded wait for the bind, then bind the file. The directory is never a
    # mountpoint, so its rmdir always succeeds. If the proxy never binds we leave
    # HUSK_NET_SOCK unset rather than binding a missing source — the relay then sees no
    # socket and the job runs without egress, which is the safe direction.
    _husk_w=0
    while [ ! -S "$_husk_net_sock" ] && [ "$_husk_w" -lt 50 ]; do
      sleep 0.1
      _husk_w=$((_husk_w + 1))
    done
    if [ -S "$_husk_net_sock" ]; then
      _husk_extra+=(--ro-bind "$_husk_net_sock" "$_husk_net_sock")
    else
      unset HUSK_NET_SOCK
      echo "husk: the egress proxy did not bind $_husk_net_sock within 5s, so this job" >&2
      echo "husk: has no network. Its own log is ${HUSK_JOB_LOG:-the husk job log}." >&2
    fi
  else
    # Report BEFORE clearing the variable - naming the path is the whole point of the
    # message, and an unattributed "no network" is exactly the failure mode husk keeps
    # having to fix.
    echo "husk: could not create a private directory under /tmp for this job's egress" >&2
    echo "husk:   socket, so this job gets no network. mktemp -d failed, or what it made" >&2
    echo "husk:   is not a directory this job owns. husk will not route a job's egress" >&2
    echo "husk:   through a directory it did not create itself." >&2
    _husk_net_dir=
  fi
  _husk_step_pid=
_husk_stub='<HUSK_STUB>'
_husk_real_srun=$(command -v srun 2>/dev/null || true)
if [ -r "$_husk_stub" ] && [ -x "$_husk_broker" ] && [ -n "$_husk_real_srun" ]; then
if [ -n "$_husk_spool" ]; then
export HUSK_STEP_SPOOL="$_husk_spool"
"$_husk_broker" --step-broker --spool "$_husk_spool" --workdir '/work/project' \
>>"$_husk_log" 2>&1 &
_husk_step_pid=$!
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
seccomp-wrapper --profile=single-node bwrap '--die-with-parent' '--ro-bind' '/' '/' '--dev' '/dev' '--proc' '/proc' '--tmpfs' '/tmp' '--tmpfs' '/dev/shm' '--unshare-pid' '--dev-bind-try' '/dev/nvidiactl' '/dev/nvidiactl' '--dev-bind-try' '/dev/nvidia-uvm' '/dev/nvidia-uvm' '--dev-bind-try' '/dev/nvidia-uvm-tools' '/dev/nvidia-uvm-tools' '--dev-bind-try' '/dev/nvidia-caps' '/dev/nvidia-caps' '--dev-bind-try' '/dev/gdrdrv' '/dev/gdrdrv' '--dev-bind-try' '/dev/nvidia0' '/dev/nvidia0' '--dev-bind-try' '/dev/nvidia1' '/dev/nvidia1' '--dev-bind-try' '/dev/nvidia2' '/dev/nvidia2' '--dev-bind-try' '/dev/nvidia3' '/dev/nvidia3' '--dev-bind-try' '/dev/nvidia4' '/dev/nvidia4' '--dev-bind-try' '/dev/nvidia5' '/dev/nvidia5' '--dev-bind-try' '/dev/nvidia6' '/dev/nvidia6' '--dev-bind-try' '/dev/nvidia7' '/dev/nvidia7' '--dev-bind-try' '/dev/nvidia-nvswitchctl' '/dev/nvidia-nvswitchctl' '--dev-bind-try' '/dev/nvidia-nvswitch0' '/dev/nvidia-nvswitch0' '--dev-bind-try' '/dev/nvidia-nvswitch1' '/dev/nvidia-nvswitch1' '--dev-bind-try' '/dev/nvidia-nvswitch2' '/dev/nvidia-nvswitch2' '--dev-bind-try' '/dev/nvidia-nvswitch3' '/dev/nvidia-nvswitch3' '--tmpfs' '/users' '--bind' '/work/project' '/work/project' '--tmpfs' '/work/project/.claude' '--tmpfs' '/work/project/.vscode' '--tmpfs' '/work/project/.idea' '--tmpfs' '/work/project/.git' '--tmpfs' '/work/project/.hg' '--ro-bind-try' '/work/project/.mcp.json' '/work/project/.mcp.json' '--ro-bind-try' '/dev/null' '/work/project/.Rprofile' '--unshare-net' ${_husk_extra[@]+"${_husk_extra[@]}"} -- /bin/bash "$0" "$@"
_husk_rc=$?
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
if [ -n "${_husk_net_dir:-}" ] && [ -d "$_husk_net_dir" ]; then
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
# The agent's staged body. Owned by the guard because it must outlive submission (the
# job has to be able to read it) but must not outlive the job.
rm -f "$_husk_body" 2>/dev/null
# The per-job /dev/shm directory the ranks create and share. It had no owner and no
# release on ANY path, not even the clean one: a step exited 0 and the directory stayed,
# RAM-backed, holding whatever MPI segments were in it, until something else on the node
# happened to clear it. rmdir, not rm -rf: this is /dev/shm, it is shared with every
# other user, and a recursive delete pointed at a path someone else may have created
# first is a deletion primitive. If it is not empty we leave it and say so.
_husk_shm="/dev/shm/husk-${SLURM_JOB_ID:-nojob}"
if [ -d "$_husk_shm" ] && [ ! -L "$_husk_shm" ] && [ -O "$_husk_shm" ]; then
rm -f "$_husk_shm"/* 2>/dev/null
rmdir "$_husk_shm" 2>/dev/null \
|| echo "husk: kept $_husk_shm - it is not empty" >>"$_husk_log" 2>/dev/null
fi
if [ -n "$_husk_spool" ] && [ -d "$_husk_spool" ]; then
rm -f "$_husk_spool"/req-*.json "$_husk_spool"/resp-*.json 2>/dev/null
rm -f "$_husk_spool"/out-* "$_husk_spool"/err-* 2>/dev/null
if rmdir "$_husk_spool" 2>/dev/null; then
echo "husk: step spool removed" >>"$_husk_log" 2>/dev/null
else
_husk_left=$(ls -A "$_husk_spool" 2>/dev/null | tr '\n' ' ')
echo "husk: kept $_husk_spool - it still holds: $_husk_left" >&2
echo "husk: kept $_husk_spool - it still holds: $_husk_left" >>"$_husk_log" 2>/dev/null
fi
else
# UNCONDITIONAL, and this is why: a job left a step spool behind with NO message
# anywhere, and the directory mtime proved this block had never run. Silence made
# "did not execute" and "executed and failed" indistinguishable, which cost a round
# of guessing. Every path through the cleanup now says what it did.
echo "husk: no step spool to clean (spool=${_husk_spool:-<empty>})" >>"$_husk_log" 2>/dev/null
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
echo "husk: to identify which one, re-run the job with your command wrapped in" >&2
echo "husk:   strace -f -o trace.log <your command>" >&2
echo "husk: the cage stays fully enforcing; the last call before the SIGSYS kill in" >&2
echo "husk: trace.log is the blocked one. Send it to us if it should be allowed." >&2
fi
exit "$_husk_rc"
fi
# --- injected by husk-slurm-broker: egress relay into the cage ---
if [ -n "${HUSK_NET_SOCK:-}" ] && [ -x "/tmp/husk-socat" ]; then
  "/tmp/husk-socat" TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:"$HUSK_NET_SOCK" \
    >/dev/null 2>&1 &
  export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128
  export http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128
  export ALL_PROXY=http://127.0.0.1:3128 all_proxy=http://127.0.0.1:3128
  export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1
elif [ -n "${HUSK_NET_SOCK:-}" ]; then
  echo "husk: the egress relay could not start (no socat in the cage), so this job has" >&2
  echo "husk: no network. The proxy outside the cage refused nothing." >&2
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
echo "husk: husk's own log for this job: ${HUSK_JOB_LOG:-<merged into stderr>}" >&2
# --- hand off to the agent's script, inside the cage ---
exec /bin/bash "$_husk_body" "$@"
