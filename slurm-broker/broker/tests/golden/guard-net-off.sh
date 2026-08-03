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
seccomp-wrapper --profile=single-node bwrap '--ro-bind' '/' '/' '--dev' '/dev' '--proc' '/proc' '--tmpfs' '/tmp' '--tmpfs' '/dev/shm' '--unshare-pid' '--dev-bind-try' '/dev/nvidiactl' '/dev/nvidiactl' '--dev-bind-try' '/dev/nvidia-uvm' '/dev/nvidia-uvm' '--dev-bind-try' '/dev/nvidia-uvm-tools' '/dev/nvidia-uvm-tools' '--dev-bind-try' '/dev/nvidia-caps' '/dev/nvidia-caps' '--dev-bind-try' '/dev/gdrdrv' '/dev/gdrdrv' '--dev-bind-try' '/dev/nvidia0' '/dev/nvidia0' '--dev-bind-try' '/dev/nvidia1' '/dev/nvidia1' '--dev-bind-try' '/dev/nvidia2' '/dev/nvidia2' '--dev-bind-try' '/dev/nvidia3' '/dev/nvidia3' '--dev-bind-try' '/dev/nvidia4' '/dev/nvidia4' '--dev-bind-try' '/dev/nvidia5' '/dev/nvidia5' '--dev-bind-try' '/dev/nvidia6' '/dev/nvidia6' '--dev-bind-try' '/dev/nvidia7' '/dev/nvidia7' '--dev-bind-try' '/dev/nvidia-nvswitchctl' '/dev/nvidia-nvswitchctl' '--dev-bind-try' '/dev/nvidia-nvswitch0' '/dev/nvidia-nvswitch0' '--dev-bind-try' '/dev/nvidia-nvswitch1' '/dev/nvidia-nvswitch1' '--dev-bind-try' '/dev/nvidia-nvswitch2' '/dev/nvidia-nvswitch2' '--dev-bind-try' '/dev/nvidia-nvswitch3' '/dev/nvidia-nvswitch3' '--tmpfs' '/users' '--bind' '/work/project' '/work/project' '--tmpfs' '/work/project/.claude' '--tmpfs' '/work/project/.git/hooks' '--tmpfs' '/work/project/.vscode' '--tmpfs' '/work/project/.idea' '--ro-bind-try' '/work/project/.mcp.json' '/work/project/.mcp.json' '--ro-bind-try' '/work/project/.git/config' '/work/project/.git/config' '--unshare-net' ${_husk_extra[@]+"${_husk_extra[@]}"} -- /bin/bash "$0" "$@"
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
export HUSK_WRITABLE='/work/project:/scratch/shared'
echo "husk: compute cage active - the filesystem is READ-ONLY except:" >&2
echo "husk:   /work/project  (project dir: where husk was launched)" >&2
echo "husk:   /scratch/shared" >&2
echo "husk: reads are unrestricted. A write outside the list above fails" >&2
echo "husk: with 'Read-only file system' - that is husk, not the filesystem." >&2
echo "husk: husk's own log for this job: ${HUSK_JOB_LOG:-<merged into stderr>}" >&2
# --- hand off to the agent's script, inside the cage ---
exec /bin/bash "$_husk_body" "$@"
