# B1 — resource lifecycle: findings

**Pass 1 (discovery).** Code-only, laptop, no cluster. Every claim marked CONFIRMED was
demonstrated by running something on this machine; everything else is marked PLAUSIBLE.
Reviewed at `f5fd395`. No source file was modified.

## Summary

husk's *login-side* resources are in good shape: the session spool has a named owner, a
cooperative release, and an ownership-gated reaper, and I demonstrated all three (SIGTERM
removes it, SIGKILL leaves it, the next session reaps it). The *compute-side* resources are
not. Three node-local resources — the step spool in the user's workdir, `/tmp/husk-<uid>-<jobid>`,
and `/dev/shm/husk-<jobid>` — are released only by a bash `trap` in the guard, and one of
them is released by nothing at all on any path. I confirmed by running the real generated
scripts that (a) `/dev/shm/husk-<jobid>` survives even a **clean** rank exit, because no
code anywhere removes it, and (b) a SIGKILL to the guard's process group leaves both the
step spool and the node-local egress directory behind with no log line. SIGKILL is not an
exotic ending here: it is what SLURM sends when `KillWait` expires, and I demonstrated that
a workload with its own SIGTERM handler makes that expiry *certain* — the guard's trap is
deferred until the caged command returns, so it never runs. The existing selftest arms
(`guard.preempt_cleanup`, `tmp.reclaimed`, `proc.reclaimed`, `job.spool_reclaimed`) all
exercise the SIGTERM/clean path only, and none of them covers `/dev/shm` at all.

---

## THE TABLE

Tier 1 = cooperative (`Drop`, `trap`, explicit remove) · Tier 2 = kernel-coupled ·
Tier 3 = reaper. **"—" means no release on any path.**

### Login node (outside the cage)

| # | Resource | Acquired at | Named owner | Tier | Evidence |
|---|---|---|---|---|---|
| L1 | Session spool dir `<proj>/.husk-slurm-spool-<pid>` | `husk-slurm-wrapper.rs:404`, `main.rs:413` | the broker that wins `claim_spool` (`main.rs:150`, called `:479`) | **1** + **3** | Demonstrated: SIGTERM → removed (`main.rs:521`); SIGKILL → survives; next broker's `reap_stale_spools` (`main.rs:483`, `lib.rs:159`) removes it. Reaper is uid-gated (`owned_by_me`, `lib.rs:123`, `symlink_metadata`) |
| L2 | `req-*.json` / `resp-*.json` / `job-*.sh` / `.*.tmp` | stub `sbatch-stub.py:182`; `spool.rs:88,173` | broker + stub, each deletes its own | **1** + **3** | `spool.rs:83,206`; stub `finally` `sbatch-stub.py:194`; `Broker::gc` at 1 h (`spool.rs:270`) never touches `req-*`; `remove_spool_dir` sweeps the rest at session end |
| L3 | The broker process | `husk-slurm-wrapper.rs:244` | the wrapper, then the agent (same pid after `exec`) | **1** + **2** | `BrokerHandle::Drop` kills on setup failure (`:196`, pre-exec only); `PR_SET_PDEATHSIG(SIGTERM)` (`main.rs:369`, `:75`) + `getppid()==1` race guard |
| L4 | Read-only query child + its process group | `spool.rs:318` (`process_group(0)`) | `run_query_cmd` | **1** + **2** | `wait_with_output` reaps; watchdog `kill(-pid, SIGKILL)` at 60 s (`:345`). Orphaned if the broker itself is SIGKILLed mid-query; bounded (fixed allowlist, no shell) |
| L5 | **The submitted SLURM job / allocation** | `spool.rs:194` | **none on husk's side** | **2 (SLURM's)** | Released only by the partition wall limit / a human. `submitted` (`spool.rs:42`) is memory-only; nothing cancels at shutdown. See F4 |
| L6 | Session log `~/.husk/log/husk-<utc>-<pid>.log` | `husk-slurm-wrapper.rs:215,236` | none | **—** | Never rotated, never pruned; uninstall deliberately keeps them (`install-husk.sh:97`). See F7 |
| L7 | Wrapper's user+mount ns; stub bind over `sbatch` + 8 query commands | `husk-slurm-wrapper.rs:292,262,374` | the agent process | **2** | Mount namespace dies with the process tree |

### Compute node — job cage layer (guard shell, inside the allocation)

| # | Resource | Acquired at | Named owner | Tier | Evidence |
|---|---|---|---|---|---|
| J1 | **Step spool `<workdir>/.husk-step-spool-<jobid>`** | `policy.rs:827` (unconditional, every brokered job) | the guard shell | **1 ONLY** | Cleanup at `policy.rs:924`. **No reaper**: `is_spool_dir_name` deliberately excludes it (`lib.rs:83`, asserted `lib.rs:360`). Demonstrated leak under SIGKILL — F2 |
| J2 | **Node-local egress dir `/tmp/husk-<uid>-<jobid>` + `net.sock`** | `policy.rs:715` (dir), `main.rs:340` (bind) | the guard shell | **1 ONLY** | Cleanup at `policy.rs:906`. **No reaper anywhere** (grep: no code reads `/tmp/husk-<uid>-*`). Demonstrated leak under SIGKILL — F2 |
| J3 | Egress proxy process | `policy.rs:721` | the guard shell | **1** + **2** | `kill $_husk_net_pid` (`policy.rs:901`) + `die_with_parent()` (`main.rs:281`) + SLURM cgroup |
| J4 | Step-broker process | `policy.rs:865` | the guard shell | **1** + **2** | `kill $_husk_step_pid` (`policy.rs:898`) + `die_with_parent()` (`main.rs:369`) + SLURM cgroup |
| J5 | Job-cage socat relay (inside the cage) | `policy.rs:766` | bwrap | **2** | Job cage has `--unshare-pid` (`settings.rs:631`); bwrap tears the pid namespace down when the job script exits |
| J6 | In-cage bind mounts, `--tmpfs` masks, `/tmp/husk-socat` | `settings.rs:597`, `rank.rs:152` | bwrap | **2** | Mount-namespace teardown. `CAGED_SOCAT` in the cage's own tmpfs is the *fix* for the earlier EBUSY leak — correct shape |
| J7 | Job log `~/.husk/log/job-<jobid>.log` | `policy.rs:846` | none | **—** | One per job, never pruned. See F7 |

### Compute node — step/rank layer

| # | Resource | Acquired at | Named owner | Tier | Evidence |
|---|---|---|---|---|---|
| R1 | **`/dev/shm/husk-<jobid>` (host, outside the cage)** | `rank.rs:272` — per rank, on every node a step lands on | **none** | **—** | **Removed by nothing, on any path.** Only removals in the tree are two unit tests (`rank.rs:631,672`) cleaning up after the generated script. Demonstrated — F1 |
| R2 | userns holder (`--hold-cage` parent) | `step.rs:132` | `StepBroker.holder` (`step.rs:85`) | **2** | stdin EOF when the step-broker's fds close (`main.rs:248`) — kernel-coupled, and Rust marks the pipe CLOEXEC so no child holds the write end; plus `PR_SET_PDEATHSIG(SIGTERM)` (`main.rs:197`), which I **measured** survives `unshare(CLONE_NEWUSER)` |
| R3 | pidns holder child (PID 1 of the job pidns) | `cage.rs:168` | the `--hold-cage` parent | **1** + **2** | Explicit `kill(held, SIGKILL)` on the clean path (`main.rs:264`); `PR_SET_PDEATHSIG(SIGKILL)` set in the child after the fork (`cage.rs:191`, correct — fork clears it); pidns + everything in it dies with PID 1 |
| R4 | The PID and user namespaces themselves | `cage.rs:124,160` | R2/R3 | **2** | Die with their last member |
| R5 | `srun` child processes (steps) | `step.rs:356` | `StepBroker.in_flight` | **1** + **2** | `try_wait` + `retain_mut` (`step.rs:160`); orphans torn down by SLURM job teardown (site-configured proctrack) |
| R6 | `out-<id>` / `err-<id>` step output files | `step.rs:347` | srun-stub, then the guard | **1** + **1** | stub `finally` (`srun-stub.py:144`); guard `rm -f out-* err-*` (`policy.rs:926`). Step-broker has **no `gc()`** of its own, unlike the login broker |
| R7 | `resp-<id>.json` in the step spool | `step.rs:376` | srun-stub, then the guard | **1** + **1** | Same as R6 |
| R8 | Per-rank socat relay (inside the rank cage) | `rank.rs:206` | none explicitly | **2 (job- or step-cgroup)** | Rank *joins* the job pidns (`rank.rs:187,194 --pidns 8`), so the relay outlives its own workload; only SLURM's cgroup teardown reclaims it. See F5 |
| R9 | ns file descriptors 8 / 9 handed to bwrap | `rank.rs:270-271` (`exec 9<`, `exec 8<`) | the rank process | **2** | Closed on process exit |
| R10 | Rank-cage mount + network namespaces | `rank.rs:187` (bwrap) | bwrap | **2** | Die with their last member — but note R8 keeps a rank netns alive past its workload |

### THE TIER-1-ONLY LIST — the headline

Resources whose **only** release is cooperative, i.e. lost on SIGKILL / OOM-kill / node failure:

1. **`<workdir>/.husk-step-spool-<jobid>`** (J1) — in the user's project tree, on the shared filesystem.
2. **`/tmp/husk-<uid>-<jobid>/` and its `net.sock`** (J2) — node-local, on a node that reboots rarely.

And, worse than tier 1 — **no release on any path**:

3. **`/dev/shm/husk-<jobid>`** (R1) — RAM-backed, per job, per node.
4. `~/.husk/log/*` (L6, J7) — deliberate, but uncapped.

Everything else in the table reaches tier 2 or tier 3.

---

## Findings, most severe first

### F1 — `/dev/shm/husk-<jobid>` has no owner and no release, not even on the clean path — CONFIRMED

**What breaks.** The rank wrapper creates a per-job directory in the compute node's real
`/dev/shm` (RAM-backed tmpfs) *before* entering the cage, and nothing in husk ever removes
it. It is not tier 1 — there is no cleanup code to defeat.

```
rank.rs:272   _d=/dev/shm/husk-${SLURM_JOB_ID}
rank.rs:273   mkdir -m 700 "$_d" 2>/dev/null || true
```

An exhaustive grep of the tree finds exactly three other mentions of this path: two are
unit tests that clean up after running the generated script (`rank.rs:631`, `rank.rs:672`)
and one is a design doc. There is no third mention in any production path — not in the
guard cleanup block (`policy.rs:902-940`), not in the step-broker, not in `selftest.sh`.

**Failure scenario.** Any brokered job that runs one `srun` step. The rank script runs
outside every cage (it is the `srun` task command; the job cage's `--tmpfs /dev/shm` does
not apply to it), so the `mkdir` lands on the node's shared `/dev/shm`. Each job leaves one
directory per node. Because the directory *is* what the rank cage binds onto `/dev/shm`
(`rank.rs:188`), it is also where Cray MPICH puts its shared-memory segments — so a rank
that is SIGKILLed (preemption, which is husk's *normal* ending on a preemptible partition)
leaves those segments resident in node RAM inside a directory nothing will ever remove.

**Demonstration.** I transcribed the script generated by `rank::wrap_command`
(`rank.rs:258-284`, `exec_line` at `:183`) verbatim, filled in the broker-supplied values
for a live holder and no egress, and ran it with a stub `seccomp-wrapper`:

```
before: <absent>
[stub seccomp-wrapper: would have entered the cage]
rank script exited rc=0
after : drwx------ 2 christoph christoph 40 /dev/shm/husk-demo26246
--- and after the whole 'job' would have finished, nothing removes it: ---
drwx------ 2 christoph christoph 40 /dev/shm/husk-demo26246   STILL THERE
```

The rank exited **cleanly**, status 0, and the directory remained.

**Why the suite would not catch it.** `steps.shm` (`selftest.sh:657`) asserts only that
ranks *share* `/dev/shm` — i.e. it tests the acquisition. The three reclamation arms cover
the other three node-local resources (`tmp.reclaimed`, `proc.reclaimed`,
`job.spool_reclaimed`); there is no `shm.reclaimed`.

**Caveat I cannot settle from here.** If Balfrin/Santis configure SLURM's
`job_container/tmpfs` plugin with a private `/dev/shm` per job, the kernel reclaims this
and the leak is invisible. That is precisely the shape of the dependency `9faad58` was
written to stop relying on ("SLURM's cgroup teardown reaps it in practice, which is why
nothing broke — but relying on that silently is not the same as saying so"). Confirming
which way it falls is one `ls /dev/shm` in an uncaged follow-up job on a known node — the
same instrument `tmp.reclaimed` already uses.

---

### F2 — the step spool and the node-local egress directory are tier-1-only, and SIGKILL is a *guaranteed* ending for a workload that handles SIGTERM — CONFIRMED

**What breaks.** Both directories are removed only by the guard's cleanup block
(`policy.rs:902-940`), which sits after the foreground `seccomp-wrapper bwrap …` line
(`policy.rs:894`) in a bash shell whose only signal handling is
`trap '_husk_signalled=SIGTERM' TERM` (`policy.rs:892`). SIGKILL is not catchable, and
there is no reaper for either directory.

**Demonstration 1 — SIGTERM vs SIGKILL.** I ran the *real* generated guard
(`broker/tests/golden/guard-net-on.sh`, with only the three install paths and the workdir
substituted) with stubs for `seccomp-wrapper`/`bwrap`/`socat`/the broker, and signalled the
guard's process group the way SLURM signals a job:

```
### SIGTERM  job=900010
  while running: spool=yes  netdir=yes
  afterwards   : spool=removed  netdir=removed

### SIGKILL  job=900012
  while running: spool=yes  netdir=yes
  afterwards   : spool=LEFT BEHIND  netdir=LEFT BEHIND
     netdir holds: net.sock
  cleanup lines in the job log:            <- none
```

Note the last line: on the SIGKILL path there is not even the "husk: kept … it still
holds:" message the design added so that a failed cleanup is never silent. The failure is
*upstream* of every branch that reports.

**Demonstration 2 — the trap is deferred, so KillWait expiry is certain for a workload
that handles SIGTERM.** bash runs a trap handler only after the current foreground command
returns, and the guard's foreground command is the whole cage. With a payload that ignores
SIGTERM (the realistic case: ICON and most MPI codes install a SIGTERM handler for
checkpointing):

```
guard=30347  running: spool=present netdir=present
T+5s after SIGTERM: guard_alive=yes  spool=present netdir=present     <- trap has NOT run
after KillWait SIGKILL: spool=present netdir=present
   netdir holds: net.sock
```

So the guard is still alive and holding both resources when SLURM's `KillWait` countdown
(default 30 s) starts, and the SIGKILL that ends it skips the cleanup entirely. This is not
an unlucky path — for that class of workload it is *the* path.

**Other reachable SIGKILL sources:** OOM-kill of the guard shell, node failure,
`scancel -s KILL`, `scancel` issued twice, `UnkillableStepTimeout`.

**Blast radius.** J1 lands in the user's project directory on the shared filesystem — the
"litter tray" outcome the design explicitly set out to prevent, and it is *not* reapable:
`is_spool_dir_name` (`lib.rs:83`) excludes `.husk-step-spool-*` on purpose, with a test
pinning that exclusion (`lib.rs:360` — "the job's, cleaned by the job"). J2 lands on
node-local `/tmp` where no husk code ever looks; job ids never repeat, so each leak is a
new directory that persists until the node reboots.

**Why the suite would not catch it.** `guard.preempt_cleanup` (`selftest.sh:945-959`) uses
`timeout -s TERM 3`, i.e. exactly the path that works. `tmp.reclaimed` and
`job.spool_reclaimed` sample after jobs that ended normally.

---

### F3 — a failing `ensure_holder()` leaks one zombie per `srun` request — CONFIRMED

**What breaks.** `StepBroker::ensure_holder` (`step.rs:126-154`) spawns the cage holder and
then `?`-propagates three failures — `child.stdout.take()` returning `None`, the `read_line`
error, and the pid parse error — each of which drops the `Child` without calling `wait()`.
Rust's `Child::drop` neither kills nor reaps, by documented design. The step-broker is
long-lived and `ensure_holder` is called from `admit()` on **every** step request
(`step.rs:305`), so the zombies accumulate for the job's lifetime.

**Failure scenario.** A compute node where the holder cannot start — unprivileged user
namespaces disabled, so `create_shared_userns` fails and `hold_cage_mode` does
`exit(1)` (`main.rs:199-202`). The holder then prints nothing, `read_line` returns `Ok(0)`,
the empty string fails to parse, and `ensure_holder` returns `Err`. A run script with
`for i in $(seq 1 500); do srun …; done` — or an agent retrying — produces one defunct
process per iteration in the one process husk cannot afford to lose. This is a self-DoS
against `RLIMIT_NPROC`, in the trusted half, driven by agent-controlled input.

**Demonstration.** I replicated the exact error path in a standalone Rust program (same
`Command`/`read_line`/`parse`/`return Err` sequence):

```
attempt 0: Err(cage holder reported "" instead of a pid)   [x5]
--- children of this process afterwards ---
  28668 Z    sh <defunct>
  28669 Z    sh <defunct>
  28670 Z    sh <defunct>
  28671 Z    sh <defunct>
  28672 Z    sh <defunct>
```

**Related, same site.** `self.holder` is never invalidated once set (`step.rs:127-129`). If
the holder dies mid-job, every subsequent step gets the stale pid and fails closed at the
rank script's `[ ! -r "$_u" ]` check (`rank.rs:261`) with "the job's cage holder is gone",
and the step-broker never tries to start a new one. Failing closed is right; failing closed
*forever* with no re-acquisition is a lifecycle gap in the other direction.

---

### F4 — the submitted job has no owner on husk's side, and the record that could stop it is memory-only — PLAUSIBLE

**What breaks.** An allocation is a held resource; husk acquires one at `spool.rs:194` and
has no release for it on any path. `main.rs`'s shutdown block (`:521`) removes the spool and
exits; nothing consults `submitted` (`spool.rs:42`). So a session that ends — cleanly or by
SIGKILL — leaves its jobs running to the partition wall limit.

The brief asks whether this is a decision or an omission. The code carries a rationale for
the *memory-only* choice (`spool.rs:38-41`): a persisted list would be agent-editable, and a
restarted broker disowns earlier jobs, "which is the right way for that to fail". But that
paragraph is about a restart, not about session end, and nothing anywhere states "an
allocation deliberately outlives the session". My reading: the **memory-only** part is a
documented decision; the **outlives-the-session** part is undocumented and should be stated
either way.

**The consequence worth naming.** `scancel` exists because husk "made it easier for an agent
to start work than to stop it" (`lib.rs:29-34`). That gap reopens on every broker restart:
after a SIGKILL and a relaunch, the new broker's `submitted` set is empty, so the
ownership gate (`spool.rs:224-243`) refuses to cancel the previous session's jobs by name,
and the agent again cannot stop what husk started. The refusal message is correct and
teaches well; the containment property is nonetheless lost until a human intervenes.

Not demonstrated — it needs a cluster.

---

### F5 — per-rank socat relays are released at job (or step-cgroup) granularity, not with their rank — PLAUSIBLE

The rank's relay is backgrounded inside the rank cage (`rank.rs:206-208`) and then the
inner shell `exec`s the workload, so the relay is not a child of anything that waits for it.
The rank *joins* the job's shared PID namespace (`rank.rs:187,194`, `--pidns 8`) rather than
creating its own, and its PID-1 is the holder child, which explicitly does not reap
(`cage.rs:198-207`). So nothing in husk ends the relay when its rank ends; what ends it is
SLURM's per-step cgroup teardown — the same unstated site dependency `9faad58` was written
to remove for the holder, restated one layer down.

Consequence if that assumption fails: a job running many short steps accumulates one live
`socat` (holding a rank network namespace and a mount namespace open) per rank per step,
for the job's whole lifetime. The `proc.reclaimed` arm does look for stray `socat`
attributed to the job — but only *after* the job has ended, so an intra-job accumulation is
invisible to it.

Not demonstrated: needs `bwrap` + `srun`.

---

### F6 — `--once` creates and claims a spool it never removes — CONFIRMED

`main.rs:512-514` returns from inside the loop, before the `if owns_spool { remove_spool_dir }`
block at `:521`. The comment says `--once` "leaves the spool … exactly as it found it", but
when no `--spool` is given it *creates* the directory (`:413`) and writes an `owner` file
into it (`:479`). Demonstrated: after `broker --once` with no `--spool`, the directory
`.husk-slurm-spool-24834` remained. Bounded — the `owner` file means the next session's
reaper removes it (tier 3), which I also demonstrated. Low severity; worth a comment fix or
an explicit cleanup so the mode does what its comment claims.

---

### F7 — `~/.husk/log/` has no owner and no bound — CONFIRMED by inspection

One `husk-<utc>-<pid>.log` per session (`lib.rs:293`) plus one `job-<jobid>.log` per job
(`policy.rs:847`), never rotated, never pruned, and deliberately kept by uninstall
(`install-husk.sh:97`). This is the right call for an audit trail, but it is a resource with
no owner and no release in a quota'd `$HOME`. The failure mode is handled and announced —
the guard falls back to `_husk_log=/dev/stderr` and says so loudly (`policy.rs:852-857`) —
but the fallback puts husk's record of the job back inside the job's own output, i.e. back
within reach of the audited party, which is the exact property `lib.rs:280-292` exists to
guarantee. Worth an explicit retention decision rather than none.

---

### F8 — the netproxy's tunnel counter is not guarded by `Drop` — PLAUSIBLE, low

`netproxy.rs:273` increments `live` in the accept loop; `:281` decrements it at the end of
the worker closure. All ordinary returns inside `serve_one` are fine (the decrement is after
the call), but an unwinding panic in the worker thread would skip it permanently. After 64
such the proxy answers every connection with 503 for the rest of the job. I found no
obviously reachable panic in `serve_one`, so this is a shape observation rather than a bug:
the counter is a resource whose release is a statement rather than an RAII guard.

---

## What I tried that did NOT turn up a problem

- **Hypothesis: `unshare(CLONE_NEWUSER)` clears `PR_SET_PDEATHSIG`, so `hold_cage_mode`'s
  `die_with_parent()` before `create_shared_userns()` (`main.rs:196-201`) is silently a
  no-op.** `commit_creds()` zeroes `task->pdeath_signal` when the new credentials are not a
  capability-subset of the old, and creating a user namespace grants `CAP_FULL_SET`.
  **REFUTED by measurement** — I compiled the exact sequence and read the flag back:
  `after PR_SET_PDEATHSIG(SIGTERM): 15` → `after unshare(CLONE_NEWUSER): 15`. The reason is
  the special case in `cred_cap_issubset()`: a credential in a *child* user namespace whose
  owner equals the caller's euid counts as a subset. The ordering in `hold_cage_mode` is
  safe. (Measured on 6.8; Balfrin's 5.14 has the same special case, but I could not measure
  it there.)
- **The pidns holder's `PR_SET_PDEATHSIG(SIGKILL)`.** Checked that it is set *in the child
  after the fork* (`cage.rs:191`) — correct, since fork clears it — and that SIGKILL rather
  than SIGTERM is required because a pidns init ignores unhandled signals except SIGKILL
  and SIGSTOP from an ancestor namespace. The kernel does deliver it: PDEATHSIG uses
  `SEND_SIG_NOINFO`, and the dying parent has no pid in the child's namespace, so
  `send_signal_locked` sets `force = true`, which defeats `SIGNAL_UNKILLABLE`. Both halves
  of the `9faad58` fix are sound.
- **The holder's stdin-EOF shutdown path.** I looked for a way the pipe's write end could
  outlive the step-broker (which would defeat the EOF path and make R2 tier 1). Rust creates
  `Stdio::piped()` fds with `O_CLOEXEC`, and the step-broker's only other spawns use
  `Stdio::null()` for stdin, so no `srun` child inherits it. Kernel-coupled as claimed.
- **The reaper's ownership gate.** `owned_by_me` (`lib.rs:123`) uses `symlink_metadata`, not
  `metadata`, so a spool-shaped symlink to someone else's directory cannot make it delete
  their state; `remove_spool_dir` (`lib.rs:131`) removes only regular files matching husk's
  own name patterns and then plain `rmdir`s, so an unexpected file keeps the directory
  alive. `pid_is_alive` (`lib.rs:110`) treats a recycled pid as live, i.e. it errs toward
  *not* deleting. I could not construct a case where the reaper touches something husk did
  not create.
- **A second "EBUSY" shape (a release that is reached but cannot succeed).** I went looking
  for a cleanup whose target is still a mountpoint. The `CAGED_SOCAT` fix (`rank.rs:140-152`)
  and the "bind the socket, not its directory" fix (`policy.rs:725-745`) both put the
  mountpoint inside a namespace that is torn down rather than on a host path that must be
  unlinked. I found no remaining instance.
- **Login-spool `gc()` deleting live state.** `Broker::gc` (`spool.rs:270`) never matches
  `req-*.json`, and its 1 h threshold is far longer than any in-flight response. When two
  brokers share a spool (`claim_spool` returns false, `main.rs:153`), the guest broker's gc
  could in principle reclaim the owner's hour-old orphans — harmless by construction, since
  an hour-old `resp-*` means the stub is gone.
- **`run_query_cmd`'s process group.** Confirmed the watchdog kills `-pid` (the group), not
  just the child, so a grandchild cannot hold the stdout pipe past the timeout; and the
  watchdog exits early on normal completion so fast queries are not delayed. The existing
  tests exercise both directions.
- **`write_atomic`'s `.tmp` files.** Covered by both `gc()` (`.` prefix + `.tmp` suffix
  pattern) and `remove_spool_dir` (`lib.rs:72`). No orphan class.
- **The known laptop fixture leak** (`/tmp/husk-test-work-<pid>`, out of scope per the
  brief) is still present on this machine. It is the same pattern as F1 — a directory
  created by a script with no matching removal — which is why it is worth one line here
  rather than none.
