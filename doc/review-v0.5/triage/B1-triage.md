# B1 — resource lifecycle: triage (pass 2)

**Instrument:** code-only, this laptop. `HEAD = 6c4e75f`. Pass 1 reviewed at `f5fd395`;
`git diff f5fd395 HEAD -- slurm-broker/broker/src/` is **empty**, so no source file has moved
under the findings. `slurm-broker/selftest.sh` *has* moved (81 insertions, commits `14d833a`,
`e4feefe`, `31a8174`, `f88e512`) and one of those additions is directly relevant to F2 — see
there.

**Binary:** rebuilt and invoked by absolute path throughout —
`slurm-broker/broker/target/release/husk-slurm-broker`, sha256 `3eb0eb86…`. The gitignored
prebuilt `slurm-broker/husk-slurm-broker-x86_64` is sha256 `ff686aff…`, differs, and was
**never used**. `seccomp-wrapper/seccomp-wrapper` sha256 `98741a98…` (rebuilt, `make`).

**Platform:** kernel 6.8.0-136, bubblewrap 0.6.1, unprivileged user namespaces enabled. This
laptop can run the *real* thing for most of B1: real `bwrap`, real `seccomp-wrapper`, real
broker, real `--hold-cage`, real `--net-proxy`, real `--step-broker`. Almost nothing here is
a stub, and where something is, it is named.

**Method.** The guard under test was produced by the real binary for a real workdir
(`husk-slurm-broker --spool … --once --dry-run` stages `job-<id>.sh`), not transcribed. One
argument pair was deleted from the scratch copy — `'--tmpfs' '/users'` — because `/users` does
not exist on this laptop and the root bind is read-only, so `bwrap` aborts with
`Can't mkdir /users`. Nothing else was changed; `diff` of the two scripts is that one line.
Harnesses live in `scratchpad/b1-lifecycle-triage/` (`run-case.sh`, `f3inner.sh`, `f5b.sh`,
`timeoutscope.sh`, `dwp.sh`).

**No repo source file was modified.**

---

## Summary

| ID | outcome | my severity | one line |
|---|---|---|---|
| **F2** | **RECHARACTERISED** | **MEDIUM** (was: implicitly high) | The leak under SIGKILL is real and I reproduced it with the real guard. But the chain that made SIGKILL *certain* breaks at its second link: the guard's foreground command is `bwrap`, which has no SIGTERM handler, so a group-scoped SIGTERM kills it and the trap fires within milliseconds **no matter what the payload does**. Whether F2 can happen at all now rests entirely on one SLURM question — see the hardware list. |
| **F2b** (mine, same site) | **CONFIRMED** | **MEDIUM** | Falling out of the F2 work: the **caged process tree has no owner at all**. On a group SIGTERM the guard cleans up, logs "step spool removed", prints "TERMINATED EARLY" and exits — while the workload is *still running* inside an orphaned `bwrap`. `--die-with-parent` is never passed to either cage; I measured that it closes the gap. |
| **F1** | **CONFIRMED** | **MEDIUM** | Reproduced end-to-end with the real step-broker driving the real generated rank script: step exits `0`, `/dev/shm/husk-<jobid>` remains, and still remains after the job's step-broker is gone. The "does SLURM clean it anyway" caveat is one `scontrol show config` away, and husk's own design premise argues it does not. |
| **F3** | **CONFIRMED** | **LOW** | Reproduced against the **real binary** in a real "user namespaces unavailable" node: 5 `srun` requests → 5 `<defunct>` children of the step-broker, with the exact predicted message. Self-limiting at `RLIMIT_NPROC`, and only on a node where husk cannot build a cage at all. The stale-`holder` half is worse than pass 1 says — see there. |
| **F4** | **CONFIRMED** (by inspection; the *decision* question is the finding) | **LOW–MEDIUM** | No release on any path, and I could find no sentence anywhere in the tree stating that an allocation deliberately outlives its session. The finder's split — memory-only is documented, outlives-the-session is not — is exactly right. |
| **F5** | **RECHARACTERISED** | **MEDIUM** | The phenomenon is real and I measured it: three finished ranks leave three live `socat`s. But the release mechanism is **not** SLURM's step cgroup — it is husk's **own** pidns holder, and killing the holder reclaims them (measured). So the "unstated site dependency" framing is wrong; the real defect is intra-job accumulation, one relay per rank per step for the whole job. |
| **F6** | **CONFIRMED** | **LOW** | `broker --once` with no `--spool` left `.husk-slurm-spool-18362` with an `owner` file in it. Tier 3 does clean it up (measured), so it is a comment-vs-code defect. |
| **F7** | **CONFIRMED** (inspection) | **LOW** | No rotation, prune, cap or retention anywhere in the tree (`grep -iE "rotate|prune|logrotate|retention"` over the broker + installer: nothing). |
| **F8** | **RECHARACTERISED** | **INFO** | The stated failure mode **cannot occur in a shipped build**: `[profile.release] panic = "abort"`. I measured both profiles — under `abort` the process dies (rc 134), the counter is never observed inflated. The real consequence is different: the job loses egress entirely and nothing restarts the proxy. |

**Nothing in B1 was left untriaged.**

---

## F2 — the step spool and the node-local egress dir are tier-1-only, and SIGKILL is a *guaranteed* ending — RECHARACTERISED

### What I did

I attacked the chain link by link, as instructed. There are three links:

1. bash defers a `TERM` trap until the foreground command returns;
2. the guard's foreground command stays alive long enough for `KillWait` to expire;
3. SLURM then sends SIGKILL and the cleanup is skipped.

**Link 1 — reproduced, and it holds.** A minimal guard whose foreground command is a payload
with its own `TERM` handler:

```
$ setsid scratchpad/b1/trapdefer.sh scratchpad/b1/payload-ignores.sh &
$ kill -TERM -$PGID ; sleep 3
   7497 ... trapdefer.sh          <- guard, STILL ALIVE
   7498 ... payload-ignores.sh    <- payload, STILL ALIVE
[payload] caught TERM, ignoring (checkpointing...)
   (no "[guard] trap ran" line)
```

Bash's deferral is exactly as described.

**Link 2 — REFUTED.** Link 1 is not the link that decides anything, because the guard's
foreground command is not the payload. It is

```
seccomp-wrapper --profile=single-node bwrap … -- /bin/bash "$0" "$@"
```

and `seccomp-wrapper` **`execvp`s** (`seccomp_wrapper.c:549`), so the process the guard shell
waits on is `bwrap` itself. `bwrap` installs no `SIGTERM` handler. I ran the real chain —
real `seccomp-wrapper`, real `bwrap 0.6.1`, `--unshare-pid`, payload with its own `TERM` trap:

```
before signal:
   8161 ... guard2.sh
   8163  8161  bwrap        <- outer bwrap, the guard's foreground process
   8164  8163  bwrap        <- pid 1 of the new pid namespace
   8165  8164  bash         <- the payload

$ kill -TERM -8161
[payload] caught TERM, checkpointing, staying alive
[guard] TERM noted
[guard] cage returned rc=143 at 1785717231   signalled=SIGTERM
[guard] CLEANUP RAN
```

Two seconds. The outer `bwrap` died of the signal (rc 143 = 128+15), the guard's `wait`
returned, the trap ran, the cleanup ran — **with the payload still alive and still refusing to
exit**. The payload's own handler is irrelevant; it never had a vote.

Then the same thing with the **real generated guard** (net on, real broker, real `--net-proxy`
bound on a real unix socket), job 900032:

```
### SIGTERM to the whole PROCESS GROUP, payload traps TERM
  while running: spool=yes netdir=yes
      15404 bash (guard)   15418 husk-slurm-brok (net-proxy)
      15421 bwrap  15422 bwrap  15423 bash  15424 husk-socat  15466 sleep
  T+6s:
    guard_alive=no
    spool=removed   netdir=removed
  job log: husk: step spool removed
```

So for a group-scoped SIGTERM the cleanup is not merely reachable — it is prompt, and the
payload's SIGTERM handling makes no difference at all. **`KillWait` expiry is not certain; on
this evidence it does not even start.**

**Link 3 — the leak itself is real, and I reproduced it.** Same real guard, job 900023:

```
### SIGKILL to the process group
  while running: spool=yes  netdir=yes  net.sock=yes
  after KILL   : guard_alive=no
                 spool=LEFT BEHIND
                 netdir=LEFT BEHIND (holds: net.sock)
  job log cleanup lines: <none>
```

Exactly as pass 1 described, including the silence: not even the `husk: kept … it still holds:`
branch fires, because the failure is upstream of every branch that reports.

**And the case where pass 1 *is* right.** If the SIGTERM reaches only the guard shell and not
`bwrap`, everything pass 1 describes happens. Real guard, job 900031:

```
### SIGTERM to the GUARD PID ONLY, payload traps TERM
  while running: spool=yes netdir=yes sock=yes
  T+8s: guard_alive=yes   spool=PRESENT netdir=PRESENT
        14980 bash(guard)  14994 husk-slurm-brok  14997 bwrap    <- all still up
  --- KillWait SIGKILL ---
        spool=LEFT BEHIND  netdir=LEFT BEHIND holds: net.sock
  job log: <no cleanup lines>
```

### Verdict

**RECHARACTERISED.** The observation (SIGKILL leaves both directories, silently, and no reaper
covers either) is confirmed. The *mechanism that made it inevitable* is wrong, and it is the
mechanism a fix would be built on, so this matters: pass 1 concludes "for that class of workload
it is *the* path", and it is not. `bwrap` is a signal-transparent link the argument stepped over.

I believe pass 1's Demonstration 2 used a stub for `seccomp-wrapper`/`bwrap` that did not die on
SIGTERM. That is the one property of the stub that decides the outcome — the harness could not
have produced any other answer.

**The whole finding now reduces to one question I cannot answer here: does SLURM's job
termination signal the whole step container, or only the batch script?** Everything I know says
container (proctrack signals every pid in the cgroup), which would mean F2's reachable triggers
are only: OOM-kill of the guard (or cgroup-v2 `memory.oom.group=1`, which kills the whole
cgroup), node failure, `UnkillableStepTimeout`, and a cleanup that itself blocks past `KillWait`
(a `rmdir` on a hung Lustre mount would do it — this project has a Lustre-stall history).

### Severity: MEDIUM

Down from what pass 1 implies. Reasons:

* The *routine* ending — preemption, wall limit, `scancel` — now looks clean, not leaky, and
  that was the argument for high severity.
* The agent cannot force it: `cancel_decision` (`policy.rs:477`) rejects **every** option, so
  `scancel -s KILL` is refused with a teaching message. I checked; there is no reachable
  agent-controlled path to a SIGKILL of the guard.
* But when it does happen the blast radius is as described and the exclusion is deliberate:
  `is_spool_dir_name` (`lib.rs:83`) rejects `.husk-step-spool-*` with a pinned test
  (`lib.rs:360`, "the job's, cleaned by the job"), and the login-side reaper walks *the very
  same directory* the step spool sits in and steps over it without a word. `reap_stale_spools`
  emits a note for every spool-shaped directory it considers; for a leaked step spool it emits
  nothing at all. Silent accumulation in the user's project tree.
* `/tmp/husk-<uid>-<jobid>` is worse in one respect and better in another: nothing anywhere
  reads `/tmp/husk-<uid>-*` (confirmed by grep), so there is no reaper even in principle — but
  it is node-local and the sockets are 0700.

### On the tests (protocol rule 7)

`guard.preempt_cleanup` (`selftest.sh:953-959`) **could not have failed** on this axis, for two
independent reasons:

1. Its cage is a stub — `$GJOB/bin/seccomp-wrapper` strips to `--` and `exec "$@"`, so there is
   no `bwrap` and the signal shape under test is not the shipped one.
2. `timeout -s TERM 3` signals the process group — I measured it (`timeoutscope.sh`: both the
   outer and the inner shell report a trapped TERM) — so the inner `sleep 30` dies, the
   foreground returns, the trap fires. Even if the trap *were* deferred the payload exits by
   itself and the arm still passes, just later. It can only fail if the `trap` line is deleted
   outright, which is the regression it was written for (`2f366d2`). Fine as far as it goes;
   it is not evidence about SIGKILL, about `/tmp/husk-<uid>-<jobid>`, or about a payload that
   traps.

`job.spool_reclaimed` is **new since pass 1** (`14d833a`) and does look at the workdir after
real compute jobs — `PASS` on Balfrin ln003. Those jobs all ended normally, so it is a clean-path
arm too. Its commit message is nonetheless the most interesting artifact in the repo for this
finding: *"a real ICON run left `.husk-step-spool-4992187` behind with a socat still in it"*.
That is a real hardware leak of J1 — by the EBUSY/unrecognised-file route, since fixed and now
covered by a test that genuinely could fail
(`every_file_the_guard_creates_in_its_own_directories_is_cleaned_up`, `policy.rs:1707`, which
strips comments precisely because a prose-satisfiable version of it once passed). So the
historical leak was a *different* mechanism from F2's, and the one still open is the untested
half: not "does the cleanup name every file" but "does the cleanup run at all".

---

## F2b — the caged process tree has no owner (mine, discovered while triaging F2) — CONFIRMED

Not a pass-1 finding; it falls straight out of the F2 measurement and belongs in the table.

The guard's cleanup explicitly kills `_husk_step_pid` and `_husk_net_pid` and says why for each.
It **never kills the cage.** On a group SIGTERM the outer `bwrap` dies, and with it husk's only
handle on the sandbox; the pid-namespace init survives (a pidns init discards SIGTERM with a
default disposition) and so does everything under it. Measured, real guard, job 900032:

```
  T+6s after SIGTERM:
    guard_alive=no     spool=removed  netdir=removed
    surviving processes from that job:
        15422  ppid 2429  bwrap     <- pid 1 of the job's pid namespace, reparented
        15423  ppid 15422 bash      <- the workload, still running
        15547  ppid 15423 sleep
```

So husk writes `husk: step spool removed` into the audit log and prints
`THIS JOB WAS TERMINATED EARLY` to the job's stderr **while the job is still running**. The
record closes before the thing it records does. Only SLURM's cgroup teardown ends it — which is
tier 2, but *unstated*, and it is the same shape as the parentless-holder bug `9faad58` was
written to remove, one layer up.

`bwrap --die-with-parent` is passed nowhere in the tree (grep: the only hits are husk's own Rust
`die_with_parent()`). I measured that it closes the gap exactly:

```
EXTRA=<none>            survivors: bwrap, bash, sleep
EXTRA=--die-with-parent survivors: (none)
```

**Severity MEDIUM.** No confidentiality consequence — the survivor is still inside the same
cage. The consequences are (a) husk's own record of a job is written before the job ends, which
is a claim about a boundary that has not yet been crossed, and (b) a tier-2 reclaim that depends
on a site's proctrack rather than on husk. Cheap to fix and the fix is one flag.

---

## F1 — `/dev/shm/husk-<jobid>` has no owner and no release on any path — CONFIRMED

### What I did

First the refutation attempt: an exhaustive grep for any production removal.

```
$ grep -rn "dev/shm" --include='*.rs' --include='*.sh' --include='*.py' . | grep -v vendor
```

Every hit is an *acquisition* (`rank.rs:272`, `settings.rs:609`, the probe scripts), a doc, or
one of the two unit tests that clean up after themselves (`rank.rs:631`, `rank.rs:672`). There
is no third mention. Pass 1's grep result holds.

Then I ran it rather than reading it — and unlike pass 1 I did not transcribe the script. I
drove the **real** step-broker, which built the **real** rank argv through `rank::wrap_command`,
with a stand-in `srun` (strips to `--`, `exec "$@"` — which is what srun does to a task command)
and a stub `seccomp-wrapper`:

```
before: <no husk dirs in /dev/shm>
step-broker: launched step for s2 (pid 16828)
resp: {"status":"ok", …, "exit_code":0}
after (step finished):                       drwx------ 2 christoph christoph 40 /dev/shm/husk-900042
after the step-broker (the 'job') exits:     drwx------ 2 christoph christoph 40 /dev/shm/husk-900042
```

The step succeeded (`exit_code: 0`) and the directory remains — before and after the job's own
processes are gone. Confirmed.

I also checked the severity half, which pass 1 asserts but does not show: a SIGKILLed writer
leaves its segment resident.

```
$ mkdir -m 700 /dev/shm/husk-triagedemo ; python3 -c 'open(...).write(b"\0"*64MiB)' & kill -9
/dev/shm/husk-triagedemo/seg-0   67108864 bytes   64M
```

64 MB of node RAM, in a directory nothing removes, from one killed writer. On a preemptible
partition — husk's *only* partition — that is the normal ending for a rank.

### The caveat, assessed

Pass 1 says: if the site runs `job_container/tmpfs` with a private `/dev/shm` per job, the kernel
reclaims this. I think that reasoning is right and I can add an argument from inside the code.
`rank.rs:241-247` gives the design premise verbatim: *"/dev/shm is world-writable and sticky, so
another user on the node could PRE-CREATE `husk-<jobid>`"*. The per-job subdirectory, the
`mkdir -m 700`, and the `[ -O ]` check exist **because /dev/shm is assumed shared across users
on the node**. If `job_container/tmpfs` were in force that premise would be false and all three
would be dead code. So husk cannot both need the subdirectory and be saved by the plugin — one
of the two is wrong, and finding out which is one command.

Note also a doc-vs-code delta that would have prevented this: `SRUN-MPI-DESIGN.md:507` says
*"the **guard** creates `/dev/shm/husk-$SLURM_JOB_ID`"*. Had it been created in the guard as
designed, the guard's cleanup block would have been the obvious place to remove it. It moved to
the rank script and the removal did not follow.

### Verdict: CONFIRMED. Severity MEDIUM

Not high: the clean-path leak is one empty directory per job per node — an inode and 40 bytes.
Not low either: (a) the preempted case leaves real segments resident in RAM on a node that
reboots rarely, and preemption is husk's designed-for ending; (b) there is no `shm.reclaimed`
arm, so nobody would notice; (c) it is the only row in the whole table with *no* release on
*any* path, which is the brief's headline question.

**Overlap flagged, not resolved:** B4's F5 concerns the same two lines (`[ -O "$_d" ]` follows
symlinks). Same site, different property. B2's F11 also touches the job-id-as-name question here.

---

## F3 — a failing `ensure_holder()` leaks one zombie per `srun` request — CONFIRMED

### What I did

Pass 1 demonstrated the Rust semantics in a standalone program. I wanted the real binary in a
real failure condition, so I built one: a user namespace in which nested user namespaces are
refused, which is precisely the "unprivileged user namespaces disabled on this node" case
`create_shared_userns` names.

```
$ unshare -Urmp --fork --mount-proc sh -c 'echo 0 > /proc/sys/user/max_user_namespaces; …'
   unshare -U true  ->  "No space left on device"      (the node condition, reproduced)
```

Then the real step-broker inside it, with five `srun` requests:

```
step-broker pid=3
--- its children ---
        7       3 Z    husk-slurm-brok <defunct>
        9       3 Z    husk-slurm-brok <defunct>
       11       3 Z    husk-slurm-brok <defunct>
       13       3 Z    husk-slurm-brok <defunct>
       15       3 Z    husk-slurm-brok <defunct>
--- defunct children: 5 ---
resp-z1: {"status":"rejected","message":"husk: cannot create the job's shared user namespace:
          cage holder reported \"\" instead of a pid"}
```

Five requests, five zombies, and the exact error string pass 1 predicted from reading the code.
The refusal itself is correct and teaches well; the corpse is the bug.

I also confirmed the reachability chain in `main.rs`: `hold_cage_mode()` → `create_shared_userns`
fails → `eprintln!` → `exit(1)` → stdout closes with nothing written → `read_line` returns
`Ok(0)` → `"".parse::<u32>()` fails → `?` → `Child` dropped unreaped
(`Child::drop` neither kills nor waits, by documented design).

### Verdict: CONFIRMED. Severity LOW

Lower than pass 1's framing ("self-DoS against `RLIMIT_NPROC`, in the trusted half, driven by
agent-controlled input"), for three reasons I checked:

* The precondition is a node where husk **cannot build a cage at all** — every step is already
  rejected. The zombies are a second symptom of an already-broken node, not a new capability.
* It is self-limiting: once `RLIMIT_NPROC` is reached, `Command::spawn` fails *before* forking,
  so no further zombie is produced. The ceiling is the nproc limit, not unbounded.
* The damage is to the user's own process budget on that node, i.e. to the job's own ranks.

### The related half is worse than pass 1 says

`self.holder` is set once and never invalidated (`step.rs:127-129`). Pass 1 calls this "failing
closed forever". It can also fail **open**. The pid husk records is not `child.id()` — it is the
*grandchild*, the pidns init returned by `create_shared_pidns`. If the holder process is killed
rather than exiting cleanly, that grandchild takes its `PDEATHSIG SIGKILL`, dies, is reparented
to init and reaped, and **its pid becomes recyclable**. `self.holder.pid` is then a stale number.
The rank script's only gate is `[ ! -r "$_u" ]` on `/proc/<pid>/ns/user`, which is readable again
as soon as anything of this user occupies that pid — and `bwrap --userns` would then join a
namespace belonging to something else entirely. Low probability, but it is the "a recyclable
name used as a capability" shape, and it is the same shape `pid_is_alive` (`lib.rs:110`)
documents as erring the safe way. Here it errs the other way.

**Overlap flagged, not resolved:** B2's F11 (job ids and pids as identity).

---

## F4 — the submitted job has no owner on husk's side — CONFIRMED (as an omission, not a decision)

Code-only; I confirmed each half rather than re-arguing.

* Acquisition at `spool.rs:194` (`run_sbatch`), recorded into `submitted` at `spool.rs:198`.
* `submitted` is `RefCell<BTreeSet<u64>>`, in-memory (`spool.rs:42`).
* `main.rs`'s shutdown block (`:521`) does exactly one thing: `remove_spool_dir`. Nothing reads
  `submitted`, nothing calls `scancel`.
* The comment at `spool.rs:38-41` justifies the **memory-only** choice — a persisted list would
  be agent-editable — and explicitly frames a *restart* as the failure it accepts. It says
  nothing about session end.
* I went looking for a sentence anywhere stating that an allocation deliberately outlives its
  session: `grep -rniE "outlive|survives the session|jobs keep running|does not cancel"` over
  `slurm-broker/*.md ROADMAP.md README.md doc/*.md`. The three hits are about the job *log*, the
  pidns holder, and rank relays. Nothing about the allocation.

So pass 1's split is right and I reached it independently: memory-only is a documented decision;
outlives-the-session is undocumented. Two defensible answers exist ("an allocation is the user's,
not the session's" is a perfectly good one) — the finding is that neither is written down.

The consequence pass 1 names is real and worth keeping: after any broker restart the `submitted`
set is empty, so the ownership gate (`spool.rs:224-243`) refuses to cancel the *previous*
session's jobs by name, and the agent is back in the "easier to start work than to stop it" state
`lib.rs:29-34` exists to prevent. The refusal message is correct and I would not change it; the
containment property is nonetheless gone until a human intervenes.

**Severity LOW–MEDIUM.** Low as a leak (SLURM has a wall limit and this is normal HPC hygiene);
medium as a *documentation* gap in the one place — "can the agent stop what it started" — that
the project itself identified as a containment property.

---

## F5 — per-rank socat relays outlive their rank — RECHARACTERISED

### What I did

The claim has a premise I did not believe: `settings.rs:621-631` states, in a comment marked
*"measured on 0.6.1"*, that `bwrap --pidns FD` is parent-only and that **without** `--unshare-pid`
bwrap "fails outright". `rank.rs:187` passes `--pidns 8` with no `--unshare-pid`. If the comment
were right, each rank would get a *fresh* pidns whose init dies with the workload — which would
take the relay with it and refute F5 outright.

So I measured it, with a real `--hold-cage` holder and bwrap 0.6.1:

```
holder pid-1 child = 18791
$ bwrap --userns 9 --pidns 8 --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-net -- sh -c 'echo $$; ls /proc'
inside: my pid=2
1 2 3 4 5
```

The rank **joins** the job's namespace (pid 2, and it can see the holder's pid 1). The
`settings.rs` comment is stale and rank.rs is right. F5's premise stands.

Then the claim itself — three short steps, each with the inner script shaped exactly as
`rank::exec_line` builds it (background the relay, then `exec "$@"`):

```
  rank 1 ran as pid 2 ; rank 2 ran as pid 5 ; rank 3 ran as pid 8
=== the JOB pid namespace after all three steps have ENDED ===
  pid 1    ppid=0   …/husk-slurm-broker --hold-cage        <- the holder's pid-1 child
  pid 3    ppid=1   /usr/bin/socat TCP-LISTEN:3128,fork,…  <- rank 1's relay, ORPHANED
  pid 6    ppid=1   /usr/bin/socat TCP-LISTEN:3128,fork,…  <- rank 2's relay
  pid 9    ppid=1   /usr/bin/socat TCP-LISTEN:3128,fork,…  <- rank 3's relay
```

Three finished ranks, three live relays, reparented to a PID 1 that `pause()`s forever and
explicitly does not reap (`cage.rs:198-207`). Each holds its rank's network and mount namespaces
open.

### Where pass 1 is wrong

It says what ends them is *"SLURM's per-step cgroup teardown — the same unstated site dependency
`9faad58` was written to remove"*. That is not what ends them. I killed the holder:

```
=== now kill the holder: does the pidns teardown reclaim them? ===
  (nothing — all three relays gone)
```

The reclaimer is **husk's own** pidns holder, which husk starts, owns, `PDEATHSIG`s and
explicitly `kill(held, SIGKILL)`s on the clean path. It is tier 2 and it is not a site
dependency at all. The `9781…`/`9faad58` analogy is the wrong way round: that fix is what makes
this work.

### What the real defect is

Granularity. The relay's lifetime is the **job's**, not the rank's, and nothing bounds how many
accumulate. One relay per rank per step, live for the whole job. A 128-rank ensemble doing a few
hundred short steps is ~10⁴–10⁵ live processes inside one job — an `RLIMIT_NPROC` wall reached by
an entirely legitimate workflow, with no adversary. `MAX_IN_FLIGHT = 32` (`step.rs:42`) caps
*concurrent* steps; it does not cap the residue.

Gated on egress: `exec_line` only emits the relay when the step-broker has **both**
`HUSK_NET_SOCK` and `HUSK_SOCAT`, i.e. only when an allowlist is configured. A job with no
network leaves nothing behind.

Pass 1 is right that `proc.reclaimed` cannot see this — it samples after the job. The project is
half-aware of it already: `PROTOCOL.md:89` says *"rank cages and their relays can outlive the
job's own `bwrap` by moments"*. "Moments" is wrong; it is the rest of the job.

### Verdict: RECHARACTERISED. Severity MEDIUM

Upgraded from PLAUSIBLE (it is now measured) and re-aimed: not a site dependency, a growth rate.

---

## F6 — `--once` creates and claims a spool it never removes — CONFIRMED

```
$ cd $S/proj-once && husk-slurm-broker --once --dry-run
broker: … spool ".../proj-once/.husk-slurm-spool-18362"
--- after: ---
.husk-slurm-spool-18362/owner        <- pid=18362, project=…, version=0.4.0
```

`main.rs:512-514` returns from inside the loop, before the `if owns_spool` block at `:521`. The
comment one line above claims `--once` "leaves the spool … exactly as it found it", and when
`--spool` is not given it created the directory (`:413`) and wrote an `owner` file into it
(`:479`).

I checked the mitigation too, because that is what decides severity. A later session's reaper
does remove it — but only once the pid is dead. Observed in the same run: session 18370's startup
reaped 18362's spool, and then session 18397 declined to reap 18370's with
`spool .husk-slurm-spool-18370 belongs to live pid 18370 — left alone`. Tier 3 works.

**Severity LOW.** A comment-vs-code defect with a working backstop. Worth fixing because the
comment is the kind of statement a future reader will build on.

---

## F7 — `~/.husk/log/` has no owner and no bound — CONFIRMED (inspection)

One `husk-<utc>-<pid>.log` per session (`lib.rs:294`), one `job-<jobid>.log` per job
(`policy.rs:847`). `grep -rniE "rotate|prune|logrotate|max.*log|retention"` over the broker
sources, the selftest and `install-husk.sh`: **no hits at all**. `install-husk.sh:97` keeps them
on uninstall deliberately.

I agree with pass 1 that this is the right call for an audit trail and the wrong call to leave
unstated, and I agree with the specific point about the fallback: `policy.rs:852-857` degrades to
`_husk_log=/dev/stderr` when `$HOME/.husk/log` is unwritable, which merges husk's record of the
job into the job's own output — inside the workdir the cage binds writable. That converts a
quota event into a violation of the property `lib.rs:280-292` exists to guarantee (the audited
party must not author the audit trail). The degradation is loud, which is right; it is still the
wrong direction to degrade in.

**Severity LOW.** Slow, visible, and the failure is announced. It earns a retention decision, not
a fix.

---

## F8 — the netproxy's tunnel counter is not guarded by `Drop` — RECHARACTERISED

`netproxy.rs:273` increments `live`; `:281` decrements it at the end of the worker closure. Pass 1
reasons that an unwinding panic skips the decrement permanently, and that 64 of those
(`MAX_TUNNELS = 64`, `netproxy.rs:75` — the number is right) leave the proxy answering 503 forever.

**That cannot happen in a shipped build.** `broker/Cargo.toml`:

```
[profile.release]
opt-level = "z" ; lto = true ; strip = true ; panic = "abort"
```

and `build-release.sh:43` builds `cargo build --release --locked`. I measured both profiles with
the exact `Arc<AtomicUsize>` + panicking worker shape:

```
--- panic=unwind (what F8 assumes) ---   main survived; live counter = 1     rc=0
--- panic=abort  (what ships) ---        worker panic                        rc=134  (SIGABRT)
```

Under `abort` there is no surviving process to observe an inflated counter.

**What is true instead:** a panic anywhere in the proxy kills the proxy outright, and the guard
does not restart it — it only `kill`s `$_husk_net_pid` at the end. So the consequence of a
reachable panic is *the job silently loses egress for the rest of its life*, not a 503 wall. Both
are availability, not confinement; the real one is arguably the safer failure (fail-closed), but
it is a different failure, and a fix aimed at the counter would address neither.

The residual shape observation survives and is worth one line in the table: the release is a
statement rather than an RAII guard, so a future `panic = "unwind"` (or anyone reasoning from a
debug build) reintroduces exactly what pass 1 describes.

**Severity INFO.** Nothing to fix today; something to pin with a comment, since the safety here
comes from a build-profile line three files away.

---

## The table — rows I checked myself

I did not re-derive the whole inventory; I verified the rows the findings rest on, plus the two
that looked most likely to be wrong.

| # | pass-1 tier | my verdict |
|---|---|---|
| L1 session spool | 1 + 3 | **Agree, measured.** SIGTERM → `broker: session ended; removed spool …`; the reaper reaps a dead owner's spool and declines a live one, by name, with a note either way. |
| J1 step spool | 1 only | **Agree.** No reaper, exclusion pinned by test, and the login-side reaper walks the same directory in silence. |
| J2 `/tmp/husk-<uid>-<jobid>` | 1 only | **Agree.** `grep` finds no reader of `/tmp/husk-<uid>-*` anywhere. |
| J3/J4 proxy + step-broker | 1 + 2 | **Agree, measured.** Both die with the guard; both set `PDEATHSIG`. |
| **the job cage itself** | *not in the table* | **New row, tier — (none).** See F2b. `--die-with-parent` is never passed. |
| R1 `/dev/shm/husk-<jobid>` | — | **Agree, measured.** |
| R2 userns holder | 2 | **Agree, measured incidentally.** A step-broker run with `--once` exits, the holder's stdin reaches EOF, and the next rank fails closed with `husk: the job's cage holder is gone (/proc/16660/ns/user)`. The EOF path works and the failure is a sentence. |
| R3 pidns holder child | 1 + 2 | **Agree, measured.** Killing the holder reclaimed every orphaned relay in its namespace. |
| R8 per-rank relay | 2 (job/step cgroup) | **Correct tier, wrong owner.** It is husk's pidns holder, not SLURM. See F5. |

Two smaller things I noticed and am not raising as findings, but which belong to this class:

* **`out-<id>` / `err-<id>` have no in-job gc.** The login broker has `Broker::gc` at one hour;
  the step-broker has nothing. The srun stub deletes its own four files in a `finally`
  (`srun-stub.py:144-149`), so the normal path is fine — but a stub that is killed leaves them
  until the guard's end-of-job `rm -f out-* err-*`. Same growth shape as F5, much cheaper.
* **`getppid() == 1` in `die_with_parent`** exits the broker silently when its legitimate parent
  *is* pid 1 of a pid namespace. It cost me an hour in this triage (a step-broker launched under
  `unshare -p` vanished with no message at all). Not reachable in production as far as I can
  see — the step-broker and proxy are started by the guard, outside the cage — but a silent
  `exit(0)` in a race guard is a diagnosis trap, and this project has a rule about that.

---

## UNRESOLVED — NEEDS HARDWARE

Four items. The first is the one that decides F2's severity and should be run first.

### H1 (decides F2) — does SLURM's termination signal reach `bwrap`, or only the batch script?

On Balfrin, from the login node, with husk running:

```bash
# 1. a brokered job whose payload absorbs SIGTERM, as an ICON-class code does
cat > /scratch/$USER/husk-h1.sh <<'EOF'
#!/bin/bash
#SBATCH --nodes=1
#SBATCH --time=00:20:00
trap 'echo "payload: TERM absorbed at $(date -u +%H:%M:%S)"' TERM
echo "payload: up at $(date -u +%H:%M:%S)"
i=0; while [ $i -lt 900 ]; do sleep 1; i=$((i+1)); done
EOF
sbatch --partition=<the forced one> /scratch/$USER/husk-h1.sh    # through husk's stub

# 2. once it is RUNNING, note the time and cancel it
date -u +%H:%M:%S ; scancel <jobid> ; date -u +%H:%M:%S

# 3. THE OBSERVABLE — timestamp of the cleanup line vs the scancel
grep -n "step spool removed\|kept \|TERMINATED EARLY" ~/.husk/log/job-<jobid>.log
ls -ld  <workdir>/.husk-step-spool-<jobid>          # shared FS: visible from the login node
sacct -j <jobid> -o JobID,State,Elapsed,ExitCode
```

**Read it like this.** If `husk: step spool removed` appears within a second or two of the
`scancel` and the step spool is gone — SIGTERM reached `bwrap`, F2's chain is broken on hardware
too, and F2 drops to "SIGKILL-only, and SIGKILL is not routine". If instead the log has no
cleanup line and the step spool survives — pass 1's chain holds on this cluster, and F2 is HIGH.

### H2 (F2 + F1 configuration) — one command, settles three constants

```bash
scontrol show config | grep -E "KillWait|UnkillableStepTimeout|ProctrackType|TaskPlugin|JobContainerType|PrologFlags"
```

`ProctrackType` tells us the signalling scope for H1. `JobContainerType` tells us whether
`job_container/tmpfs` gives each job a private `/dev/shm` (F1's caveat). `KillWait` is the
countdown in F2's argument. Run on **both** Balfrin and Santis — they are configured
independently.

### H3 (F1) — does `/dev/shm/husk-<jobid>` survive on a real node?

Same instrument `tmp.reclaimed` already uses: an **uncaged** follow-up job pinned to the node a
brokered job just ran on.

```bash
# after a brokered job with at least one srun step has finished on node <nid>:
sbatch --nodes=1 --nodelist=<nid> --partition=<same> --wrap \
  'ls -ld /dev/shm/husk-* /tmp/husk-'"$(id -u)"'-* 2>&1; df -h /dev/shm'
```

Non-empty `/dev/shm/husk-<jobid>` on a node whose job is finished ⇒ F1 confirmed on hardware and
the arm should become `shm.reclaimed`. Also worth running once **after a preempted or scancelled
MPI job**, where the interesting number is `du -sh /dev/shm/husk-*` — that is the resident-RAM
half.

### H4 (F5) — does the relay count grow with steps?

Inside one long brokered job, from the job's own log rather than after the fact:

```bash
# job script: run 20 trivial steps, then look at the job's pid namespace
for i in $(seq 1 20); do srun -n 4 /bin/true; done
ps -eo pid,ppid,cmd | grep -c "TCP-LISTEN:3128"      # expect ~80 if F5 holds, ~0 if not
```

Requires an allowlist configured (no allowlist ⇒ no relay ⇒ nothing to count). Needs `bwrap` +
`srun`, so it cannot be done here.

---

## Suspected overlaps (flagged, not resolved)

* **F1 ↔ B4 F5** — same two lines of `rank.rs`; B4 has the symlink-follow property of `[ -O ]`,
  B1 has the lifetime. A fix to one should not be written without reading the other.
* **F3 (stale holder pid) ↔ B2 F11** — a recyclable pid used as a capability.
* **F2b ↔ B5** — a caged workload that outlives husk's supervision is a containment statement as
  well as a lifecycle one; B5 found ways out of the cage and may have looked at this from the
  other side.
