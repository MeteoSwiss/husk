# B4 — the holder, the shared namespaces, and the CMA concession

**Pass 1 (discovery).** Code-only on the laptop, plus local kernel measurements on
6.8.0-136-generic / bwrap 0.6.1 / glibc x86_64. **No cluster access was used and no job was
submitted.** Every claim below is marked `[source]` (read from the code) or `[demonstrated]`
(measured here, with the harness described). Nothing marked `[demonstrated]` is a hardware
result — Balfrin runs 5.14 Cray Shasta and Santis aarch64, and two of the findings turn on
kernel behaviour, so they carry an explicit "verify on target" note.

## Summary

The shared-namespace concession is bounded roughly as claimed, and the two structural walls
— the user namespace for `ptrace_may_access`, the PID namespace for addressability — both
hold under measurement. The join is fail-closed on every path I could find, including the
ones the code does not itself guard (bwrap refuses a bad fd, a non-namespace fd and a
foreign namespace, all exit 1). But the boundary is *not* enforced by the mechanisms the
source says it is. The one un-caged, un-seccomped, full-capability process a rank can name
is the holder itself, at PID 1; a rank cannot read or write it, and the reason is the
capability-subset arm of `cap_ptrace_access_check`, not the "mm belongs to the initial user
namespace" reason recorded in `main.rs` — I demonstrated the difference by dropping the
holder's capabilities and watching a rank read *and write* it. That property is undocumented
as an invariant, has no test, and is not covered by any selftest arm (`pid.isolated`
explicitly skips PID 1; `cma.outside` targets only the step-broker). Separately, three
documents record a measurement — "the holder can clear `PR_SET_DUMPABLE`" — that I could not
reproduce for the holder *as built* and that would kill every step on both clusters if acted
on, and the non-reaping PID 1 turns orphaned rank children into **node-global** zombies,
which is the one place I found where a rank's behaviour reaches past the job.

---

## The boundary as built

### What a rank CAN reach

| target | mechanism that permits it | evidence |
|---|---|---|
| other ranks of the same job — memory, via `process_vm_readv` | shared user namespace: `cap_ptrace_access_check` takes the same-`user_ns` branch and both sides have an empty capability set, so `cap_issubset` holds | `[demonstrated]` rank read a 32-byte canary out of a peer rank under `--profile=single-node` |
| other ranks — signals, `/proc`, `kill` | shared PID namespace: peers are nameable | `[demonstrated]` `/proc` inside a rank listed exactly the holder plus the rank's own tree |
| PID 1 (the holder) — `cmdline`, `comm`, `status`, `stat` | world-readable procfs entries, no `ptrace_may_access` gate | `[demonstrated]` |
| its own workdir + the `allowWrite` roots, the fabric and GPU device nodes, the bound `/dev/shm` subdirectory, the egress socket | `rank_bwrap_args` (`settings.rs:597-815`) plus the two per-task binds in `rank.rs:183-220` | `[source]` |
| open file descriptors 8 and 9 — live handles to the job's PID and user namespaces | bwrap does not close them before exec | `[demonstrated]`; no escape from them, see "what held" |

### What a rank CANNOT reach, and by which mechanism

| target | mechanism that denies it | evidence |
|---|---|---|
| the un-caged **step-broker** (MUNGE, daemon route, real `srun`) | **PID namespace** — it is not in the rank's `/proc` and its host pid is not resolvable, so there is no target to check. `PR_SET_DUMPABLE=0` (`main.rs:65-73`) is the second, weaker layer | `[demonstrated]` `kill -0 <host pid>` from a rank → ESRCH; `[source]` `main.rs:370` |
| the **egress proxy** | same | `[source]` `main.rs:282` |
| the **holder** at PID 1 — `environ`, `maps`, `mem`, `process_vm_readv`, `process_vm_writev` | **capability subset**: the holder holds `CAP_FULL_SET` in the shared user namespace, a rank holds none, so `cap_issubset(holder.permitted, rank.permitted)` fails and `ns_capable(shared_ns, CAP_SYS_PTRACE)` fails too | `[demonstrated]` EPERM on all five, with Yama neutralised on **both** sides via `PR_SET_PTRACER_ANY`. **See F1 — this is not the reason the source gives.** |
| anything in the **initial user namespace** | `cap_capable` walks up from the target namespace and returns `-EPERM` on reaching `init_user_ns`; a rank has capabilities only in the shared namespace | `[demonstrated]` `ioctl(9, NS_GET_PARENT)` → EPERM; `setns` on a foreign userns fd → bwrap "might not be a descendant" |
| **another job's ranks** (same user, same node) | their holder owns a *sibling* user namespace; neither side is capable in the other | `[source]` + the sibling-EPERM result the project already measured. One reuse path could break this — see F4 |
| **another user's** anything | uid check in `__ptrace_may_access` | `[source]` |
| killing the holder from inside | a PID-namespace init ignores every signal it has no handler for, `SIGKILL` included, when the sender is inside the namespace | `[demonstrated]` `kill -9 1` from a rank returned success and the holder survived |
| `process_vm_writev` against **anything** | seccomp-wrapper, under every profile (`seccomp_wrapper.c:89`, absent from `SINGLE_NODE_EXEMPT:246-251`) | `[demonstrated]` rank died with exit **159** (128+SIGSYS) on `process_vm_writev` under `--profile=single-node`, immediately after a *successful* `process_vm_readv` in the same process. Under `--profile=login` it died on the readv instead. **SIGSYS = ours; the EPERMs above = the kernel.** |

Note the asymmetry's real shape: rank→peer-rank `process_vm_writev` is permitted by the
**kernel** (`[demonstrated]`: it returned 8 with errno 0 when seccomp was not in the way).
The write block is *entirely* seccomp-enforced. That is fine — the filter is inherited across
fork and exec under `NO_NEW_PRIVS` and cannot be shed — but it means seccomp is load-bearing
alone for the write half, whereas the read half has a kernel wall behind it.

### The holder is the sharp edge, and it deserves naming

`[source]` The holder is started by the step-broker (`step.rs:126-154`), which the guard
starts **before** it enters the cage (`policy.rs:862-868` vs the `seccomp-wrapper … bwrap`
line at `policy.rs:894`). So the holder:

- is **not** under any seccomp filter,
- is **not** inside bwrap — it has the node's real mount namespace (`/users` visible,
  `/run/munge` visible) and the node's real network namespace,
- holds `CAP_FULL_SET` in the user namespace every rank runs in,
- and is **addressable from every rank as PID 1**.

Code execution in that process is code execution outside the cage. Two independent things
stop it today: seccomp's `process_vm_writev` block, and the capability-subset check. F1 is
about the second one.

### Fail-closed paths on the join — the full enumeration

| # | where the join can fail | what happens | evidence |
|---|---|---|---|
| 1 | `create_shared_userns` — `unshare(CLONE_NEWUSER)`, `setgroups`, `uid_map`, `gid_map` (`cage.rs:114-136`) | any `Err` → `hold_cage_mode` prints and `exit(1)`; the namespace dies with the process | `[source]` `main.rs:199-202` |
| 2 | `create_shared_pidns` — `unshare(CLONE_NEWPID)` or `fork` (`cage.rs:158-173`) | `Err` → `exit(1)` | `[source]` `main.rs:233-239` |
| 3 | the holder dies before reporting | step-broker's `read_line` gets EOF → empty line → parse fails → `Err` | `[source]` `step.rs:141-148` |
| 4 | the holder reports garbage | parse fails → `Err` | `[source]` `step.rs:145-148` |
| 5 | `ensure_holder` returns `Err` | the **step is rejected** with a husk-attributed message; no rank runs | `[source]` `step.rs:305-313` |
| 6 | `/proc/<pid>/ns/user` unreadable at rank start | script prints "the job's cage holder is gone" and `exit 1` | `[source]` `rank.rs:261-264`; `[demonstrated]` exit 1 |
| 7 | `/proc/<pid>/ns/pid` unreadable | same, "the job's PID namespace is gone", `exit 1` | `[source]` `rank.rs:267-270` |
| 8 | `exec 9<` / `exec 8<` fails after the `-r` test passes (TOCTOU) | **shell-dependent** — `dash` exits, `bash` continues with the fd unopened. bwrap then fails `Bad file descriptor`, exit 1 | `[demonstrated]`, see F7 |
| 9 | fd 8/9 point at something that is not a namespace | bwrap: "might not be a descendant of the current user namespace", exit 1 | `[demonstrated]` |
| 10 | the pid names a live process in the **wrong** (initial) user namespace — the pid-reuse case | bwrap refuses, rank exits 1 | `[demonstrated]` |
| 11 | the holder dies between the check and bwrap's `setns` | the open fd pins the user namespace, so the userns join still succeeds; a pidns whose init is dead cannot be entered | `[source]` + kernel semantics; not separately measured |
| 12 | a rank silently getting a **private** namespace instead | not reachable: `--userns`/`--pidns` are unconditional in `exec_line` (`rank.rs:187,194`), the shell `exec`s into the cage so there is no fallback branch, and `--unshare-user`/`--unshare-pid` are absent and asserted absent (`rank.rs:518-533`) | `[source]` |

I found no path that degrades to a private namespace. **That is a null result and it is the
main deliverable of this brief.**

---

## Findings

### F1 — the holder's protection rests on a property nothing states, tests or measures; the source records a different mechanism · **CONFIRMED**

**Scenario.** A future change drops the holder's capabilities — the obvious "harden the
process that has full caps and needs none" move, and one the project is already circling in
`CAGE-PROFILES.md:204-212`. Every rank can then `process_vm_readv` **and**
`process_vm_writev` the holder at the kernel level, and only the seccomp `process_vm_writev`
block stands between a rank and arbitrary code execution in a process that has no seccomp
filter, the node's real mount namespace (`/users`, `/run/munge`) and the node's real network
namespace.

**Evidence** `[demonstrated]`, kernel 6.8, Yama neutralised on both sides:

```
holder as built  (CapPrm 000001ffffffffff):  READV pid=1 -> -1 EPERM   WRITEV pid=1 -> -1 EPERM
same holder, caps dropped (CapPrm 0):        READV pid=1 -> 32         WRITEV pid=1 -> 8
```

The only variable changed is the holder's capability set. The operative gate is therefore
`cap_ptrace_access_check` — same `user_ns`, so it needs
`cap_issubset(holder.permitted, rank.permitted)`, which holds only while the holder keeps
more capabilities than the rank (bwrap leaves a rank with `CapPrm=CapBnd=0`, `[demonstrated]`).

**The source says something else.** `main.rs:218-224`:

> "The likely reason — explanation, not measurement — is that this process's mm belongs to
> the INITIAL user namespace … so the kernel's ptrace-attach check demands CAP_SYS_PTRACE
> there"

That branch of `__ptrace_may_access` is only reached when the target is **non-dumpable**, and
the holder is dumpable: `[demonstrated]` `/proc/<holder>` is user-owned and a sibling can
open `/proc/<holder>/ns/user`, which is exactly the property `cage.rs:89-97` relies on. The
comment is honest that it is an explanation rather than a measurement; it is the wrong one.

`THREAT-MODEL.md:208-211` generalises it further — "a rank cannot `process_vm_readv`
anything outside the shared user namespace — not the holder" — but the holder is *inside*
the shared user namespace, so that sentence describes the wall as being somewhere it is not.

**Why it matters as a finding rather than a nit.** The invariant that actually protects the
one reachable out-of-cage process is "the holder must never drop capabilities", and nothing
in the repo says so, no unit test pins it, and no selftest arm exercises it:

- `selftest.sh:1143-1154` — the `pid.isolated` broker hunt **explicitly `continue`s on PID 1**
  ("PID 1 is never a finding") with a correct explanation of *why it is there* and no probe of
  whether it is *reachable*.
- `selftest.sh:1397-1439` — `cma.outside` locates its target by scanning `/proc` for
  `--step-broker`, which by construction is never in a rank's `/proc`, so it now short-circuits
  to `NOBROKER → PASS`. The rank-visible target is never attempted.

**Suggested reproducer for triage / a new arm.** In the existing two-task CMA probe step, add
a third line: `process_vm_readv(1, 0x1000, 8)` from rank 1. `errno==EPERM` → PASS
(`cma.holder`); anything else → the holder became a valid target. Cheap, and it is the arm
that would catch the regression this finding is about.

---

### F2 — "the holder can clear `PR_SET_DUMPABLE`" is recorded in three places as a measured fact; I measure the opposite for the holder as built, and acting on it kills every step · **CONFIRMED**

**Scenario.** Someone takes up the two-minute check offered by
`CAGE-PROFILES.md:204-212` ("It *can*: measured on kernel 6.8, a holder with the flag cleared
is still openable and still joinable with `bwrap --userns` by a sibling — which corrects an
earlier claim here that it could not"), echoed at `main.rs:204-217` and
`THREAT-MODEL.md:212-217`. Every rank on both clusters then dies at the
`[ ! -r "$_u" ]` gate.

**Evidence** `[demonstrated]`, kernel 6.8 — the same kernel the note cites:

| holder shape | `[ -r /proc/<pid>/ns/user ]` from a same-uid sibling | rank |
|---|---|---|
| as built (dumpable) | TRUE | joins, runs |
| clears `PR_SET_DUMPABLE` **before** writing the maps | n/a — `/proc/self/setgroups` becomes root-owned, holder cannot even be created ("Permission denied") | — |
| clears it **after** the maps, no exec (husk's actual shape) | **FALSE** | "the job's cage holder is gone", exit 1 |
| execs inside the new userns, then clears it | TRUE | joins |

The last row explains the contradiction rather than merely refuting it: `mm->user_ns` is
fixed at `exec`. For a process that execs *inside* the new namespace, the sibling is that
namespace's **owner** and therefore `ns_capable(mm->user_ns, CAP_SYS_PTRACE)` — the
`get_dumpable` branch passes and the link stays open. husk's holder never execs after
`create_shared_userns` (`cage.rs:114-136` runs in-process by design, `main.rs:180-183`), so
its `mm->user_ns` is the initial namespace and the same branch denies.

**Verdict on the contradiction:** `cage.rs:89-97` is right ("a holder that had cleared
`PR_SET_DUMPABLE` would be one whose namespace no rank can open"). The three "corrections" are
wrong *for this process*, and reproducible for a differently-shaped one.

This fails closed — a job dies loudly rather than running uncaged — so it is a landmine, not a
hole. But it is a landmine currently labelled "cheap win", which is the expensive kind.

---

### F3 — the non-reaping PID 1 turns orphaned rank children into **node-global** zombies; "harmless" does not survive contact · **CONFIRMED** (accumulation) / **PLAUSIBLE** (exhaustion)

`cage.rs:198-203` accepts this explicitly: *"orphaned ranks reparent to this PID 1 and their
zombies accumulate for the job's lifetime. Harmless — the namespace and every zombie in it are
destroyed when the job ends — and a subtly wrong reap loop would be worse than none."*

**Evidence** `[demonstrated]`: 40 orphans created inside a rank produced **40 host-visible
zombies** parented to the holder's host pid, persisting until the holder was killed:

```
host zombies parented to holder BEFORE: 0
host zombies parented to holder AFTER : 40
  30507 28102 Z  sh <defunct>   (and 39 more)
```

The reasoning to refute is "destroyed when the job ends". True — but *during* the job each
zombie holds a pid number in **every ancestor PID namespace, including the node's**, plus a
`task_struct` and a per-uid ucounts slot. Pid numbers are a node-global resource shared with
every other user's job on that node. This is the one mechanism I found by which a rank's
behaviour reaches past the job boundary. It is also *new*: before the shared PID namespace an
orphan reparented to a reaping ancestor on the node and was collected.

Whether it can be pushed to node-wide `fork()` failure is **PLAUSIBLE, not confirmed** — I did
not try, and the rules of engagement forbid it. Locally `pid_max=4194304` and
`ulimit -u=123979`, so the per-uid limit binds first; on a Cray Shasta node with a smaller
`pid_max` and a large `ulimit -u` the ordering may invert. Worth a two-line check on target
(`cat /proc/sys/kernel/pid_max; ulimit -u`) before deciding it is not worth fixing.

**The fix is one line, and it is not the reap loop the comment rightly rejects.** In the
holder child, `signal(SIGCHLD, SIG_IGN)` makes the kernel auto-reap with no wait loop to get
wrong. `[demonstrated]` with the same 40-orphan test:

```
zombies with SIGCHLD=SIG_IGN : 0      (vs 40)
kill -9 1 from inside a rank : still ignored, holder alive
```

`SIG_IGN` is not a handler, so it does not weaken the "namespace init ignores signals it has
no handler for" protection for any other signal — confirmed in the same run. Both teardown
paths were re-verified with the change in place (`[demonstrated]`: SIGKILL to the holder
parent and SIGTERM to the holder parent each took the child with them).

---

### F4 — the holder is named by a bare pid that is cached forever and never revalidated · **PLAUSIBLE**

`[source]` `step.rs:126-133`:

```rust
fn ensure_holder(&mut self) -> Result<u32, String> {
    if let Some(h) = &self.holder {
        return Ok(h.pid);      // no liveness check, ever
    }
```

Two consequences.

**(a) Permanent wedge, `[source]`.** If the holder child dies for any reason the step-broker
cannot see (OOM killer, an external `kill -9` on the host pid, a cgroup event), every
subsequent step in the job dies at the rank's `-r` gate with "the job's cage holder is gone",
for the remaining wall time, and nothing re-creates it or reports that the holder is dead. The
message is correct and attributed, but it is emitted per rank, forever, with no remedy — it
fails item 1 of the six teaching-message properties (actionable in one step) through no fault
of the message. `pid_is_alive` already exists at `lib.rs:110-113` and is used for the spool
owner; the holder is the one lifetime that does not use it.

**(b) Pid reuse, `PLAUSIBLE`.** A bare pid is a name that can be recycled. `[demonstrated]`
the benign case fails closed: a rank pointed at a live same-uid pid in the initial user
namespace is refused by bwrap ("Joining the specified user namespace failed, it might not be a
descendant of the current user namespace", rank exit 1). The case that would **not** fail
closed is a pid recycled onto *another husk holder of the same user on the same node* — the
rank would successfully join a different job's user **and** pid namespace, landing in that
job's CMA domain. Same uid, so the confidentiality cost is small, but it contradicts
`THREAT-MODEL.md:220-223`'s stated scope ("not another job's ranks"). I did not attempt to
force pid wraparound.

**Cheap fix that closes both:** record `readlink("/proc/<pid>/ns/user")` and `.../ns/pid` at
`ensure_holder` time and interpolate the expected `user:[…]` / `pid:[…]` strings into the rank
script, so the rank compares identity rather than existence; plus a `try_wait()` on the holder
each `tick()`. Both are testable without hardware.

---

### F5 — the rank's `/dev/shm` ownership check follows symlinks, so the bind source can be redirected from outside the job · **CONFIRMED** (mechanism) / **PLAUSIBLE** (exploitability)

`rank.rs:272-277`:

```sh
_d=/dev/shm/husk-${SLURM_JOB_ID}
mkdir -m 700 "$_d" 2>/dev/null || true
if [ ! -O "$_d" ]; then
echo "husk: $_d exists and is not owned by this user - refusing to share it" >&2
exit 1
fi
```

The comment above it states the threat exactly right — "/dev/shm is world-writable and sticky,
so another user on the node could PRE-CREATE `husk-<jobid>` (job ids are guessable) … The
sticky bit stops them deleting our entries, not creating the directory first." The check does
not implement it: `[ -O ]` **resolves symlinks**, and the sticky bit does not stop a symlink
being created either.

**Evidence** `[demonstrated]`: with `/dev/shm/husk-<id>` planted as a symlink to a
directory owned by the running user, `mkdir` fails with `EEXIST`, `[ -O ]` **passes**, and the
bind source becomes the symlink's target.

**Consequence.** `--bind "$_d" /dev/shm` is emitted *after* the policy arguments
(`rank.rs:187-199`, `{bwrap}` expands first), so bwrap applies it last and it wins. An
attacker who can write the node's `/dev/shm` chooses a victim-owned directory — including one
the cage masks, e.g. under `/users` — and it appears **read-write at `/dev/shm`** inside every
rank cage of that job. That is a read/write hole through the home-hiding cage and through the
F6b auto-exec masking, opened by a third party rather than by the confined agent.

Preconditions: a co-tenant process on the node (husk forces `--nodes=1` but not `--exclusive`,
`profile.rs:62-66`), and the job id, which is public in `squeue`. The caged side cannot plant
it itself — the job cage has a private `--tmpfs /dev/shm` and a rank's `/dev/shm` *is* the
bind — so this is not an agent-reachable escalation, which is why it is PLAUSIBLE rather than
CONFIRMED end to end.

Fix: `[ -d "$_d" ] && [ ! -L "$_d" ] && [ -O "$_d" ]`. This may belong to **B3**
(mount-table construction) — I raise it here because it is in the rank wrapper, three lines
from the namespace join.

---

### F6 — `settings.rs` states, twice, that a rank cannot do what `rank.rs` does · **CONFIRMED** (doc defect)

`settings.rs:621-631` and again at `settings.rs:1194-1200`:

> "`bwrap --pidns FD` is parent-only — with `--unshare-pid` it makes the given namespace the
> PARENT of a fresh one, and without it bwrap fails outright ('Can't send pid: Invalid
> argument', measured on 0.6.1). So ranks cannot JOIN a shared PID namespace the way they join
> the shared user namespace"

`rank.rs:187,194` emits `bwrap --userns 9 --pidns 8` with no `--unshare-pid`, and
`THREAT-MODEL.md:189-191` records the correction (the failing case was a holder with no uid
map). `[demonstrated]` on **bwrap 0.6.1**, the exact version cited: the join works, the payload
lands in the holder's PID namespace as a low pid, and `/proc` shows two entries.

The test at `settings.rs:1201-1218` asserts only the negative (`!rank.contains("--unshare-pid")`),
so a reader who trusts the comment and "fixes" the rank path would be told nothing by the
suite. The stale text argues *for* per-rank PID namespaces, which is the ICON failure one layer
down.

---

### F7 — the rank script's fail-closed guarantee is shell-dependent · **CONFIRMED** (minor; bwrap covers it)

`rank.rs:252-257` describes the `-r` test and `bwrap --userns` as a belt-and-braces pair. The
third link, `exec 9<"$_u"`, is neither. `[demonstrated]`:

```
dash / /bin/sh : exec 9</missing  -> shell exits
bash           : exec 9</missing  -> prints an error and CONTINUES
```

`/bin/sh` is bash on both target clusters, and `rank::wrap_command` builds
`["sh", "-c", script, …]` (`rank.rs:286-292`). So in the TOCTOU window between the `-r` test
and the open, the script proceeds with fd 9 unopened. `[demonstrated]` bwrap then fails
`Joining specified user namespace failed: Bad file descriptor` and exits 1, so the outcome is
still correct — but the guarantee is bwrap's, not the script's, and the comment credits the
script. One `|| exit 1` per redirection makes the stated pair real.

---

### F8 — the namespace fds leak into the workload · **CONFIRMED** (hygiene, no impact found)

`[demonstrated]` inside a rank cage:

```
lr-x------ 8 -> pid:[4026532980]
lr-x------ 9 -> user:[4026532979]
```

Hostile code in the cage holds live handles to the job's two shared namespaces. I looked for a
use and found none: `setns` on either returns -1 (own namespace), `ioctl(9, NS_GET_PARENT)`
returns **EPERM** so the initial user namespace cannot be walked to, and a fresh
`unshare(CLONE_NEWUSER)` inside the rank grants nothing outside. They do pin both namespaces
alive for as long as any rank holds them, which is harmless here since the holder outlives the
ranks anyway. Recording it because "no use found" is a weaker statement than "closed".

---

## What I checked that held

- **No path degrades to a private namespace.** Twelve join-failure paths enumerated above; all
  twelve either refuse the step, exit the rank, or make bwrap exit non-zero. `--unshare-user`
  and `--unshare-pid` are absent from the rank arguments and asserted absent
  (`rank.rs:518-533`). `[source]` + `[demonstrated]` for paths 6-10.
- **The map is an identity map on every path.** `identity_map` (`cage.rs:106-108`) is the only
  producer, has a unit test pinning `inside == outside` and count 1 (`cage.rs:244-256`), and a
  repo-wide grep for `uid_map` writers finds exactly two sites — `cage.rs:133` and the login
  wrapper at `husk-slurm-wrapper.rs:298` — both identity. No root-map path exists. `[source]`
- **Ordering is forced by the kernel and the code obeys it.** Ids are read *before* the
  unshare (`cage.rs:121`, avoiding the overflow-uid write), `setgroups deny` precedes
  `gid_map`, and the PID namespace is created after the user namespace. `[source]`;
  `[demonstrated]` by the holder reproduction, which fails at `setgroups` if the order is
  disturbed.
- **A rank cannot kill the holder.** `[demonstrated]` `kill -9 1` from inside returns success
  and the holder survives — the namespace-init signal rule, confirmed independently of the
  project's own measurement.
- **The holder does not outlive the job.** `[demonstrated]` both teardown paths: SIGKILL to the
  holder parent (child's `PDEATHSIG=SIGKILL` fires) and SIGTERM to the holder parent (no
  handler is installed in `hold_cage_mode`, so the default action runs — verified `[source]`
  that `catch_shutdown_signals` is reached only *after* the mode dispatch in `main.rs:359-370`,
  which is what keeps SIGTERM lethal for the holder). The explicit `kill(held, 9)` on the
  stdin-EOF path (`main.rs:264`) is SIGKILL for the right reason. The 9faad58 fix is sound.
- **The step-broker is not addressable from a rank.** `[demonstrated]` ESRCH on its host pid;
  `[source]` it is in neither shared namespace (`main.rs:185-189` states the invariant and
  `step.rs:132-137` spawns the holder as a separate process rather than becoming one).
- **The seccomp asymmetry is real and correctly attributed.** `[demonstrated]`
  `--profile=single-node`: readv succeeds, writev → exit 159 (SIGSYS). `--profile=login`: readv
  → 159. Every denial I attributed to the kernel returned EPERM/EINVAL/ESRCH, never 159.
- **`--proc /proc` reflects the joined PID namespace**, not the node's — `[demonstrated]` two
  entries inside a rank. There is no window in which bwrap mounts procfs against the outer
  namespace.
- **The user's command is never interpolated into the rank script.** Existing tests already run
  the script with a stub and check argv (`rank.rs:598-690`); I did not find a gap.
- **`req.env` cannot redirect the join.** `HUSK_` is in `RESERVED_ENV_PREFIXES`
  (`rank.rs:35-36`) and the holder pid is broker-derived and shell-quoted (`rank.rs:280-281`).
  `[source]`

## Harness (for the triage pass)

All local artefacts were built in the session scratchpad and removed afterwards; no repo file
was modified. To reproduce: a ~50-line C holder replicating `cage.rs::create_shared_userns` +
`create_shared_pidns` + `main.rs::hold_cage_mode`; variants that (a) drop the child's
capabilities via `capset`, (b) clear `PR_SET_DUMPABLE` before / after the maps, (c) exec
inside the new userns before clearing it, (d) set `SIGCHLD` to `SIG_IGN`; a probe that reports
its namespaces/caps/`/proc` and performs `process_vm_readv`/`writev` with the errno; and a
shell reproducing `rank.rs`'s script verbatim (`-r` test, `exec 9<`, `exec 8<`,
`bwrap --userns 9 --pidns 8 …`). Yama (`ptrace_scope=1` here, absent on Balfrin) was
neutralised with `PR_SET_PTRACER_ANY` on **both** sides wherever a negative result was claimed,
so no denial below is a Yama artefact.
