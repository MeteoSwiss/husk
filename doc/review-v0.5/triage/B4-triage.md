# B4 — triage (pass 2): the holder, the shared namespaces, the CMA concession

**Stance:** refutation. Every candidate was attacked, not confirmed. Code-only, this laptop
(**kernel 6.8.0-136**, bwrap **0.6.1**, glibc x86_64, `/bin/sh -> dash`, Yama
`ptrace_scope=1`, `suid_dumpable=2`). No cluster access. All harness code was built in the
session scratchpad and left the repo untouched; **no source file was modified.**

The pass-1 findings are marked `CONFIRMED` in their own document. I inherited none of that.
The single most consequential result of this pass is that **F1 — the sharpest and
highest-severity candidate — does not reproduce with a faithful rank, and its stated
mechanism is backwards.** The source comment it attacks (`main.rs`, "mm belongs to the
initial user namespace") is closer to correct than the finding.

## Summary

| ID | Outcome | My severity | One line |
|----|---------|-------------|----------|
| **F1** | **REFUTED** | — (was HIGH) | Dropping the holder's caps does **not** open it to a faithful (empty-caps, bwrap) rank — read+write stay `EPERM`. Capabilities are not the gate; the finder's reader was more capable than a real rank. |
| **F2** | **CONFIRMED** | LOW | For husk's actual (no-exec) holder, clearing `PR_SET_DUMPABLE` makes `/proc/<pid>/ns/user` unreadable → every rank fails closed. The three "cheap win" notes are wrong for this holder; `cage.rs:89-97` is right. Landmine, not a hole. |
| **F3** | **CONFIRMED** (accumulation, node-global) / **NEEDS-HARDWARE** (exhaustion) | MED-LOW | 30 orphans → 30 host-visible zombies on the non-reaping PID 1, holding node-global pid numbers for the job's life. Node-wide `fork()` failure depends on Balfrin's `pid_max` vs `ulimit -u`. |
| **F4** | **CONFIRMED** (a: wedge) / **PLAUSIBLE** (b: pid reuse) | MED-LOW | `ensure_holder` caches the holder pid with no liveness check; a dead holder wedges every later step for the wall time. Pid reuse onto another same-user holder is mechanically possible, not forced. |
| **F5** | **CONFIRMED** (mechanism, end to end) / **PLAUSIBLE** (exploitability) | MEDIUM | `[ -O "$_d" ]` follows symlinks; a co-tenant's planted `/dev/shm/husk-<jobid>` symlink lands a victim-owned dir **read-write** inside every rank cage. Read a secret and wrote back. Defeats home-hiding. |
| **F6** | **CONFIRMED** (doc defect) | LOW | `settings.rs` says twice ranks cannot join a shared pidns and bwrap 0.6.1 fails without `--unshare-pid`; on 0.6.1 the join works and `rank.rs` does it. **Overlaps B3** — flagged, not resolved. |
| **F7** | **CONFIRMED** (minor) | INFO | `exec 9<` fail-closed is shell-dependent (dash exits, bash continues); bwrap's `--userns` catches the window, so the outcome is still fail-closed. |
| **F8** | **CONFIRMED** (hygiene) | INFO | Namespace fds 8/9 leak open into the workload; `NS_GET_PARENT` on both → `EPERM`, `setns` own userns → `EINVAL`. No use found. |

The brief's own **null result — no join path degrades to a private namespace — held under
every probe** (see F6/F7 work: `--userns`/`--pidns` are unconditional, bwrap is fail-closed on
a bad/absent/foreign fd). That remains the main deliverable and I found nothing that breaks it.

---

## F1 — REFUTED. The holder's protection is *not* capabilities, and dropping them does not open it.

**The claim.** A future change drops the holder's capabilities; every rank can then
`process_vm_readv` **and** `process_vm_writev` the holder at the kernel level, because the real
gate is `cap_ptrace_access_check`'s `cap_issubset(holder.permitted, rank.permitted)` — which
holds only while the holder keeps more caps than the rank. The finder demonstrated it:

```
holder as built  (CapPrm 000001ffffffffff):  READV pid=1 -> EPERM   WRITEV pid=1 -> EPERM
same holder, caps dropped (CapPrm 0):        READV pid=1 -> 32       WRITEV pid=1 -> 8
```

and asserts the `main.rs` comment ("mm belongs to the INITIAL user namespace") is the wrong
explanation.

**What I did.** I built a faithful holder in C (`create_shared_userns` +
`create_shared_pidns` + `hold_cage_mode`, in-process, forked PID-1 child, no exec — exactly
`cage.rs`), and — critically — I made the **rank faithful too**: a real
`bwrap --userns 9 --pidns 8 … -- reader` process. A real husk rank has `CapPrm=0`
(`settings.rs` adds no `--cap-add`; bwrap drops all caps on exec — I verified both). My first
attempt used a `setns`+`fork` reader, which is **not** faithful: it never `exec`s inside the
shared userns, so its `mm->user_ns` and its whole ptrace posture differ from a bwrap rank. The
tell that my harness was finally faithful: it reproduces the ground truth **`cma.peers`** — an
empty-caps rank reads a peer rank — which any correct harness must.

**What happened** (`runb.sh`/`runc.sh`, faithful bwrap ranks, Yama neutralised on the reader):

```
holder AS BUILT (CapPrm full):
  reader→peer rank (pid 3):   READV 8  WRITEV 8      # cma.peers reproduced ✓
  reader→holder   (pid 1):    READV EPERM  WRITEV EPERM
holder CAPS DROPPED (CapPrm 0):
  reader→peer rank (pid 3):   READV 8  WRITEV 8
  reader→holder   (pid 1):    READV EPERM  WRITEV EPERM      # UNCHANGED
```

Dropping the holder's capabilities changes **nothing** — the holder stays unreadable and
unwritable to a faithful rank. The finder's second row does not reproduce.

**Why the finder got a different answer.** Their reader was more capable than a real rank.
I proved capabilities are not the discriminator with a controlled sweep (`run2.sh`,
`run3.sh`): a reader with **only `CAP_SYS_PTRACE`** in the shared userns reads the caps-0
holder fine; a reader with **empty caps** cannot — *regardless of the holder's caps*. So the
gate is the reader's privilege (`ns_capable(target_userns, CAP_SYS_PTRACE)`), and
`cap_issubset(0,0)` — which the finder's mechanism says would *grant* the read when both are 0
— demonstrably does **not** grant it. That is a direct refutation of the stated mechanism: if
`cap_issubset` governed, holder-0 / rank-0 would succeed. It does not.

**What actually protects the holder** (`runc.sh`, one reader, three targets, everything else
held constant — same uid, shared userns membership, shared pidns, dumpable=1, empty-caps
reader):

| target | how it was made | `mm->user_ns` | empty rank can read? |
|---|---|---|---|
| pid 1 holder | forked, never `exec`'d after unshare | initial ns | **EPERM** |
| pid 2 grandchild | forked in the shared ns, never `exec`'d | initial ns | **EPERM** |
| pid 3 peer | **`exec`'d by bwrap** inside the shared ns | shared ns | **OK** |

The discriminator is that the holder is **not a bwrap-constructed process exec'd into the
shared namespace** — its `mm` belongs to the initial user namespace because it does everything
in-process (`main.rs:180-183`, by design). That is exactly what the `main.rs` comment says. I
add one honest correction to *both* documents: `mm->user_ns = shared` alone is **not
sufficient** — a process I re-`exec`'d in place inside the shared ns (no bwrap;
`rund.sh`) stayed `EPERM`; being a genuine bwrap rank (which also carries `NoNewPrivs=1`, an
emptied bounding set, and its mount/AppArmor posture) is what makes ranks mutually readable.
The precise final gate is partly platform-specific (this box has AppArmor + Yama; Balfrin has
neither), but the finding's headline does not survive on any reading: **capabilities are not
the wall, and dropping them does not breach it.**

**Verdict / severity.** REFUTED. Acting on F1 would install a spurious invariant ("the holder
must never drop capabilities") that is simply false — the holder is protected structurally,
caps or no caps. **One sub-observation is still worth keeping:** the holder's unreachability
has no test, and `cma.outside` (scans `/proc` for `--step-broker`, never in a rank's `/proc`)
short-circuits to `NOBROKER→PASS`, so it never probes the rank-visible PID 1. A `cma.holder`
arm (`process_vm_readv(1,…)` from a rank, expect `EPERM`) is cheap and would *pass today*,
pinning the wall. Add it — but not for the reason F1 gives, and run it on 5.14 since the exact
gate is platform-sensitive.

Commands: `gcc holder.c reader.c peer.c …`; `runb.sh ""`, `runb.sh --drop-caps`,
`runc.sh ""`, `runc.sh --drop-caps`, `run2.sh --drop-caps --keep-ptrace`, `rund.sh`.

---

## F2 — CONFIRMED. "The holder can clear `PR_SET_DUMPABLE`" is a landmine for the real holder.

**The claim.** `CAGE-PROFILES.md:204-212`, `main.rs:204-217` and `THREAT-MODEL.md:212-217`
each record as measured that a non-dumpable holder is "still openable and joinable with
`bwrap --userns` by a sibling" and call it a two-minute "cheap win." The finder measures the
opposite for the holder *as built* and says `cage.rs:89-97` is the correct one.

**What I did.** Ran the faithful holder in four shapes and, for each, tested exactly the rank's
own gate — can a same-uid sibling open `/proc/<held>/ns/user`? I confirmed the three docs make
the claim verbatim (`grep`).

**What happened** (kernel 6.8, the same kernel the notes cite):

| holder shape | `[ -r /proc/<held>/ns/user ]` | rank outcome |
|---|---|---|
| as built (dumpable, no exec) | **TRUE** | joins |
| clears dumpable **after** the maps, no exec (**husk's shape**) | **FALSE** | "cage holder is gone", exit 1 |
| clears dumpable **before** the maps | holder cannot be created (`open /proc/self/setgroups: Permission denied`) | — |
| `exec`s inside the new userns, then clears (userns-only variant) | **TRUE** | joins |

The last row explains the contradiction: `mm->user_ns` is fixed at `exec`, so a process that
`exec`s inside the new namespace is owned by it and `ns_capable(mm->user_ns, CAP_SYS_PTRACE)`
keeps the link open. husk's holder never `exec`s after `create_shared_userns`
(`main.rs:180-183`), so its `mm->user_ns` is the initial namespace and clearing dumpable shuts
the door. This is the **same mechanism** that refutes F1, applied the other way. (My harness
could not build the exact `exec`-inside-**and**-pidns holder because `exec` drops the caps that
`unshare(CLONE_NEWPID)` needs — which is itself *why* husk's holder stays in-process; the
userns-only variant isolates the readability question cleanly.)

**Verdict / severity.** CONFIRMED. `cage.rs:89-97` ("a holder that had cleared
`PR_SET_DUMPABLE` would be one whose namespace no rank can open") is right; the three
"corrections" are wrong for this process. It fails **closed** — a job dies loudly, it does not
run uncaged — so it is a landmine, not a hole. **LOW.** Its danger is the "cheap win" label
inviting a change that kills every step. Note the docs *also* say "measure on 5.14 before
trading," so the residual is a hardware check, but the mechanism is a stable kernel invariant
and there is no reason to expect 5.14 to differ.

Commands: `holder --dumpable-after`, `--dumpable-before`, `--no-pidns --exec-then-dump`,
`--no-pidns --dumpable-after`, each with stdin held open by a pipe feeder.

---

## F3 — CONFIRMED (accumulation, node-global) / NEEDS-HARDWARE (exhaustion).

**The claim.** The non-reaping PID 1 turns orphaned rank children into **node-global** zombies
that hold a pid number in every ancestor pid namespace, including the node's — the one place a
rank's behaviour reaches past the job. `cage.rs:198-203` calls this "harmless."

**What I did.** setns into the holder's user+pid ns, forked into the shared pidns, created 30
orphan grandchildren (parent exits, grandchild `_exit`s → reparents to PID 1), and counted
**host-visible** zombies. (A bwrap-launched orphan-maker hid them behind bwrap's
child-subreaper — worth knowing — so I orphaned them directly in the pidns.)

**What happened.**

```
host zombies parented to the holder-child (pidns PID 1) BEFORE: 0
after 30 orphans:                                               30
  21330 21320 Z nsorphan2 <defunct>   (…and 29 more, all ppid = the holder's host pid)
total host (node namespace) zombies: 30      # visible in `ps -e`, i.e. node-global
after the holder is torn down:                0
```

Each zombie is listed by `ps -e` in the **initial** pid namespace and occupies a host pid
number — a node-global resource shared with every other user's job on the node — plus a
`task_struct` and a per-uid ucounts slot, for the job's lifetime. "Destroyed when the job ends"
is true; "harmless" is not, *during* the job. This is the only mechanism I found by which a
rank reaches past the job boundary, and it is new: before the shared pidns an orphan reparented
to a reaping ancestor and was collected.

I also validated the proposed one-line fix: with the holder child running
`signal(SIGCHLD, SIG_IGN)`, the same 30-orphan test leaves **0** zombies, and `kill -9 1` from
inside a rank is **still ignored** (holder survives) — so `SIG_IGN` does not weaken the
namespace-init signal protection.

**Verdict / severity.** CONFIRMED for accumulation and node-global visibility. **MED-LOW.**
Whether it can be pushed to node-wide `fork()` failure is **UNRESOLVED — NEEDS HARDWARE**:
locally `pid_max=4194304`, `ulimit -u=123979`, so the per-uid limit binds first and the DoS is
self-limited; on a Cray Shasta node the ordering may invert.
**Settle it on Balfrin:** `cat /proc/sys/kernel/pid_max; ulimit -u` — if `pid_max` is not
comfortably larger than `ulimit -u`, a rank spawning orphans can consume node-global pids that
affect other users, and the fix stops being optional.

Commands: `nsorphan2.c` under `holder` (and `holder --sigchld-ign`); `ps -eo pid=,ppid=,stat=`.

---

## F4 — CONFIRMED (a: permanent wedge, source) / PLAUSIBLE (b: pid reuse).

**(a)** `step.rs:126-129`: `ensure_holder` returns `Ok(h.pid)` whenever `self.holder` is
`Some`, with no liveness check, and `self.holder` is never reset to `None` (`reap` touches only
`in_flight`). `pid_is_alive` exists (`lib.rs:110-113`) and is used for the spool owner
(`lib.rs:182`) but **not** for the holder — the one lifetime that does not use it. So if the
holder child dies (OOM, external `kill`, cgroup event) its parent keeps blocking on stdin,
`ensure_holder` keeps returning the dead pid, and every later step dies at the rank's `-r` gate
with "the job's cage holder is gone" for the remaining wall time, with nothing re-creating it.
CONFIRMED by source; fails closed and loud, no containment impact. **MED-LOW** (availability).

**(b)** A bare pid is a recyclable name. The benign case fails closed — I reproduced it
throughout F1/F2 work: a rank pointed at a live pid in the initial user namespace is refused by
bwrap ("might not be a descendant"). The case that would **not** fail closed is a pid recycled
onto *another husk holder of the same user on the same node*: the rank script uses whatever pid
it is handed, so it would join that job's user+pid namespace and land in its CMA domain —
contradicting `THREAT-MODEL.md`'s "not another job's ranks." The mechanism is trivially true;
the precondition (holder death + pid wraparound onto a concurrent same-user holder) I did not
force (impractical, and out of the rules of engagement). Same uid, so the confidentiality cost
is small. **PLAUSIBLE, LOW.** The finder's fix (record `readlink` of `ns/user`+`ns/pid` at
`ensure_holder`, interpolate the expected `user:[…]`/`pid:[…]` into the rank script, and
`try_wait()` each tick) closes both and is testable without hardware.

---

## F5 — CONFIRMED (mechanism, end to end) / PLAUSIBLE (exploitability). The only cross-user finding.

**The claim.** `rank.rs:272-277`'s `[ ! -O "$_d" ]` ownership check follows symlinks, so a
co-tenant can pre-create `/dev/shm/husk-<jobid>` as a symlink to a victim-owned directory and
redirect the `--bind` source.

**What I did.** Reproduced the exact shell snippet against a stand-in world-writable dir, in
both `dash` and `bash`, then confirmed bwrap follows the symlink source end to end.

**What happened.**

```
planted:  /dev/shm-stand-in/husk-9999 -> <victim-owned dir with secret.txt>
dash:  mkdir -m 700 → EEXIST (|| true);  [ -O ] → PASS;  target = <victim dir>
bash:  same → PASS
bwrap --bind "$_d" /dev/shm:
   inside the cage, /dev/shm shows the victim dir, read-write
   cat /dev/shm/secret.txt → "SECRET-HOME-DATA"     (read through the home-hiding cage)
   echo PWNED > /dev/shm/attacker-wrote-here → landed in the victim dir  (write, too)
```

`[ -O ]` uses `stat` (follows symlinks), and the sticky bit stops deletion, not creation of the
symlink — exactly as the code's own comment warns, and exactly what the check fails to prevent.
The `--bind "$_d" /dev/shm` is emitted **after** the policy args (`rank.rs:187-199`), so bwrap
applies it last and it wins; nothing else validates the path.

**Reachability.** Path predictable (`/dev/shm/husk-$SLURM_JOB_ID`, job id public in `squeue`);
co-tenancy real (`--nodes=1` is forced but **`--exclusive` is not** — `profile.rs:62-66`);
window real (the attacker plants before the first rank's `mkdir`, and the sticky bit then stops
the victim removing it). One important bound: `[ -O ]` only passes when the symlink target is
owned by the **job's** user, so the attacker can only surface *victim-owned* dirs *into the
victim's own cage* — they cannot inject their own data and gain nothing for themselves. So this
is a third party **defeating the victim's containment** (home-hiding, and the F6b auto-exec
masking), not classic cross-user theft. The confined agent cannot plant it itself (its
`/dev/shm` *is* the bind), which is why exploitability is PLAUSIBLE rather than demonstrated
against the live broker.

**Verdict / severity.** CONFIRMED mechanism (I ran the read *and* the write through a real
cage). **MEDIUM** — it defeats a documented containment control with a trivial fix
(`[ -d "$_d" ] && [ ! -L "$_d" ] && [ -O "$_d" ]`), bounded by needing a co-tenant and by the
attacker gaining nothing directly. **Overlaps B3** (mount-table construction): B3-findings.md
line 87 lists this same `--bind "$_d" /dev/shm` and marks the `mkdir -m 700` + `[ -O ]` guard
"**Correct**." It is not. Flagged, not resolved.

---

## F6 — CONFIRMED (doc defect). `settings.rs` says twice that a rank cannot do what `rank.rs` does.

`settings.rs:621-628` and `settings.rs:1195-1200` state that `bwrap --pidns FD` is parent-only,
that **bwrap 0.6.1** "fails outright (`Can't send pid: Invalid argument`)" without
`--unshare-pid`, and therefore "ranks cannot JOIN a shared PID namespace." On **bwrap 0.6.1**
(the exact version cited) I ran `bwrap --userns 9 --pidns 8 … ` with **no** `--unshare-pid`
dozens of times across F1/F2/F3/F8: it joins, the payload lands as a low pid in the holder's
pidns (peer reported `pid-in-ns=3`), and `/proc` reflects the joined namespace. `rank.rs:187,194`
emits exactly that. The comment is stale and argues *for* per-rank PID namespaces — the ICON
failure one layer down.

The adjacent test (`only_the_job_cage_unshares_pids…`, `settings.rs:1201-1218`) asserts only
`!rank.contains("--unshare-pid")` and `job.contains("--unshare-pid")` — both consistent with
the *wrong* comment and the *correct* code, so a reader who trusts the comment and "fixes"
`rank.rs` gets no complaint from it. (The positive behaviour is in fact pinned elsewhere, by
`rank.rs`'s own `the_rank_joins_the_jobs_shared_user_namespace`, which asserts `--pidns 8`.)

**Verdict / severity.** CONFIRMED doc defect. **LOW** — no runtime impact; `rank.rs` is
correct. **Overlaps the B3 shard** (`B3-findings.md:423` repeats the same parent-only claim).
Per the brief: flagged, **not resolved.**

---

## F7 — CONFIRMED (minor). The rank script's fail-closed guarantee is shell-dependent.

`rank.rs:261-265` gates on `[ -r "$_u" ]` then `exec 9<"$_u"`. The redirection is not itself
guarded:

```
dash:  exec 9</missing → shell EXITS (rc=2)
bash:  exec 9</missing → prints an error and CONTINUES (rc=0)
```

So in the TOCTOU window between the `-r` test and the open, `bash` proceeds with fd 9 unopened;
`bwrap --userns 9` then fails "Bad file descriptor" and exits 1. The outcome is still
fail-closed, but the guarantee is **bwrap's**, not the script's, and the comment credits the
script. The finder's "`/bin/sh` is bash on both clusters" I could **not** verify here (my
`/bin/sh` is dash, which fails-closed even harder), so it is the load-bearing assumption; either
way the result is fail-closed. **INFO/LOW.** `|| exit 1` per redirection makes the stated
belt-and-braces real.

---

## F8 — CONFIRMED (hygiene, no impact found).

Inside a real bwrap rank, `/proc/self/fd` shows `8 -> pid:[…]` and `9 -> user:[…]` — the job's
two shared-namespace handles, left open into the workload (bwrap does not close them). I
attacked them: `ioctl(9, NS_GET_PARENT)` → **EPERM** (cannot walk to the initial user
namespace), `ioctl(8, NS_GET_PARENT)` → **EPERM** (cannot reach the node's pid namespace),
`setns(9, CLONE_NEWUSER)` → **EINVAL** (already a member). No escalation available; they only
pin the two namespaces alive, which is harmless because the holder outlives every rank anyway.
**INFO.** "No use found" is a weaker statement than "closed," which is why it is recorded.

---

## What held (independently re-checked during this pass)

- **`cma.peers` reproduces** — an empty-caps bwrap rank reads a peer rank's memory
  (`READV/WRITEV 8`). This is the ground truth that validated the F1 harness.
- **No join path degrades to a private namespace.** `--userns`/`--pidns` are unconditional in
  `rank.rs`; bwrap refuses a bad, absent, or foreign fd (exit 1). The brief's null result holds.
- **The map is an identity map, never a root map**; `[ -O ]` aside, every namespace-fd join is
  fail-closed at bwrap.
- **A rank cannot kill the holder** — `kill -9 1` from inside returns success and the holder
  survives (namespace-init signal rule), confirmed again, including under `SIGCHLD=SIG_IGN`.
- **SIGSYS vs EPERM discipline held throughout:** every kernel denial in this pass was
  `EPERM`/`EINVAL`/`ESRCH`; nothing here exercised the seccomp filter (no exit 159).

## Not reached / gaps

- **F3 exhaustion** and **F2 on 5.14** are the two open hardware questions, each with an exact
  command above.
- The **precise** kernel gate distinguishing a readable bwrap peer from an unreadable
  re-exec'd process (`NoNewPrivs` / bounding set / AppArmor) was not pinned to a single cause —
  it is partly specific to this Ubuntu box (AppArmor + Yama), and Balfrin has neither. It does
  not change F1's verdict: capabilities are not the gate, and the holder stays protected.
