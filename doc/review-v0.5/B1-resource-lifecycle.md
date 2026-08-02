# B1 — resource lifecycle: RAII mapped onto the OS

**Workstream B** (control-coverage) · **code-only, laptop** · **deliverable is a table**

## The question

Does every resource husk acquires have a named owner and a release on **every** exit path —
including the error paths — and which of three tiers is each one actually in?

## Why this is on the list

Two of our own bugs, both the same shape:

- **Parentless processes.** `create_shared_pidns()` forked a child to hold the namespace and
  nothing owned it; it outlived the broker on every job. Fixed with `PR_SET_PDEATHSIG`, a
  `getppid()==1` guard, and an explicit `kill(held, SIGKILL)` at exit.
- **Spools not cleaned up.** Login and step spool dirs survived their session. Fixed with
  ownership records, `remove_spool_dir`, and a startup reaper — and the step spool *also*
  needed the socat bind moved, because a live mountpoint cannot be removed (`EBUSY`). **A
  cleanup that cannot execute is not a cleanup.**

Note how each was found: the spool leak by **looking at the directory afterwards**, the
untrapped `SIGTERM` (`2f366d2`) by **sending the signal**. Neither by reading code. That is
where this class hides.

## The three tiers

`Drop` is **cooperative**, and SIGKILL, OOM-kill, node failure and preemption all defeat it.
So the question is never "is there a release?" but "which tier?":

1. **Cooperative release** — Rust `Drop`, a shell `trap`, an explicit close. Correct on clean
   paths, **worthless under a hard kill**. Anything with only this is a leak awaiting SIGKILL.
2. **Kernel-coupled lifetime** — release does not depend on our code running: `PDEATHSIG`, a
   pidns dying with its PID 1, cgroup teardown, mount-namespace teardown, `O_TMPFILE`, SLURM's
   own proctrack. **This is the tier to prefer.**
3. **A reaper** — an out-of-band sweep repairing what 1 and 2 missed (our startup spool
   reaper). Must itself be **ownership-gated** (`owned_by_me`), or it becomes a way to delete
   other people's state.

## Inventory to start from

Not exhaustive — extending it is part of the task:

session spool · step spool · the userns holder · the pidns holder child · socat relays (one
per job, one per rank) · the netproxy · the step-broker · the namespace file descriptors
handed to bwrap · the egress unix socket · the broker request socket · bind mounts inside the
cage · **the submitted SLURM job itself**.

That last one is deliberate: an allocation is a held resource too, and today it outlives the
session that created it. The review should confirm that is a **decision**, not an omission.

## What counts as a finding

- **Any resource whose only release is tier 1.** That list is the headline deliverable.
- A resource with no named owner at all.
- A release that can be reached but cannot succeed (the `EBUSY` shape).
- A reaper that is not ownership-gated, or whose ownership test is spoofable.
- An error path — `?`, early return, panic, signal — that skips a release the happy path runs.
- A resource acquired inside a loop or retry whose release is outside it.

## What a null result looks like

A complete table: every acquisition, its owner, its tier, and the evidence for that tier. "I
reviewed the cleanup code and it looks thorough" is not an answer. **A table where every row
is tier 2 or 3 is an excellent result and should be stated as one.**

## Out of scope for this item

- Memory and file-descriptor hygiene *within* a process where Rust's own `Drop` already
  applies and no OS-visible resource outlives it.
- Performance of cleanup paths.
- The laptop's leaking Rust test fixtures (`husk-test-work-<pid>` and friends) — known, and
  test-only. Mention if it informs the pattern; do not spend time there.

## Verdict

Code-only, so the verdict is the argument itself plus, where cheap, a demonstration: kill a
process with `SIGKILL` rather than `SIGTERM` and look at what remains. Any claim of the form
"this is released on every path" that can be tested by sending a signal **should be**.
