# A4 — the step spool, a new agent-writable trust seam

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

> **Refreshed 2026-08-03, after the v0.5 fixes.** The step spool itself is largely unchanged
> and everything below still applies. Three things around it moved — the holder's liveness, the
> per-rank `/dev/shm` check, and what survives a job — and one of them turned a starting point
> below into a CONFIRMED bug that has since been fixed. Marked ★ where it matters.

## The question

The step spool is a directory the caged ranks can write and the **trusted** step-broker reads.
Can a rank write something into it that makes the step-broker do its bidding?

## Why this is on the list

It is a new trust seam introduced by the srun/step architecture, and it has the same shape as
the original spool bug: **`F1` — the spool `id` let the broker write anywhere, as you.** Any
directory where the confined side writes and the trusted side reads is a candidate for the
same class.

The step-broker reads step requests from this spool, validates them **as hostile input**
(`step.rs` header says so), and launches ranks. So the design already treats it as adversarial;
this brief tests whether that treatment is complete.

## What the code does today

- The step spool lives in the workdir: `<workdir>/.husk-step-spool-<jobid>`.
- `step.rs` reads step requests from it and validates them. `is_workdir_allowed` gates the
  step's cwd (absolute, not under `/users`, no traversal).
- The spool is removed when the job ends — egress socket and socat included (verified by
  `job.spool_reclaimed` after a real job on hardware, and `guard.spool_removed` for the guard
  path).

★ **Changed since this brief was written, all in the "what a rank can leave behind" area:**

- **`--die-with-parent`** is now on both cages. A task that ends takes its sandbox with it, so
  a process backgrounded by a rank no longer outlives the rank. This closed a real gap (the
  guard used to clean up and announce the job finished while the workload ran on in an orphaned
  bwrap) — and it is worth knowing because it changes what "still running" means when you
  measure.
- **`/dev/shm/husk-<jobid>` is now owned and released**, and its ownership check is
  symlink-safe. Starting point 5 below asked whether a rank could point a shared resource at
  something else: **the answer was yes** — `[ -O "$_d" ]` followed symlinks, so a co-tenant who
  won the race to create that path could land a directory of ours read-write inside every rank
  cage. Fixed (`916880b`). **The lesson generalises to the rest of this brief: test every
  ownership and existence check for symlink-following, not just this one.**
- **The holder pid is liveness-checked** before reuse, and PID 1 reaps by disposition. A stale
  holder used to wedge every later step; a stale *recycled* pid could have named a different
  process.

## Starting points

1. **The request fields.** Every field a rank can set in a step request is agent-controlled.
   For each: is it validated before it becomes a path, an argv element, a mount, or an
   environment entry? `req.cwd`, the argv, and any forwarded environment are the ones to press.
2. **Path handling.** A field that becomes a filename in the trusted process — can it contain
   `..`, an absolute path, a symlink, or a `NUL`? `F1` was exactly a spool id used as a path.
3. **Symlink races.** The spool is agent-writable and the step-broker reads it. Between the
   step-broker's `stat` and its `open`/`read`, can a rank swap a file for a symlink? (`F20` was
   a symlink swapped while a job waited in the queue — the same TOCTOU shape.)
4. **Request injection.** Can a rank write a *second*, forged request into the spool that the
   step-broker will act on — one the srun stub never sent?
5. **The socket and socat.** They live in this directory. Can a rank replace the egress socket
   with its own, or point socat at a different target, before the trusted side binds it?
   ★ The neighbouring version of this question — the `/dev/shm` ownership check — was a real
   cross-user break. Assume this one deserves the same suspicion, and note the egress socket
   now lives in node-local `/tmp/husk-<uid>-<jobid>/` rather than the spool, which moved the
   target rather than removing it.
6. **Non-emptiness at cleanup.** A directory that still holds a live mountpoint cannot be
   removed (`EBUSY`) — can a rank *keep* the spool un-removable to force accumulation, or to
   preserve something across the boundary?
7. **★ The body file.** New since Fix 1: the agent's job script is staged at
   `<write-root>/.husk-body-<req.id>.sh` and the guard `rm -f`s it. That is another
   agent-influenced path in a directory the job can write — same family as everything else
   here. (Owned by A3; flag overlaps rather than chasing them.)

## What counts as a finding

- Any step-request field that reaches a path, argv, mount, or environment in the trusted
  step-broker without validation.
- A forged request the step-broker acts on.
- A TOCTOU between validation and use.
- A rank causing the trusted side to read, write, or execute outside the job's own resources.
- A rank preventing cleanup, or preserving state past the job's end.

## What a null result looks like

An enumeration of the step-request fields, each with how it is validated and what was tried
against it; plus the race attempts, with timing. "The step-broker validates its input" is not
an answer — name the fields and the attempts.

## Out of scope for this item

- The session (login) spool — same class, but that is exercised by the lifecycle tier and B1.
- The network hole reachable *through* the socket (A9); here the question is only whether the
  socket itself can be subverted at the spool.
- `req.env` semantics in general (A2) — here, only its arrival via a step request.

## Verdict

Execution inside a rank; verdict from the step-broker's log or a marker the trusted side wrote
where it should not have. A rank asserting it influenced the step-broker is a hypothesis; the
step-broker's own record is the proof.
