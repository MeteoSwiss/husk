# A4 — the step spool, a new agent-writable trust seam

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

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
- The spool is removed when the job ends — egress socket and socat included (verified now by
  `job.spool_reclaimed` after a real job, and `guard.spool_removed` for the guard path).

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
6. **Non-emptiness at cleanup.** A directory that still holds a live mountpoint cannot be
   removed (`EBUSY`) — can a rank *keep* the spool un-removable to force accumulation, or to
   preserve something across the boundary?

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
