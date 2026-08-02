# B4 — the holder, the shared namespaces, and the CMA concession

**Workstream B** (control-coverage) · **code-only, laptop** · hardware claims must be marked

## The question

Is the shared-namespace concession correctly **bounded**? Ranks can see and read each other by
design — can anything reach beyond the job, and can a rank ever end up in a *private*
namespace instead of the shared one?

## Why this is on the list

This is the newest architectural invariant and the one most likely to be assumed correct.

The principle: **the unit of confinement is the job on a node, not the process.** All ranks of
one job share a uid, an allocation, files and data — they are one trust domain. So there is
one cage per node that tasks *join*, rather than a cage per rank. Per-task cages were N
redundant copies of the same boundary, and one of those copies — the user namespace — was
what **blocked CMA**, because sibling user namespaces cannot `ptrace_may_access` each other.

The deliberate consequence, which must be stated to any reviewer or they will report it as a
bug: **a rank can `process_vm_readv` its peers. That is intended.** MPICH needs it. What must
*not* be reachable is anything outside the job — the un-caged step-broker, the egress proxy,
another user's work, the node itself.

## What the code does today

- `cage.rs::create_shared_userns()` — one bare identity-mapped user namespace per job.
  **Identity-mapped, never root-mapped**: `EUID==0` flips the agent runtime into a
  `--cap-drop ALL` branch that empties the bounding set.
- `cage.rs::create_shared_pidns()` — forks a holder child, which sets
  `PR_SET_PDEATHSIG(SIGKILL)`, guards `getppid()==1`, then parks in a `pause()` loop.
- Ranks join with `bwrap --userns <fd> --pidns <fd>`, then build their own cage inside.
- `PR_SET_DUMPABLE` is used to refuse ptrace/CMA against the broker.

Kernel rules that force this shape, each measured rather than assumed: creating a pidns needs
`CAP_SYS_ADMIN`, so the userns must come first; `unshare(CLONE_NEWPID)` affects only children,
hence the fork; a pidns dies with its PID 1, so the holder must outlive every rank; and **a
handler-less namespace init ignores every signal it has no handler for, even from an ancestor
namespace** — only SIGKILL and SIGSTOP get through, which is why `PDEATHSIG=SIGTERM` silently
failed.

## Starting points

1. **Fail-closed on join.** A rank that cannot enter the shared namespace must *die*, never
   fall back to a private one. Find every path where the join can fail and check what happens.
2. Holder lifetime at both ends: it must not die early (that would take every rank with it)
   and must not survive the job (that is the leak fixed in `9faad58`).
3. The `PR_SET_DUMPABLE` refusal — what exactly does it protect, and is it applied everywhere
   that assumption is relied on?
4. The seccomp delta that permits `process_vm_readv` but not `process_vm_writev`. Is the
   asymmetry actually enforced, and is read-only sufficient for the threat we accepted?
5. PID 1 in the job's pidns does not reap, so orphaned ranks leave zombies for the job's
   lifetime. Known and accepted as harmless — confirm the reasoning, or refute it.

## What counts as a finding

- A rank reaching **any** process that is not a rank of the same job.
- A join failure that degrades to a private namespace instead of dying.
- A holder that can be killed by something inside the cage, or that outlives the job.
- A path where the userns is root-mapped rather than identity-mapped.
- `process_vm_writev` succeeding against anything, from inside a rank.

## What a null result looks like

A statement of the boundary as built — what a rank can reach, what it cannot, and by which
mechanism each is enforced — with the fail-closed paths enumerated. Marking a claim
"hardware-verified" vs "read from source" matters here; do not blur them.

## Out of scope for this item

- Whether sharing a namespace across ranks is the right design. That decision is made and
  documented; the question is whether it is bounded as claimed.
- Multi-node MPI. Single-node is the shipped profile.
- Attempting to break out from inside a rank — that is workstream A.

## Verdict

Mostly source-level. Where a claim can be settled by a probe (`cma.peers`, `cma.outside`,
`steps.pidns*` already exist), say which arm settles it. **Read the errno before widening a
filter: `SIGSYS` is ours, `EPERM` is the kernel's** — conflating them has cost us a round.
