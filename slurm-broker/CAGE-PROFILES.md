# husk — cage profiles (design)

**Status: decided 2026-07-29. Topology selection + forcing IMPLEMENTED (`broker/src/profile.rs`);
the seccomp profile flag is not.**

| piece | state |
|---|---|
| `Profile` enum, broker-side selection | done — `profile.rs` |
| single-node **forced** via `--nodes=1` | done — `--nodes` is `Class::Forced`, policy.rs validates + the profile emits |
| multi-node rejected with a teaching message | done |
| MUNGE mask in the floor | done, verified 33/33 on Balfrin |
| AF_UNIX block as a `seccomp-wrapper --profile` flag | **not yet** — see Open |
| rank-cage args (per-job `/dev/shm`, apinfo bind, CXI) | **not yet** — arrives with the srun step-broker |

## Why profiles exist

The compute cage and the login cage have diverged — GPU device nodes, CXI NICs, a
per-step apinfo bind — and every one of those divergences was justified. The defect was
never that they diverged; it is that the divergence was **accidental**. Nobody decided
that a compute job may use AF_UNIX where the agent may not; it simply was never wired.

Profiles make the divergence **declared, bounded and reviewable**.

## The invariant

Literal configuration parity between login and compute is impossible: an agent shell and
an MPI job need different things from the kernel. The requirement that actually matters
is narrower:

> **No escape-relevant capability may be available on compute that is denied on login.**

*Escape-relevant* = can reach outside the cage: network egress, credentials, job
submission, planting code that runs later, writing outside the workspace. GPUs, the
fabric and shared memory are **resource** access, not escape surface — diverging there
costs nothing.

AF_UNIX shows why this has to be judged per *destination*, not per syscall: a unix socket
to `sssd` for name lookups is not escape surface; a unix socket to MUNGE is. That is why
the MUNGE **mount mask** and any future syscall filter are complementary rather than
redundant — and why the mask belongs in the floor even if a profile allows AF_UNIX. It is
in exactly that case that the mask becomes the only wall between the job and the
scheduler.

## Direction of convergence

The login cage runs on **Anthropic's runtime, which ROADMAP step 5 drops**. The compute
cage is **ours**. So compute is not the thing that should imitate login — compute is the
reference implementation of the sandbox we intend to own, and convergence runs
**login → compute**.

Practical consequence: a rule we want on compute (say, restricting AF_UNIX) is
implemented in **our** `seccomp-wrapper`, never by shipping their `apply-seccomp` to
compute nodes. When step 5 arrives, login adopts our filter and nothing needs porting.

## The three profiles

The axis is **topology**, because topology *is* the threat axis — it determines what
network and credential reach the job requires.

| profile | escape-relevant delta | status |
|---|---|---|
| **login** | interactive adversary with tool access; no compute resources | today: Anthropic runtime + husk settings |
| **single node** | none — needs no IP at all (measured) | the Chapter-1 target |
| **multi node** | requires an IP path for the PMI bootstrap | **rejected today**; own phase |

**CPU vs GPU is not a profile.** The only difference is the `/dev/nvidia*` nodes, and
`--dev-bind-try` is already absent-safe: on a node without GPUs the binds silently skip.
The variant is implicit in the mechanism, so there are three profiles, not six.

Each profile is **floor + declared delta**, and every delta entry carries three fields:
*what it opens*, *why the workload needs it*, *what compensating control bounds it*. A
divergence without a written justification is a bug, not a feature.

## Who picks — and why that is safe

**The broker picks.** The profile is a *function of an option the broker already forces*,
so it introduces **no new agent-facing input language**: nothing to parse, nothing to
attack. Strictly less surface than letting the agent request a profile.

**It must be forced, not inferred.** `--nodes` is `Class::Allowed` today, and
`--ntasks N` *alone* can be spread across several nodes by the scheduler — so the node
count is not always knowable at submit time. A profile derived by *reading* the request
could therefore dress a two-node job in the single-node cage. So the single-node profile
**emits `--nodes=1`** as a forced option, exactly like `--partition`: guaranteed by
construction, not predicted. (Same lesson as the option allowlist: capture values, don't
trust references.)

## Failure mode: loud

Blocked syscalls kill the process (`SCMP_ACT_KILL_PROCESS`), rather than returning an
error the program might quietly absorb. The `pmix` episode is the argument: a graceful
`EPERM` let MPI "succeed" as two independent one-rank jobs — a run that reports success
and computes the wrong answer is worse than a crash.

Loud must not mean cryptic. A `SIGSYS` death tells a scientist nothing, so the guard
detects status 159 and prints which layer killed the job and how to identify the syscall.

It points at **`strace` inside the unchanged cage**, *not* at `SECCOMP_WRAPPER_DEBUG`.
That variable swaps `KILL` for `ERRNO(ENOSYS)`, so blocked calls return and the program
continues — an off-switch, not a diagnostic, and one whose safety would depend on who
controls the environment. **A diagnostic may change what we OBSERVE, never what we
ENFORCE** — the same reason the broker has `--dry-run` and no debug mode. Under strace the
filter still kills; strace merely shows the call it died attempting. The broker also
strips the variable from the submission environment, so no brokered job can run weakened
even if it is set in the launching shell. Revisit the kill-vs-error choice if users find
it too blunt.

## Keeping the tedium bounded

Discovering what each profile needs is the tedious part. Four things bound it:

1. **Profiles** mean requirements are not re-derived per job — new workloads mostly fit
   an existing one.
2. **`fabric-probe.sh` already does the discovery**: start from the strictest profile,
   run the workload, record what it needs, add exactly that, re-run. Every addition is a
   diff with hardware evidence — the same loop as *"unsupported sbatch option → add it to
   the registry"*, which worked.
3. **Failures name their cause**, including which profile would permit the operation.
4. **Every discovered requirement becomes a `selftest.sh` arm**, so it cannot silently
   regress. The profile documents state *intent*; the tests state *facts* — when they
   disagree, the tests win.

## Open

- ~~Does a caged MPI job need AF_UNIX at all?~~ **ANSWERED — no** (gate C12, Balfrin
  2026-07-29, job 4972255): **zero** `socket()`/`connect()` calls mentioning AF_UNIX in a
  caged 2-rank run, and the traced run was a verified real 2-rank job. PMI is TCP, shared
  memory is `mmap`, CXI is `ioctl` — the MPI stack simply does not use unix sockets.
  So the **single-node profile carries the AF_UNIX block**, giving capability parity with
  the login cage on that axis rather than only the MUNGE mask.
  *Scope of the claim:* `socketpair(AF_UNIX)` was not traced and is deliberately not
  blocked — it yields a pair of the process's own fds with no path, so it cannot reach a
  daemon; reaching one needs `socket()`+`connect()` to a `sun_path`, which is what was
  measured (the same line Anthropic's filter draws). *Limitation:* the sample is a tiny
  MPI program that never resolves a user, so **ICON's first run under the block is the
  real validation** — `getpwuid` via sssd is exactly the sort of call that would open one.
  Failure will be loud and diagnosable, which is the point of the SIGSYS message.
- Implementation note: the block must be a **profile flag on our `seccomp-wrapper`**, not
  a new default. The login launcher wraps the whole session (`seccomp-wrapper claude`),
  and the agent runtime plausibly needs unix sockets for its own IPC (MCP, IDE
  integration) — which is presumably why Anthropic applies their AF_UNIX block per Bash
  command rather than to the runtime. So: `--profile=login` (current behaviour) stays the
  default; the compute guard passes the stricter profile explicitly. Verify when
  implementing that `bwrap` itself survives the block — the wrapper installs the filter
  and then execs bwrap, so bwrap runs under it.
- Whether SLURM's device cgroup constrains a job to its *allocated* GPUs (it is the same
  exposure uncaged either way, so not a husk regression).
- The full syscall-set delta between our `seccomp-wrapper` and Anthropic's
  `apply-seccomp` — worth enumerating before step 5, so login's move onto our filter is
  a diff nobody has to rediscover.
