# husk — cage profiles (design)

**Status: decided 2026-07-29. Broker-side selection, forcing and the seccomp profile flag
are IMPLEMENTED; the rank-cage args arrive with the srun step-broker.**

| piece | state |
|---|---|
| `Profile` enum, broker-side selection | done — `profile.rs` |
| single-node **forced** via `--nodes=1` | done — `--nodes` is `Class::Forced`, policy.rs validates + the profile emits |
| multi-node rejected with a teaching message | done |
| MUNGE mask in the floor | done, verified 33/33 on Balfrin |
| `seccomp-wrapper --profile` flag | done — `login\|single-node`, unknown = fatal; smoke tests 5-7 |
| AF_UNIX block for single-node | **REVERTED** — CUDA needs unix sockets (see Open) |
| rank-cage args (per-job `/dev/shm`, apinfo bind, CXI) | done — `settings::CageKind::Rank` + `rank::wrap_command` |
| in-cage `srun` stub, step-broker, guard bootstrap | done — **ICON ran to completion, 2026-07-31** |
| broker refuses ptrace/CMA (`PR_SET_DUMPABLE`) | done — `df414ea` |
| `process_vm_readv` for single-node (CMA) | done — `SINGLE_NODE_EXEMPT`, smoke 8-10 + selftest `cma.*`, **37/37 green on Balfrin** |
| **shared user namespace per job** | **done** — `cage.rs` holder + `bwrap --userns` per rank; **ICON completed on Balfrin with CMA enabled**, no `MPICH_SMP_SINGLE_COPY_MODE=NONE` |
| **shared PID namespace per job** | **done 2026-08-01** — job cage `--unshare-pid`, ranks JOIN via `--pidns`; selftest `pid.isolated`, `steps.pidns`, `steps.pidns_peers`, `cma.outside` |

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
| **login** | interactive adversary with tool access; no compute resources | today: Anthropic runtime + husk settings. AF_UNIX is already blocked here by their `apply-seccomp`, per **Bash command** — not on the runtime process, which needs unix sockets for MCP/IDE. husk's login profile takes that block over at the same granularity when step 5 drops their runtime. |
| **single node** | none — needs no IP at all (measured) | the Chapter-1 target |
| **multi node** | requires an IP path for the PMI bootstrap | **rejected today**; own phase |

**CPU vs GPU is not a profile.** The only difference is the `/dev/nvidia*` nodes, and
`--dev-bind-try` is already absent-safe: on a node without GPUs the binds silently skip.
The variant is implicit in the mechanism, so there are three profiles, not six.

**A profile describes what the wall permits; it does not say where the wall goes.** The profile answers
*what the wall permits*; this answers *where the wall goes*, and the two are independent
questions we conflated at first. All ranks of a job are one trust domain — same uid,
allocation, files, data — so they **share one user namespace**, created once per job,
while each rank still builds its own cage. See "the unit of confinement" in
[THREAT-MODEL.md](THREAT-MODEL.md); the short version is that a cage per task adds no
boundary, only N copies of the same one, and one of those copies — the user namespace —
was what blocked CMA. Joining must be **fail-closed**: a rank that cannot enter the
shared namespace must die, never fall back to a private one.

**The PID namespace follows the same rule, with one asymmetry.** The job cage creates its
own (`--unshare-pid`); ranks **join** the job's (`bwrap --userns FD --pidns FD`) rather than
creating one each. So ranks can see and signal each other — which MPI needs — while none of
them can see the node: not the un-caged step-broker, not the egress proxy, not another user's
work. Creating the namespace needs `CAP_SYS_ADMIN`, which is why the user namespace must come
first, and a PID namespace dies with its PID 1, which is why the holder process is the thing
that must outlive every rank. See "The PID namespace: the job cage has one, a rank cannot" in
[THREAT-MODEL.md](THREAT-MODEL.md).

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

### The exceptions, and the criterion that bounds them

That argument turns on a property the `pmix` case had: the caller's fallback **changed the
result**. Where a fallback is merely *slower*, a returned error buys none of that risk and
a kill costs a working program. So `GRACEFUL_ERRNO_SYSCALLS` (in `seccomp_wrapper.c`) holds
the names that are blocked just as hard but report `ENOSYS` instead of dying, and the bar
for adding one is:

> Name the fallback the caller takes when this call fails, and show it computes the same
> thing. Slower is fine. Semantically different — a different collective, a different rank
> layout, a silently reduced mode — keeps `KILL_PROCESS`, because there a returned error
> buys exactly the `pmix` failure.

**The founding instance, measured 2026-08-29.** CMake 4.4.2 died under the filter with
`SIGSYS` and *zero bytes* of output, even for `cmake --version`. CMake never asks for
io_uring: it bundles libuv, and libuv ≥ 1.45 probes for a ring in `uv_loop_init`, before
`main()` reaches any of CMake's own logic. libuv handles that probe failing — it falls back
to its threadpool, the original path, which predates io_uring entirely. Same filesystem
operations, lower throughput, identical results. Under `KILL_PROCESS` that correct fallback
is unreachable, because there is no return value to inspect. Two sessions and one hand-off
produced three different wrong root causes, because the failure carries no information.

Docker blocks io_uring for the same kernel-attack-surface reason and returns an errno, which
is why the same CMake runs there and dies here; the vendored `apply-seccomp` also blocks it
with `SCMP_ACT_ERRNO` (`constraints.md` C1.2), so this makes husk's layer agree with the one
stacked beside it. **Of the io_uring trio, only `io_uring_setup` moves.** `io_uring_enter`/`io_uring_register`
operate on a ring, and no process under this filter can create one — reaching them means
holding a ring obtained *outside* the cage, which is the case that should die loudly. The
probe is survivable; the capability is not usable. Both halves are pinned by tests 11 and 12
of the wrapper's smoke suite, test 11 baselined against the unwrapped syscall so it cannot
pass on a kernel that never had io_uring.

**Second instance, and it widened the criterion (2026-08-31).** `personality` with any
non-query argument now returns `EINVAL` rather than killing. Measured on Santis: `lscpu`
calls `personality(PER_LINUX32)` at startup and the KERNEL answers `-1 EINVAL` there, because
that node has no 32-bit EL0 — lscpu handles it, prints `64-bit` only, and exits clean.
Inside husk the same call took SIGSYS and lscpu died with no output, in both cages, once per
rank.

That does not fit the fallback test cleanly, and the honest reading is that it needs a
sibling rather than a stretch. lscpu computes nothing — its output IS its result, and the
missing field is *absent* rather than *slower*. The category it actually belongs to is:

> **a request whose refusal the caller already handles, and which real hardware already
> refuses.** There husk returning the error the kernel would have returned makes it
> indistinguishable from the machine, and killing makes it worse than the machine.

Two caveats kept deliberately. The argument came from ONE caller and applies to EVERY
persona value: a `setarch -R` caller now gets `EINVAL` instead of dying, and that request is
an ASLR downgrade — still refused, but the blast radius is wider than the motivating case.
And on x86_64 the bare kernel ACCEPTS `PER_LINUX32`, so "indistinguishable from hardware
without that ABI" is true on Santis and not on Balfrin.

Note also what the personality rule is NOT. It was documented for years as what stops a
process reaching the 32-bit syscall table; measured false — the seccomp arch follows the
syscall entry path, not the persona, and `SCMP_ARCH_*` registration is what closes that.
The rule protects the persona itself, most usefully `ADDR_NO_RANDOMIZE`.

**`B6-8`, decided 2026-09-01 — and it is NOT the question this section answers.** The kernel
declares `personality`'s argument `unsigned int` and truncates it, so every value whose low 32
bits are all ones is the same read-only query: `personality(0xffffffff)` and `personality(-1)`
— the natural C spelling, because glibc's prototype takes an `unsigned long` — are one kernel
operation. The rule compares the full 64-bit datum, so husk answers `EINVAL` to the second
spelling although the kernel would have answered it. **Kept, deliberately.**

The criterion above would mis-answer this. It governs a call husk *intends to block* and asks
only whether husk may report instead of kill. Here husk intends to **allow** the call — the
query form is explicitly permitted, and smoke test 3 pins it — and the rule's condition names
an object slightly larger than the one meant. That is **`P15`**, the same class as the
deny-list name that resolved to nothing, not a graceful-errno trade.

It stands because libseccomp cannot express *"refuse unless the low 32 bits are all ones"*, and
that was measured rather than assumed (four measurements, all four re-confirmed by `RHGN`):
two conditions on one argument in one rule give `-EINVAL`; a second rule ORs, so it only ever
**widens** the refusal; an `SCMP_ACT_ALLOW` rule on an `ALLOW`-default filter gives `-EPERM`;
and there is no masked NOT-EQUAL. The exact form is 32 masked rules, one per low bit — correct
and expressible, and a rebuild of a live control on both clusters, verifiable on only one of
them, to fix a wrong answer to a *query* rather than a wrong computation.

**The cost, stated rather than assumed away.** Since 2026-08-31 the false positive is also a
*quiet* one: such a caller used to die on `SIGSYS` and now silently misreads its own persona.
One doing `personality(0xffffffff) & ADDR_NO_RANDOMIZE` on the `-1` spelling reads `-1` —
every bit set — and concludes ASLR is already off. Nothing probed that spelling before;
**smoke test 16 now does, in both directions**, failing if the sign-extended query starts being
allowed *and* if it goes back to killing, because this is the one disposition in the wrapper
supported by an argument rather than a measurement. Changing the comparison means changing
`seccomp_wrapper.c`, this file and test 16 **together** — which is what test 16's own failure
message tells you.

This section used to end by inviting a revisit of the kill-vs-error choice "if users find
it too blunt". That revisit has now happened, once, and produced the criterion above rather
than a general softening — so the open invitation is gone deliberately. Everything else in
the deny-list still kills, and widening the table means meeting the bar, not reopening the
question.

Loud must not mean cryptic. A `SIGSYS` death tells a scientist nothing, so the guard
detects status 159 and prints which layer killed the job and how to identify the syscall.

It points at **`strace` inside the unchanged cage**, *not* at `SECCOMP_WRAPPER_DEBUG`.
That variable swaps `KILL` for `ERRNO(ENOSYS)`, so blocked calls return and the program
continues — an off-switch, not a diagnostic, and one whose safety would depend on who
controls the environment. **A diagnostic may change what we OBSERVE, never what we
ENFORCE** — the same reason the broker has `--dry-run` and no debug mode.

**Correction, 2026-08-29: strace does not work inside the cage.** `ptrace` is itself on the
deny-list, so `strace` is killed by the same `SIGSYS` before it can report anything — which
is how the io_uring syscall above stayed unidentified from inside. The principle above is
right and the conclusion drawn from it is not reachable: husk prints a remediation husk
forbids, so the one message meant to end the guessing is what sustains it. Reproducing the
command **outside** the cage under strace does work, and **is what the guard prints now**
(`policy.rs`, fixed the same day). Two further measurements, because they change how bad
the old advice was: in-cage `strace` does not merely fail, it leaves an **orphan blocked in
`pause()` holding the job's stdout and stderr** — so in a batch job the advice converted a
diagnosable `SIGSYS` into a leaked process sitting on the output. And the message now names
the common causes, because with `ptrace` unavailable the honest fallback is elimination
against a 49-name list, not identification.

The broker also strips `SECCOMP_WRAPPER_DEBUG` from the submission environment, so no
brokered job can run weakened even if it is set in the launching shell.

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

- **CMA is the first genuine profile delta, and it is now implemented.** Cray MPICH needs
  `process_vm_readv` for intra-node transfers; blocked, ICON dies with SIGSYS once ranks
  exchange data, and `MPICH_SMP_SINGLE_COPY_MODE=NONE` is only a diagnostic (it taxes
  every message). `single-node` therefore permits `process_vm_readv` and keeps
  `process_vm_writev` blocked. Read = same-uid memory disclosure between caged ranks of
  one job, which already share uid, files and allocation; write = arbitrary code
  execution in the un-caged step-broker, i.e. the escape itself. The broker already
  refuses to be a target (`PR_SET_DUMPABLE`), so the concession is rank-to-rank only.

  **It is expressed as an exemption from the floor, not as a per-profile deny-list.**
  `BLOCKED_SYSCALLS` still applies to every profile and still lists both calls;
  `SINGLE_NODE_EXEMPT` names the one syscall that is subtracted. This keeps the safe
  default: a syscall added to the floor is blocked under every profile unless someone
  deliberately writes it into an exemption table with a reason. Forking the list per
  profile would have made *forgetting* an entry the way a hole appears.

  **Answered on hardware 2026-07-31, and the answer was not the one on offer.** The
  exemption is *necessary but not sufficient*: ICON now fails with
  `process_vm_readv: Operation not permitted` — **EPERM, not SIGSYS**. Since the filter
  kills with `SCMP_ACT_KILL_PROCESS`, an errno proves the call passed seccomp and the
  **kernel** refused it. The cause is the per-task cage: each rank's bwrap creates its
  own user namespace, and sibling user namespaces cannot `ptrace_may_access` each other.
  Verified by isolating the variable — two sibling bwrap cages fail with `EPERM` even
  with Yama neutralised via `PR_SET_PTRACER_ANY`, while two cages sharing one
  identity-mapped userns succeed.

  So `process_vm_writev` is **not** required and stays blocked; the fix is structural
  (one cage per node) rather than another exemption. **Read the errno before widening a
  filter** — the difference between SIGSYS and EPERM named the layer, and had we treated
  "CMA still fails" as "the filter is still too strict" we would have opened the write
  side for nothing.

- ~~Does a caged MPI job need AF_UNIX at all?~~ **Measured twice, and the second
  measurement overturned the first.**
  - Gate C12 (job 4972255): **zero** AF_UNIX `socket()`/`connect()` calls in a caged
    2-rank MPI run, so the single-node profile took the block. The limitation was recorded
    at the time: *the sample is a tiny MPI program that never resolves a user, so ICON's
    first run under the block is the real validation.*
  - ICON's first run under the block (2026-07-30): every rank died at
    `cuInit -> 304 CUDA_ERROR_OPERATING_SYSTEM`. `cuda-probe.sh` isolated it one variable
    at a time — uncaged OK, `--profile=login` OK, `--profile=single-node` **FAILS**, both
    bwrap cage shapes OK. CUDA needs a unix socket and treats the refusal as fatal; it
    does not fall back the way glibc's NSS does, which is what the `EPERM`-over-`KILL`
    choice had assumed.
  - **The block is reverted.** What it was defending — a caged job authenticating to
    slurmctld via MUNGE — is enforced by the `/run/munge` **mount mask**, verified on
    hardware (`cred.munge tmpfs_mounts=1`). That was always the load-bearing control:
    AF_UNIX has to be judged per *destination* (a socket to sssd is not escape surface,
    one to MUNGE is), and only the mount layer can do that. The syscall block was defence
    in depth, and it cost GPU support.
  - Kept as a lesson: a measurement is only as good as its sample. C12 was correct and
    its scope was written down; the workload that fell outside that scope found it on the
    first run.

- **Whether the cage holder should clear `PR_SET_DUMPABLE`.** It *can*: measured on
  kernel 6.8, a holder with the flag cleared is NOT openable and every rank then fails at
  its own fail-closed gate — which corrects the correction: an earlier note here claimed it
  stayed joinable, and the v0.5 review measured the opposite for husk's ACTUAL holder. The
  earlier measurement holds for a process that `exec`s inside the new userns, which the
  holder never does. `cage.rs:89-97` was right all along.
  Left off deliberately. The gain is a third layer on a process that a rank measurably
  cannot read anyway, and which holds no credentials, no daemon route and no memory worth
  reading; the risk is kernel-dependent, since that measurement is from 6.8 while Balfrin
  runs 5.14 Cray Shasta, and if joining broke there every step would die. **Revisit if**
  the holder ever comes to hold something worth reading, or once the behaviour has been
  measured on the target. **Not a "cheap win": it fails CLOSED, taking every rank with it.**
  Anyone acting on the old wording would have broken all steps and blamed something else.

- Whether SLURM's device cgroup constrains a job to its *allocated* GPUs (it is the same
  exposure uncaged either way, so not a husk regression).
- The full syscall-set delta between our `seccomp-wrapper` and Anthropic's
  `apply-seccomp` — worth enumerating before step 5, so login's move onto our filter is
  a diff nobody has to rediscover.
