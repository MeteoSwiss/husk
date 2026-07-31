# husk — srun / MPI phase design (experimental)

**Status: DONE. ICON ran to completion inside husk on Balfrin (2026-07-31) — single node,
4 MPI ranks, GPU, brokered end to end, with Cross Memory Attach ENABLED and no
`MPICH_SMP_SINGLE_COPY_MODE=NONE`.** No user pays the intra-node message tax.

Getting the last blocker required a design change rather than a filter change: all ranks
of a job share ONE USER NAMESPACE instead of each `bwrap` making a private one, because
sibling user namespaces cannot `ptrace_may_access` each other. See "The redesign" below;
the principle is "the unit of confinement" in [THREAT-MODEL.md](THREAT-MODEL.md).

Branch `experimental`, off the frozen v0.4 `main`. Built and on hardware: cage profiles
(topology forced, multi-node rejected), the seccomp `--profile` flag with the CMA
exemption, the step allowlist, the per-task rank cage, the in-cage `srun` stub, the
step-broker and the guard bootstrap. The self-test suite is now 39 checks; run it with
`--broker` pointing at the **installed** binary, because `husk_paths()` derives the srun
stub from the broker's own location and a repo checkout has no `<prefix>/lib/husk/`, which
leaves the step pair inactive (the guard now says so out loud).
See [BROKER.md](BROKER.md) (current broker), [THREAT-MODEL.md](THREAT-MODEL.md)
(AV1–AV8 + the design principles), [ROADMAP.md](../ROADMAP.md).

## Scope & premise

We extend brokering to **`srun` issued from *inside* an already-launched `sbatch`
job on a compute node** — the job launching its own steps / MPI ranks. Interactive
`srun`/`salloc` from the login node stay **rejected** (out of scope, like today).

The whole phase rests on one split, established in THREAT-MODEL.md and restated here
because it is the spine of the design:

> **Spawning a step and running the ranks are two different problems, with two
> different rights, held by two different principals, for two different durations,
> contained by two different primitives.** We design them as two chapters and never
> conflate them.

| | **Spawn** (Chapter 1) | **Run / communicate** (Chapter 2) |
|---|---|---|
| holder | the broker, **outside** the cage | every **rank**, inside the cage |
| duration | transient (launch) | the whole run |
| mechanism | MUNGE + RPC to slurmctld/slurmd + job credential | CXI device + allocated VNI(s) + PMIx + shm |
| containment | **mediation / withholding** — the cage never gets these | **device exposure + VNI scoping** — orthogonal to `--unshare-net` |
| question | "who may launch?" | "what may a running rank reach?" |

---

## Chapter 1 — Control-plane authority (spawn)

### The rights, precisely
To create and launch a job step, `srun` performs a control-plane transaction needing:
1. **MUNGE auth** — the local `munged` socket (`/run/munge/munge.socket.2`); every
   slurm RPC is MUNGE-signed.
2. **Route to `slurmctld`** — register the step, obtain a step credential.
3. **Route to `slurmd`** — the "launch tasks" RPC on the allocated node(s).
4. **The job credential** — signed by slurmctld at `sbatch` time, authorising step
   creation within *this* allocation.

`{ MUNGE socket, slurmctld+slurmd route, job credential }` is exactly the out-of-cage
executor capability that makes srun-from-inside-the-job an escape today (AV8): whoever
holds it can launch **arbitrary** work as the user. It is **transient** and must be
held **only by the broker**, never by the caged job process.

### The mechanism — a recursive broker/stub pair
This mirrors the login-node sbatch pair, recursed onto the compute node:

- **In-cage `srun` stub** — shadows `srun` inside the job's bwrap cage (bind-mounted
  over it, same trick as the sbatch stub). Dumb plumbing: serialises the request
  (argv, cwd, env, the command + args) to a **step-spool** and waits for a response.
- **Compute-node step-broker** — runs **outside** the job's bwrap cage but **inside**
  the job allocation, so it holds MUNGE + the real `srun` + the daemon route. It reads
  the request, validates it as hostile input, and performs the real launch.
- **Bootstrap** — the sbatch staged script's re-exec guard is extended: *before*
  `exec`ing the job script into the cage, it launches the step-broker in the un-caged
  context (backgrounded, `PR_SET_PDEATHSIG`/allocation-scoped lifetime), then re-execs
  the job into the cage. The step-spool is a dir the caged stub can write and the
  un-caged broker reads — the new trust seam (untrusted stub → trusted broker), exactly
  as with sbatch.

### What the step-broker validates (the step allowlist)

> **Implemented and live** in `broker/src/srun.rs` (registry + `interpret`), consumed by
> the step-broker. The login-side `policy::decide` still rejects `tool="srun"` — that is
> correct and unrelated: interactive srun from a login node stays out of scope. The parser
> is shared with `sbatch.rs` rather than copied — two option parsers would be two things
> to keep in sync, and a gate that drifts from its twin is what the allowlist redesign
> removed.

Same discipline as the sbatch `REGISTRY` — **build the srun invocation, don't forward
agent bytes**. srun's own options are allowlisted (resource opts validated + re-emitted;
output/error/chdir forced; unknown rejected). The genuinely dangerous srun options that
must be **rejected** because they run code *outside* our per-task wrap:
- `--task-prolog` / `--task-epilog` (runs arbitrary scripts around each task),
- `--multi-prog` (a config mapping ranks to different programs),
- `--bcast` (stages a file to the nodes), `--pty` (interactive),
- `--export` / `--get-user-env` (env injection — forced instead).

The **command** srun launches is the user's program — we don't allowlist it; we **wrap**
it. Each task becomes:

```
srun <validated opts> -- seccomp-wrapper bwrap <rank-cage args> -- <user command>
```

so every rank slurmstepd launches is itself caged. The wrap is **forced** by the broker,
never supplied by the stub — the untrusted side cannot opt out of the cage.

### Chapter-1 open decisions
- Where exactly the step-broker sits in the process tree, and its teardown on job
  end/preemption (leak-free like the sbatch `BrokerHandle` drop-kill).
- Step-spool location + isolation (per-job dir under the workdir; the sbatch spool
  precedent applies).
- ~~Does per-task `bwrap` work when launched by slurmstepd?~~ **ANSWERED — yes** (gate
  **C3**, Balfrin 2026-07-28, `-n1` and `-n2`, full `seccomp-wrapper bwrap` stack). The
  mechanism this chapter is built on is confirmed on hardware.
- ~~Step-broker concurrency~~ **ANSWERED (C7, Balfrin)**: steps run concurrently, with and
  without `--overlap` — the step-broker need not serialise and a long step will not wedge
  it. (Not yet shown for steps contending for the same node's CPUs.)
- ~~The per-task cage must preserve the PMI bootstrap~~ **ANSWERED (C8/C9)**: the cause
  was neither a mask nor the netns but the READ-ONLY ROOT — Cray MPICH opens the
  per-step `apinfo` file `O_RDWR` and got `EROFS`. The rank cage therefore binds that one
  per-step directory read-write, and a per-job `/dev/shm` so same-node ranks can share
  segments. `--mpi` is dropped rather than forced: `MpiDefault=cray_shasta` works, and an
  agent-chosen `pmix` silently produced independent single-rank jobs (run 8).

---

## Chapter 2 — Data-plane capability (run / communicate)

### The rights, precisely
Once launched, ranks talk to **each other** over the Slingshot fabric (libfabric/OFI,
`cxi` provider; exact NIC generation/device surface is a hardware gate, not assumed
here) — not to the control plane. For their lifetime they need:
1. **The fabric NIC device** — `/dev/cxi*` + the libcxi/OFI userspace. A **char-device,
   kernel-bypass** path (RDMA-style), *not* the IP socket stack.
2. **The job's allocated VNI(s)** — Slingshot isolates traffic by Virtual Network
   Identifier; the NIC tags/checks traffic against the VNIs assigned to the job. **This
   is the "checked hole."**
3. **The PMIx bootstrap channel** — the node-local `slurmstepd` PMIx server (endpoint
   exchange at MPI init); after wire-up, comm is direct rank↔rank over the fabric.
4. **Shared memory / CMA / XPMEM** (`/dev/shm`) for intra-node ranks.

Ranks need **none** of the control-plane rights once running. And the fabric is
**device + VNI**, not IP sockets — so it is *orthogonal* to `--unshare-net`.

### The cage — and the best case
The current compute cage relies on `--unshare-net` (IP isolation). That does **not**
contain CXI traffic, so the MPI cage's boundary is **device exposure + VNI scoping**.
The best-case rank-cage (contingent on gate **C1**):

```
--unshare-net           # kills the IP stack: no internet, no IP route to slurmctld
+ --dev-bind /dev/cxi*  # fabric device only
+ the allocated VNI(s)  # from the job env / libcxi allocation
+ PMIx socket, /dev/shm
```

If netns and CXI are orthogonal (**C1**), we keep **IP isolation for free** *and* enable
the fabric — the only "network" a rank has is the VNI-scoped fabric; IP egress stays
blocked. That is the cleanest possible data-plane cage and the reason C1 is the first
gate.

### Chapter-2 open decisions
- Whether IP `--unshare-net` can be kept alongside an open fabric (C1).
- How VNIs are exposed to the job and whether they can be forged/escaped (**C2** — the
  security of the whole "checked hole").
- ~~Exact `/dev/cxi*` set + any capability/hugepages requirement~~ **ANSWERED (C4,
  Balfrin)**: bind `/dev/cxi[0-9]*` only (4 NICs; `cxi_sbl` is 0600 root and excluded),
  no capability beyond the device node, no hugepages, `/sys/class/cxi` already covered by
  `--ro-bind / /`.
- Whether to add seccomp on CXI ioctls (likely not without breaking the fabric — the VNI
  is the boundary, not syscall filtering).

---

## Staging — get real ICON progress before Chapter 2

The chapters are separable, and single-rank work needs Chapter 1 but **not** the fabric
hole. Ordered by increasing new-surface:

- **Stage 0 — singleton, no srun.** Run ICON as a plain process (`./icon`, MPI singleton
  init, no launcher) inside the **existing v0.4 cage**. Zero new code. If Cray MPICH
  allows singleton init, this validates the base cage against a real workload
  immediately. *Try this first.* (Gate **C5**: does singleton init work here?)
- **Stage 1 — single rank via `srun -n1`.** Needs **Chapter 1** (recursive spawn broker).
  Data-plane cage stays `--unshare-net` — one rank has no peer, so no fabric hole. (Gate
  **C6**: does 1-rank `MPI_Init` touch the NIC at all?) **This is the ICON target.**
- **Stage 2 — multi-rank, single node.** Chapter 1 + intra-node comm (shm/CMA/XPMEM);
  may still avoid the inter-node fabric.
- **Stage 3 — multi-rank, multi-node.** Chapter 1 + **Chapter 2** (fabric cage: `/dev/cxi`
  + VNI scoping). The full data-plane design; gated on C1/C2.

Christoph's "one MPI rank if I can manage" maps to Stage 0 → 1. We do **not** need the
hard fabric/VNI design to get ICON running single-rank.

---

## Verify-on-hardware gates (Balfrin/Santis)

Answered by [`fabric-probe.sh`](fabric-probe.sh) — a **discovery** probe (facts the
design needs), run by the operator on a compute node; distinct from `selftest.sh`
(containment pass/fail). The load-bearing unknowns:

- **C1 — netns × CXI orthogonality.** Does `--unshare-net` break the fabric? If not, the
  best-case cage (IP isolation + open fabric) is available. *Probe: run a 2-rank MPI job
  uncaged, then under `bwrap --unshare-net`, then under `bwrap` with `/dev/cxi` bound and
  no netns; compare.*
- **C2 — VNI enforcement (the security of the checked hole).** How are VNIs exposed to
  the job, and can an in-cage process use an **un-allocated** VNI or reach `slurmctld` /
  another user's job over the fabric? **This is the AV8-reopening risk** — giving ranks
  the fabric *is* giving them a network. *Probe: record the VNI env; a true escape test
  needs a small libfabric program targeting an un-allocated VNI — scoped as a follow-up,
  not shell-doable.*
- **C3 — per-task bwrap under slurmstepd.** Does `srun … seccomp-wrapper bwrap … -- cmd`
  actually launch a caged task (userns nesting vs stepd task setup)? *Probe: srun a
  bwrap'd `hostname` at `-n1` and `-n2`.*
- **C4 — device/cap inventory.** Exact `/dev/cxi*` nodes, `/sys/class/cxi`, hugepages,
  and whether CXI needs any capability beyond the device files. *Probe: enumerate.*
- **C5 — singleton MPI init** (Stage 0 viability). *Probe: `./mpi_hello` with no srun.*
- **C6 — 1-rank NIC dependency** (Stage 1 cage choice). *Probe: does `srun -n1 ./mpi_hello`
  need `/dev/cxi` present, or run fine without it?*
- **C7 — concurrent steps.** Can several `srun` steps run at once, or do they serialize?
  Decides whether the single step-broker may block on a long step. *Probe: two overlapping
  `srun … sleep 5`, with and without `--overlap`; time them.*
- **C8 — which cage element breaks the PMI bootstrap?** Uncaged `srun` MPI works, caged
  fails at `pals_init2()=ENOENT`; the netns is exonerated (it fails without
  `--unshare-net` too), so a masked path is the cause. **Chapter-1 blocker.** *Probe:
  caged-vs-uncaged env diff, visibility test on every path-valued `PALS*`/`PMI*` variable,
  then a bisection dropping one masking element per run.*

### Hardware results — run 1, Balfrin, 2026-07-28

`sbatch -N2 -n2`, job 4965235, nodes nid001100+nid001101, uenv `icon:default`, x86_64.

**C3 — ANSWERED, PASS. The load-bearing gate for Chapter 1 is green.**
`srun -n1` and `srun -n2` both launched `seccomp-wrapper bwrap --ro-bind / / --dev /dev
--proc /proc --tmpfs /tmp --tmpfs /dev/shm --unshare-net -- /bin/hostname` and returned
the two node names. Userns nesting survives stepd's task setup, and because
`seccomp-wrapper` was on PATH this exercised the **full compute-cage stack**, not plain
bwrap. Note the srun was issued from the *un-caged* batch script — which is precisely
the step-broker's position in the design, so it is the right test. It says nothing about
an in-cage `srun` reaching slurmctld, and does not need to: mediating that is Chapter 1.

**C1 — LEANS ORTHOGONAL (enumeration), not yet confirmed (data plane).** CXI endpoints
seen by `fi_info -p cxi`: **8 uncaged, 8 under `bwrap --unshare-net` with `/dev/cxi*`
bound, 8 under bwrap without `--unshare-net`, 0 with no device bound.** So enumeration is
**device-gated and netns-independent**, and no capability beyond the device node was
needed (an unprivileged bwrap userns enumerated all 8). The best-case rank-cage — keep
`--unshare-net` for IP isolation *and* bind the NICs — is therefore available as far as
enumeration goes. **Enumeration is not traffic**: C1-def (a real 2-rank MPI run through
each cage shape) is still open, and only that confirms the data plane.

**C4 — ANSWERED for Balfrin.** 4 NICs `/dev/cxi0…3`, plus `/dev/cxi_sbl` at **0600
root:root** (Slingshot base-link, an admin device) → the cage binds `/dev/cxi[0-9]*`
**only**; a user job cannot open `cxi_sbl` anyway and the cage should not bind what it
cannot use. Accelerators: `/dev/nvidia0…3`, `nvidiactl`, `nvidia-modeset`, `nvidia-uvm`,
`nvidia-uvm-tools`, `nvidia-nvswitchctl`, `nvidia-caps/`, and `/dev/dri/{card0…3,
renderD128…131}`. `/sys/class/cxi` **and** `/sys/class/infiniband` both present — both
are already covered read-only by the cage's `--ro-bind / /`, so no new bind is needed.
`HugePages_Total: 0` → no hugepage requirement to model.

**C2 — UNANSWERED, and the reason is instructive.** No `SLINGSHOT_*`/VNI variable exists
in the **job** environment. That is expected rather than alarming: the switch plugin
allocates VNIs per **step**, so the batch script is the wrong scope to look in. The probe
now dumps the env from inside an `srun` step and records `SwitchType` from
`scontrol show config` — if `SwitchType` turns out to be `switch/none`, there is no
hardware job isolation on this fabric and Chapter 2's "checked hole" premise needs
rethinking before anything else.

**C5 / C6 / C1-def — NOT ANSWERED: probe bug, not a hardware finding.** The probe chose
its compiler by presence and preferred `cc`; under the uenv `/usr/bin/cc` is plain gcc
with no `mpi.h`, while the uenv's `mpicc` was right there. Fixed by *try-compiling* with
each candidate and keeping the first that builds — compiling is the only honest test of
"this toolchain has MPI". The generalisable point: **probe on capability, not on name.**

### Hardware results — run 2, Balfrin, 2026-07-29

Same shape (`-N2 -n2`, job 4965322). Slurm **23.02.7**.

**C2 — the Chapter-2 premise HOLDS.**
`SwitchType = switch/hpe_slingshot`, `SwitchParameters = vnis=32768-65535,job_vni`.
There *is* a switch plugin allocating VNIs, with a per-job VNI (`job_vni`) out of the
32768–65535 range. So "the fabric confines a job's traffic in hardware" is a real
mechanism on this machine, not an assumption — the checked-hole design has something to
rest on. Still open, and still the crux: **whether an in-cage rank can use an
un-allocated VNI.** That is the AV8-over-fabric escape test and needs a libfabric
program; `SwitchType` tells us the lock exists, not that it cannot be picked. No
`SLINGSHOT_*` variable was visible even inside a step, but the probe's grep was
over-anchored (`^PMI` cannot match `SLURM_PMI_*`), so that "NONE" is not yet evidence.

**C7 — ANSWERED: steps run CONCURRENTLY.** Two `srun … sleep 5` finished in 5s both with
`--overlap` and with plain `srun`. The step-broker therefore does **not** need to
serialise, and a long-running step will not wedge it — a real simplification for
Chapter 1. Caveat on the strength of this: with `-N2 -n2` the two steps landed on
*different nodes*, so it does not yet prove concurrency when steps contend for the same
CPUs on one node.

**C5 — singleton init works** (again): `./mpi_hello` with no launcher returns
`rank 0/1`. Stage 0 remains technically viable, though it stays rejected as a shortcut.

**C6 / C1-def — still open, and run 2 taught us why.** Three separate causes, only one of
them about hardware:
1. *Probe bug — node-local build dir.* The binary was compiled into `mktemp -d` under
   `/tmp`, which is node-local; the 2-rank runs died with `execve(): No such file or
   directory` on nid001101. Every multi-node number in run 2 is void. Fixed: build on the
   submit dir, and **verify** visibility with an `srun test -x` across all nodes.
2. *Probe bug — no uncaged control.* There was no `srun -n1` baseline, so a failure could
   not be attributed to the cage. Fixed: every caged run now has an uncaged twin, run
   first; if the baseline fails, the probe says the cage is *not* implicated.
3. *A real finding — the PMI bootstrap, not the NIC.* The caged runs hit
   `_pmi_pals_init: pals_init2() failed: 2` → `PMI_Init returned 1`. Run 2's probe
   labelled this "1-rank MPI_Init touches the NIC" — an attribution it was in no position
   to make. It now classifies failures (`PMI/launcher` vs `fabric/NIC` vs `binary not
   visible`) and calibrates the launcher against an uncaged baseline. *(Run 3 localised
   this further — see below; run 2's guess that the uenv's MPICH simply cannot bootstrap
   under `srun` was **wrong**.)*

### Hardware results — run 3, Balfrin, 2026-07-29

`-N2 -n2`, job 4965387, nodes nid001096+nid001097. First run with a shared build dir and
uncaged controls — i.e. the first run whose MPI numbers mean anything.

**The uncaged baseline works, including across nodes.** `MpiDefault = cray_shasta`;
`srun --mpi=list` offers `cray_shasta, pmi2, pmix (pmix_v4)`. Plain `srun -n2` (no `--mpi`
flag) returned `rank 0/2` and `rank 1/2` on **two different nodes**, so the inter-node
fabric, the launcher and PMI are all healthy outside the cage. `srun -n1` likewise.

**Correction to run 2.** The PALS failure is **not** a launcher-configuration problem and
the uenv's MPICH bootstraps fine under `srun`. Consequently the design note that the
step-broker must force a site-configured `--mpi=` type is **not supported** — the default
already works here. `--mpi` stays a *modelled, value-validated* option in the step
allowlist (a rank may legitimately ask for `pmix`), but forcing it is not required.

**The cage is what breaks PMI — and the network namespace is exonerated.** Both caged
shapes failed *identically* at `pals_init2() failed: 2` (ENOENT): with `--unshare-net`
**and without it**. Since the no-netns variant fails too, the IP namespace is not the
cause. Something the cage **masks** is missing — a filesystem-visibility problem, which
is the pre-registered risk arriving with a name attached.

This is good news for **C1**: the best-case rank-cage (keep `--unshare-net`, bind the
NICs) is still standing. It is a **Chapter-1** blocker, not a Chapter-2 one — a 1-rank
`srun` fails on it, before any fabric question arises.

**C8 (new gate) — which cage element?** Guessing is unnecessary; the answer is
mechanically findable. The probe now (a) diffs the task environment caged vs uncaged,
(b) takes every path-valued `PALS*`/`PMI*` variable and tests whether that path exists
inside the cage — the mount namespace as oracle again — and (c) bisects the cage:
`full`, `no_tmp_mask`, `no_shm_mask`, `dev_bind`, `no_proc_mask`, `robind_only`, one
masking element dropped per run, until `MPI_Init` survives. Prime suspects are
`--tmpfs /tmp` and `--tmpfs /dev/shm` hiding the PALS apinfo/rendezvous file, but the
bisection decides it, not this paragraph.

### Hardware results — runs 4 and 5, Balfrin, 2026-07-29 — **C8 SOLVED**

Run 4 (job 4965415) killed the masking theory: **every** bisect arm failed, including
`robind_only` = bare `bwrap --ro-bind / /` with no mask at all. That bisection was
incomplete — every arm still had a **read-only root**, so the one property shared by all
failures was the one never varied. Run 5 (job 4965492) varied it and straced the failure:

```
openat("/var/spool/slurmd/mpi_cray_shasta/4965492.33/apinfo", O_RDWR) = -1 EROFS
```

**The mechanism, exactly.** Slurm's `mpi/cray_shasta` plugin writes a per-step `apinfo`
file under `SlurmdSpoolDir`; Cray MPICH opens it **`O_RDWR`** — read-write, though it
only consumes it — and `--ro-bind / /` makes the whole tree read-only. Nothing was
hidden: the probe's own listing shows `mpi_cray_shasta/<jobid>.<stepid>` present *inside*
the cage. **Visibility was never the problem; writability was.** That is why no
mask-removal arm ever helped, and why `robind_only` failed too.

Two of my earlier readings were wrong and are corrected here: the `2` in
`pals_init2() failed: 2` is a PALS return code, **not** `ENOENT` — I built the whole
"hidden path" theory on that misreading; and the pre-registered guess that the PMI
rendezvous would be hidden by `--tmpfs /tmp` is not what happened.

**Consequences.** This is a **Chapter-1** blocker with a small, targeted fix, not a
structural one. The cage does not need a writable root — it needs one per-step
directory writable. The step id is not known at submit time, so the **guard computes the
path inside the task** from `SLURM_JOB_ID`/`SLURM_STEP_ID` and binds only that directory
— the same "glob in the guard, not in the broker" pattern used for the GPU device binds.
Gate **C9** tests the candidates: coarse `mpi_cray_shasta` bind, precise per-step bind,
and `--mpi=pmi2`/`pmix` (which may need no write at all), each with an uncaged control.

Also observed: `srun -n1 env` returned **zero** lines uncaged while the caged variant
returned 191, so run 5's env dump was empty rather than "nothing lost" — the probe now
uses `sh -c /usr/bin/env` and prints a sample line, because a silent dump that looks like
a clean result is worse than a loud failure.

### Hardware results — run 6, Balfrin, 2026-07-29 — **C9 answered: both fixes work**

Job 4965535. **The apinfo file is user-owned** (`-rw------- 27069 30382`), so the wall was
purely the namespace's read-only mount — not kernel permissions. A bind is sufficient;
no privilege question arises. Results at 1 rank, each with an uncaged control:

| candidate | result |
|---|---|
| `--bind` whole `mpi_cray_shasta` dir | **OK** |
| `--bind` only this step's dir, path computed in-task | **OK** |
| `--mpi=pmi2`, full cage, **no carve-out** | **OK** |
| `--mpi=pmix`, full cage, **no carve-out** | **OK** |

So there are two independent fixes, and the `--mpi=pmix`/`pmi2` one is preferable on
security grounds: it needs **no writable carve-out into a Slurm-owned directory at all**.
The per-step bind stays the fallback if a workload requires the site-default
`cray_shasta`. Both are small; neither touches the cage's shape.

**What the env dump finally showed — the control plane is TCP.** `PALS_APINFO`,
`PALS_SPOOL_DIR`, and crucially `PMI_CONTROL_PORT=29468`, `SLURM_STEP_RESV_PORTS=
29468-29469`, `SLURM_STEP_LAUNCHER_PORT`, `PMI_SHARED_SECRET`. The `cray_shasta` PMI
bootstraps over **TCP ports**, which is why the netns question was always going to
resurface. (The earlier `env_lost_in_cage` list was a false positive of my own: it diffed
`NAME=value` lines across *two different steps*, so per-step values looked "lost". Now
diffs names only.)

**The 2-rank arm failed — but that arm was confounded.** It changed rank count *and*
added `--unshare-net`, so its failure attributes to neither:

```
[PE_0]:_pmi_set_af_in_use:PMI ERROR: Unable to obtain IP address information on nid001097
```

That is the netns having no routable address, exactly what a TCP control plane would hit.
But "exactly what I expected" is not evidence, and I built the wrong theory from a
plausible-looking error message twice already in this investigation.

### C10 (new gate) — where does `--unshare-net` stop being affordable?

One variable at a time: **PMI type × geometry × netns**, 11 arms — `cray_shasta` and
`pmix`/`pmi2`, at 1 rank / 2 ranks on one node / 2 ranks across two nodes, each with and
without `--unshare-net`. This is the gate that decides the rank-cage's network boundary:

- If 1 rank and same-node multi-rank survive `--unshare-net`, Stage 1 and single-node
  multi-GPU keep **full IP isolation** and Chapter 1 ships without touching the network.
- If only multi-**node** needs IP, the boundary lands exactly where Chapter 2 / the
  network phase already expected it, and AV8 stays closed for the single-node case.
- If even 1 rank needs IP, the current cage's unconditional `--unshare-net` has to be
  reopened as a design question before any of this ships.

Requires an allocation with **≥2 tasks per node** (`-N2 --ntasks-per-node=2`) so the
same-node 2-rank arms have somewhere to run.

### Hardware results — run 7, Balfrin, 2026-07-29

Job 4965622. **One clean result, and it is the one Stage 1 needed:**

> **`cs_1rank_netns` — OK.** A single rank, in the full cage, with the per-step apinfo
> bind, **with `--unshare-net`**. So a 1-rank `srun` job keeps **complete IP isolation**.
> ICON-single-rank — the actual near-term target — needs no network concession at all.

Everything else in the matrix was invalidated by bugs in my own harness, so no other arm
is evidence of anything:

1. **All five `pmix`/`pmi2` arms** died on `bwrap: Can't find source path
   .../mpi_cray_shasta/<jobid>.<stepid>`. Those PMIs never create the `cray_shasta` step
   directory, and `--bind` is fatal on a missing source. I unified the arms' bwrap body to
   avoid confounds and thereby broke every arm that didn't need the carve-out. → `--bind-try`.
2. **No arm bound `/dev/cxi*`.** The 2-node arms therefore ran with no NIC at all (one
   segfaulted, rc=139). A matrix meant to inform the rank cage must use the rank cage's
   device set. → CXI binds in every arm.
3. **Both same-node 2-rank arms HUNG** (killed at the 90s wall) and were reported as
   ordinary failures. A hang is a distinct outcome and now says so. The likely cause is
   the pre-registered one: per-task `--tmpfs /dev/shm` gives each rank a *private*
   `/dev/shm`, so same-node ranks cannot share segments. → new `shm private|shared` axis,
   with `--bind /dev/shm /dev/shm` arms to confirm or refute it directly.
4. **C11 answered nothing**: its caged arms lacked the apinfo fix (so they failed for the
   already-known reason and printed nothing), and its regex guessed the output format —
   `provider ofi_rxd` is a provider *list*, not a selection. → caged arms now carry the
   fix, and the probe dumps the verbose lines instead of pattern-matching a format nobody
   has looked at yet.

The standing lesson, now earned three times in this investigation: **when a probe and a
hypothesis disagree, suspect the probe first** — and never let one arm's fix (the unified
body) silently become another arm's precondition.

### Hardware results — run 8, Balfrin, 2026-07-29 — **the rank cage is decided**

Job 4965756. A properly controlled matrix. Every "OK" below is a **real** communicator
(N lines, each reporting size N and the correct allreduce), not merely exit 0:

| geometry | `--unshare-net` | `/dev/shm` | result |
|---|---|---|---|
| 1 rank | **yes** | private | **OK** |
| 2 ranks, same node | yes *or* no | private | **HANG** |
| 2 ranks, same node | **yes** | **shared** | **OK** |
| 2 ranks, two nodes | no | private | **OK** |
| 2 ranks, two nodes | **yes** | private | **FAIL** — `_pmi_set_af_in_use: Unable to obtain IP address` |

Three conclusions, each now resting on a control that differs in exactly one variable:

1. **Everything on ONE node keeps full IP isolation.** 1 rank and same-node multi-rank
   both work with `--unshare-net`. Single-node multi-GPU — 4 GPUs on Balfrin — is
   achievable inside the cage with the network namespace intact.
2. **`--tmpfs /dev/shm` per task is what breaks same-node multi-rank**, exactly as
   pre-registered. Sharing `/dev/shm` fixes it, and the netns is irrelevant to it (both
   shm variants pass with and without). Ranks talk over shared memory; a private tmpfs per
   rank cuts that channel.
3. **Multi-NODE genuinely needs IP.** Same geometry, same everything, only the netns
   differs: without it OK, with it the PMI cannot obtain an address. That is the network
   phase's problem, precisely located — not something to be worked around in Chapter 1.

**Design: a per-job `/dev/shm` subdirectory.** Binding the node's whole `/dev/shm` would
work but exposes every other user's segments to the caged job — a containment regression.
Instead the guard creates `/dev/shm/husk-$SLURM_JOB_ID` and binds *that* onto `/dev/shm`
inside each rank's cage: this job's ranks share segments, other users' stay invisible.
Gate C10 now tests this `jobdir` variant directly against the `shared` one.

**Correction — the `--mpi=pmix` recommendation was unsupported and now looks wrong.**
Run 6 scored `caged_mpi_pmix`/`pmi2` as OK, and I concluded they were preferable because
they need no writable carve-out. Both arms ran at **`-n1`**, where MPICH's *singleton
init* is indistinguishable from a real PMI bootstrap — the probe was reading exit status
only. Run 8 exposed it: at 2 ranks, `--mpi=pmix` printed `MPI rank 0/1` **twice** and
exited 0 — two independent singleton jobs, not a communicator. So:

- The **per-step apinfo bind with the site-default `cray_shasta` is the fix with actual
  evidence** behind it (the passing 2-rank rows above all used it).
- The pmix/pmi2 route is unproven and currently appears to **degrade silently to
  singletons**, which is the worst possible failure mode — a "successful" run that
  computed the wrong thing.
- The probe now asserts the communicator on every multi-rank arm (`ranks_ok`), so exit 0
  can never again be mistaken for a working MPI job.

**C11 — the caged job is genuinely on CXI.** With the NICs bound:
`MPICH CH4 OFI detected 4 NICs/node`, `netmod using cxi provider (domain_name=cxi0)`,
`CXI counters initialized`. Without them the job **segfaults** rather than quietly falling
back to `tcp` — so the silent-degradation worry did not materialise here, though a
segfault is a poor way to learn it and the assertion stays in.

### Hardware results — run 9, Balfrin, 2026-07-29 — **discovery phase complete**

Job 4965792. Every run-8 conclusion reproduced, and the two open items closed:

- **`cs_1node2rank_netns_jobdir` — OK, real 2-rank communicator.** The proposed design
  (per-job `/dev/shm/husk-$SLURM_JOB_ID` bound onto `/dev/shm`) works *with*
  `--unshare-net`. It is not a compromise over binding the whole `/dev/shm` — it is
  equivalent in function and strictly better in containment.
- **All four `pmix`/`pmi2` arms → `WRONG SIZE`.** With the assertion in place they report
  `MPI rank 0/1` twice: two singletons. The route is now closed by direct evidence rather
  than inference. Note they fail this way *with and without* the netns, so the cage is not
  what breaks them — this MPICH build simply does not wire up through Slurm's pmix/pmi2.
  *Untested control:* uncaged 2-rank pmix. It does not matter here (cray_shasta works and
  is the site default) but it would matter at a site where pmix is the only option, so the
  probe now carries an uncaged 2-rank arm for that case.
- `cs_1rank_netns`, `cs_1node2rank_netns_shm`, `cs_2node2rank_nonet` all reproduced;
  `cs_2node2rank_netns` failed again. The netns boundary is confirmed twice over.

---

## Chapter 1 — DONE, demonstrated by a real workload

**ICON ran to completion inside husk, Balfrin 2026-07-31.** Single node, 4 MPI ranks, GPU.
Every layer exercised by a production model rather than a probe:

`sbatch` brokered from the login cage → job guard → re-exec into the compute cage →
in-cage `srun` stub → step-spool → step-broker (un-caged, inside the allocation) → step
allowlist → four ranks each in its own cage (read-only root, homes hidden, CXI bound,
per-job `/dev/shm`, per-step apinfo bind, `--unshare-net` intact) → PMI bootstrap → CUDA
init → GPU compute → MPI collectives → model run to completion.

Getting there cost four real fixes, each found by a workload rather than by inspection:
1. `--distribution=plane=4` — the value grammar had no `=`.
2. `cuInit -> 304` — the AF_UNIX block. **Reverted**; CUDA needs unix sockets and treats
   the refusal as fatal. What it was defending (MUNGE) is enforced by the mount mask,
   which is destination-aware in a way a syscall filter cannot be.
3. `Could not open icon_master.namelist` — the step-broker forced `--chdir` to the job's
   start directory instead of the caller's. Run scripts `cd` into their case directory.
4. `SIGSYS` mid-run — CMA, below.

### The last blocker: CMA

Cray MPICH uses `process_vm_readv`/`process_vm_writev` (Cross Memory Attach) for
intra-node transfers, and both are in seccomp-wrapper's deny-list, so ranks died with
exit 159 once they began exchanging grid data. `/dev/xpmem` is not bound, so MPICH has no
alternative single-copy path. **`export MPICH_SMP_SINGLE_COPY_MODE=NONE` makes ICON
complete** — that is the diagnostic, not the fix: it forces a copy-through-shared-memory
path and taxes every intra-node message.

**Read and write are not one concession.** `process_vm_readv` lets a caged rank read
same-uid memory; `process_vm_writev` lets it *write* into an un-caged process — arbitrary
code execution in the one process holding MUNGE. Only the read side should move.

Gating is the ptrace-attach check: credentials, Yama `ptrace_scope`, the dumpable flag,
and PID visibility. **Balfrin has no Yama**, so credentials are the only gate there.
`--unshare-pid` is not available as a defence: each task gets its own bwrap, so it would
put every rank in a separate PID namespace and break the rank-to-rank CMA being enabled.

**Mitigation already shipped** (`df414ea`): the broker calls `prctl(PR_SET_DUMPABLE, 0)`,
so it is not a ptrace/CMA target whatever the filter allows — verified, its
`/proc/<pid>/maps` is refused while an ordinary same-uid process stays readable. That
makes the concession rank-to-rank only.

**Implemented** — `process_vm_readv` is now exempt under `--profile=single-node`;
`process_vm_writev` stays blocked under every profile.

The mechanism is deliberately an **exemption table**, `SINGLE_NODE_EXEMPT`, and not a
second deny-list. The floor still lists both calls and applies to every profile; a
profile subtracts from it only by naming a syscall explicitly. Adding an entry to the
floor therefore blocks it everywhere unless someone also writes it down as an exemption,
with a justification — default-strict, opt-out-by-name. Splitting the list per profile
would have made "forgot to add it to the compute list" a silent hole.

Pinned in three places, because build-time and deploy-time are different failure modes:

| check | where | what it catches |
|---|---|---|
| smoke 8 — CMA read blocked under `login` | build host | the exemption leaking into the default cage |
| smoke 9 / 10 — read allowed, **write killed**, under `single-node` | build host | either half of the delta moving |
| selftest `cma.read` / `cma.write` | inside a real brokered job | a **stale wrapper on the compute node** — the deployment skew that has cost more bring-up rounds than any other bug here |

The selftest probe self-attaches, so the kernel's ptrace-attach check always permits it
and the only thing under test is the seccomp filter.

**Answered on hardware 2026-07-31 — and the answer sent us one layer down.** The
exemption deployed cleanly (selftest 37/37, both `cma.*` arms green), and ICON then died
with:

```
process_vm_readv: Operation not permitted
```

**EPERM, not SIGSYS.** The filter kills with `SCMP_ACT_KILL_PROCESS`, so a returned
errno proves the syscall passed seccomp and the *kernel* refused it — `ptrace_may_access`,
not our deny-list. Isolated one variable at a time on a laptop, with Yama taken out of the
picture via `PR_SET_PTRACER_ANY`:

| target | reader | result |
|---|---|---|
| plain process | plain sibling | OK — so Yama really was neutralised |
| inside bwrap | outside (owns the namespace) | OK |
| inside bwrap A | inside **sibling** bwrap B | **EPERM** |
| inside cage A | inside cage B, **sharing one identity-mapped userns** | OK |

**The per-task cage is the blocker.** Each rank's `bwrap` creates its own user namespace,
and sibling user namespaces cannot attach to each other whatever the seccomp filter says.
`process_vm_writev` is therefore **not** required and stays blocked — the fix is structural,
and the next section is the redesign.

**Lesson worth keeping: read the errno before widening a filter.** SIGSYS versus EPERM
named the layer. Treating "CMA still fails" as "the filter is still too strict" would have
opened the write side — the concession we had explicitly agreed not to make casually — and
it would not have worked either.

**And the selftest arm could not have caught this**, by construction: the probe
self-attaches, which I documented as a feature ("the only thing under test is the seccomp
filter"). That is exactly the blind spot — it validates the layer we changed, not the thing
the workload needs. It has to become a **two-process, two-cage** probe. Same shape as gate
C12, which measured AF_UNIX on a sample containing no CUDA: *a green probe means the
probe's scenario passes.*

## The redesign — one shared user namespace per job (DONE, ICON verified)

**The border is the job on a node, not the process.** Ranks of one job share uid,
allocation, files and data; there is no boundary between rank 0 and rank 3 to defend. The
per-task cage was making N redundant copies of the *job ↔ host* wall — and one of those
copies, the user namespace, was silently costing us a capability. See "the unit of
confinement" in [THREAT-MODEL.md](THREAT-MODEL.md).

**Shape — and it is smaller than it first looked.** The step-broker starts a **cage
holder**: a child process that owns one *bare* user namespace, identity-mapped, and does
nothing else. Every rank still builds its own cage with `bwrap`, but hands it that
namespace via `--userns` instead of letting bwrap make a private one.

**Only the user namespace is shared, and that is the whole finding.** It is the sole
namespace that was costing us a capability — sibling user namespaces cannot
`ptrace_may_access` each other, which is what killed CMA. Mount and network namespaces
stay per rank: they are identical copies built from identical arguments, they never
blocked anything, and duplicating them is free.

An earlier draft had ranks `setns` into a cage that bwrap had built. **That cannot work**,
measured rather than reasoned: `bwrap` constructs its sandbox through an intermediate user
namespace and then switches to a second one, so the mount and network namespaces it
creates are owned by a user namespace no rank ever joins — `setns` into either fails
`EPERM` however it is ordered (holder userns `…4687`, initial `…1837`, holder netns owned
by `…4599`). bwrap is not built to be joined from outside. Hence a *bare* namespace with
nothing in it to join incorrectly.

Measured end to end on a laptop, 2026-07-31:

| case | result |
|---|---|
| two ranks sharing the holder's userns, CMA read | **OK** |
| control: same two ranks, each with its own userns | **EPERM** — ICON's exact error |
| uid inside the cage | `1000` — identity map, not a root map |
| holder teardown on stdin EOF, and on parent death | both clean, no leaked namespace |

**Fail-closed in two places.** The rank script refuses to run if the holder's namespace is
not readable, with a sentence rather than a shell diagnostic; and `bwrap --userns` exits
rather than inventing a namespace. Falling back to a private namespace would be the
dangerous outcome — the workload would run in a cage that cannot talk to its peers, which
surfaces as an obscure MPI abort rather than as the containment change it actually is.

**Holder lifetime.** One per JOB, not per step: nothing in it is step-specific, and a
namespace per step is a process per step to leak. It dies two ways — EOF on stdin when the
step-broker drops the pipe, and `PDEATHSIG` if the step-broker dies without dropping
anything. It must stay **dumpable**: reading `/proc/<pid>/ns/user` goes through
`ptrace_may_access`, so a holder that cleared `PR_SET_DUMPABLE` like the broker does would
be one whose namespace no rank could open.

**Consequence for the network phase.** Ranks keep separate network namespaces, so the
*relay* into a cage stays per rank. The filtering proxy — the allowlist, the TLS
termination, the audit point, the expensive part — is **one per node**, reached through a
unix socket bind-mounted into every rank's cage. A unix socket crosses a network namespace
because it is a filesystem object: the same reasoning that makes the MUNGE *mount* mask
load-bearing rather than a syscall filter. Policy is never duplicated; only a byte-shuffler
is, at a couple of MB per rank. A single relay per node would need a shared network
namespace, which needs a sandbox builder we own — roadmap step 5, and exactly the shape of
Anthropic's `srt-launcher`.

## Chapter 1 — the rank cage, as specified by hardware

**Still current.** The redesign above changes only where the *user namespace* comes from;
every bind below is unchanged and still applied per task. Everything here is measured on
Balfrin, not inferred. Per task, the guard runs:

```
--ro-bind / /                                  # root read-only (unchanged)
--dev /dev  --dev-bind-try /dev/cxi[0-9]*      # fabric NICs; NOT /dev/cxi_sbl (0600 root)
            --dev-bind-try /dev/nvidia*        # as today
--proc /proc
--tmpfs /tmp
--bind /dev/shm/husk-$SLURM_JOB_ID /dev/shm    # per-JOB shm, created by the guard (0700)
--bind-try $SlurmdSpoolDir/mpi_cray_shasta/$SLURM_JOB_ID.$SLURM_STEP_ID  <same>
--userns <fd of the job's shared user namespace>  # NOT --unshare-user: see the redesign
--unshare-net                                  # KEPT — full IP isolation, per rank
+ the existing filesystem policy (homes hidden, credentials masked, workdir writable)
```

Two paths are computed **inside the task**, not by the broker: the step id does not exist
at submit time, and the job's shm directory is per-node. Same pattern as the GPU device
binds — *glob in the guard, not in the broker*.

**Scope: single node.** Multi-node steps must be **rejected** by the step allowlist with a
teaching message, because they require an IP path for the PMI bootstrap, and dropping
`--unshare-net` reopens AV8 (a job that reaches `slurmctld` can submit un-caged jobs).
That is a network-phase decision, not a Chapter-1 workaround. What single-node buys:
1-rank `srun` (the ICON target) and full single-node multi-GPU.

**C1 status — honest.** `fi_info` enumerates all 8 CXI endpoints under `--unshare-net`,
and a caged 2-node run on CXI works *without* the netns, so netns and the fabric look
orthogonal. But no inter-node run has ever completed *with* the netns — the PMI bootstrap
fails first — so orthogonality for real inter-node **traffic** remains unproven. It is
moot while multi-node is out of scope; re-test it if the network phase gives PMI an IP
path.

---

## TODO — read-only shim for the apinfo file (Christoph, 2026-07-30)

The rank cage currently binds `<SlurmdSpoolDir>/mpi_cray_shasta/<job>.<step>` **read-write**,
because Cray MPICH opens `apinfo` `O_RDWR` although it only ever reads it (gate C8/C9).
That hands a caged rank write access to a directory inside the scheduler's own spool —
narrow (the per-step dir is user-owned, 0700, and belongs to this job) but not nothing,
and it is write access we never actually needed.

**The shim:** copy `apinfo` to a location husk owns, bind the copy over the original path,
and let MPICH open *that* read-write. The scheduler's spool stays read-only from inside
every cage. This is the same move as the broker itself — don't grant the capability,
grant a mediated stand-in — applied to a file instead of a command.

The wrapper already runs before `bwrap`, so it has the right moment to do the copy.
Two things to verify when building it:
- that `apinfo` exists by the time the task starts (stepd writes it at step launch —
  plausible, and C9 saw the file present, but that is not the same as guaranteed);
- that a file-level bind over the original path satisfies MPICH's `O_RDWR` open.

Not urgent: the current bind works and is bounded. Worth doing before anything relaxes
who can reach that spool.

## Threat-model deltas (vs the current single-node cage)

- **AV8 (broker bypass) recurses, not disappears.** The step-broker now runs on the
  compute node holding MUNGE. Its **step-spool** is the new sensitive seam: the in-cage
  stub may *request*, the broker *validates as hostile* and *forces the per-task wrap* —
  the stub cannot launch an un-caged task. slurmctld stays unreachable **iff** IP
  `--unshare-net` is kept (C1); the fabric must not provide an IP path to the controller.
- **New AV: cross-VNI / cross-job over the fabric** (C2) — the data-plane analogue of
  AV8. Contained only if the NIC/fabric manager refuses un-allocated VNIs.
- **New AV: srun "run-something-else" options** (`--task-prolog`, `--multi-prog`, …) run
  code outside the per-task wrap → **rejected** by the step allowlist.
- **Unchanged invariants:** filesystem cage (homes hidden, root ro, workdir writable,
  credentials masked) applies to every rank via the per-task bwrap, exactly as today.

---

## Hardware portability (Alps now, general where it's free)

Cross-site heterogeneity is **low-cardinality**, not per-machine chaos — two axes, each
a short enumerable list:
- **Interconnect**: Slingshot (`cxi` provider, `/dev/cxi*`) — Alps, LUMI; InfiniBand
  (`verbs`, `/dev/infiniband/*`) — Euler, DKRZ/Levante; (OPA `/dev/hfi1*`; `tcp`
  fallback). libfabric abstracts the *provider*; the **device nodes** and the
  **isolation model** are what differ.
- **Accelerator**: NVIDIA (`/dev/nvidia*`; A100/GH200 — Alps, DKRZ), AMD (`/dev/kfd` +
  `/dev/dri/*`; MI250X — LUMI), Intel (`/dev/dri/*`).

The response splits by axis — and the split is the cheap part:

- **Device exposure = runtime detection in the GUARD, not config.** The guard already
  `--dev-bind-try`s a device list; generalise it to a **union of known globs**
  (`/dev/nvidia*`, `/dev/kfd`, `/dev/dri/*`, `/dev/cxi*`, `/dev/infiniband/*`,
  `/dev/hfi1*`). `--dev-bind-try` binds a node **iff present**, so a union opens exactly
  the holes this node has and nothing more — zero-config, adapts to
  Alps/LUMI/Euler/DKRZ unchanged. It **must** live in the guard: detection is node-local
  and the broker submits from the login node (login ≠ compute). This subsumes the
  pending GPU-list generalisation — GPU and fabric device exposure are the *same*
  mechanism.
- **Isolation model = explicit per-fabric config + hardware verification, NOT
  auto-detected.** Whether the fabric confines a job from other jobs — Slingshot
  **VNI**, InfiniBand **pkey**, or **nothing** — is the security-load-bearing "checked
  hole" and *cannot* be safely derived from device presence. It is a site/fabric
  property: declared (like `HUSK_SLURM_PARTITION`) and **verified per fabric** (gate C2
  is the Slingshot case; IB pkey isolation is a separate, weaker story to assess).

This maps Christoph's two ideas — *detect* vs *config file* — onto the axis each fits:
**detect the devices** (mechanical, node-local, low-risk) and **configure the isolation**
(security-bearing, site property, must be explicit + verified).

Reframe of "open only the correct holes": for devices that falls out for free
(try-bind-union skips absent nodes) — but **the device is not the security boundary, the
isolation model is.** Exposing `/dev/cxi` doesn't let a rank reach another job; the VNI
scoping is what does or doesn't. Trimming device globs is hygiene; a tight, *verified*
isolation model is the actual containment — so we spend the care there.

**Now:** implement Alps/CXI + VNI. Keep the guard's device binding a general try-bind
union (free), and structure the isolation model as a **named per-fabric profile** so
IB/pkey (Euler, DKRZ) or AMD (LUMI) slot in later without re-architecting. Do **not**
build the multi-fabric config system yet — one profile (Alps) + a general device union is
exactly the "general-ish where it's cheap" point.

## What ships when

Chapter 1 (+ Stages 0/1) is buildable and verifiable with the **existing** `--unshare-net`
data-plane cage — it needs only C3/C5/C6. Chapter 2 (Stage 3) is gated on C1/C2 and is
the harder, network-phase work. We build and verify Chapter 1 first; Chapter 2's fabric
cage is designed in detail only once C1/C2 come back from hardware.
