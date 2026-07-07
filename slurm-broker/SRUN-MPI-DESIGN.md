# husk — srun / MPI phase design (experimental)

**Status: design, pre-implementation.** Branch `experimental`, off the frozen v0.4
`main`. Nothing here ships until the hardware gates below are answered on Balfrin/
Santis. See [BROKER.md](BROKER.md) (current broker), [THREAT-MODEL.md](THREAT-MODEL.md)
(AV1–AV8 + the two design principles), [ROADMAP.md](../ROADMAP.md).

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
- **Does per-task `bwrap` work when launched by slurmstepd?** (gate **C3** below.)

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
- Exact `/dev/cxi*` set + any capability/hugepages requirement (**C3/C4**).
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

---

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
