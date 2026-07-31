# husk roadmap (post-v0.4)

## Design axiom (the through-line for everything below)

**The confiner must be EXTERNAL to, INDEPENDENT of, and NOT reliant on the
cooperation of, the confined.**

- The untrusted set is the agent **and everything it ships with** — especially any
  software advertised as *restricting* it. A vendor's self-sandbox is
  self-restriction, architecturally weaker than external restriction no matter how
  well written: the process you're worried about is the one meant to jail itself.
- Therefore husk uses a **per-session, kernel-enforced (bwrap + seccomp), external
  wrap** — never a per-command hook the agent has to invoke. A per-command hook
  makes containment only as correct as the untrusted orchestrator's code that calls
  it (as many escape paths as it has bugs). An external wrap holds regardless of how
  buggy or hostile the agent is, because nothing it does is on the enforcement path.
- **Trust base = the kernel + husk's own small, auditable core.** Nothing else.
- Open-source vendor sandboxes (Anthropic) are for **adopting + auditing** ideas —
  never for husk to *depend on*. Run one too if present (free defense-in-depth), but
  the guarantee never routes through it.
- **Consequence:** husk wraps *any* agent — Claude, a closed OpenAI/MS agent, or a
  self-hosted open-weight model (DeepSeek etc.) — identically, because none of them
  are on the enforcement path. Generalization falls out of the right trust model; it
  isn't a separate feature. (See `slurm-broker/THREAT-MODEL.md`.)

## Strategy

Incrementally reimplement Anthropic's Linux sandbox pieces in Rust — each one
independently useful — until the marginal cost of dropping their runtime is ~zero,
then own it and generalize. This de-risks the rewrite by never doing it big-bang.

## Steps (dependencies noted)

**v0.4 (SHIPPED 2026-07-27):** single-node broker — `sbatch` + compute-side re-sandbox
+ the fs cage (F1–F6) + GPU carve-outs + read-only SLURM queries (Tier 1). The
submission surface is default-deny by construction (option allowlist: parse → validate →
re-emit → reject unknown). Verified on Balfrin hardware, 32/32
(`slurm-broker/selftest.sh --full`). Still layers on Anthropic's runtime.

**Steps 1+2 SHIPPED (branch `experimental`, 2026-07-31) — not yet released.** `srun`
brokering works end to end: the recursive stub/step-broker pair, the step option allowlist,
per-rank cages, and single-node multi-rank MPI. **ICON ran to completion on Balfrin** —
one node, 4 MPI ranks, GPU, brokered throughout, with Cross Memory Attach enabled and no
`MPICH_SMP_SINGLE_COPY_MODE=NONE`, so nobody pays an intra-node message tax. Design and
the hardware gates are in
[`slurm-broker/SRUN-MPI-DESIGN.md`](slurm-broker/SRUN-MPI-DESIGN.md).

The structural lesson of that phase is now a design principle in
[`THREAT-MODEL.md`](slurm-broker/THREAT-MODEL.md), **the unit of confinement**: the
security border is the job on a node, not the process. All ranks of a job are one trust
domain, so they share one user namespace; a cage per task added no boundary, only N
redundant copies of the same wall, and one of those copies silently cost us CMA.

1. ~~**Architecture decision — recursive sandbox-broker pairs**~~ **DONE.** A sandbox
   always has a paired broker outside it; crossing a boundary spawns a new pair. The
   `PDEATHSIG` chain holds per level.

2. ~~**`srun` brokering → single-node multi-process MPI**~~ **DONE, ICON verified.**

3. ~~**Network: socat + allowlist on compute nodes.**~~ **BUILT 2026-07-31** — allowlist
   (`netallow.rs`), egress proxy (`netproxy.rs`), guard wiring, and four selftest arms.
   Off unless an operator configures `sandbox.network.allowedDomains`; `*` available for
   deliberate open egress; SLURM daemon ports refused regardless. **Not yet exercised on
   hardware** — that is the next Balfrin run.
   Original scope note kept for the record: Reimplement the network layer rather than depending on Anthropic's. **Scope it:**
   an SNI/host allowlist likely suffices; full TLS-MITM only if content filtering is
   actually needed. Reactivates **AV8** (broker bypass) and is safe *only because* srun is
   now brokered and `slurmctld` stays off the allowlist.
   Shape decided by measurement (see SRUN-MPI-DESIGN.md): the **filtering proxy is one per
   node**, reached through a unix socket bind-mounted into every rank's cage — a unix
   socket crosses a network namespace because it is a filesystem object. Only a dumb relay
   is per rank. The host-side allowlist must accept **host-or-IP + port**, not just
   domains, because a self-hosted model endpoint is an internal address with no SNI.

3b. ~~**Rank egress**~~ **BUILT 2026-07-31.** Every rank starts its own relay to the same
   single proxy, so `wget` behaves the same inside `srun` as in the sbatch script. The
   per-rank piece is an adapter, not a policy — each rank has its own network namespace and
   `HTTP_PROXY` names a `host:port`, so something must listen on that address inside each
   one. One proxy, one allowlist, one log. Motivated by asymmetric pipelines (one rank
   fetches, another parses, a third computes), which is where this would otherwise have
   bitten someone.

   **Known limitation, by design:** `CONNECT` only, so `https://` works and plain `http://`
   does not. A proxied `http://` request is an absolute-URI `GET`, and serving it would mean
   a second HTTP parser — the F13/F14 shape. The refusal names `https://` so it is
   actionable.

4. **Security review before release** — a multi-agent adversarial pass over the whole
   surface, as was done for v0.4, where it found four criticals. The submission surface,
   the step surface and the new network surface all get it. Nothing ships to users until
   this has run.

**→ RELEASE v0.5.** Worth stating plainly what it buys, because it is already a lot: an
agent on a CSCS system, externally confined, that can run its own single-node 4-GPU jobs.
That is a daily-work tool, not a demo.

5. **`salloc`: block / defer** (interactive allocation = highest complexity, lowest value
   for an agent; revisit only on a concrete need).

6. **Own the sandbox + generalize — v0.6.** By here fs, network and seccomp are all ours,
   so the marginal cost of dropping Anthropic's runtime is small. **Split in two:**
   - **6a — provide the login sandbox ourselves, still Claude only.** The deliverable is
     three agent-NEUTRAL pieces: husk's own policy source (theirs reads
     `.claude/settings.json`), **credential masking** (our compute cage is ~40% of their
     fs model — a known gap), and a session-level wrap instead of their per-Bash-command
     one. What is actually Claude-specific is a three-column table: binary to exec, config
     dir to allow, API hosts to allowlist. **Acceptance test: the string `claude` appears
     nowhere except one row of that table** — otherwise 6b is a rewrite, not an extension.
     Also fixes the Balfrin/Santis lag, whose real cause is an in-process deny-set walk on
     Lustre metadata, *provided* our policy layer expresses itself as **mounts, not a
     scanned deny-set**. The compute cage is already built that way.
   - **6b — open it to other agents**, including self-hosted. Note that self-hosted at
     CSCS is a *network* case, not a no-network one: the model is served on the H100
     vcluster while the harness runs on Balfrin, so they talk across vclusters. Two things
     to pin early: which side dials (our proxy model is egress-only; anything dialling
     *in* is materially new work) and who starts the model job (if the agent can, it
     controls an un-caged process — the sbatch/ssh/tmux class again).
   **Do before their runtime goes away** (laptop task, no allocation): enumerate what it
   enforces *while it is still there to diff against* — the `seccomp-wrapper` vs
   `apply-seccomp` syscall delta and the fs-model delta. Afterwards that is archaeology;
   today it turns 6a from "reimplement a sandbox" into "close a known list".

## Smaller items (not blocking a phase)
- **Allow a LIST of partitions, not one forced value.** Today `HUSK_SLURM_PARTITION`
  is a single partition the broker forces onto every job, which is the tightest
  policy but also the bluntest: a site may legitimately want short test jobs on one
  queue and longer runs on another (Santis has both `debug` and `shared`). Natural
  shape: the operator records an allow-set, the agent may pick from it, and anything
  else is rejected with the same teaching message — i.e. the option-registry pattern
  applied to a value rather than a flag. Keeps "the operator decides the policy, the
  agent cannot escape it" while dropping the one-size restriction.
- Validate the configured partition at broker startup (`sinfo`) and fail fast with an
  actionable message, instead of surfacing a raw `invalid partition` from sbatch at
  first submission.

## Open questions to resolve along the way
- Recursive lifecycle robustness (PDEATHSIG chains across nested pairs).
- Network scope: SNI/host allowlist vs full TLS-MITM.
- `salloc`: block permanently, or revisit?
- Step 6a "naked Claude" check: confirm Claude runs correctly wrapped per-session
  (its per-command sandbox should be a security layer, not a functional dependency).
- Whether the cage holder should clear `PR_SET_DUMPABLE`. It *can* — measured on kernel
  6.8, a non-dumpable holder is still joinable via `bwrap --userns`. Left off because the
  gain is a third layer on a process that is already unreadable and holds nothing, while
  the risk is kernel-dependent (Balfrin runs 5.14; if joining broke there, every step
  would die). Revisit if the holder ever comes to hold something worth reading, or once
  the behaviour is measured on the target.

See also: `slurm-broker/THREAT-MODEL.md` (the AV1–AV8 threat model, incl. the AV8
broker-bypass landmine that step 3 must respect) and `slurm-broker/BROKER.md`.
