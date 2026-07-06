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

**Step 1+2 are now the active phase** — and the trigger is empirical, not theoretical:
ICON's runscript calls `srun -n1` inside a brokered job and `srun` dies at
`Unable to establish control machine address`, because the compute cage's
`--unshare-net` leaves no route to `slurmctld`. That is the control-plane right the cage
exists to withhold, so `srun` cannot work without the recursive pair. Design (the
two-rights split, the stub/step-broker mechanism, staging, hardware gates C1–C6) is in
[`slurm-broker/SRUN-MPI-DESIGN.md`](slurm-broker/SRUN-MPI-DESIGN.md); run
`slurm-broker/fabric-probe.sh` (gate **C3**: does per-task `bwrap` launch under
`slurmstepd`?) before writing code — it is the assumption the whole chapter rests on.

1. **Architecture decision — FIRST: recursive sandbox-broker pairs** (not a central
   login broker). A sandbox always has a paired broker *outside* it; crossing a
   boundary (`sbatch`/`srun`/`ssh`) spawns a new pair, to arbitrary depth. It is the
   existing wrapper+broker+stub brick stacked, not new architecture. This decision is
   **forced by srun** (below) and it unifies SLURM + ssh. Cost: recursive lifecycle
   (the `PDEATHSIG` chain must hold per level) + per-level trust.

2. **`srun` brokering → single-node multi-process MPI.** `srun` launches a *step
   inside an allocation*, so it must run on the compute node within the allocation →
   it needs a **compute-node broker = the recursive pair** (hence step 1 first). Each
   rank is re-sandboxed. Single-node multi-rank likely needs **no compute network**
   (NVLink + AF_UNIX PMIx). Harder than `sbatch`: it's a live process (proxy
   stdio/signals/exit), not fire-and-forget.

3. **Network: socat + allowlist on compute nodes → multi-NODE MPI + general egress.**
   Reimplement Anthropic's network layer in Rust. **Scope it:** an SNI/host allowlist
   likely suffices; full TLS-MITM only if content-level filtering is actually needed.
   This reactivates **AV8** (broker bypass) and is safe *only because* srun is already
   brokered (step 2) and `slurmctld` is kept off the allowlist. Coupled to
   *multi-node* (single-node didn't need it).

4. **`salloc`: block / defer** (interactive allocation = highest complexity, lowest
   value for an agent; revisit only on a concrete need).

5. **Own the sandbox + generalize.** By here fs + network + seccomp are all
   reimplemented → the marginal cost of dropping Anthropic's runtime is small. Drop
   it. **Validate:** run Claude *naked* (`sandbox: off`) wrapped in husk's own
   per-session cage; get it smooth; then swap Claude for any agent (closed big-tech,
   or self-hosted DeepSeek). **Granularity = per-session base + broker-mediated
   exceptions**, NOT uniform per-command (which is the Lustre-freeze source *and*
   agent-coupled — it violates the axiom). The broker (which already exists) buys
   back per-operation policy where it's actually needed.

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
- Step 5 "naked Claude" check: confirm Claude runs correctly wrapped per-session
  (its per-command sandbox should be a security layer, not a functional dependency).

See also: `slurm-broker/THREAT-MODEL.md` (the AV1–AV8 threat model, incl. the AV8
broker-bypass landmine that step 3 must respect) and `slurm-broker/BROKER.md`.
