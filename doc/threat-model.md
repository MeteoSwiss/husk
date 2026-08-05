# Threat model

**Level 2 of four.** [`PRINCIPLES.md`](PRINCIPLES.md) holds what would be true of any
confinement system; this file holds what is true of *husk's situation* — who the
adversary is, what it can reach, what is lost if it wins. Controls are
[`constraints.md`](constraints.md) (L3); findings are [`review-v0.5/`](review-v0.5/)
and the git log (L4).

Where a claim here is an instance of a principle it is cited (`P2`), not re-argued.
If you find yourself explaining *why* a rule is a rule in this file, it belongs one
level up.

Status: v0.5. Last reviewed 2026-08-05 against `review-v0.5/SYNTHESIS.md`.

---

## 1. Premise

**The confiner must be external to, independent of, and not reliant on the
cooperation of, the confined.**

This is a design premise, not a lesson — it decided the architecture before there
was evidence either way, and it is why husk wraps *any* agent rather than trusting a
runtime's own sandbox. It appears under "Not yet earned" in `PRINCIPLES.md` because
no incident has yet tested it, which is a fact about our evidence rather than about
its standing.

Two things follow directly:

- **Trust base: the kernel, plus husk's own small auditable core.** Nothing else. A
  vendor sandbox may be *run* for defence in depth; the guarantee never routes
  through it.
- **Generality is not a feature.** Because no agent is on the enforcement path, husk
  wraps Claude, a closed third-party agent, or a self-hosted open-weight model
  identically. That falls out of the trust model.

---

## 2. Adversary

Two vectors with the same output, not distinguished by any control:

1. **Prompt injection.** Untrusted content the agent reads — web pages, fetched
   docs, shared files, MCP responses, a colleague's paste, *the output of a job it
   just ran* — contains instructions that redirect it.
2. **Misaligned optimisation.** The agent, acting in good faith, satisfies the
   literal objective by destroying the structure that defines it. Canonical case:
   asked to maximise a benchmark score, it deletes the benchmark.

**The agent is treated as the adversary** — not as a component that might be
compromised, but as the attacker, continuously, by default.

**Capabilities assumed.** Runs as the user's uid with the user's filesystem reach
and cluster identity. Reads and writes wherever the user can (modulo the cage),
spawns and execs, may attempt kernel-CVE escalation, and authors every byte of any
script or request it submits. On a compute node it starts inside a process tree
running as the user among the user's other processes.

**Capabilities assumed absent.** No root at start. No ability to tamper with the
sandbox layers from outside — they run before it starts. No control of the
scheduler, the fabric, or site admin policy.

**The human is inattentive by default.** No control may depend on careful review of
an individual prompt or approval. The primary use case is an unattended multi-day
run with nobody present. §7 lists what this assumption still costs.

---

## 3. Trust domains

Four, each strictly outside the next:

| domain | holds | reachable by the agent |
|---|---|---|
| **kernel + site policy** | everything | only through permitted syscalls |
| **husk trusted side** — login wrapper, broker, holder, egress proxy | MUNGE, the route to `slurmctld`, the network, the policy files, the partition/account record, the log | only through the stub protocol |
| **the cage** — login session, job cage, rank cages | the project directory; the software stack read-only | this is where the agent lives |
| **the agent** | its own context | — |

The stub protocol is the only channel from cage to trusted side. It carries data —
never an executable, never a path the trusted side will later open (`P3`).

Two facts hold this on compute, both load-bearing:

- `/run/munge` is masked in the cage, so a job cannot authenticate to SLURM even
  though it runs as the user on a node where MUNGE exists.
- Trusted-side processes are in neither the job's PID nor its user namespace, so a
  job cannot name, signal, or `process_vm_readv` them. The holder that keeps the
  shared namespace alive *is* visible as PID 1 and is deliberately bare — no mounts,
  no network, no MUNGE, nothing worth reading (`P1`).

**The observer sits outside the boundary it measures** (`P2`). The broker log lives
under `$HOME`, not in the agent-writable spool; the job guard writes refusals there
rather than to the job's stdout, because stdout is the thing under suspicion.

---

## 4. The load-bearing set

The guarantee must hold if every cooperative layer fails. Only these are part of it.

**Load-bearing** — kernel- or Rust-enforced, deterministic: the bwrap filesystem
cage (login and compute); the network boundary (`--unshare-net` plus husk's egress
proxy outside the cage); `seccomp-wrapper`; the broker (submission allowlist, forced
options, re-sandbox on every job, provenance gate on `scancel`); the tool allowlist
that keeps every agent file operation inside the cage.

**Not load-bearing** — noise reduction only: the agent runtime's permission rules,
its command analyser, its intent classifier, interactive prompts, and anything a
human is asked to notice.

Two rules the v0.5 review enforced:

1. **No test or claim may rest on a non-load-bearing gate.** A probe blocked by a
   prompt has proven nothing about containment (`P10`).
2. **Encode expectations about cooperative layers as tests, not prose** (`P8`) —
   they changed twice in one day on 2026-07-27.

An AI intent classifier can never be part of the guarantee: intent is unbounded and
its verdicts are non-deterministic.

---

## 5. Harms

What the user, their colleagues, or the site loses. Stable IDs, cited by
`constraints.md` and the review shards.

| id | harm | one line |
|---|---|---|
| **H1** | privilege escalation | kernel CVE → root → cluster state, other users' sessions |
| **H2** | credential theft | SSH keys, tokens, `.env`, cluster credentials — the user's or a co-tenant's |
| **H3** | compute resource abuse | bulk allocation, mining, submission storms; cost, and queue pressure on others |
| **H4** | data destruction at rest | deletes or corrupts files in the writable set; may be unreproducible |
| **H5** | reaching other nodes directly | SSH or equivalent, bypassing the scheduler |
| **H5′** | lateral movement to internal services | LDAP, NFS, monitoring — reachable from a login node |
| **H6** | exfiltration | reads something sensitive and gets it off the machine |
| **H7** | persistence | plants code executed later, outside the cage, as the user |
| **H8** | identity abuse | acts as the user — commits, pushes, posts, mails |
| **H9-in** | input poisoning | corrupts data a workflow will consume, before it runs |
| **H9-out** | output incorrectness | the analysis is wrong; the result looks plausible — *out of scope, §8* |
| **H10** | destruction of work in progress | cancels or disrupts running jobs, **including other people's** |
| **H11** | silent truncation reported as completion | an interrupted run is indistinguishable from a finished one |

**H10 and H11 are new in this revision**, and neither collapses into its neighbour:

- **H10 is not H4.** H4 is data at rest; H10 is a 24-hour production run destroyed
  at hour 23. SLURM cannot help — the agent's jobs and the user's production jobs run
  under one uid, so the scheduler correctly sees one person. The gate is therefore
  **provenance, not permission**.
- **H11 is not H9-out.** H9-out is the agent's science being wrong, which husk
  cannot reason about. H11 is a failure mode **husk introduces** by forcing a
  preemptible partition. For a forecasting service, reporting that a truncated run
  completed is worse than an escape.

---

## 6. Compute-side attack vectors

AV IDs describe *routes* on a compute node, assuming worst case that the network is
open. Not a competing taxonomy — each realises one or more harms. Mechanism lives in
[`slurm-broker/`](../slurm-broker/).

| av | route | realises | status |
|---|---|---|---|
| AV1 | read a secret in the workdir or a carve-out, then exfiltrate | H2, H6 | covered |
| AV2 | plant an auto-exec payload that fires later, outside the cage, as the user | H7 | covered by a **denylist** — residual, §9 |
| AV3 | tamper with the job's own outputs | H4 (integrity) | accepted, §8 |
| AV4 | read a co-tenant's loose-permission data | H2 | bounded by unix perms; not a cage regression |
| AV5 | symlink out of the writable root into a hidden home | H2 | covered |
| AV6 | general internet abuse — C2, download-and-run, internal scan | H6, H5′ | covered when an allowlist is configured; open under `*` |
| AV7 | read a secret from the inherited environment | H2, H6 | **partial** — §9 |
| AV8 | submit directly from a compute node, bypassing the broker | H3, H10, and voids the gate | covered by three independent controls |

**AV8 is the sharpest landmine in the design.** On a compute node AF_UNIX is not
blocked and MUNGE exists. Held today by three controls, not one: `/run/munge`
masked, scheduler ports refused by the proxy even under `*`, and `srun` itself
brokered. **Any future relaxation of the network must re-verify all three** — a hard
prerequisite, not a note.

---

## 7. What still depends on a human being right

The inattentive-user assumption now holds almost everywhere: the agent has no
host-side file tools, cannot request unsandboxed execution, cannot edit any settings
file, and cannot reach SLURM except through the broker. There is essentially no
approval prompt left to social-engineer.

What remains is short, and operators should treat it as a checklist:

1. **Who chooses the write root.** husk refuses a home, announces the writable set
   in every job, and confines output paths to that subtree. It cannot know what else
   is in a directory a human points it at. The AV2 mask being a denylist is what
   makes this matter.
2. **Who chooses the partition, and whether it is actually preemptible.** H3 rests
   entirely on this. `scontrol show partition <name>` plus the QOS preempt settings
   is the check. **Nothing in husk verifies it and nothing fails loudly if it is
   untrue.** The default is the safe one, so weakening it takes a deliberate act.
3. **Who maintains the egress allowlist.** The agent can surface a refusal but
   cannot widen the list.
4. **Who reads the preemption signal (H11).** Until preemption is loudly
   distinguishable from completion, a human is the only thing between a truncated run
   and a reported result. *Open.*

**Items 2 and 4 are the two places where a silent human error produces a silent
failure**, and are therefore the highest-value targets for the next round.

---

## 8. Out of scope

- **H9-out — output correctness.** husk cannot reason about whether the science is
  right. The user reviews the code.
- **AV3 — the job tampering with its own outputs.** No boundary exists inside the
  job's own writable space. Treat agent-produced artifacts as untrusted.
- **Targeted attacks on the model provider, runtime image, or proxy
  infrastructure.**
- **Physical attacks; site-wide DoS.** Bounded in practice by accounting and site
  policy.
- **Inference-time disclosure to the model vendor.** Real, but not addressable by a
  sandbox.
- **Centralised cross-user audit and real-time alerting.** Admin domain. husk
  provides per-user forensic material only.
- **Subprocess-level activity below the bash invocation.** A transcript-coverage
  limit, not a defence gap.
- **User mistakes outside the agent session.**

---

## 9. Residual and accepted risks

Kept short on purpose: a residual list that only grows stops being read.

| residual | why accepted | closes when |
|---|---|---|
| **AV2 mask is a denylist** (`P5`) — enumerates `.git`, `.hg`, `.Rprofile`, `.claude`, `.mcp.json`, editor dirs | the by-construction version — *the job may write outputs but may not create or modify dot-entries at the root of a writable directory* — is not expressible in bwrap, which masks paths rather than classes of future creation. It means staging output and filtering on the way out. | the list keeps growing → build the staging filter. Recorded, not pretended away. |
| **AV2 nested config dirs** — the mask applies at the top level of each writable root | finding `<root>/sub/.claude` means walking the project tree, the in-process walk that causes the Lustre stalls | bounded instead by making *readers* use trusted paths (`P2`) |
| **AV7 env secrets** — forced `--export=ALL` (only `ALL` activates the uenv view), so an undeclared secret reaches the job | declared credentials are masked; the alternative breaks uenv | a vetted baseline env allowlist. The submission env is already allowlist-built (`P5`). |
| **apinfo write** — the rank cage binds one per-step `apinfo` dir read-write | Cray MPICH opens it `O_RDWR` though it only reads. User-owned, 0600, belongs to this job. The fix (a husk-owned copy bound over the path) can only be built per-rank after the step exists, putting a race into the path MPI bootstrap depends on. | reviewer judgement — flagged deliberately |
| **`--output` leaf TOCTOU** (`P3`) — husk confines and canonicalises; slurmd opens later | narrowed from an arbitrary-write primitive to a race by the leaf `lstat`, the post-open `/proc/$$/fd/1` re-check, and forced `--open-mode=append` | not closeable unprivileged — needs a job prolog or SPANK |
| **H11 preemption** | — | **open, and the most consequential item here for a forecasting service** |
| **partition preemptibility unverified** | husk cannot check it by construction | an install-time `scontrol show partition` warning |
| **agent cancels its own jobs** | same authority it had by not submitting them | n/a — this is the intent |

---

## 10. What changed in v0.5

Two of these reverse statements earlier revisions asserted as permanent.

- **The SLURM-path escape is closed.** Previous revisions stated no sandbox attribute
  reaches a submitted job. Brokered jobs are re-caged on the compute node, `srun` is
  brokered, and MPI ranks share one deliberately scoped namespace (`P1`).
- **The bash-vs-native-tool asymmetry is closed by architecture.** The agent is given
  a tool *allowlist*, so the host-side file tools that bypassed bwrap no longer exist
  in the session (`P5`).
- **Egress exists and is enforced outside the cage** — host-or-IP plus port, with
  scheduler ports refused regardless of configuration.
- **`scancel` is gated on provenance** — the reason H10 now has an ID.
- **Policy parse failures fail closed.** A malformed settings block previously
  resolved to an empty policy, silently dropping every `denyRead` and credential mask.
- **H10 and H11 added.** Neither is new as a concern; both were unnamed.
