# husk roadmap

**Where husk is going.** Its sibling [`doc/context.md`](doc/context.md) holds where husk *is*
— together they are the ⟂ time axis of the [documentation stack](doc/README.md), and both are
expected to rot on purpose. Nothing here re-argues *why*: the design premise lives in
[`doc/threat-model.md §1`](doc/threat-model.md), the reasoning that outlives any scheduler in
[`doc/PRINCIPLES.md`](doc/PRINCIPLES.md), and the agent contract in
[`doc/sandbox-interface.md`](doc/sandbox-interface.md). If a paragraph here explains a rule
rather than scheduling work, it is in the wrong file.

**Strategy, unchanged:** reimplement the vendor runtime's pieces in Rust incrementally, each
independently useful, until the marginal cost of dropping it is ~zero — then own it and
generalise. Never big-bang.

---

## Shipped

**v0.4 (2026-07-27)** — single-node broker: `sbatch`, compute-side re-sandbox, the fs cage
(F1–F6), GPU carve-outs, read-only SLURM queries. Submission surface default-deny by
construction. Balfrin-verified.

**Steps 1–3b (2026-07-31, branch `experimental`, unreleased)** — `srun` brokering end to end
(recursive stub/step-broker pairs, step option allowlist, per-rank cages, single-node
multi-rank MPI); network egress (allowlist, one proxy per node, per-rank relays, `CONNECT`
only by design). **ICON ran to completion with CMA enabled**, and a **production KENDA
assimilation experiment ran green** — the first real production workload through husk.

**v0.5 fix round (2026-08-05)** — the security review's whole above-LOW set plus the eight LOW
code fixes, hardware-green on Balfrin *and* Santis, ICON running again. Details in
[`doc/review-v0.5/`](doc/review-v0.5/).

---

## Track A — finish and release v0.5

Everything else assumes a released baseline.

1. **Santis at HEAD.** It was green at `2f1a0b0`, before both the Lmod env fix and the
   ghost-file TOCTOU fix. Re-run.
2. **The A1 file-descriptor question.** One grep of `~/.husk/log/job-*.log` for
   `not regular files on this node`. Empty ⇒ the run-time guard enforces and the CRITICAL is
   closed; a hit ⇒ it is inert on that site and A1 is only narrowed, which changes the design.
3. **Pen-test re-run** — [`doc/review-v0.5/RE-RUN-PLAN.md`](doc/review-v0.5/RE-RUN-PLAN.md).
   A5 first: it never actually ran (the cage-build collision killed 3 of its 4 jobs), so its
   hop 2–4 verdicts came from laptop triage rather than the cluster. Then A1, then the new
   briefs aimed at the code the fix round added — two of which are a *gate* nobody has
   attacked.
4. **→ RELEASE v0.5.** An agent on a CSCS system, externally confined, running its own
   single-node 4-GPU jobs. A daily-work tool, not a demo.

---

## Track B — own the boundary (6a, then 6b)

**6a is the keystone, and it is not only a security milestone.** Today the vendor runtime owns
the login-side boundary and wraps each *command*; husk wraps the *harness* only on compute.
Three consequences close together when husk owns the outer cage:

- **The two-door problem disappears.** In-process file tools stop being a hole — not because
  the tools changed, but because a path that is not mounted is unreachable by any of them
  ([`sandbox-interface.md §4.1`](doc/sandbox-interface.md)).
- **`--tools Bash` can be deleted**, which is the single largest usability win available:
  native file tools come back at full speed instead of every touch being a sandboxed command
  on Lustre.
- **husk can own policy** (§6 of the contract), because it owns what is mounted.

*Acceptance test for 6a:* land the outer cage, **delete `--tools Bash`, and verify `/users` is
still unreachable from the agent's own file tools.** If it holds, the workaround was
redundant; if not, husk does not own the boundary it claims.

*Prerequisite, now measurable:* user namespaces must **nest** — husk's cage will sit around a
runtime that creates its own. `husk-site-check.sh` tests it.

**6b** — the contract is written and passes its own acceptance test (the vendor's name appears
once, in the integration table). What remains is husk's own policy schema plus a vendor
adapter. **Deliberately unspecified: the field names** — the property is the commitment, the
encoding is 6a's to choose. husk's own non-conformance is tracked in
[`sandbox-interface.md §8.1`](doc/sandbox-interface.md), and those rows are deleted when
closed, never reworded.

---

## Track C — more machines

Parallel to everything; blocks nothing. The architecture already ports (no root, no site
cooperation, per-arch binaries, degrades without uenv). The details are where the work is.

**Run [`slurm-broker/husk-site-check.sh`](slurm-broker/husk-site-check.sh) first, on every
candidate.** It answers the one fatal, binary question — are unprivileged user namespaces
available — in five seconds, before anyone invests a week. It also emits the draft site
profile.

**Targets, chosen for what they teach rather than for coverage:**

| target | new axis | note |
|---|---|---|
| **LUMI** | AMD GPUs (`/dev/kfd`) | Cray EX, so Slingshot and the OS are familiar — one new variable, well isolated. Highest information per unit effort. |
| **Euler (ETH)** | InfiniBand fabric, non-Cray OS | second device family and a different module system |
| **DKRZ Levante** | — | mostly confirms what LUMI and Euler already teach; do it later, cheaply |

**Known work:** the GPU device list is hard-coded NVIDIA and must become a runtime glob **in
the guard** (the broker cannot enumerate at submit time; login ≠ compute). Same for the fabric
list. The env allowlist needs one measured bringup per site — that is `P5`'s documented tax,
and it is now routine: read the "not forwarded" line.

---

## Track D — multi-node MPI — **MEASURED 2026-08-05: days, not weeks**

The experiment ran (`fabric-probe.sh` C10, Balfrin, real 2-node allocation, job 5019306).
**Exactly one thing blocks multi-node: `--unshare-net` per rank.** `cs_2node4rank_nonet`
gives a real 4-rank communicator — the ICON shape, intra-node shared memory and the
inter-node NIC at once — while `cs_2node4rank_netns` fails with `_pmi_set_af_in_use:
Unable to obtain IP address`. `cray_shasta` PMI is TCP, and a rank alone in a netns has no
IP to bind.

Everything else is clear: the **fabric is orthogonal** (proven twice — the no-unshare arm
failed identically, and `C11` shows a caged job really is on CXI, not degraded to TCP);
**`/dev/shm` must be shared per node** (private tmpfs *hangs*; the per-job-subdir design is
now measured); AF_UNIX can stay blocked at no functional cost; steps run concurrently.
**The escape hatch is closed** — `pmix_2rank_UNCAGED` is also wrong-size, so this MPICH does
not speak Slurm pmix at all, and `pmi2` fails the same at two nodes.

**The open decision, and it is a real one.** Dropping `--unshare-net` gives those ranks the
HOST network, so the egress proxy and allowlist stop applying — on the largest jobs. Three
shapes: (1) accept it and document it as a capability difference between cage profiles, the
way `single-node` and `multi-node` already differ; (2) **one netns per job-on-a-node** rather
than per rank, with an address PMI can bind — consistent with `P1`, looks right on principle,
needs its own measurement; (3) treat the fabric as the checked hole VNIs already make it.

**Security item surfaced by the same run:** `SLINGSHOT_VNIS` is in the step environment and
steers which VNI a process uses, while `SLINGSHOT_` is not in `RESERVED_ENV_PREFIXES` — so a
caged rank can set it. Whether the NIC validates it against Slurm's grant is the
AV8-over-fabric question, which needs a libfabric program rather than shell. Reserve the
prefix regardless.

---

## Track E — usability

Not a phase — a lens. The evidence so far says usability is mostly **precision work**, not
"make husk weaker": in each case the control's blast radius exceeds its target, and tightening
the aim costs no security.

| symptom | control | actual target | shape of the fix |
|---|---|---|---|
| agent memory does not persist across sessions | `~/.claude` is read-only | `settings.json` only | bind a husk-owned writable state dir over the agent's state path — needs `AgentProfile` |
| cannot read another user's data tree (e.g. operations data) | the `/users` floor | credentials in home *roots* | **NOT DECIDED — see below** |
| every file touch is a slow sandboxed command | `--tools Bash` | the two-door problem | dissolves with 6a |
| per-site setup needs undocumented knowledge | — | — | site profile + `husk-site-check` |

**Introspection is one problem wearing three hats**, and it has cost real time: a stale
prebuilt binary reported the A1 escape as still open; a stale in-session broker cost a whole
diagnosis round on ICON (a session keeps the broker it started with, so reinstalling does
nothing); `exit` backgrounds a session rather than ending it, producing a phantom DRIFT. The
build stamp fixed one instance. **`husk status`** would generalise it: which build, which
broker, which session, which policy, which partitions, is the boundary actually up.

---

## Cross-cutting — profiles as first-class

Today site knowledge is scattered across install flags, Rust constants, env vars and a shipped
JSON; agent knowledge is scattered similarly, and some of it (the agent's state directory) does
not exist as a concept at all. The proposal is to make both **data with a schema**, so the cage
becomes a function of `(site, agent, operator policy, workdir)` rather than of constants —
which also makes it testable against a synthetic LUMI without a LUMI.

**Three kinds of data, and naming the third is what stops profiles becoming a dumping ground:**

- **SiteProfile** — devices, scheduler, module system, site path vars, socket path budget.
  First draft already exists: the `[site]` block `husk-site-check.sh` emits.
- **AgentProfile** — state directory, egress needs, config paths, mediated binaries. This is
  [`sandbox-interface.md §5`](doc/sandbox-interface.md) made real.
- **husk's own catalogues** — auto-exec surfaces, blocked syscalls, the sbatch option registry.
  These vary with the *ecosystem*, not with site or agent, and must ship with husk: `.Rprofile`
  executes everywhere, and re-discovering that per site would be strictly worse.

*Note the tangle this exposes:* `AUTO_EXEC_DIRS` currently mixes axes — `.claude` is
agent-specific, `.vscode`/`.idea` are ecosystem. Invisible today, obvious under the split.

**The discipline, mirroring L1's entry bar:** *a field enters a profile when a **second** site
or agent disagrees about it.* Until then it stays a constant. On today's evidence that admits
four fields, not a rewrite — `GPU_DEVICES` (LUMI is AMD), `SUBMIT_ENV_ALLOW_SITE` (Santis ≠
Balfrin), `DEFAULT_PARTITION` (Santis has no preemptible), `FABRIC_DEVICES` (on checking
Euler) — plus one *new* `AgentProfile` field driven by a real bug rather than by symmetry: the
state directory.

**Warning: a profile is a policy input.** It inherits `P2` (must live where the agent cannot
write it) and `P8` (must join the `SETTINGS_SOURCES ↔ denyWrite` pairing test). Get that wrong
and this has built a fresh way for the confined side to supply its own boundary — which is
F17, the bug that started the whole write-root saga.

*Migration:* start from the site-check's schema → move the four earned constants → add
`AgentProfile.state_dir` and fix memory with it → leave everything else alone until a second
instance appears.

---

## Smaller items

- **Validate the configured partitions at startup** (`sinfo`/`scontrol`) and fail fast with an
  actionable message. This is also the open instance of `P7` behind H11: nothing verifies that
  a partition is actually preemptible, and nothing fails loudly if it is not.
- **Report carve-outs that silently did not apply.** Floor-overlapping ones are already
  reported; a symlinked component (F20) and a non-existent path are both dropped in silence.
  Same teaching-message machinery, three sentences.
- ~~Allow a LIST of partitions~~ **DONE** — shipped; `HUSK_SLURM_PARTITION` takes a list.

---

## Open questions

- **Sub-home carve-outs — NOT DECIDED, needs separate reasoning.** Whether an operator may
  expose a path *below* another user's home (operational data) while the floor keeps home
  roots hidden. It is a real workflow with no workaround today, and it is a genuine policy
  change rather than a bug fix, so it gets its own discussion before any code.
- `salloc`: block permanently, or revisit? (`srun`/`salloc` from the login node stays low
  priority.)
- Network scope: SNI/host allowlist vs full TLS-MITM.
- Recursive lifecycle robustness (`PDEATHSIG` chains across nested pairs).
- Whether the cage holder should clear `PR_SET_DUMPABLE` — measured on 6.8 a non-dumpable
  holder is still joinable, so the reasoning and the measurement disagree; the flag stays set
  because the failure mode is fail-closed on the MPI path. Revisit only with a measurement on
  the target kernel.
