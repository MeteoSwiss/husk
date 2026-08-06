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

**(4) — added 2026-08-06, Christoph: let the endpoint pre-exist the boundary.** Rather than
carrying PMI *through* the netns, arrange that the connection it needs already exists when the
cage is built — the spirit of the egress relay, where the real socket lives outside and the
caged side only holds a handle. Two mechanisms do this without any address rewriting:

- **an inherited fd** — `PMI_FD` exists precisely so a launcher can hand a bootstrapped
  connection to the process it spawns, and husk already passes fds through bwrap
  (`--userns 9 --pidns 8`);
- **a Unix socket path** — `PMIX_SERVER_URI` names a *filesystem* rendezvous, and a filesystem
  path crosses a netns natively. husk already bind-mounts exactly this shape for egress.

**What does NOT work, and it is worth writing down so nobody spends a day on it:** "let MPI
bootstrap, then wrap it." bwrap execs, and exec destroys the in-process MPI state, not merely
its sockets. The in-process variant — the workload calling `unshare(CLONE_NEWNET)` on itself
after `MPI_Init` — is mechanically fine but requires the confined side to cooperate, which is
the one thing husk's axiom forbids.

**ANSWERED 2026-08-06 (jobs 5021103/5021116), and the answer is the expensive one.** Neither
cheap mechanism exists on this stack: `C12` measured **zero AF_UNIX socket/connect calls** in a
caged 2-rank run, so the rendezvous is not a Unix socket; and the rank's environment offers
neither `PMIX_SERVER_URI` nor `PMI_FD`, so there is no filesystem path and no inherited fd to
adopt. What is offered is `PMI_CONTROL_PORT` + `SLURM_STEP_RESV_PORTS`, and the netns failure
is `_pmi_set_af_in_use: Unable to obtain IP address` — PMI determining **its own** address.
That is the hardest sub-case: an address used as identity cannot be rewritten the way an HTTP
proxy target can, so option 4 would have to supply a *bindable* address, not merely
reachability.

### DECIDED 2026-08-06: ship it as a named, weaker profile; real support is v0.7

Dropping `--unshare-net` for multi-node is **unsatisfying, and that is the point** — so it
gets advertised as what it is rather than hidden. A `MultiNode` profile whose boundary is
explicitly weaker: ranks share the host network, so **the egress proxy and its allowlist do
not apply**, and AV8 (broker bypass) is reachable from a rank. Everything else — the
filesystem cage, the seccomp profile, the resource envelope — is unchanged.

Two constraints on how it ships, both from `P7` and from this project's own history:

- **It must be LOUD.** `Profile::select` currently *rejects* multi-node rather than silently
  downgrading to one node, for exactly the right reason (a wrong answer that looks like a
  right one is the worst outcome available). The same rule applies here: a job that gets the
  weaker boundary must say so, in the banner and in the job log, every time. An operator who
  discovers the difference by reading the roadmap has been failed.
- **It must be opt-in at the operator level**, not something an agent reaches by asking for
  `--nodes=2`. The agent picks from what the operator allows; it does not pick its own
  boundary.

**Real multi-node containment is v0.7**: per-rank routable addressing (veth + bridge +
routes), which is real container networking and the first thing husk would have built that
needs it. Not before the v0.6 boundary work — owning the login cage is worth more.

**MEASURED 2026-08-06 (job 5022735), and it settles the boundary question.** Instrumented
`mpi_hello` dumped its own fd table after `MPI_Init` in an uncaged 2-node run:

```
rank=0 host=nid001227 fd=3 local=0.0.0.0:27702        peer=0.0.0.0:0      st=0A  <- LISTENING
rank=0 host=nid001227 fd=4 local=…97.54:27702  peer=…97.74:56708  st=01
rank=1 host=nid001237 fd=4 local=…97.74:56708  peer=…97.54:27702  st=01
```

**Each rank LISTENS and they cross-connect directly across nodes.** So option 4 is out for
this stack: there is no pre-existing connection to inherit when the rank itself creates the
listener, and an inherited fd cannot cover a listener plus N inbound.

**The decision that follows is robust to what that traffic actually is:** either way a rank
must bind a listener and advertise an address another node can dial, and loopback is not
advertisable — which is exactly what `_pmi_set_af_in_use` reports. **Multi-node therefore means
dropping the per-rank netns, or building real container networking (veth + bridge + routes).**

**Still genuinely open, and it decides how big the fix is, not whether one is needed:** is
27702 the PALS/PMI control plane or MPI's own transport? It is NOT `PMI_CONTROL_PORT` (that was
22125/22275, always the first of `SLURM_STEP_RESV_PORTS`), and both ranks listen on the same
number, which reads as a derived service port rather than an ephemeral data socket. The
discriminator is one run with the TCP provider disabled and CXI forced: if 27702 survives it is
control, if it vanishes it was transport.

**Not answered: whether PMI accepts an address it is handed.** The `pmi_addr_hint` arm came
back inconclusive because the caged run died at `pals_init2() failed: 2` — the PALS launcher
failing UPSTREAM of the address lookup, so `MPICH_INTERFACE_HOSTNAME` was never reached.

Superseded, kept for the reasoning: the refinement worth measuring was the PEER of that
connection: does a rank talk
to its LOCAL stepd, or to a remote node? Local-only would mean a per-node relay is enough;
remote means full inter-node routing. `C13` does not answer it yet — it inspects a `sh -c`,
which never calls `MPI_Init` and so never opens the socket. It needs to dump the fd table from
inside the probe's own `mpi_hello` after `MPI_Init`, which is a small change to a binary the
probe already builds.

**Also now measured, and it narrows the problem a lot:** intra-node ranks in separate netns
wire up **fine** — `cs_1node2rank_netns_shm` and `cs_1node2rank_netns_jobdir` both form real
2-rank communicators, twice, reproducibly. PMI finds its same-node peer through the filesystem.
So the netns boundary is not broken by PMI in general, only by the **inter-node** hop.

Historic framing kept for the record:
`_pmi_set_af_in_use: Unable to obtain IP address` is a real failure mode naming a real IP
lookup, not merely a variable being set; and "obtain **its own** address" is the harder
sub-case, because an address used as *identity* cannot be rewritten the way an HTTP proxy
target can. `fabric-probe.sh` **C13** settles which of the three transports is actually in use
by dumping what a rank is offered *and* what it holds open — the environment says what was
offered, the fd table and `ss` say what was taken. One 2-node run, no new experiment.

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

## Track F — break up the two functions that carry the bug history

**The module structure survived 213 commits; the function structure did not.** Measured
2026-08-06, on the code that ships v0.5:

| | |
|---|---|
| `wrap_script` | 624 lines |
| `decide` | 454 lines |
| **together** | **1,078 of `policy.rs`'s 1,563 code lines — 69%** |

The dependency graph is still a clean DAG with no cycles, and the seven modules added since
v0.4 (`rank`, `step`, `srun`, `netproxy`, `netallow`, `profile`, `cage`) all landed as proper
layers rather than as extensions of existing files. That is the part that usually rots first
under incremental growth, and it held.

What drifted is inside those two functions, and **they are the two most security-critical in
the project**: `decide` is the submission gate (F13/F14/F24/F26/F27 and the `#SBATCH` CRITICAL
all lived there), `wrap_script` is the guard generator (B5's *4 of 7 shipped guard bugs were
quoting, interpolation or scoping*, plus the 2026-08-06 silent hang).

That is not coincidence. **Both of this project's recurring bug classes are the failure mode of
a 500-line linear sequence of conditionals** — in a function that long, "is this handled on
every path" is not visible by reading, so it does not get checked. The srun hang was a nested
`if` with no `else` at line ~1375 of a 624-line emitter. The `#SBATCH` outage was a branch that
validated body directives and then failed to re-emit them.

Three ordered steps. **The order is the point:** each one makes the next checkable.

### F1 — split `guard.rs` out of `policy.rs`

`policy.rs` does two unrelated jobs that share a name and nothing else: a **gate** (decide what
is permitted) and a **code generator** (emit the guard). Separating them halves the file and
gives the guard a defined input type instead of eight captured locals.

Mechanical, and **verifiable byte-for-byte against `tests/golden/guard-net-{on,off}.sh`** —
"prove the bytes are identical." Do it FIRST, because F2 retires that oracle: a program emits
no bytes to compare. This is the last moment the goldens can check a refactor of this code.

### F2 — the guard becomes a program

**Decided 2026-08-06: the job guard should be compiled Rust, not generated bash.** This
supersedes the "deferred typed shell builder" that `review-v0.5/B5-guard-generation.md` left
open — that option is now judged to be aimed at the wrong bug class.

**Why the builder is not enough.** B5's own verdict: the emitted shell is auditable, the
generator is not, and *4 of 7 shipped guard bugs were quoting, interpolation or scoping*. But
it also found that a builder "would not have caught the two most severe findings, which are
semantic, not syntactic." 2026-08-06 confirmed that from the other direction: srun hung in
five or six jobs because a nested `if` had no `else` and a backgrounded child was never
checked. Both semantic. A builder that owns quoting would have shipped both.

**Why a binary, specifically.** Not for speed and not for elegance — for the acquisition-side
twin of [`PRINCIPLES.md` P6](doc/PRINCIPLES.md): *make the unverified state unrepresentable*.
husk already does this on the login side, where `SandboxReady` (`husk-slurm-wrapper.rs`) can
only be minted by a verified bind, so the agent exec cannot be reached without proof. The
compute side has no such thing, because a shell cannot carry a proof. In Rust the guard's
sharp edges become types:

| today, in shell | as a program |
|---|---|
| `mkdir -p … \|\| _husk_spool=` — error becomes an empty string | a `Result` that must be handled |
| broker started, never checked; `if` with no `else` | entering the cage needs a `StepBrokerReady` witness |
| `trap` per exit path, correct only while maintained | `Drop`, which runs on every path including unwind |
| a resource released in one branch and not another | acquiring *is* registering the release |

**The feasibility question is settled and was never actually asked.** No document anywhere
argues the guard must be bash. The recorded constraint is different: late-binding facts (GPU
devices, MUNGE sockets, credential dirs) can only be resolved on the compute node — which is
why guard *logic* exists, not why it is *shell*. And the binary is already there: the same
artifact runs on compute nodes as `--step-broker`, which is how the step pair works at all.
Observed on Balfrin 2026-08-06: `/users/cmueller/.local/bin/husk-slurm-broker --net-proxy`
running on nid001231. SLURM needs a script as the entry point; that script can be one `exec`
line. There is also a recorded decision *against* adding more compute-side guard shell, on
fragility grounds — which points the same way.

**The oracle changes, and this is the part to get right before starting.** The goldens
(`tests/golden/guard-net-{on,off}.sh`) were built specifically to make this rewrite checkable
— "prove the bytes are identical" instead of "hope the refactor was faithful". **That works
for a builder and not for a binary**, which emits no bytes to compare. A Rust guard needs a
*behavioural* oracle: drive both implementations through the same scenarios and compare what
is observable — mount table, processes, exit status, messages, what survives cleanup. Building
that harness is the first deliverable, not the second; without it this is the act of faith the
goldens exist to prevent.

### F3 — `decide` becomes a sequence of named rules

A different argument from F2's, and worth keeping distinct: this one is not about types or
RAII, it is about **making a property checkable that is currently only hoped for**.

454 lines of inline conditionals decide, among other things, which options reach sbatch. The
`#SBATCH` CRITICAL was an option that no rule re-emitted, and nothing could have told you that
by reading — there is no place where "every option is decided by exactly once rule" is
expressible. As a sequence of named rules over a request, it becomes a test: enumerate the
registry, assert each entry is claimed by exactly one rule, fail on an option that is claimed
by none or by two.

That directly retires the shape of F13/F14/F24/F26/F27 and the `#SBATCH` outage, none of which
were quoting bugs and none of which F2 would catch either.

### Sequencing for the whole track

**After v0.5 ships.** The guard is hardware-verified at 91/0/0 on Balfrin and 92/0/1 on Santis
at `7505d67`, and the pen-test briefs were refreshed against exactly this code; refactoring now
discards that verification and sends reviewers at a ghost. F2 likely lands with or before 6a,
since both are "husk owns this layer rather than driving someone else's". F1 is cheap and
should not wait long after the release — it is the one step whose oracle expires.

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
