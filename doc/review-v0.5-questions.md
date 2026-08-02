# husk v0.5 — the review question list

Working list. Each item is meant to be **falsifiable**: a reviewer should be able to come
back with "I tried, here is what happened", not with an opinion. Once this list is settled,
each item gets expanded into a full review request (scope, instrument, what evidence counts).

Grouped by **instrument**, not by topic — grouping by topic is what overscoped the first
attempt, because the same question then had to be asked three ways.

## Two passes: discovery, then triage

The v0.4 review ran as **propose-and-verify** and that is the shape to keep. Pass 1 produces
*candidate findings*; pass 2 **triages** them — confirm with a reproducer, or refute. The
reason this works is the **generator–verifier gap**: checking a specific claim is far cheaper
and more reliable than producing it, so the expensive pass can afford to be speculative.

Rules that made it work last time, and are not optional:

- **Triage is INDEPENDENT.** A fresh agent gets the claim and the repo, *not* the finder's
  reasoning. An agent handed its own argument agrees with itself; that is not a check.
- **Refuted is a real outcome, and it gets recorded.** `doc/broker-security-review.md` has a
  "What held up (refuted findings)" section. A refuted finding is evidence about the system.
- **Every finding carries a verdict**: `CONFIRMED` (reproducer exists), `REFUTED`, or
  `PLAUSIBLE` (argued but not reproduced — explicitly *not* the same as confirmed).
- **For workstream A, the reproducer should be a selftest arm.** We already turn each bug into
  an invariant test; doing it during triage means the pipeline is candidate →
  confirmed-with-arm → fix, and the arm outlives the review and blocks the regression.

## Standing rules for every workstream

- **Falsification only.** "Try to break X" beats "assess X".
- **Execution inside, verdict outside.** A caged agent may run the attempt; the verdict comes
  from the selftest, the broker log, or a human. Otherwise it is the confined party attesting
  to its own containment.
- **Exercise error paths, do not audit them.** Both cleanup bugs we found were found by
  *doing* — looking at the directory afterwards, sending the signal — not by reading code.
- ≤4 concurrent agents, MAX account, **sequential** rather than wide fan-out.

---

## A — assumed-breach penetration test
*Offensive, in-cage on Balfrin. The biggest share.*

The sharpest single instruction: **hunt any value the agent supplies that becomes a boundary,
or the base for one.**

- **A1.** The write-root / `cwd` / `settings.json` family. *First*, because a selftest arm
  already found a real hole here (`b4879f0`): the cage's write root came from agent-supplied
  `req.cwd`, so the confined side was supplying its own boundary.
- **A2.** `req.env`, forwarded into rank cages. Unexamined.
- **A3.** The job-script body, forwarded whole into slurmd's parser. Unexamined.
- **A4.** The step spool — a new agent-writable trust seam.
- **A5.** The full chain: `sbatch → broker → srun → broker → ranks`.
- **A6.** The parser's newest features: the multi-partition list, and `scancel` (a second
  mutating verb, gated on provenance rather than permission).
- **A7.** *(added 2026-08-02)* **Does any teaching message disclose something the cage
  otherwise withholds?** We announce the writable set, name resolved paths, and list this
  session's job ids in the scancel refusal. Belief: all are obtainable by trying anyway. A
  message revealing a path outside the cage, or a job the agent did not submit, is a real
  finding.
- **A8.** *(added 2026-08-02)* **Can a teaching message be turned into a tool?** An agent
  learning the exact writable roots learns where to aim. Ask the reviewer to *falsify*
  "announcing costs nothing" — not to agree with it.
- **A9.** The network allowlist: the differential between host/SNI matching and what the
  proxy actually dials.

## B — control-coverage review
*Defensive, code-only, laptop. Owns the **trusted** side, which an in-cage reviewer cannot
exercise and will otherwise assume is covered.*

- **B1.** *(added 2026-08-02)* **Resource lifecycle — RAII mapped onto the OS.** Every
  resource acquired must have a named owner and a release on *every* exit path. Place each in
  one of three tiers: (1) cooperative release — `Drop`, a shell `trap` — correct on clean
  paths and worthless under SIGKILL; (2) kernel-coupled lifetime — `PDEATHSIG`, a pidns dying
  with its PID 1, cgroup teardown — the tier to prefer; (3) a reaper, ownership-gated.
  Inventory to start from: both spools, the userns holder, the pidns holder child, socat
  relays (job + per rank), the netproxy, the step-broker, the ns file descriptors handed to
  bwrap, the egress socket, the broker request socket, in-cage bind mounts, and **the
  submitted SLURM job itself**. **Ask for the tier-1-only list — that list is the finding.**
- **B2.** *(added 2026-08-02)* **Is any denial path unattributed?** Mechanical and complete:
  enumerate every refusal in the code and check each emits husk-attributable output meeting
  the six properties below.
- **B3.** Mount-table construction — the actual enforcement boundary.
- **B4.** The holder and the shared namespaces, including the CMA concession.
- **B5.** Guard-script generation in `policy.rs`. Also wanted: a verdict on whether this file
  is **auditable**, which is the evidence that would justify the deferred typed builder.
- **B6.** The SINK × channel matrix — is any cell still unproven?

## C — Anthropic-substitution gap analysis
*Narrow, one agent, code-only. The crux is **plumbing**, not security.*

- **C1.** What is the real remaining delta now that the PID-namespace half is closed? Believed
  to be fs telemetry (a feature) plus login plumbing.
- **C2.** If husk owns the sandbox, the login-side agent's own egress to its API becomes
  husk's problem. Pin the shape of that early.
- **C3.** The 6a acceptance test: does the string `claude` appear anywhere except one row of
  the binary/config/hosts table?

---

## The six properties a teaching message must have

Used by A7/A8 and B2. Each earned from an observed failure or success, not from taste.

1. **Actionable in one step** — names the constraint *and* the remedy.
2. **Attributed** — says *who* denies. 22 `EROFS` lines mentioning husk zero times produced
   confident, wrong remediation.
3. **Believable** — must not appear to contradict what the agent can observe. "Only `short` is
   permitted" while `sinfo` shows `normal` idle made the agent suspect a spoofed message.
4. **Stable** — byte-identical on retry. That is what made it read as standing policy rather
   than transient failure; the caged agent said so explicitly.
5. **Consequence-bearing** — states what the rule *costs*, not just the rule.
6. **Correctly scoped** — never claims a cause it cannot know. SIGTERM means preemption *or*
   wall limit *or* scancel, so the message says "ended early".

## Deliberately out of scope

- **"Is a sandbox the right answer / is this useful / should the community adopt it."** An
  agent gives a fluent answer with no evidential basis. These are questions for CSCS and
  MeteoSwiss engineers, and a working two-cluster demo makes that conversation cheap.
- **Generalisation** (AMD/Intel, InfiniBand) — a literature task, not a review.
- **Usability — do not review it, MEASURE it.** An agent that does not know husk exists, given
  a real task, is the instrument that produced the two sharpest reports so far.
- **Whether the teaching messages *work*** — same reason: measurable, not reviewable.
