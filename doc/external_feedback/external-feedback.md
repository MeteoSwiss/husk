# External feedback — doc restructure for v0.5

> **Note added on merge:** principle numbers here have been remapped to the post-review
> numbering of `PRINCIPLES.md`, which gained P4 (control what executes) and P7 (a control
> that can fail silently) *as a result of this review*. Citations are to the current
> numbering, not the one the reviewer saw.

**What this is.** Notes from a third-party review session with a separate Claude
instance that had no prior context on husk, no write access to the repo, and no
hardware. Handed over so the working instance can act on it or argue with it.

**What it read.** `MeteoSwiss/husk`, branch `experimental`, at `396ae7b`
("The ICON outage: stop stat'ing the project dir…"), cloned fresh. Specifically:
`README.md`, `ROADMAP.md`, `doc/threat-model.txt`, `doc/constraints.txt`,
`doc/context.txt`, `doc/sandbox-interface.txt` (partial),
`slurm-broker/THREAT-MODEL.md`, `review-v0.5/SYNTHESIS.md`,
`review-v0.5/TRIAGE-SYNTHESIS.md`, `user-config/settings.json`,
`project-config/settings.json`, and the relevant parts of `install-husk.sh`. Plus
`principles.md`, supplied in the conversation rather than read from the tree.

**What it did NOT do.** No code read beyond filenames and the excerpts quoted in the
review docs — `settings.rs`, `sbatch.rs`, `policy.rs`, `rank.rs`, `netproxy.rs` were
never opened. No tests run. No hardware. **Every claim about mechanism below is
derived from your own documentation, so it inherits any error in it** — if a doc
overstated a control, this review propagated that overstatement.

---

## The ask, and the answer

*"Take a step back and rewrite `threat-model` / `constraints` / `context` for 0.5."*

The finding was that these are not stale so much as **wrongly shaped**. They were
written when husk was a settings.json plus a seccomp wrapper on a login node. It is
now five enforcement surfaces, most of them Rust, and the docs still organise around
the JSON.

Six structural problems identified:

1. **Two threat models, two taxonomies, no mapping.** `doc/threat-model.txt` (H1–H9)
   and `slurm-broker/THREAT-MODEL.md` (AV1–AV8) had both grown into real documents,
   with the broker one carrying the design principles, the sink matrix, and the
   load-bearing set. Nothing stated how H and AV relate. **Resolution: keep both,
   state the relation.** H is what the user loses; AV is how you get there on compute.
   A mapping table, not a merge.
2. **Three headline caveats were false.** The bash-vs-native-tool asymmetry (closed by
   `HUSK_TOOLS="Bash"` — the agent gets a tool *allowlist*, so `Read`/`Edit`/`Write`
   no longer exist to bypass bwrap); the SLURM-path escape (closed by the broker);
   and "SLURM does not work inside the sandbox" (now backwards). All three had been
   load-bearing caveats in H2/H7/H8 and in the gaps register.
3. **`context.txt` was doing three unrelated jobs** — repo map, config dump, gap
   register. The config dump had already drifted from the shipped file (missing
   `denyWrite`, the `network` block, and ~25 credential globs rendered as `...`).
4. **`constraints.txt` was organised by config file → key**, which hides that most
   enforcement moved into Rust. Reorganised by **enforcement surface**.
5. **The design axiom lived in `ROADMAP.md`.**
6. **Nothing carried review state.** A 102-candidate review returned "do not release
   as-is," six fix groups, and nine hardware residuals; the docs didn't know.

Two additions proposed and taken:

- **H10 and H11.** H10 = destruction of work in progress, *including other people's*
  — not the same harm as H4, and the reason `scancel` needs provenance rather than
  permission. H11 = silent truncation reported as completion — a harm **husk itself
  introduces** via the forced preemptible partition, and distinct from H9-out.
- **"What still depends on a human being right"** (threat-model §7). Post-`--tools
  Bash` the inattentive-user assumption barely load-bears. What's left is four items,
  and **two of them fail silently** (partition preemptibility; the preemption signal).
  That framing is what an operator actually needs.

---

## On `principles.md`

Assessment: it outranks two of the three files it sits above, and the four-level
scheme is a better spine than the flat peer arrangement originally proposed. Three
structural notes and one substantive disagreement.

### 1. `context.md` is orthogonal, not a fifth level

L1–L4 descend in abstraction; context descends in time. It sits *beside* the stack.
This gives a clean membership test — **if a line would still be true next release, it
is in the wrong file** — which has been written into `context.md`'s header.

### 2. The stack is a loop

L4 is where L1's entry bar is satisfied, and "Not yet earned" is the pipeline from L4
back to L1. Worth stating in `principles.md` itself: a reader who sees only the
descending arrow reads L1 as the authority and L4 as an appendix, which is backwards.
L1 has authority *because* L4 paid for it.

### 3. Disagreement: the axiom belongs in both places

The confiner-must-be-external axiom is listed under **Not yet earned**. By the stated
bar that is correct — no incident has tested it. But the bar asks *what did an
incident teach us*, and the axiom is not a lesson; it is a **premise**. It decided the
architecture before there was any evidence, and it is why husk wraps any agent rather
than trusting a runtime's sandbox.

**Proposed resolution, implemented in the drafts:** `threat-model.md §1` asserts it as
a design premise. `principles.md` keeps it under Not-yet-earned with a pointer saying
*this is not where its authority comes from — see threat-model §1; it is listed here
because it has not yet been tested by an incident, and that is a fact about our
evidence, not about its standing.* More interesting than either version alone.

Its three corollaries as originally drafted did **not** survive: "the confined side
never supplies its own boundary" is P2 verbatim, and "containment is a property of the
execution, not an artifact" is an instance of P3.

### 4. Promotion nomination — *a control that can fail silently has already failed*

Four instances, three subsystems, not covered by P3 (a race), P11 (attribution of a
refusal to the confined party), or P5:

- `unwrap_or(false)` swallowed the allowlist parse error at submit time — egress
  vanished with no report **to anyone**: not the agent, not the operator, not the log.
- A malformed settings file resolved to an empty policy, dropping every `denyRead` and
  credential mask.
- The guard's cleanup missed `net.sock`/`socat`/`net-proxy.log` and leaked every
  networked job's spool. P5's own text says it: *"silently, because the failure had no
  branch that reported it."*
- The partition's preemptibility is unverified and nothing fails loudly if untrue.
  Still open, and the reason H11 exists.

**The distinction from P11 is the audience.** P11 is about a refusal that reached a wrong
conclusion in the confined party's head. This is about a control that did not apply and
told *nobody*. The fix shape differs too: P11's is a better message, this one's is a
required branch.

### 5. A second instance for a promotion candidate

"Containment is a property of the execution, not an artifact" was treated as a P3
instance, but it has an independent second instance from the design record rather than
a finding: the shim-vs-broker decision — *a submitting shim is porous; keeping the real
binary outside is the only non-porous option*. Same shape, different subsystem. That
may warrant its own entry rather than folding into P3.

### 6. Three defects in the file as supplied

- **P10 has dropped text.** `"…while the suite was green. / husk session*. So no login
  cage is running…"` — orphan fragment with an unmatched closing `*`. A sentence is
  missing, probably *"the selftest never runs inside a real husk session."*
- **P5 ends with a duplicated line** — `"with the remedy in the message. / the
  message."`
- **P6's "Taught by" does not meet the file's own bar.** Every other entry names a
  concrete failure; P6 names mechanisms (`--die-with-parent`, `PDEATHSIG`, the
  holder). The incident is available and was measured: the holder outlived its parent
  on *every job* because a PID-namespace init discards `SIGTERM`, including one
  delivered by `PDEATHSIG`. Promote that to Taught-by, and the netproxy tunnel counter
  becomes a clean Caught-again.

---

## What the regenerated docs did

`constraints.md` lost roughly a third of its length, almost all of it rationale that
`principles.md` now owns. Duplicated rationale is exactly the drift P8 warns about.

Each control now carries a fourth field, `principle:`, beside `defends` / `weight` /
`asserted by`. The cuts:

| control | kept | deleted, cites instead |
|---|---|---|
| C3.1 construct-and-re-emit | `sbatch::REGISTRY`, `interpret_cli`, `Ignored` = *dominated* | the denylist argument → **P5** |
| C3.2 guard is the execution | wrapper-on-stdin, body-as-data | the three-masks narrative → **P3** |
| C4.1 trusted write root | `is_workdir_allowed` on the bind, normalise before floor compare | the reasoning → **P2** |
| C4.4 unit of confinement | `--userns`/`--pidns` mechanics, fail-closed joining, CMA scope | why one cage per job → **P1** |
| C4.5 lifecycle | `--die-with-parent`, SIGKILL-not-SIGTERM | RAII rationale → **P6** |
| C4.6 announce the boundary | banner contents, the three failure shapes, the two rejected approaches | why unattributed denials cost → **P11** |
| C5.2 policy outside | one proxy, one decision | → **P2** |
| prose-only section | the list | the five-false-friend-tests discussion → **P9/P10** |

`threat-model.md §1` shrank to the premise plus a pointer. Everything else in that
section was P2/P3.

Two controls were **added** to `constraints.md` that had no entry before, both drawn
from `principles.md` rather than from the old docs:

- **C6.2 broker log placement** — under `$HOME`, not the agent-writable spool, because
  the audited party must not be able to rewrite its own audit trail (`P2`).
- **C6.3 split the audience** — the confined party gets the teaching message, the
  operator gets the detail on a channel the confined party cannot read. This is the
  clean resolution of the A7-1 tension (P11 wants detail; the refusal was an existence
  oracle for `~/.ssh` present / `~/.gnupg` absent). It is listed as prose-only — no arm
  asserts that a refusal reaching the agent contains no host fact.

---

## Open items handed back

1. **The files are `.txt`, not `.md`.** Drafts are `.md`, since the content is already
   markdown and everything under `review-v0.5/` is. If the extension matters somewhere,
   `sandbox-interface.txt` cross-references these by name.
2. **`slurm-broker/THREAT-MODEL.md` should split.** It holds both the model and the
   design principles. The principles that generalise — construct-and-re-emit, reason
   about the sink, capture values not references, the unit of confinement — are now L1.
   What remains is compute mechanism and would read better as `slurm-broker/DESIGN.md`.
   The regenerated `threat-model.md` points into `slurm-broker/` for mechanism and no
   longer for rationale, so the split is already assumed by the cross-references.
3. **`sandbox-interface.txt` is now the stalest file in the repo.** It describes a
   v0.2/v0.3 contract and cites the old H-IDs against a model that has moved. It is
   also the acceptance criterion for ROADMAP 6b (*the string `claude` appears nowhere
   except one row of that table*), so it is worth rewriting before 6a rather than after.
4. **C3.4's preemptibility check has no home.** Nothing in husk verifies it, no test
   can, and the failure is silent. An install-time `scontrol show partition` warning is
   the natural place — same shape as the existing roadmap item to validate the
   partition at broker startup with `sinfo`, and could ride along with it. This is also
   instance #4 of the proposed silent-failure principle.
5. **Three docs still call clearing the holder's `PR_SET_DUMPABLE` a "cheap win."**
   Flagged in the review as a landmine (`cage.rs:89-97` is the correct one). Not fixed
   in these drafts — outside the three files in scope.
6. **`principles.md` was not regenerated.** The three defects in §6 above are left for
   the working instance, since it has the incident record and can pick the right
   wording for P6's Taught-by.

---

## Caveats on this review

- **It is documentation-derived.** Where a doc overstated a control, this review
  repeated the overstatement. The one place that is most likely to bite: statements
  about what `selftest.sh` asserts were taken from prose, not from the suite.
- **The "asserted by" fields are inferences.** Test names were read from review docs
  and commit messages, not verified against the suite. Treat every one as a claim to
  check — which is, per P9, the correct disposition for any test reference.
- **No judgement is offered on the apinfo residual**, which `slurm-broker/THREAT-MODEL.md`
  explicitly flags to reviewers for a build/don't-build decision. That needs someone
  who has read `rank.rs` and knows what the MPI bootstrap race would cost.
