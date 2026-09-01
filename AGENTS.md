# AGENTS.md — working on husk

## What husk is

husk wraps an AI coding agent on a shared HPC login node. The confiner is **outside** the
confined process: a launcher (`husk-slurm-wrapper`) sets up namespaces, binds a stub over
`sbatch`, and only then execs the agent; a trusted broker running outside every cage holds
MUNGE and the network and validates each SLURM request as hostile input. **The agent never
decides whether it is caged, and its cooperation is never required.** The axiom is
`doc/sandbox-interface.md §1`; `README.md` is the user-facing view.

You are probably running *inside* husk while working on it. `skill/SKILL.md` — installed to
`~/.claude/skills/husk/` — explains what that costs you.

## Where to look

Documentation is organised by **rate of change**, not by topic. `doc/README.md` defines the
stack and the membership tests; read it before adding a document.

| | file | answers |
|---|---|---|
| **L1** | `doc/PRINCIPLES.md` | why a control has the shape it has. Cite `P<n>` instead of restating |
| **L2** | `doc/threat-model.md` | harms H1–H11, compute vectors AV1–AV8, what depends on a human |
| **L2** | `doc/sandbox-interface.md` | the agent-agnostic contract: provided / must-tolerate / not-required |
| **L3** | `doc/constraints.md` | every control by enforcement surface, what asserts it, which principle |
| **L3** | `doc/agent-profile-claude-code.md` | the agent husk wraps: tool surface, state dirs, host-side vs caged split |
| **L4** | `doc/srt-watch.md`, `slurm-broker/*.md`, the git log | mechanism, bring-up, fix rationale |
| **⟂** | `doc/context.md` | where the work stands right now (moves every release) |

**L4 is only half here, deliberately.** The finding-by-finding record — review rounds,
bring-up transcripts, friction logs — lives in a private repository, because it was written
against a specific production cluster and carries its operational detail. Documents in this
tree cite paths like `W-KNOWN-ISSUES.md`; those are pointers into that record, **not missing
files**. Do not go looking for them and do not recreate them.

Broker design: `slurm-broker/BROKER.md` (pipeline + policy), `PROTOCOL.md` (wire format,
spool layout, the invariants marked *do not regress*), `THREAT-MODEL.md` (compute-job model),
`CAGE-PROFILES.md` (login-vs-compute divergence), `BRINGUP.md` (hardware runbook).

## The tree

- `slurm-broker/broker/src/` — the trusted side, Rust. `sbatch.rs`/`srun.rs` are the option
  **registries**; `policy.rs` is every decision; `settings.rs` resolves the FS policy into a
  bwrap profile; `spool.rs` is the request lifecycle; `step.rs`/`rank.rs` are the compute-node
  step-broker and per-rank cage; `netallow.rs`/`netproxy.rs` are the egress allowlist and the
  `CONNECT`-only proxy; `cage.rs` holds the shared user namespace; `profile.rs` picks topology.
- `slurm-broker/broker/src/bin/husk-slurm-wrapper.rs` — the fail-closed launcher, and `mod witness`.
- `slurm-broker/{sbatch,srun}-stub.py` — the in-cage stubs. They carry no policy.
- `seccomp-wrapper/` — the C syscall filter and its probes. `install-husk.sh`, `make-release.sh`,
  `scripts/merge-claude-settings.py`, `skill/`.

## Invariants — do not break these

1. **The confined side supplies neither its own boundary nor its own record** (`P2`). The write
   root is the directory husk was launched from, captured before the agent ran — never
   `req.cwd`. Readiness is a byte on a descriptor created before the agent existed, never a
   file in a directory the agent can write.
2. **Construct what is allowed; never forward agent bytes** (`P4`, `P5`). The broker does not
   pass options to slurmd's parser — it parses, validates, re-emits canonically, rejects the
   unrecognised. A new option is a registry entry, not a special case. A denylist is a bug list.
3. **Put the control in the layer that can enforce it** (`P6`). Every acquired resource gets an
   owner and a release on *every* path. Shell may sequence; it must not decide.
4. **A value meaning "a check passed" must not be constructible where the check is not**
   (`P17`). In Rust: a private field in a module its consumers are outside of, exposing only
   `establish`. Where there is no type system: a channel the other side cannot write. Tests get
   a constructor whose *name* says validation was skipped, never a struct literal.
5. **A control names a target; check the name resolves to the object you meant** (`P15`). The
   evidence must be about the **object**, not the control. "The entry is in the list" is not
   evidence; `grep /proc/self/mountinfo` is.
6. **A fail-closed control's failure mode is a denial of service aimed at the operator**
   (`P16`). Every fail-closed change answers: *what does this newly refuse, and who can trigger
   it* — the agent, the operator, the site environment, or a nested husk? State the number a
   real submission produces against any bound you add. Measure; do not argue.
7. **Validation is not enforcement** (`P3`). If the subject can change between check and use,
   move the question to the moment of use.
8. **A control that can fail silently has already failed** (`P7`); **announce what husk changed,
   not only what it refused** (`P13`). husk is the only layer the agent can see, so it is blamed
   for everything it does not explain.

## Build and test

There is **no CI**. Nothing runs these for you except `make-release.sh`, which gates only Rust.

```sh
# Rust — from the crate dir: the vendored-source config is slurm-broker/broker/.cargo/
(cd slurm-broker/broker && cargo test --offline --no-fail-fast)

# seccomp-wrapper: dev check, then the release build that produces the arch-tagged binary
make -C seccomp-wrapper check
(cd seccomp-wrapper && ./build_and_test.sh)      # -> seccomp-wrapper-<arch>
(cd slurm-broker && ./build-release.sh)          # -> husk-slurm-{broker,wrapper}-<arch>

# shell suites — each runs anywhere: no cluster, no broker, nothing installed
./install-husk.test.sh          ./make-release.test.sh
./scripts/merge-claude-settings.test.sh          ./slurm-broker/selftest.test.sh
./slurm-broker/sbatch-stub.test.sh               ./slurm-broker/srun-stub.test.sh
./slurm-broker/slurmd-differential.test.sh

./skill/build.sh --check        # the skill's option table is GENERATED from the registry

# hardware
./slurm-broker/selftest.sh                       # policy tier, safe anywhere
./slurm-broker/selftest.sh --full                # submits real jobs; exit 3 = arms unmeasured
./slurm-broker/husk-verify.sh                    # from INSIDE a live session: does the cage hold
```

`--no-fail-fast` is the convention: plain `cargo test` stops at the first failing **binary**
and hides the rest of the suite.

**Two tests fail for environmental reasons on a dev laptop. Do not "fix" them.**
`netproxy::tests::the_allowlist_gates_real_connections` needs a bindable AF_UNIX socket;
`policy::tests::guard_stays_quiet_and_transparent_for_an_ordinary_failure` needs a writable
`~/.husk/log`. Both pass on the clusters. Everything else must be green.

## Rules of the road

- **A fix ships with a test pinned at the bug's level, and removing the fix is the acceptance
  criterion** (`P9`). A test one layer above the defect proves the layer, not the defect.
- **Write down what your harness substitutes** (`P10`). A green suite is necessary, never
  sufficient; the real-workload run is the verdict.
- **A security change gets an adversarial review before it is committed** — including
  one-liners. Verify by mutation, not by reading.
- **Generated content is regenerated, never hand-edited.** `skill/SKILL.md`'s option table comes
  from `husk-slurm-broker --print-option-contract`. Two statements of one contract drift (`P8`).
- **Cite, do not restate.** A paragraph of *why* in a code comment means you are re-deriving an
  L1 principle — find it and cite `P<n>`.
- **Read every doc claim as something to falsify** (`P12`); never edit an L4 record to match
  the present.

## What husk does not do — do not claim otherwise

- **Multi-node MPI is REFUSED, not contained and not shipped.** `Profile::select` rejects any
  `--nodes` other than `1` and says so; there is one variant, `SingleNode`, pinned by
  `multi_node_is_rejected_not_downgraded`. `ROADMAP.md` Track D *decided* to one day ship a
  named weaker profile, and real containment is v0.7 — neither exists yet. The docs have drifted
  toward the decision before; check the code.
- **`apply-seccomp` is telemetry, not enforcement** — it fails open and is login-side only. It
  is stacked, not relied on.
- **The compute cage is a subset of the login cage.** Its credential auto-scan uses a built-in
  pattern set, not your `Read()` deny globs. The invariant is narrower than parity: no
  escape-relevant capability on compute that login denies (`CAGE-PROFILES.md`).
- **husk does not own the login cage** — Anthropic's runtime does, so its settings are a
  *request* and the boundary is the observed *effect*. Test it; never infer it. A
  `sandbox-runtime/` tree in the working copy is a reference copy, **not the code that runs**.
- **The agent has no file tools under husk.** Only wrapped Bash enters the cage, so `Read`,
  `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` are denied and the agent uses shell equivalents.
- Interactive `srun`/`salloc` and read-only `scontrol show`/`sacctmgr list` are not brokered.
