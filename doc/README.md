# Documentation map

husk's documentation is organised by **rate of change**, which is also roughly abstraction.
The test for where something belongs is *how often would this line need editing?* — not what
it is about.

```
                          PRINCIPLES.md          L1  ~never
                               ↑ ↓
                         threat-model.md         L2  on architecture change
                        sandbox-interface.md
                               ↑ ↓
                          constraints.md         L3  on control change
                               ↑ ↓
        (internal findings) · slurm-broker/ · git log    L4  constantly

                            context.md           ⟂  orthogonal: where we are NOW
```

| | file | holds | edit when |
|---|---|---|---|
| **L1** | [PRINCIPLES.md](PRINCIPLES.md) | what would still be true if husk were rewritten for another scheduler in another language | a principle is contradicted, or a candidate earns its second instance |
| **L2** | [threat-model.md](threat-model.md) | the harm catalog (H1–H11), the compute-side attack vectors (AV1–AV8), what depends on a human | the architecture or the harm set changes |
| **L2** | [sandbox-interface.md](sandbox-interface.md) | the agent-agnostic contract: what husk provides, what an agent must TOLERATE, and what is deliberately not required | the axiom changes, or an integration finds a requirement the contract missed |
| **L3** | [agent-profile-claude-code.md](agent-profile-claude-code.md) | the one agent husk wraps, as `sandbox-interface.md §5` requires: its tool surface, state directory, egress, delegation, and which of its capabilities meet the cage at all. Also the specification 6a builds from | the agent changes, or an upgrade moves a measured assumption |
| **L3** | [constraints.md](constraints.md) | every control, by enforcement surface: what it defends, what asserts it, which principle it serves | a control is added, changed, or removed |
| **L4** | [srt-watch.md](srt-watch.md) | what changed in Anthropic's sandbox-runtime on each pull, and what husk learned or should check — cumulative, so a pull is not a re-derivation | every time the vendored tree is pulled |
| **L4** | [../slurm-broker/](../slurm-broker/), the git log — plus a finding record kept **internally** (see below) | findings, bringups, mechanism, fix rationale — append-only | continuously |
| **⟂** | [context.md](context.md) | current state, open gaps, what is in flight | every release, and whenever the state changes |

### Why L4 is only half here

The finding-by-finding record — review rounds, bring-up transcripts, friction logs — is kept in
a private repository and is **not** published. Those documents were written as working notes
against a specific production cluster and carry its operational detail: account names, host
names, filesystem layout, captured environments. That belongs to the site, not to husk.

Nothing about husk's design or its defects is being withheld: the principles, the threat model,
the controls and their rationale are all here, and the git log carries the fix reasoning. Where
a document below cites a path like `W-KNOWN-ISSUES.md`, that is a pointer into the internal
record, not a missing file.

## The two rules that keep it from rotting

**The stack is a loop.** L1 does not have authority because it is on top; it has authority
**because L4 paid for it**. Every principle names the incident that taught it and a second one
that confirmed it, and `PRINCIPLES.md`'s "Not yet earned" section is the pipeline running the
other way — candidates waiting for a second instance to arrive from below. Read the arrows in
both directions or L1 looks like opinion.

**Rationale lives in exactly one place.** A control in L3 says *what it does, what asserts it,
and which principle it serves* — and then stops, citing `P5` instead of restating the argument.
Duplicated rationale is the drift P8 warns about, and it is why `constraints.md` lost about a
third of its length when `PRINCIPLES.md` was written.

## Membership tests

- **`context.md`:** if a line would still be true next release, it is in the wrong file.
- **`PRINCIPLES.md`:** if you cannot name two distinct failures, it goes under "Not yet earned".
- **`constraints.md`:** if it explains *why* rather than *what*, it belongs in L1 with a citation.
- **L4:** never edit a finding to match the present. It is a record of what was true when it was
  written; the cross-references in `review-v0.5/findings/` still point at `.txt` filenames for
  that reason.

## Provenance

The L2/L3 rewrite came out of an [external review](external_feedback/external-feedback.md) by a
Claude instance with no prior context on husk, no repo access and no hardware — deliberately, for
fresh eyes. Its drafts are kept in `external_feedback/` next to the notes, so the merge can be
audited. Two things to know when reading them: every mechanism claim there is **derived from our
own documentation**, so it inherits any error we had; and its principle citations were written
against a numbering that this review itself changed (`PRINCIPLES.md` gained P4 and P7 as a
result), so they were remapped on merge. The identifier and test-name claims were checked against
the suite before landing — all held.
