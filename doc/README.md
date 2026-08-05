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
             review-v0.5/ · slurm-broker/ · git log     L4  constantly

                            context.md           ⟂  orthogonal: where we are NOW
```

| | file | holds | edit when |
|---|---|---|---|
| **L1** | [PRINCIPLES.md](PRINCIPLES.md) | what would still be true if husk were rewritten for another scheduler in another language | a principle is contradicted, or a candidate earns its second instance |
| **L2** | [threat-model.md](threat-model.md) | the harm catalog (H1–H11), the compute-side attack vectors (AV1–AV8), what depends on a human | the architecture or the harm set changes |
| **L2** | [sandbox-interface.md](sandbox-interface.md) | the agent-agnostic contract — the acceptance criterion for wrapping something that is not Claude | ⚠ **stale**; rewrite before ROADMAP 6a |
| **L3** | [constraints.md](constraints.md) | every control, by enforcement surface: what it defends, what asserts it, which principle it serves | a control is added, changed, or removed |
| **L4** | [review-v0.5/](review-v0.5/), [../slurm-broker/](../slurm-broker/), the git log | findings, bringups, mechanism, fix rationale — append-only | continuously |
| **⟂** | [context.md](context.md) | current state, open gaps, what is in flight | every release, and whenever the state changes |

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
