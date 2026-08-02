# A6 — the newest parser surface: the partition list and `scancel`

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

## The question

Two pieces of parser surface landed after the review plan was written and have never been
attacked. Can the multi-partition list be widened, or `scancel`'s provenance gate be bypassed?

## Why this is on the list

Not because anything is suspected, but because **they are the newest code on the submission
surface and nobody has decided they need reviewing.** Every critical the v0.4 review found was
on this surface, and both features change a control that the threat model describes in the
singular: the partition row said "force exact partition", and `scancel` adds a second mutating
verb where there was one.

## What the code does today

**The partition list.** `HUSK_SLURM_PARTITION` may hold a comma-separated set (Balfrin: GPU
`short` plus CPU-only `pp-short`). `parse_partition_list` splits it; a job may request **any
member** and is refused otherwise. The value is still constructed and re-emitted by husk, never
forwarded from the agent. Refusal names the permitted set.

**`scancel`.** The gate is **provenance, not permission** — SLURM would happily let the user
cancel their own jobs, because the agent's jobs and the user's production jobs run under the
same uid. So the broker remembers the ids *it* submitted (`Broker.submitted`) and refuses
anything else. Three properties: any argument starting with `-` is refused outright (default-
deny, not a selector denylist); ids must match `<digits>[_<digits>|.<digits>]`, ≤20 digits;
and a multi-id request is **all-or-nothing**, so ownership cannot be probed by watching which
of a batch died.

## Starting points

**Partition list**
1. Spelling: glued (`-pshort`), `--partition=short,pp-short`, repeated `--partition`, trailing
   comma, empty element, whitespace, case differences, a member that is a prefix of another.
2. Does a *list* reach slurmd anywhere? Slurm itself accepts a comma-separated partition list
   and picks one — if husk ever emits more than one value, the scheduler chooses, not husk.
3. `#SBATCH --partition` and `SBATCH_PARTITION` against the forced CLI value (domination).
4. A partition name that is valid to husk but means something else to slurmd — an alias, a
   partition that is itself a superset, or one whose QOS grants more than the operator intended.

**`scancel`**
5. Id grammar edges: leading zeros, `+`, whitespace, 20 vs 21 digits, `4991406_`, `4991406.`,
   `4991406_3.0`, unicode digits, a very long array-task suffix.
6. Aliasing: can an id the broker owns be *decorated* into one it does not — or the reverse,
   an unowned base id smuggled as an array task of an owned one? `cancel_base_id` maps
   decorated ids back to the base; test that mapping in both directions.
7. Can the `submitted` set be **grown** — a request that causes the broker to record an id it
   did not actually submit, or to record one the agent chose?
8. The all-or-nothing property: confirm a mixed owned/unowned batch cancels **nothing**.
9. Does anything else in the system cancel jobs (cleanup, preemption handling, a trap)? A
   second cancellation path would not go through this gate.

## What counts as a finding

- A job accepted onto a partition outside the configured set.
- More than one partition value reaching slurmd, so the scheduler picks.
- Any job cancelled that this session did not submit.
- A way to add an id to the `submitted` set other than by submitting.
- Partial cancellation of a mixed batch.

## What a null result looks like

The spelling and grammar tables — what was tried, what husk did — for both features. These are
small, closeable surfaces; a complete enumeration is achievable here in a way it is not for the
body (A3), so **aim for completeness rather than depth.**

## Out of scope for this item

- Whether the *resource envelope* is the right control (that is a design decision, documented).
- Whether QOS limits are set correctly at the site — operator configuration, not husk.
- Other read-only verbs (`squeue`, `sinfo`, `sacct`): they mutate nothing. Note anything odd,
  do not spend time.

## Verdict

Execution inside; verdict from the broker log and from `sacct`/`scontrol`. For `scancel`,
**never test against a job this review did not submit** — submit your own targets, including
the "unowned" ones, from a second session. The rules of engagement are binding here in
particular: cancelling someone's production run is the exact harm the gate exists to prevent.
