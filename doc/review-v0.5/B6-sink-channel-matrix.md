# B6 — the SINK × channel matrix: is any cell unproven?

**Workstream B** (control-coverage) · **code-only, laptop** · **completeness is the point**

## The question

For every security-relevant decision **slurmd** makes, is every channel that can influence it
listed, and does husk's control actually dominate all of them?

## Why this is on the list

Every critical the v0.4 review found — F13, F14, F24, F26, F27 — was **the same bug wearing
different clothes: the broker secured its *model* of sbatch, not sbatch.** The exploit always
lived in the delta between the argument grammar husk parses and the one slurmd obeys.

The matrix exists because enumerating *inputs* is open-ended, while enumerating the
**decisions slurmd makes** is closeable. Three findings were visible holes in it before anyone
drew it: F24 = (code-runs × body/env), F27 = (code-runs × `--wrap`), F13 = (output-path ×
glued spelling).

The current matrix is in `THREAT-MODEL.md`, under *"Reason about the SINK, not the source"*.

## What the matrix says today

Rows: what code runs · stdout/stderr path · working dir · partition/account/qos · uenv/repo
mount · inherited env · node/resources · identity. Each row lists its channels, husk's control,
and what must dominate.

Two general rules underneath it:

1. **Never forward adversary bytes into a second parser.** Two parsers that can disagree is a
   parser-differential hole.
2. **A denylist is a bug list.** The submission surface must be default-deny: construct the
   invocation, force everything security-relevant, parse benign options into typed values and
   **re-emit them canonically**, reject anything unrecognised.

## What has changed since the matrix was drawn

Both need checking against it, and neither has been:

- **`scancel`** — a *second mutating verb*. The matrix covers submission only. `scancel`'s
  decision is "which jobs die", its channels are the argument list, and its control is
  provenance (`Broker.submitted`) rather than permission. Does it need a row, or is it a
  second matrix?
- **The multi-partition list** — the partition row said "force exact partition". It now forces
  *one of a set*. Confirm the row still describes the control.

## Starting points

1. For each existing row: is the channel list **complete**? Environment variables, `#SBATCH`
   directives, glued short spellings, stdin, the script body, and site config are the ones
   that have bitten us.
2. For each row: does husk's control **dominate**, or merely *usually win*? sbatch precedence
   is command line > environment > `#SBATCH`; a control that relies on the agent not setting
   something is not domination.
3. Any decision slurmd makes that has **no row at all**. Job arrays, dependencies, signals
   (`--signal`), mail, licences, reservations, `--prolog`/`--epilog`, `--container`.
4. The `Forced` / `Allowed` / `Ignored` / `Rejected` taxonomy in `sbatch::REGISTRY` — does
   every option's class match what the matrix claims for its row?

## What counts as a finding

- A cell that is unproven: a channel listed with no evidence the control beats it.
- A channel missing from a row.
- A **decision missing a row entirely** — the highest-value finding available here.
- An option whose registry class contradicts its row.
- A control that depends on the agent *not* doing something.

## What a null result looks like

The matrix, extended and re-verified, with each cell marked proven / unproven and the evidence
named (a test, an emitted argv, a doc line). New rows for `scancel` and any decision found
without one. **A completed matrix is the deliverable even if nothing is broken.**

## Out of scope for this item

- Exploiting anything found — hand it to workstream A.
- The step allowlist's own parser (that is its own surface; note overlaps, do not chase).
- Whether the resource *magnitudes* are safe. Shape is enforced here; magnitude is delegated
  to the partition and QOS by an explicit decision, documented under "The resource envelope".

## Verdict

Source and docs, but a cell is only "proven" if something demonstrates it: a test, a golden
argv, or a probe. **Prose in `THREAT-MODEL.md` asserting the control is not proof** — a test
satisfiable by prose tests nothing.
