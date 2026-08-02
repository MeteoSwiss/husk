# A3 — the job-script body, forwarded whole

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

## The question

The agent authors the job script body and husk forwards it **verbatim** into slurmd's parser.
What can be put in it that husk's parser does not see the same way slurmd does?

## Why this is on the list

The second of the two unexamined candidates, and the higher-consequence one — because this is
the exact shape of the worst bugs the v0.4 review found.

**Two of the five criticals lived here.** `F24` — a `#SBATCH --export` line turned the cage
off. `F26` — a `#SBATCH --uenv` line mounted the agent's filesystem as root. Both were the
same underlying defect: **husk secured its model of sbatch, not sbatch.**

It is also a deliberate, documented seam. husk gates `#SBATCH` directives with its own parser
but forwards the body verbatim, so **two parsers read the same bytes**. That is a
parser-differential by construction. The question is whether the gate is complete.

## What the code does today

- husk parses the body for `#SBATCH` directives and **rejects unknown ones** — default-deny,
  not a strip list.
- Security-relevant options are **emitted by husk on the command line**, which outranks
  `#SBATCH` under sbatch's precedence (command line > environment > `#SBATCH`). The intent is
  **domination**, not removal.
- `#BB` / `#DW` burst-buffer directives are rejected outright.
- The body is staged as a guarded script; `--wrap` is stripped so only the staged script runs
  (`F27`).

`sbatch.directive_parity` exists precisely for this seam: it asks the *site's own Slurm* which
`#SBATCH` spellings it honours, and fails if slurmd honours one husk's parser cannot see.

## Starting points

1. **Spelling differentials.** `#SBATCH` with leading whitespace, tabs, `\r\n`, a form feed,
   `#!SBATCH`, `# SBATCH`, mixed case, a UTF-8 BOM, a NUL byte, or the directive on a
   continuation line. `directive_parity` covers a set — find one it does not.
2. **Where the scan stops.** sbatch stops reading directives at the first non-comment line.
   Does husk stop at the same place? A directive *after* husk stops scanning but *before*
   slurmd stops is a live hole.
3. **Domination, not absence.** For each security-relevant option, put it in the body and
   confirm husk's CLI value wins — including when the body sets it twice, or sets it to the
   same value, or sets a synonym (`-o` vs `--output`, `-p` vs `--partition`).
4. Directives that are neither in the allowlist nor obviously dangerous: `--dependency`,
   `--signal`, `--array`, `--licenses`, `--reservation`, `--prolog`, `--epilog`, `--container`,
   `--mail-user`. Which are rejected, and which pass through unexamined?
5. The body is also **shell**. It runs inside the cage, so shell tricks are expected and fine —
   the question is only whether any of it escapes the cage or influences the *trusted* guard.

## What counts as a finding

- Any `#SBATCH` spelling slurmd honours and husk's parser does not see. (`F13`/`F14` were
  glued short options; the class is not closed until parity is demonstrated, not argued.)
- A directive that changes what code runs, where output lands, what is mounted, or what
  environment the job inherits, despite husk's CLI value.
- A body construct that influences the **guard** rather than the payload.
- A directive husk rejects but that slurmd would have ignored anyway (a false rejection —
  worth knowing, low severity).

## What a null result looks like

The enumeration of spellings and directives tried, each with what husk did and what slurmd did.
Where they agree, say so. **This brief's value is largely in the negative result** — a
demonstrated parity across a wide spelling set is exactly the evidence the two-parser seam
needs, and it is directly convertible into selftest arms.

## Out of scope for this item

- The `--wrap` path (covered, `F27`) except as a comparison.
- The step request body (A5).
- Attacking slurmd itself, or anything requiring privileges we do not have.

## Verdict

The site's own Slurm is the oracle, not the documentation and not our reading of it. Evidence
is a submitted job (held, if it would otherwise run) plus `scontrol show job` /
`sacct` showing what slurmd actually recorded.
