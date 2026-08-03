# A2 — `req.env`, forwarded into rank cages

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

> **Refreshed 2026-08-03, after the v0.5 fixes.** The environment path itself is UNCHANGED —
> `env_args`, the reserved prefixes, the name grammar and the bound are all as they were, so
> everything below about them still holds. What changed is the rank cage they land in, and one
> NEW instance of this brief's own theme arrived with Fix 1. Both are marked ★ below.

## The question

The job script's environment is carried into rank cages. Can the agent put something in it
that changes what a rank *is*, rather than what it merely *knows*?

## Why this is on the list

Flagged as one of two unexamined candidates when the review plan was drawn. Nothing has tested
it. It qualifies under the workstream's organising instruction — **any value the agent supplies
that becomes a boundary, or the base for one** — because an environment variable can select a
loader, a library path, or a runtime's own security branch.

## What the code does today

`rank::env_args` computes the **delta** between the job script's environment and what the ranks
already inherit: added or modified names become `--setenv`, removed names become `--unsetenv`.
Both directions, because a half-carried environment differs silently from the job's.

Three existing defences to probe rather than re-derive:

- **`RESERVED_ENV_PREFIXES`** — `SLURM_*` and friends are refused, because `SLURM_EXPORT_ENV`
  would redirect propagation and others contradict the validated `--ntasks`.
- **`is_valid_env_name`** — POSIX name grammar, enforced rather than assumed.
- **`MAX_FORWARDED_ENV = 512`** — a bound, so an environment cannot become an enormous command
  line in the trusted process.

Two design decisions that are load-bearing, and worth attacking directly:

1. **Applied through bwrap, not through srun's environment.** A brokered `srun` runs `sh` and
   `bwrap` as the user *before any cage exists*, so an `LD_PRELOAD` in that environment would
   execute in the trusted process. bwrap applies `--setenv` to the process it launches — inside
   the cage. Test whether that separation actually holds on every path.
2. **bwrap applies arguments in order**, so a `--setenv` after a credential `--unsetenv`
   re-sets it. The credential mask and the forwarded delta therefore interact. **Ordering is
   the control here** — try to invert it.

## ★ New since this brief was written

Three changes to the surface, none of which touched `env_args` itself:

- **★ The rank cage now builds a MUNGE mask at runtime, in POSIX sh, and expands it
  UNQUOTED.** `rank.rs` emits a loop that reads `/run/munge` and `/var/run/munge`, resolves
  each with `readlink -f`, and accumulates `_m="$_m --tmpfs $_r"` — then puts bare `$_m` on
  the bwrap command line, where it is word-split. That is deliberate (dash has no arrays) and
  it is guarded by refusing any resolved path containing whitespace. **It is also the exact
  shape this brief exists to attack**: a value assembled at runtime and expanded unquoted into
  a trusted command line. The inputs are compile-time constants and a `readlink`, so the
  question is whether anything can influence what `readlink -f` returns for those two paths on
  a compute node — a symlink, a bind, a mount the job can make.
- **★ `job_args` now travel INSIDE the guard**, not on sbatch's command line. Fix 1 removed the
  script operand (husk submits on stdin), so the agent's argv for its own script is emitted as
  a `sh_quote`d `set -- '...' '...'` line in the generated script. Agent-controlled bytes,
  quoted by husk, into a shell script that the guard's **uncaged first instance also parses**.
  Parsing is not executing — but a quoting break there is a syntax error at best and code
  execution outside the cage at worst. `sh_quote` is the whole boundary. Attack it: quotes,
  newlines, `NUL`, backslashes, `$(...)`, `!`, unbalanced quotes, very long values,
  non-UTF-8. (Overlaps A5; flag it, do not chase the chain.)
- **`--die-with-parent`** is now on both cages, and the rank `/dev/shm` ownership check is
  symlink-safe (`-L` before `-O`). Neither is an env question, but both changed what a rank
  can leave behind, so do not read old behaviour from an old run.

## Starting points

1. Names that survive the grammar and the prefix list but change execution:
   `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PATH`, `PYTHONPATH`, `PERL5LIB`,
   `BASH_ENV`, `ENV`, `IFS`, `SHELL`, `TMPDIR`.
2. A name that collides with the credential mask — can a forwarded value re-set a variable the
   cage `--unsetenv`s? Order matters; find out which side wins.
3. Values (not names) containing quotes, newlines, `NUL`, `=`, or shell metacharacters.
4. Names differing only by case, or by Unicode that normalises onto a reserved prefix.
5. The `MAX_FORWARDED_ENV` boundary: what happens at 511, 512, 513 — refusal, or silent
   truncation? **Silent truncation would be the finding**, because a dropped `--unsetenv`
   leaves a variable set that the job removed.
6. `PROXY_ENV` — the proxy variables are set for the agent's benefit; can they be overridden to
   point the rank's traffic somewhere else?

## What counts as a finding

- Any environment variable that reaches the **trusted** process (guard, `sh`, `bwrap`,
  step-broker) rather than the caged one.
- A credential the mask removes and the delta restores.
- A forwarded value that changes which binary or library a rank executes.
- Silent truncation or silent dropping at any bound.
- A reserved prefix that can be smuggled past the check.

## What a null result looks like

An enumeration of what was tried — the names, the values, the boundary cases — and what each
produced. A table of "sent X, rank saw Y, trusted process saw Z" is exactly the useful shape.

## Out of scope for this item

- The job script *body* itself (A3) and the step request path (A5).
- Whether credential masking covers the right variables by default (that is a policy question,
  not an escape).
- Attacking `bwrap`'s own `--setenv` implementation.

## Verdict

Execution inside; verdict outside. The decisive evidence is what the **trusted** side saw — the
broker log, an emitted argv, or a marker file written outside the cage — not what the rank
reports about itself.
