# A6 — the newest parser surface

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `A-RULES-OF-ENGAGEMENT.md`

## The question

Two pieces of parser surface landed after the review plan was written and have never been
attacked. Can the multi-partition list be widened, or `scancel`'s provenance gate be bypassed?

## Why this is on the list

Not because anything is suspected, but because **they are the newest code on the submission
surface and nobody has decided they need reviewing.** Every critical the v0.4 review found was
on this surface, and both features change a control that the threat model describes in the
singular: the partition row said "force exact partition", and `scancel` adds a second mutating
verb where there was one.

> **Refreshed 2026-08-03, after the v0.5 fixes.** The partition list and `scancel` are
> unchanged and everything below about them holds. But the surface this brief covers —
> "the newest thing on the submission path" — has grown a great deal since it was written:
> `--qos` and `--reservation` are now REJECTED, the read-only verbs gained a per-verb option
> allowlist, and the whole `#SBATCH` channel to slurmd closed. Those are the newest features
> now, so they belong here. Marked ★.

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

★ **New surface since this brief was written — this is where the newest code is:**

- **`--qos` and `--reservation` are `Class::Rejected`**, on the CLI *and* in the body. They
  were `Allowed` — agent-chosen and re-emitted — while the threat model claimed the family was
  forced. Both move the resource envelope out from under the partition, which is the control
  that carries it. **The refusal is new code on the hottest path**, and finding them exposed a
  second gap: the body gate had four registry classes and distinguished two, so a `Rejected`
  option in a `#SBATCH` line fell into the catch-all and was accepted. That is fixed; the
  question for you is whether the *fourth* class is now handled everywhere the other three are.
- **The read-only verbs have a per-verb option allowlist** (`policy::query_spec`), 147 entries
  across six verbs, values charset-checked with **no slash**, re-emitted canonically as
  `--long=value`. Before this they forwarded the agent's entire argv into another SLURM binary
  running **outside the cage with the human's full filesystem view** — `sacct --completion
  --file=X` reads X, `--batch-script` prints any job's stored script. This is the largest piece
  of brand-new parsing in the release and it deserves the most attention in this brief.
  The tables were checked against SchedMD's man pages for 23.02.7 and verified on both clusters
  by `query.parity`, so do not hunt for *missing* options — hunt for **the arity and
  canonicalisation logic**: an option on both lists, a value that survives the charset and
  still means a path, a short form whose long form is wrong, `--opt=` with an empty value,
  an option repeated, a value containing a space (allowed, for format strings).
- **No streaming options, on any verb.** `-i/--iterate` was removed after it hung a selftest:
  the protocol is request/response, so an endless stream has nowhere to go, and the broker is
  single-threaded so it would sit there until the watchdog fired — with `scancel` queued
  behind it. **Look for another option with that property**, on any verb, that the table still
  allows.
- **`run_sbatch` now has a watchdog** and its own process group, like `run_query_cmd`. A hung
  submission used to wedge the broker, `scancel` included.

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

10. ★★ **The read-only twin: what can this agent learn about its neighbours, and does husk
    intend that?** Measured 2026-08-07, from inside a husk session on Balfrin — `squeue` with
    no arguments returned the whole cluster:

    ```
    5039893     debug interact alexeedm  R    15:08  1  nid001117
    5038531    normal LM.icon_    mslel  R  2:41:37  5  nid[001033,001036-001037,...]
    5039905  postproc LM.letkf mlbadaou  R     6:29  4  nid[001231-001234]
    ```

    Five other users: job names, partitions, states, runtimes and **node assignments**.

    That is SLURM's default and it is the same view the human has, so it is not privilege
    escalation — and it is exactly why nobody looked at it. But **`scancel` in this same brief
    is narrowed by provenance to jobs this session submitted**, so the principle that the
    agent gets *less* than its user is already established here. It was simply never applied
    to the read-only verbs.

    The shape is the familiar one: **the query allowlist vetted 147 options and never asked
    about the default output scope.** A gate on the arguments, with the unargued case passing
    through untouched.

    What to establish:
    - **What is reachable.** Enumerate what an agent can learn about other users through the
      brokered read-only verbs — `squeue`, `sacct`, `sinfo`, and the format strings (`-o`,
      `--format`) which can request fields the default view does not show. `sacct` is the
      interesting one: it reaches *historical* jobs, so the window may be much larger than
      "what is running now".
    - **Whether it composes into targeting.** Node assignments plus timing is what you would
      want before a co-tenancy attempt, and this project has already found one real cross-user
      break of exactly that kind (the `/dev/shm` ownership race, `916880b`). Can an agent
      determine *which node* a named user is on, and *when* it will still be there?
    - **What a format string reaches.** `-o` accepts a charset that includes `%`; establish
      whether any field exposes something the default columns do not — a working directory, a
      command line, an account, a comment.

    **A null result is a real deliverable here**, and possibly the likeliest one: "an agent
    sees exactly what any cluster user sees, and here is the enumeration" turns an
    undeliberated default into a recorded decision. That is worth as much as a finding,
    because the asymmetry with `scancel` is currently an accident.

    Out of scope: actually disturbing another user's work. Read, enumerate, report — the rules
    of engagement apply with full force, and this is the brief most likely to tempt past them.

## What counts as a finding

- A job accepted onto a partition outside the configured set.
- More than one partition value reaching slurmd, so the scheduler picks.
- Any job cancelled that this session did not submit.
- A way to add an id to the `submitted` set other than by submitting.
- Partial cancellation of a mixed batch.
- Anything about another user reachable through the read-only verbs that is **not** in the
  default `squeue` view — a format field, a `sacct` history window, a path or command line.
- A demonstrated targeting chain: a named user resolved to a node, with timing.

## What a null result looks like

The spelling and grammar tables — what was tried, what husk did — for both features. These are
small, closeable surfaces; a complete enumeration is achievable here in a way it is not for the
body (A3), so **aim for completeness rather than depth.**

## Out of scope for this item

- Whether the *resource envelope* is the right control (that is a design decision, documented).
- Whether QOS limits are set correctly at the site — operator configuration, not husk.
- **NOT the read-only verbs — those are now IN scope and are the biggest new thing here.**
  (An earlier version of this brief dismissed them as "they mutate nothing"; that was written
  before they had a parser of their own, and it was wrong even then — a read-only verb reads,
  and it reads outside the cage as you.)
- Re-deriving which options each SLURM version has. The tables are checked against SchedMD's
  versioned man pages and confirmed by `query.parity` on 23.02.7 and 25.05.4. Attack the
  logic, not the list.

## Verdict

Execution inside; verdict from the broker log and from `sacct`/`scontrol`. For `scancel`,
**never test against a job this review did not submit** — submit your own targets, including
the "unowned" ones, from a second session. The rules of engagement are binding here in
particular: cancelling someone's production run is the exact harm the gate exists to prevent.
