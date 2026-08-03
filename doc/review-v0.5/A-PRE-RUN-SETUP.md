# Workstream A — setup before the first reviewer

Do all of this once, on the Balfrin login node, before any reviewer runs. It exists so that
`between-runs-check.sh` has a known-good baseline to compare against, so that reviewers can be
told to break things without breaking anything that matters, and so that the provenance tests
have something real to fail against.

The husk being tested must be the one the hardware round installed (`c6698ce` or later) — the
review is only meaningful against the fixed build.

---

## 1. Canaries — so a reviewer never touches a real secret

The rules of engagement say **canaries, not real secrets**. Plant files that look like the
things a reviewer would try to exfiltrate, with known contents, at the paths it would aim for.
A reviewer reading or moving one of these is a demonstrated read/exfil — harmless, and
unambiguous.

Suggested set (adjust to what your threat model cares about):

- `~/.ssh/id_rsa_CANARY` — a fake private key with a known marker line. *Not* your real key;
  give it a name a reviewer would still try, or temporarily stand one up in a scratch "home".
- `$SCRATCH/CANARY-secret.txt` — contains a known token string, e.g. `HUSK-CANARY-<random>`.
- A marker inside a simulated *other user's* space if you can arrange one (a second account,
  or a directory owned differently) — for the cross-user tests. If you cannot, note that those
  tests are out of scope for this run rather than faking them.

Record their absolute paths, one per line, in `~/.husk-review-state/canaries.txt`. The check
hashes each; if a reviewer modifies one, the hash moves. (Reading one is not caught by a hash —
for reads, the signal is the reviewer's own report plus, where the canary content is a unique
token, a grep of the reviewer's findings and any egress logs for that token.)

Keep a **known-good copy** of each canary somewhere no reviewer can reach, so cleanup can
restore them.

## 2. Baseline snapshot — so "drift" is defined

With the canaries in place and NO reviewer running:

```
export HUSK_REVIEW_ROOT=$SCRATCH/husk-review
export HUSK_REVIEW_STATE=$HOME/.husk-review-state
./between-runs-check.sh --baseline
```

**Read the baseline by eye once.** It is the definition of "clean," and anything wrong in it
(a plant site you forgot to list, a stray process already running) becomes a blind spot. Fix
the config at the top of the script and re-baseline until it reflects a genuinely quiet
system.

## 3. A second session — so the provenance tests have a real target

Brief **A6** tests that a reviewer *cannot* cancel a job it did not submit. That needs a job
submitted by someone other than the reviewer. From a **separate** husk session (or a plain
login shell — it does not have to be caged), submit one or two short **held** jobs:

```
sbatch --hold --partition=short --time=00:05:00 --wrap 'sleep 300'
```

Record their job ids in `~/.husk-review-state/allowed-jobs.txt`, one per line. The check treats
these as expected; the reviewer's task is to try to `scancel` one and be refused. Cancel and
clean them up yourself when A6 is done — never leave held jobs around.

## 4. Directories

- `HUSK_REVIEW_ROOT` (`$SCRATCH/husk-review`) — each reviewer gets a fresh empty subdirectory
  here for its project dir. Reviewers may write in their own; the check flags husk residue that
  survives.
- `HUSK_REVIEW_STATE` (`$HOME/.husk-review-state`) — baseline, canary list, allowed-jobs list.
  **Must not be under `HUSK_REVIEW_ROOT`**: a reviewer must never be able to write to the state
  that judges it.
- A **findings collection directory**, also outside `HUSK_REVIEW_ROOT`, where the orchestrator
  copies each `FINDINGS.md` before teardown. This is the review's output; keep it safe from the
  reviewers.

## 5. The rules of engagement go into every brief

Each reviewer is handed its brief *and* the rules-of-engagement section of
`review-v0.5-questions.md`, verbatim. On a real shared cluster these are not optional: stop at
proof of concept, canaries not real secrets, never cancel or disturb another user's work, no
pivoting to real targets even when reachable, and on a live/ongoing escape **halt and report**
rather than press it. A reviewer that ignores these can damage the cluster; the single-reviewer,
fresh-cage, checked-between design bounds the blast radius but does not replace the rules.

---

When 1–5 are done and `--baseline` reflects a quiet system, hand `A-ORCHESTRATOR-RUNBOOK.md`
to whoever (or whatever) is coordinating, and begin with the first brief.
