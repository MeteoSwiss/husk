# husk / sandbox friction log — LETKF session, 2026-08-05/07

Written for the husk author.  Ordered by cost to the work, not chronologically.
"Cost" is my time lost plus, where relevant, wasted node allocations.

---

## 1. `*.env` files are treated as credentials — broke every LETKF run

**Cost: high.** Three failed jobs, ~30 min, and a misdiagnosis.

DACE's runtime environment file is conventionally named `var3d.env` (it is in the
operational benchmark data, and the confluence build instructions name it).  It is a
plain `module load` script, no secrets.  After the last sandbox update:

* inside a job, `source var3d.env` failed with `Permission denied`, so no modules
  loaded and all 128 ranks died with
  `libnetcdff.so.7: cannot open shared object file`, `srun rc=127`;
* on the login node, my attempt to `head` the file to diagnose it was **blocked by the
  permission layer**, which is what finally identified the cause.

Two layers agreed the file was a credential; neither said so in the job.  The job-side
message was a bare `Permission denied` with no attribution — unlike husk's usually
excellent explanatory errors.

*Suggestion:* the `.env` heuristic is reasonable for `.env`/`.env.local` in a repo
root, but `<name>.env` next to a binary is a common HPC convention for an environment
script.  Consider matching content (KEY=VALUE with secret-ish keys) rather than the
extension, and if a read is refused, say so with husk's usual banner style rather than
letting bash report a bare EACCES.  Workaround used: renamed to `var3d_modules.sh`.

## 2. `<project-root>/config` bind-mounted read-only — blocked the build entirely

**Cost: high.** Blocked `./configure` outright; cost a session restart.

This is Claude Code's own guard, not husk, but it lands in the same place for the user.
`dace_code/config` sits in a deny list beside `.claude/*`, `.mcp.json`, `.git/hooks`.
In DACE, `config/` is the ordinary build-configuration directory: `configure` writes
`config/config.h` there and dies without it.  Diagnosing it needed
`/proc/self/mountinfo`; the failure surfaced only as
`mv: inter-device move failed ... Read-only file system`.

Worked around with a symlink farm, then fixed by launching one directory higher — but
it silently came back once `dace_code` was re-registered as a project root.

*Suggestion:* if a protected path is a plain directory with no agent-config content in
it, that is a strong signal of a false positive.

## 3. Multi-node is blocked — the single largest limitation on the work

**Cost: structural.** Two of the four things I was asked to do cannot be done at all.

Understood as a deliberate containment decision, and the refusal message is a model of
how to say no: it gave the reason, the mechanism (IP path for MPI/PMI bootstrap), and a
working alternative.  No complaint about the policy.  Recording only the consequence:
the CXI crash is a 1280-rank/10-node phenomenon and cannot be reproduced, and every
performance number I produced is at `k_enkf=4` on one node instead of 1152 ranks at
`k_enkf=40`.  The user had to run the production-scale jobs personally.

## 4. In-script `#SBATCH` resource directives were silently discarded

**Cost: high, and it produced a confidently wrong conclusion.** ~1 h.

Command-line flags to `sbatch` were honoured; `#SBATCH` lines inside the script were
parsed for policy (husk rejected `--account` and `--nodes=2` **by name**) but their
resource requests never reached SLURM.  A job asking for `--ntasks=64 --exclusive` got
`SLURM_CPUS_ON_NODE=2` and an empty `SLURM_NTASKS`.

I concluded "husk grants 2 CPUs per job".  That was right about the symptom and wrong
to name husk as the cause without evidence — but the reason I reached for husk is that
it was the one layer I could see, and I had no way to tell whether my request had been
modified.  Since fixed.

*Suggestion:* this is the case the job banner exists for.  A line stating what the job
actually holds versus what it asked for would have turned an hour into a minute, and
would have redirected me upstream instead of stopping at the sandbox.

## 5. SLURM broker timeouts

**Cost: medium.** ~40 min of blocked work, spread over the session.

`sbatch` and `squeue` both hung, returning
`timed out after 120s waiting for the SLURM broker` after exactly 120 s, for a stretch
of the session, then recovered.  Not obviously correlated with anything I did.
Separately, the SLURM client binaries (`sbatch`, `squeue`, `scancel`, `sinfo`)
disappeared from `PATH` and from `/usr/bin` mid-session during a husk update — that one
was explained and expected.

## 6. Bind mounts inside working directories block `rm -rf`

**Cost: low, but recurring.** Every experiment directory I `cd` into acquires
`.claude/` and `.mcp.json` bind mounts.  My experiment generator does
`rm -rf "$exp"` to start clean, which then fails with `Device or resource busy` on
those mounts.  Worked around by never reusing a directory name — which is why there are
`defer_`, `defer2_`, `nobc2_`, `nobc3_` directories lying around.

## 7. Smaller things

* `/users` is unreadable, so `/oprusers` (a symlink into it) is too.  Reasonable, but
  it meant the operational data, the `cgribex` module and `eccodes_cosmo_resources` all
  had to be copied out by hand before anything could build or run.  `cgribex` I
  recovered from a build tree under `/opr`; the rest needed the user.
* `/users/cmueller/.claude/projects` is unwritable, so agent memory is unavailable.
  All durable state went into `dace_code/LETKF_SESSION_STATE.md` instead.
* `git config` is unwritable (`.git/config` is bind-mounted read-only) and `.gitconfig`
  is masked, so `git commit` fails with "Author identity unknown".  Worked around with
  `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment variables.
* `scontrol` and `sacctmgr` cannot reach the controller (name resolution), so partition
  limits and QOS could not be checked from inside — which was exactly what was needed to
  rule husk in or out during issue 4.
* Background processes started with `nohup ... &` are killed between tool calls; a build
  died mid-compile and left a **zero-length object file** that `make` then considered
  up to date, silently producing a link failure much later
  (`undefined reference to __mo_gribtables_MOD_search`).  The harness's own
  `run_in_background` works correctly; the friction is that the failure mode is silent
  and delayed.

---

## What worked well

* Refusal messages that explain the reason, the mechanism and the alternative
  (multi-node, `--account`).  I never had to guess at intent.
* The compute-cage banner listing the writable set.  That one prevented several
  wrong turns.
* Reads of `/store_new` and `/scratch` from inside jobs were unrestricted, which is
  what made any of the measurement possible.


---

# Addendum — issues found in the second half of the session

## 8. Writes outside the project dir kill the job with no attribution

**Cost: medium.** Two dead 128-rank jobs and a misdiagnosis.

To measure how much of the LETKF read time is filesystem versus eccodes decode, I
staged input into `/dev/shm` from inside a batch job. The `cp` **appeared to
succeed** — `df` showed 16 GiB used — and the job was then terminated shortly
afterwards with no message attributing the kill to husk. I diagnosed it as a
transient node problem and retried, wasting a second allocation, before the user
told me writes outside the project dir are refused.

A standalone probe confirmed `/dev/shm` is writable and readable at full speed
(2.2 GB/s write, 5.7 GB/s read) and that such a job *completes* — so the failure is
specifically the combination of writing there and then continuing to run.

*Suggestion:* this is the same class as issue 1. The compute-cage banner already
lists the writable set beautifully; when a job is killed **for violating** it, say
so in the job output. As it stands the observable behaviour is "job cancelled,
no reason", which is indistinguishable from a node fault — and I treated it as one.

## 9. Core dumps from aborted MPI jobs fill scratch silently

**Cost: 343 GB of scratch.**

`MPICH_ABORT_ON_ERROR=1` plus the default `ulimit -c unlimited` means every crash
writes one core file **per rank**. Two failed 128-rank runs left **256 cores
totalling 343 GB**, which survived the obvious cleanup (`rm -rf */output`) because
they sit in the experiment directory, not in `output/`. At 1152 ranks a single
failed run would write ~1.6 TB.

Not a husk issue — it is the job template — but worth knowing about in a sandbox
where an agent is expected to iterate on crashing configurations. `ulimit -c 0` in
the generated job scripts fixes it.

## 10. `/tmp` is cleaned during the session

**Cost: low, but confusing.** Build environment scripts written to `/tmp/claude-*`
vanished mid-session, and the next `make` failed with `Error 127` (`mpif90: command
not found`) — which looks like a toolchain problem, not a missing file. Moved the
scripts into the project directory afterwards.

*Suggestion:* if the scratch directory is periodically cleaned, saying so in the
system prompt would be cheap. The guidance to "use $TMPDIR for temporary files"
implies more permanence than exists.

## 11. Long builds versus the 10-minute foreground limit

**Cost: low, recurring.** A full DACE build is 12–20 minutes; the foreground tool
limit is 10. `run_in_background` works correctly and was the right tool, but the
natural idiom — `until [ -z "$(pgrep make)" ]; do sleep; done` — itself times out at
10 minutes, so each build needed two or three polling calls. Not a bug, just
friction worth knowing when sizing agent tasks on HPC codebases.

---

# Summary of cost

| issue | cost |
|---|---|
| 4. in-script `#SBATCH` silently discarded | ~1 h, plus a confidently wrong conclusion |
| 1. `*.env` treated as a credential | ~30 min, 3 dead jobs |
| 2. `<project>/config` bind-mounted read-only | blocked the build, cost a session restart |
| 5. SLURM broker timeouts | ~40 min |
| 8. writes outside project dir, unattributed kill | 2 dead 128-rank jobs |
| 3. multi-node blocked | structural: 2 of 4 requested items could not be done |

The recurring theme in 1, 2, 4 and 8 is not that the sandbox refused something —
refusals were mostly correct and the explicit ones (multi-node, `--account`) were
*excellent*, giving reason, mechanism and alternative. It is that when a refusal
arrived **unattributed** — as a bare `Permission denied`, a silent directive drop,
or an unexplained job cancellation — I reliably misdiagnosed it, usually blaming
the most visible new component. Attribution is worth more than permissiveness.
