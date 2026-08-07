# husk 0.4.0 — friction log

Recorded live while doing real work (ICON KENDA-CH1 startup optimisation) on balfrin,
2026-08-07. Ordered roughly by how much time each cost me. "Harness" = Claude Code
itself, not husk — included because from inside it is one environment and you may want
to know which is which.

---

## 1. Background processes are killed when the tool call returns  [cost: one wasted build]

I started the ICON build with `cd <build> && nohup bash -lc '...' > log 2>&1 &`, saw it
start correctly, and the tool call returned. Three minutes later the build was dead:
no processes, no file activity, log frozen mid-`depgen`. `nohup` did not save it.

I had to restart it via the harness's own `run_in_background: true`, which worked.

**Impact:** ~5 min lost, plus a stale binary I nearly measured. On a machine where a
build is the long pole, silently losing one is expensive.

**Suggestion:** if husk can detect a session-leader kill of detached children, warn.
Otherwise this is worth one line in the husk docs: *"detached background jobs do not
survive a tool call; use the harness's background mechanism."* (Possibly a harness issue
rather than husk — but it bites hardest here because the workloads are long.)

---

## 2. `sbatch --parsable` is not honoured by the broker  [cost: a bungled first run]

My run driver used `sbatch --parsable` and captured the output as a job id. The broker
always prints `Submitted batch job N` regardless, so `JID` became the whole sentence,
`squeue -j "$JID"` errored, my wait loop exited instantly, and the driver "finished"
while the job was still running. I only noticed because the reported state was `RUNNING`
at 0:02 in the same output as "completed".

**Suggestion:** either honour `--parsable` (emit just the id) or reject it explicitly so
it fails loudly. Silently ignoring a flag whose entire purpose is machine-readable
output is the worst of the three options. This one is a genuine trap for any automation
layer, not just an LLM.

---

## 3. `squeue -u $USER` does not show the user's own externally-launched jobs

Christoph told me he was running two compile jobs. `squeue -u $USER` showed nothing, and
`ps` shows only my own handful of processes (PID namespace). So I had no way to see
whether the builds were running, progressing, or dead. I ended up inferring build
liveness from `find -newermt '-3 minutes' | wc -l` on the build tree, which worked but is
obviously a hack.

Later this mattered a second time: I needed to know whether it was safe to start my own
build in the same directory without colliding with his.

**Suggestion:** consider surfacing the user's real jobs read-only (`squeue` visibility
without `scancel` rights). Not being able to see the state of the machine you share with
your operator is a real handicap; the risk of *reading* the queue seems low.

---

## 4. Memory directory is not writable from Bash  [cost: findings not persisted]

`/users/cmueller/.claude/projects/.../memory/` is in the harness's write allowlist but
`/users` is in husk's read-deny list, so writing memory files from Bash fails with
`Read-only file system`. I had three durable findings to record and could not.

I worked around it by writing `FINDINGS_session2.md` into the project instead — arguably
better for this user anyway — but the memory mechanism was simply unavailable.

**Suggestion:** carve `~/.claude/projects/*/memory/` out of the `/users` deny rule, the
same way `/users/cmueller/.claude` is already carved out for other paths.

---

## 5. Submission is confined to the project directory  [cost: ~1 min; good error]

`sbatch` from `$TMPDIR` was rejected:

> husk: the directory this job was submitted from: "/tmp/claude-27069/probe" is not
> inside any directory this job may write. husk confines --chdir/--output/--error to the
> writable set, because SLURM writes those files as you and OUTSIDE the sandbox.

**This is the best error message in the system** — it says what was blocked, why, and
what the writable set is. It cost me one retry and taught me the rule permanently. More
of husk's refusals should read like this. Not a complaint; a template.

The one thing it does not say is that the *scratchpad* the harness hands me
(`$TMPDIR`) is outside that set, which is mildly surprising given the harness tells me to
prefer `$TMPDIR` for temporary files. The two pieces of guidance conflict.

---

## 6. Environment does not fully propagate through `--export=ALL,VAR=val`  [unresolved]

I submitted with `--export=ALL,iau_keep_gpu=.true.,ICON_REPORT_AFFINITY=1`.
`iau_keep_gpu` reached the namelist (verified: `iau_iter_keep_gpu_state = .true.`), but
`ICON_REPORT_AFFINITY` never reached the wrapper — zero `affinity` lines in a 1.9 MB log,
where the wrapper only needs `[[ -n "${ICON_REPORT_AFFINITY:-}" ]]`.

I could not determine whether the broker rewrites `--export`, or whether something in
ICON's runscript sanitises the environment. Flagging it because if husk *does* filter
`--export`, that is worth documenting — env-var-driven switches are the normal way to
A/B a scientific code without touching tracked files.

---

## 7. Cannot read husk's own session log

`HUSK_SESSION_LOG=/users/cmueller/.husk/log/husk-...log` is advertised in the
environment, but `/users/cmueller/.husk/` is unreadable from inside. Pointing at a file
I cannot open is a small papercut; either drop the variable or make it readable.

---

## 8. No network breaks from-scratch builds  [cost: one failed build, ~20 min]

A clean rebuild re-runs ICON's DACE `FetchContent` step, which clones
`git@gitlab.dkrz.de:dwd-sw/dace-icon-interface.git`. The sandbox allows only
`opendatadocs.meteoswiss.ch:443`, so configure aborted with
`configuration of externals/dace/fetch failed`. The underlying git error
("Connection closed", "Could not read from remote repository") does not mention the sandbox,
so it reads like a credentials problem rather than a policy one.

Worked around without network: another build directory happened to hold a checkout of the
exact required commit, so git was pointed at it with
`url.<local path>.insteadOf <remote>` via `GIT_CONFIG_GLOBAL` (`~/.gitconfig` is a device
node here, so it cannot be edited). Fine as a one-off, but it only worked by luck — had that
checkout not existed, a from-scratch build would have been impossible inside the sandbox.

**On the access question.** Christoph notes the current choice is all-of-GitHub or none, and
that GitHub is full of prompt-injection bait. That is a fair reason to keep it closed, and
I would not argue for blanket access. Two narrower options would unblock this specific case
with far less exposure:

- **Host allowlist rather than all-or-nothing.** What a build actually needs here is
  `gitlab.dkrz.de` (and whatever the spack mirror uses) — internal, curated hosts, not
  GitHub. If the sandbox can take an allowlist of hosts the way it already takes an
  allowlist of writable directories, that covers builds without opening GitHub at all.
- **Pre-populated sources.** If dependencies were fetched once outside the sandbox into a
  known location, builds inside would never need the network. This is roughly what the
  accidental workaround above did.

Worth noting the threat model differs between the two: cloning a pinned commit from an
internal GitLab is a much smaller injection surface than fetching arbitrary GitHub content,
since the content is fixed by hash and is not read as instructions.

## 9. Unmapped GID in file ACLs silently breaks `spack install`  [cost: two from-scratch builds]

**This is the highest-value item in this log** — it is subtle, it fails late, and the error
message points nowhere near the cause.

Every file in the project carries a POSIX ACL entry for group **4294967295**
(`0xFFFFFFFF`, i.e. `(gid_t)-1` — an *unmapped* group):

```
$ getfacl -p icon-nwp/src/shared/mo_timer.f90
group::r-x
group:4294967295:r-x      <-- unmapped
$ id
uid=27069(cmueller) gid=30382(s83) groups=30382(s83),65534(nobody)
```

Outside the sandbox the user is presumably in a group that is not mapped into the agent's
user namespace, so it surfaces as `(gid_t)-1`.

### The chain

1. `shutil.copystat` copies extended attributes, including `system.posix_acl_access`.
2. Setting that ACL on a new file fails, because the blob contains the unmapped group:
   `os.setxattr(dst, "system.posix_acl_access", ...)` -> **EINVAL (22)**.
   `setfacl` fails independently for the same reason:
   *"Malformed access ACL ... Duplicate entries at entry 4"*.
3. Python's `shutil._copyxattr` tolerates `ENOTSUP`/`EACCES`/`ENODATA` but **not `EINVAL`**,
   so the exception propagates.
4. `spack install` dies copying its package repo into the install prefix:
   `OSError: [Errno 22] Invalid argument: .../cosmo-eccodes-definitions/package.py`.
5. `config/cscs/spack_install` runs under `set -e`, so it never reaches its final step,
   `create_sh_env`.
6. `create_sh_env` is what writes `<build>/setting`, which the ICON runscript sources.
7. So `ECCODES_DEFINITION_PATH` is never exported, the COSMO GRIB definitions are not found,
   and the model dies at runtime with something that looks completely unrelated:
   `mo_util_cdi::get_cdi_varID: Variable RAD_PRECIP not found!`

Incremental builds hid this for a long time, because `setting` survived from an older
successful build. It only appeared once the build directory was wiped — and then it cost two
full from-scratch builds to track down, because the symptom is a missing GRIB variable.

### Fix

Map the group properly in the sandbox, so file ACLs contain valid GIDs. Failing that,
present files without the unmapped ACL entry.

**Workaround in the meantime:** run `create_sh_env` by hand after every from-scratch build:

```bash
cd icon-nwp && ./config/cscs/create_sh_env mch_gpu_mixed "$PWD/mch_gpu_mixed"
```

(`user.*` xattrs also fail here, with `ENOTSUP` — that is just Lustre without `user_xattr`
and is harmless, since `copystat` tolerates it.)

## What worked well

- `sbatch`/`squeue`/`sacct`/`scancel` behaved exactly like the real thing otherwise. I
  submitted 7 jobs (probes, baselines) and never thought about the broker except where
  noted above. That is the right outcome for a MITM layer.
- Partition confinement via `HUSK_SLURM_PARTITION` was discoverable from the environment,
  and `--partition=short` on the command line cleanly overrode the runscript's hardcoded
  `#SBATCH --partition=normal`. I never had to edit a tracked file to get a job to run.
- Nothing ever silently *corrupted* state. Every failure was a refusal, not damage — which
  is the property that actually matters when an agent is driving.
- One node with 4 GPUs was sufficient to reproduce production geometry exactly, so the
  sandbox never limited the science.

## Suggested priority

0. **(9) the unmapped GID in ACLs** — silently breaks any from-scratch spack build, and the
   symptom appears at model runtime as a missing GRIB variable. Worst cost-to-diagnose ratio
   in this list by a wide margin.
1. (2) `--parsable` — silent flag-dropping breaks automation, cheap to fix.
2. (1) background-process lifetime — expensive when builds are the long pole.
3. (3) read-only visibility of the user's own jobs.
4. (8) a **host allowlist** for the network, so from-scratch builds work without opening
   GitHub wholesale.
5. (6) clarify `--export` handling.
6. (4) memory-dir carve-out, (7) session log readability — papercuts.
