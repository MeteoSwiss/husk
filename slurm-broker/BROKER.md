# husk SLURM broker — design & policy

The broker is the **trusted, out-of-sandbox** half of the SLURM gateway. It runs
on the login node in the user's normal context (MUNGE + network + the Mode-1
uenv session available), watches the [spool](PROTOCOL.md), and turns an agent's
intercepted `sbatch` into a safe, re-sandboxed submission. The in-sandbox
[`sbatch-stub.py`](sbatch-stub.py) is dumb plumbing; **all policy lives here.**

Language: **Rust** (it parses adversary-controlled `req-*.json` across a
privilege boundary — memory-safe, strict, typed hostile-input parsing is the job).
Ships as a dual-arch compiled binary like `seccomp-wrapper` (x86_64 + aarch64).

Scope: **`sbatch`** (batch submission) plus **read-only queries** — `squeue`,
`sinfo`, `sacct`, `sstat`, `sprio`, `sreport`, `sshare` (Tier 1; the allowlist
lives in [`src/lib.rs`](broker/src/lib.rs) as the single source of truth).
Standalone interactive `srun`/`salloc` are denied for now (they need a
live-stream/PTY proxy; out of scope). State-changing verbs (`scancel`,
`scontrol update`, `sacctmgr`, …) are denied — a verb-gated Tier 2 is deferred
(see the roadmap). **`srun` used *inside* a brokered job is not yet contained:** it
launches steps via slurmd that run *outside* the batch script's re-sandbox cage.
Wrapping those steps (a compute-node broker = the recursive sandbox-broker pair) is
the next roadmap step — `srun`/MPI, then compute-node network (socat). Today's
single-node scope assumes the job does its work directly, not via `srun`.

## Pipeline

```
spool/req-*.json  ─►  parse (serde, bounded)  ─►  validate (hostile input)
   ─►  force-safe + build real sbatch argv  ─►  submit (or --dry-run)
   ─►  spool/resp-*.json  ─►  stub mirrors sbatch to the agent
```

A read-only query takes the same spool path but skips force-safe/submit: the
tool name is checked against the Tier-1 allowlist, the command runs as an argv
array, and its captured stdout/stderr/exit-code come back in the response
(output capped at 1 MiB). See [Read-only queries](#read-only-queries--tier-1).

Treat every field of the request as hostile. Build the real `sbatch` invocation
as an **argv array**, never a shell string. Fail closed: any validation or
submission error becomes a `rejected`/`error` response, never a silent pass.

## Policy

### Partition — reject and teach (no silent rewrite)
Only **one** partition is permitted, and the broker both requires the agent to
request it and forces it on the real CLI. The partition is **site-configurable**
via `HUSK_SLURM_PARTITION` in the broker's trusted env (operator-set,
agent-inaccessible), defaulting to `preemptible`. It is NOT hard-coded: Balfrin has
`preemptible`; Santis does not (use `debug` or `shared`), so submitting there with
the default fails at sbatch (`invalid partition "preemptible"`). Pick a
low-priority/preemptible partition — every brokered job lands on it.

`HUSK_SLURM_PARTITION` is a **comma-separated list**, because a cluster is not
homogeneous: on Balfrin `short` is the GPU partition and `pp-short` the CPU-only
postprocessing one, and a workflow legitimately needs both. Which one a job needs is
a hardware fact only the job knows, so husk bounds the **set** and the job picks from
it.

Resolve the effective partition from the agent's CLI args (`-p`/`--partition`) and
`#SBATCH` directives. Then:
- resolves to one of the allowed partitions → accept, and **re-emit husk's own copy of
  that entry** — the agent influences the value, the bytes that reach `sbatch` are
  ours. Same construct-and-re-emit shape as `--chdir`, which is confined to the
  writable set rather than forced to a constant.
- names several at once (`--partition=a,b`, which real `sbatch` accepts and lets the
  scheduler resolve) → **reject**: that would make the hardware choice implicit again,
  and the wall-limit note describes one partition.
- anything else, **or unspecified** → **reject** with a message naming every allowed
  partition (so it learns the constraint and can reason about preemption).

#### How that refusal is worded, and why

A caged agent hit this guard on 2026-08-01 and reported back. Three properties came
out of it, all now pinned by tests:

1. **Say authorization, not availability.** The message used to read *"Only
   `--partition=short` is permitted here"*. The agent checked `sinfo`, saw `normal`
   up with 28 idle nodes, and read the contradiction as a possibly **spoofed**
   message — spending calls corroborating before it would act. It now names husk as
   the restricting party and concedes that other partitions exist and may be idle.
   A guardrail that appears to make a false claim about the world invites the reader
   to disbelieve it.
2. **Be byte-identical on retry.** The agent's own account: the repeat is what let
   it conclude *"standing policy"* rather than *"transient failure"* — an
   intermittent-looking gate "would likely have gotten a blind retry instead". So
   nothing volatile (timestamps, queue depth, set iteration order) may enter it.
3. **Teach the consequence, not just the rule.** The old message taught the
   partition rule but not what it costs. The agent's job silently inherited a
   30-minute wall limit and it only found out from `squeue` afterwards — harmless at
   7 minutes, fatal for a longer run. husk moves jobs onto a partition their author
   did not choose, so it is the right place to say what that partition does to an
   untimed job.

That third point applies to the **accepted** path too, which is where it actually
bit: a submission with the right partition and no `--time` is accepted, and now
carries the limit note on stderr (stdout stays the bare `Submitted batch job N`
that tooling parses — the same split real `sbatch` uses).

The numbers come from `scontrol show partition` at broker startup, never from a
constant: they are site config and would rot. `DefaultTime` is what an untimed job
gets; `MaxTime` is what `sinfo`'s TIMELIMIT column shows, which is why reading
`sinfo` does not answer the question. A site QOS can lower both and husk cannot see
that from here, so the note says so and gives the advice that is right either way —
set `--time`. When `scontrol` cannot be read, husk says **nothing** about limits: a
confidently wrong number is worse than no number.

### Resources — pass through, do not manage
The broker does **not** parse/cap/forward `--nodes`/`--time`/etc. They reach
SLURM natively and are bounded by the required partition's own limits. This
is what lets the re-sandbox be a *prepended re-exec guard* in the agent's script
(below) rather than a broker-authored wrapper that would have to copy resource
directives. (Future, optional/DiD: a dedicated capped "bot" partition.)

### uenv — inherit the Mode-1 session
The agent does **not** choose the uenv. The broker captures the human-activated
session uenv from its **own** startup env (`UENV_LABEL`/`UENV_MOUNT_LIST`/
`UENV_VIEW` — trusted) and uses that for every submission.
- **Strip** agent-supplied `--uenv`/`--view`/`--repo` from the **CLI** (they're in
  the owned-family strip list). A `#SBATCH` directive or `SBATCH_UENV*` env var is
  **not** rewritten — the broker never edits the script body — but is instead
  **rejected fail-closed** (see reject-and-teach below): any `--repo`, or a
  `--uenv`/`--view` that differs from the session (or any when no session uenv is
  loaded), aborts the submission. Reject is stronger than strip for the dangerous
  cases, and avoids re-implementing sbatch's parser on the body.
- **Force** `--uenv=<session>` on the real submission (also satisfies uenv's rule
  that `sbatch`-from-a-session must name `--uenv` explicitly).
- **Force** a **normalized** `--view` (`uenvname:viewname`). `UENV_VIEW` is
  mount-qualified on current uenv (e.g. `/user-environment:icon:default`), which is
  NOT a valid `--view` argument — passing it verbatim made sbatch reject every job
  ("invalid view description"). The broker strips the leading `/mount-point:` field.
  This sets the job's `UENV_VIEW` *marker* to match the session; the live view PATH
  comes from `--export=ALL` (below), not from `--view`.
- If the agent explicitly asked for a **different** uenv → **reject + teach**
  (*"uenv is inherited from the launching session; you're running in `<X>` and
  can't change it"*) — same philosophy as partition, and it tells the agent which
  software stack it has.
- Security: because the value is the broker's trusted session env, the agent
  cannot make root (slurmstepd) mount an arbitrary squashfs via `UENV_MOUNT_LIST`.

### Export — inherit the trusted session (`--export=ALL`)
Force `--export=ALL` so the job inherits the broker's environment — which is the
human's **trusted** Mode-1 login session (the agent runs sandboxed and cannot taint
it; same basis as a no-uenv submission).

Verified on Balfrin (uenv 8.1) and Santis (uenv 10.0.1) with
`verify-uenv-passthrough.sh`: the uenv **mounts** under any export, but the **view
only activates** (PATH into `/user-environment`) under `--export=ALL`. The view PATH
is carried from the human's session; a locked env allowlist strips it — jobs mount
but can't find the software (`VIEW_ACTIVE=no` on both machines). So `--export=ALL` is
what makes brokered jobs actually usable.

Security: the exported env is trusted (the broker's, never the agent's), and the
compute-side re-sandbox `--unsetenv`s the configured credential env vars and
`--unshare-net`s the job. **AV7 caveat:** an env secret NOT listed in
`credentials.envVars` still reaches the caged (network-off) job — widen that list to
mask it.

(History: an earlier design forced a `UENV_*` allowlist; hardware showed it kills the
view, so it was dropped. `--uenv-passthrough=use` exists only on uenv v10+ — Santis
has it, Balfrin 8.1 does not — so the explicit `--uenv` + normalized `--view` +
`--export=ALL` path is the single uniform one that works across versions.)

### Dangerous options — force-safe on the real CLI
slurmd acts on these *outside* the job sandbox (e.g. `-o ~/.bashrc` makes slurmd
overwrite `.bashrc`). Force them on the real `sbatch` CLI, which outranks any
`#SBATCH` directive (CLI > env > directive):
- `--output`/`-o`, `--error`/`-e` → broker-controlled safe paths
- `--chdir`/`-D` → a safe working dir
- `--export` → `ALL` (see above), overriding any `--export=NONE` the agent set
- `--wrap` → stripped, so slurmd runs the staged guarded script rather than the
  agent's wrap string uncaged (F27)

### Options — allowlist, not passthrough (deny by construction)
The broker does **not** forward the agent's options; it **builds** the invocation from
an allowlist (`sbatch::REGISTRY`, the single source of truth). See THREAT-MODEL.md
"Design principle (the gate)".
- **Forced** families (partition/output/error/chdir/export/uenv/view/repo/wrap) → the
  broker emits its own; the agent's occurrence is dropped.
- **Ignored** (mail, `--parsable`, verbosity) → accepted, dropped.
- **Allowed** benign resource options (`--nodes`/`--ntasks`/`--time`/`--mem`/`--gpus`/
  `--constraint`/… ) → parsed, **validated against a per-option grammar** (charset +
  length bounds; no whitespace/newlines/shell metacharacters), and **re-emitted
  canonically** as `--long=value` (glued/short/`=` all normalise). `interpret_cli`.
- **Anything else** — unknown option, or an out-of-grammar value → **rejected**.
- **Body `#SBATCH` directives** (the body is never rewritten):
  - `--output`/`--error`/`--chdir`/`--export` are **accepted and ignored** — the broker
    forces all four on the real CLI, and sbatch precedence is *command line > env >
    `#SBATCH`*, so the directive is **dominated** and cannot take effect. Real run
    scripts (ICON and most others) always carry `#SBATCH --output=…`; rejecting them
    bought nothing. **Consequence for users: job stdout/stderr land in
    `<workdir>/slurm-%j.{out,err}`, not the path the script asked for.**
  - `--uenv`/`--view`/`--repo` are **rejected** — those are only *conditionally* forced
    (no session uenv ⇒ nothing to dominate them), so the reject is load-bearing (F26).
  - Unrecognised options and `#BB`/`#DW` burst-buffer lines are **rejected**.
  - Benign resource directives are accepted.

> **Known residual — job-output symlink swap.** slurmd opens the `--output` file
> *outside* the job sandbox, as you, and does not use `O_NOFOLLOW`. The forced path lives
> in the agent-writable workdir, so an agent that pre-creates
> `slurm-<guessed-jobid>.out` as a symlink can redirect job stdout into any file you can
> write. Submit-time checking cannot close it (the file is opened when the job starts —
> same TOCTOU shape as F20). Honouring an agent-*requested* output path would be no
> worse, and no better, which is the other reason the forced path is not a security
> boundary here. Mitigation is operational: treat the workdir as agent-controlled and
> don't keep anything you rely on at a predictable `slurm-*.out` path next to it.

So a spelling or channel we didn't enumerate (glued shorts, `#SBATCH`-only, `--wrap`,
next year's option) fails closed *by construction* — this retired the whole
F13/F14/F24/F26/F27 class rather than patching instances. Extending the allowlist as
real job scripts need it is an operator task; rejections surface as "unsupported option
X" (fail-closed + visible), never as a silent escape.

### Script — inline snapshot (TOCTOU)
The stub already snapshots the script **body** inline. The broker writes that
immutable snapshot to a broker-controlled path and submits *that* — never a path
the agent can rewrite between validation and slurmd reading it.

### Re-sandbox — prepended re-exec guard
The submitted job must run under `seccomp-wrapper + bwrap` on the compute node.
The broker injects a guard at the top of the snapshot that re-execs the script
inside the sandbox once (env-var `_HUSK_RESANDBOXED` guards against recursion),
keeping the agent's own `#SBATCH` resource directives intact and native. bwrap is
confirmed to run on Balfrin/Santis compute nodes, and the uenv
`/user-environment` mount inherits through the guard's `--ro-bind / /`.

### Compute-side cage — the re-sandbox profile
The bwrap profile the guard runs under is generated by
[`settings.rs`](broker/src/settings.rs) (`compute_bwrap_args`), from the same
`sandbox.filesystem` / `sandbox.credentials` policy the login sandbox uses,
unioned across the global / project / local settings layers. It is a Rust
reimplementation adapted from Anthropic's Linux model (read-default-allow /
write-default-deny), and its threat rationale (AV1–AV8) is in
[`THREAT-MODEL.md`](THREAT-MODEL.md). In brief the job gets:
- a read-only root (`--ro-bind / /`) with `/dev`, `/proc`, and fresh
  `--tmpfs` for `/tmp` and `/dev/shm`;
- **homes hidden** — `--tmpfs /users` (plus any `denyRead` paths), so the job
  cannot read other users' or your own home; the writable workdir is bind-mounted
  back in;
- **credentials masked** — configured credential files and a bounded, best-effort
  auto-scan of the workdir (`.env*`, `*.pem`, `*.key`, `*.p12`, `.pgpass`, `id_rsa`,
  …) `--ro-bind /dev/null`ed to empty, and secret env vars `--unsetenv`. The scan is
  depth- and entry-capped; if the entry cap is hit it warns to stderr (it is
  incomplete) — the authoritative masks are the explicit `sandbox.credentials.files`
  entries and the hidden-home floor, not the scan;
- **auto-exec paths masked** in every writable root, so a job can't plant a payload
  that fires on a later login-side action (AV2): a fresh `--tmpfs` over the whole
  `.claude` directory plus `.git/hooks`, `.vscode`, `.idea` — writes land in the tmpfs
  and are discarded — and a read-only bind for `.mcp.json`/`.git/config`, which must
  stay readable. Masking the *directory* is deliberate: it applies to paths that don't
  exist yet (a job could otherwise simply **create** `.claude/settings.local.json`) and
  it covers agent-config features upstream adds later, with no list to keep in sync;
- **GPU device binds** (`--dev-bind-try`) for the accelerators; and
- **network unshared** (`--unshare-net`) — this release runs compute jobs with no
  network (a compute-node allowlist is on the roadmap).

**Carve-out placement (operational rule).** A read/write carve-out
(`allowRead`/`allowWrite`) is symlink-checked at submit time (every path component,
not just the leaf), but the bind itself is frozen into the queued job and re-run
later on the compute node. That leaves a narrow queue-wait TOCTOU: if a carve-out
sits under an **agent-writable** parent, the agent could swap an intermediate
component to a symlink after submit and redirect the bind. The broker does not add a
compute-node re-check (that guard shell would run in agent-influenced space and
re-implement the check fragilely). Instead, **keep carve-outs off agent-writable
parents** — put shared read-only assets (models, datasets) on a path the job cannot
rewrite. Carve-outs under `/users` are dropped outright (the hidden-home floor).

### Read-only queries — Tier 1
`squeue`/`sinfo`/`sacct`/`sstat`/`sprio`/`sreport`/`sshare` are run **as-is** by
the broker on the agent's behalf — they change no scheduler state, so there is no
policy to enforce beyond the allowlist membership itself. Unlike `sbatch` these
are best-effort inside the sandbox: the stub shadows them if it can, and a query
that isn't shadowed simply fails closed (it cannot reach the scheduler), so a
missed shadow is a lost feature, never an escape. Anything not on the Tier-1
allowlist is rejected. Verb-gated read-only introspection (`scontrol show`,
`sacctmgr list`) is Tier 2, deferred.

## Open / verify-on-hardware
- Whether the export allowlist needs a minimal safe base beyond `UENV_*`.
- GPU device binds are a hardcoded NVIDIA list today; generalize to a runtime
  glob in the guard (login ≠ compute, so the broker can't enumerate at submit).
- Broker startup: created/launched by the outer wrapper, which also bind-mounts
  the stub over `sbatch` (and shadows the read-only tools), creates the spool, and
  exports `HUSK_SLURM_SPOOL`.
