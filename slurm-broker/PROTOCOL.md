# husk SLURM broker — request/response protocol (v1)

The agent never runs the real `sbatch`. Inside the sandbox a **stub** shadows
`sbatch` (bind-mounted over it by the outer wrapper — inheritance into claude's
inner bwrap is confirmed). The stub is a dumb serializer: it captures the
request, drops it in a **spool** directory, and waits for a response. A trusted
**broker** running *outside* the sandbox (where MUNGE + network work) picks the
request up, validates it, forces safe options, wraps the job in the compute-side
re-sandbox, and submits the real `sbatch`.

```
agent: sbatch job.sh
  │  stub (in sandbox)
  ▼
SPOOL/req-<uuid>.json ───►  broker (outside sandbox)
  ▲                           │ validate, force-safe, re-sandbox, real sbatch
SPOOL/resp-<uuid>.json ◄──────┘
  │  stub reads response, prints like sbatch, exits
  ▼
agent sees: "Submitted batch job 12345"
```

This file is the **wire contract** (the request/response schema). The broker's
*policy* — partition/uenv/export/force-safe rules — lives in [BROKER.md](BROKER.md).

Design seam: the schema, the broker's validate/submit logic, and the compute-side
wrapper are stable; only *how the stub is injected* and *how the spool is mounted
in* may be re-wired later (e.g. for `srun`/recursive brokering). Keep this versioned
(`version` field); bump on any incompatible change.

## Spool

- **Location:** a per-session subdir of the project directory,
  `./.husk-slurm-spool-<pid>/`. The stub finds it **only** via the
  `HUSK_SLURM_SPOOL` env var, set by the outer wrapper; there is deliberately no
  guess-the-path fallback, because a stale spool from an earlier session looks
  exactly like a live one and picking it up silently is how a dead session's
  project root gets read as the current one.

  It has to live in the project directory: the stub runs *inside* the cage, and
  the project directory is the one place the sandbox makes writable. That is a
  constraint, not a preference, and everything below follows from it.
- **Files:** `req-<uuid>.json` (stub → broker), `resp-<uuid>.json`
  (broker → stub). `<uuid>` pairs a response to its request. `owner` records the
  pid, start time, project dir and husk version of the session using the spool.
- **Atomicity:** every file is written to `.<name>.tmp` in the same directory
  and then `rename()`d into place, so a reader never sees a partial file.
- **Lifecycle (per request):** the stub owns its pair — it deletes both `req-`
  and `resp-` after reading the response. There is no staged `job-<id>.sh` any
  more: husk's script goes to `sbatch` on **stdin**, so it is never a file and
  never has a path (a path in an agent-writable spool was a TOCTOU the review won
  33 times in 100). What *is* staged is the AGENT's own script, as data, at
  `<write-root>/.husk-body-<id>.sh`; it must outlive submission because the job
  reads it, so its owner is the guard, which removes it on every exit path. If a
  submission fails, no job will ever read it and the broker removes it instead.
  A dry run additionally writes `dry-<id>.sh` so the guard stays inspectable.
  At the start of each scan the broker GCs orphaned `resp-*.json`/`.*.tmp` older
  than a cutoff — it never touches `req-*.json`.
- **Lifecycle (per session):** the spool is a directory husk creates in someone
  else's source tree, so it cleans up after itself, by two independent paths
  because neither alone is sufficient:
  1. the broker removes its own spool when its session ends (it receives SIGTERM
     via `PDEATHSIG`), and
  2. a starting broker reaps the dead spools it finds **beside its own** — those
     whose `owner` names a pid that no longer exists, plus pre-v0.5 fixed-name
     spools once everything in them has gone an hour untouched.

  The reaper never leaves the directory husk was launched in, never considers a
  directory owned by another user, and removes only the filenames husk creates
  before `rmdir`-ing — so a spool holding anything else survives intact.

## The step spool (compute side)

`<workdir>/.husk-step-spool-<jobid>/`, holding the srun request/response pair and
the step-broker's captured stdout/stderr. Per-job by construction,
and removed when the job ends — by name, then `rmdir`, never `rm -rf`: the cleanup
runs with the user's rights in a directory the *job* can write, so a recursive
delete would be a deletion primitive aimed at whatever else ended up there. If
anything unrecognised is left, `rmdir` fails, the directory survives, and the job
says so.

That list must cover every file the guard creates. When egress was added it did not
— `net.sock`, `socat` and `net-proxy.log` were never removed, so `rmdir` failed and
**every networked job leaked its spool**, silently, because the failing branch had
nothing to report it. A test now derives the required names from the generated
script — and from `step.rs`, the *other* producer, which the first version of that
test ignored: a completeness check has to cover the **directory**, not one writer of
it.

**Fixed 2026-08-02.** A job that ran an `srun` step used to leave the empty `socat`
placeholder behind, so the `rmdir` failed and the directory persisted. The cleanup
ran and the `rm` failed: `socat` was a **bind-mount target**, and a dentry that is
still a mountpoint cannot be unlinked (`EBUSY`) while anything holds that mount —
rank cages and their relays can outlive the job's own `bwrap` by moments. A later
manual `rm` succeeded, which is what made it look mysterious.

The fix was structural rather than another filename: **stop creating a bind-mount
target inside a directory you intend to delete.** `socat` is now bound to
`/tmp/husk-socat` in the cage's *own* tmpfs. bwrap creates that mountpoint inside its
namespace, so the binary is usable inside and **nothing exists on the host** — no
placeholder, nothing to clean up, nothing to leak. The bind *source* is read in the
host namespace before the cage is sealed, so this needs no re-exposure of `$HOME`.

The step spool now holds only `req-*.json`, `resp-*.json`, `out-*` and `err-*`.

## The egress socket is not in the step spool

`/tmp/husk-<uid>-<jobid>/net.sock`, node-local, mode 0700, bound **read-only** into
the cage at the same path.

Node-local `/tmp` is the right home for a per-job socket — short, fast, and gone with
the job — **provided it is actually removed**. Compute-node SSDs are small and the
nodes restart rarely, so a directory that fails to clean up accumulates across every
user, which is the one thing node-local scratch must not do.

That is why the **socket** is bind-mounted into the cage, not its **directory**. A
directory bind makes the directory a mountpoint, and a dentry that is still a
mountpoint cannot be removed while anything holds that mount — the mechanism that
stranded the `socat` placeholder in the step spool, silently, under `2>/dev/null`.
Binding the file leaves the directory an ordinary directory, so its `rmdir` always
succeeds.

The socket cannot use the cage's own tmpfs the way `socat` does, because the **proxy
binds it outside the cage**: it must exist on the host and stay inside `sun_path`'s
108 bytes. It does not exist yet when bwrap runs, and a bind with a missing source
kills the cage — so the guard waits (bounded, 5s) for the proxy to bind before
building the cage. If it never binds, `HUSK_NET_SOCK` is unset and the job runs
without egress rather than with a broken one.

A unix socket address must fit in `sun_path` — 108 bytes, fixed by the kernel, with
no way to ask for more. In the step spool the address was
`<workdir>/.husk-step-spool-<jobid>/net.sock`, ~34 bytes of suffix, leaving ~73 for
the project path. A real Balfrin project measured ~57: it worked, with under 20
bytes to spare, and a project a couple of directories deeper would have lost its
network to a bare `AF_UNIX path too long`.

`/tmp` is world-writable and job ids are public in `squeue`, so the directory is
created with `mkdir` (no `-p`) at mode 0700 and the proxy re-checks owner and mode
before binding. A directory husk cannot own means **no egress** — that is a safe
outcome; egress routed through a directory someone else controls is not.

Read-only into the cage, and the **directory** rather than the socket: the socket
does not exist yet when bwrap runs (a bind with a missing source kills the cage),
and binding the directory means the socket appears inside the moment the proxy
creates it. `connect(2)` works through a read-only bind under `--unshare-net` —
measured on 6.8, then confirmed on the kernel that matters when `net.live` fetched
through this socket on Balfrin (5.14.21, Cray Shasta, 2026-08-01). The job then
cannot delete or replace its own socket — which it could when the socket sat in the
writable spool.

## The session log is not in the spool

Both halves of husk keep their record outside the directory the confined side can
write, for the same reason:

| | log | pointed at by |
|---|---|---|
| login session | `~/.husk/log/husk-<utc>-<pid>.log` | `HUSK_SESSION_LOG` |
| compute job | `~/.husk/log/job-<jobid>.log` | `HUSK_JOB_LOG`, and the cage banner |

A spool must be writable by the confined side — the login stub and the in-cage
`srun` stub both have to write into one. A log kept there is therefore one that
side can truncate, rewrite, or plant lines in, and **the audited party must not be
able to author the audit trail**.

The two differ in what the confined side can still *read*. On the login node reads
are unrestricted, so the agent can open its own session log to diagnose itself; it
simply cannot write it. Inside the compute cage `$HOME` is tmpfs-masked, so the job
log is beyond the job's reach entirely — it is read from the login node, which is
why the cage banner prints its path.

For a job, the step-broker and the egress proxy both append to the one file. They
are two trusted processes telling one story about one job, they prefix their lines
distinctly (`step-broker:`, `husk-proxy:`), and one place to look beats two.

One file per session or job also answers what a shared append-only `broker.log`
could not: which lines belong to *this* run.

## Request  (`req-<uuid>.json`, written by the stub)

| field         | type   | notes                                                        |
|---------------|--------|--------------------------------------------------------------|
| `version`     | int    | protocol version (currently `1`)                             |
| `id`          | string | uuid; matches the filename                                   |
| `tool`        | string | `"sbatch"`, or a Tier-1 read-only query (`"squeue"`, `"sinfo"`, `"sacct"`, `"sstat"`, `"sprio"`, `"sreport"`, `"sshare"`). `srun`/`salloc`/`scancel` rejected |
| `submitted_at`| string | ISO-8601 UTC                                                  |
| `cwd`         | string | absolute working dir, for resolving relative paths           |
| `argv`        | array  | the args the agent passed (excluding `argv[0]`)              |
| `script`      | object | the job script — see below                                   |
| `job_args`    | array  | args passed to the batch script (after the script name)      |
| `env`         | object | captured `SBATCH_*` / `SLURM_*` vars for the broker to strip/override |

`script` object:

| field    | type   | notes                                                            |
|----------|--------|------------------------------------------------------------------|
| `source` | string | `"file"`, `"wrap"`, `"stdin"`, or `"none"` (read-only queries: no script) |
| `name`   | string\|null | original filename when `source=file` (for messages only)    |
| `body`   | string | **the script content, inline** — an immutable snapshot           |

**The inline `body` is the load-bearing security choice.** The broker submits
*this snapshot*, never a path the agent could rewrite between validation and
slurmd reading it (TOCTOU). For `source=wrap`, `body` is the `--wrap` string;
for `source=stdin`, it is what the stub read from stdin.

```json
{
  "version": 1,
  "id": "f1e2d3c4-...",
  "tool": "sbatch",
  "submitted_at": "2026-06-11T12:00:00Z",
  "cwd": "/users/hpcuser/project",
  "argv": ["--time=01:00:00", "--nodes=1", "job.sh", "42"],
  "script": { "source": "file", "name": "job.sh", "body": "#!/bin/bash\nsrun hostname\n" },
  "job_args": ["42"],
  "env": { "SBATCH_OUTPUT": "/users/hpcuser/.bashrc" }
}
```

## Response  (`resp-<uuid>.json`, written by the broker)

| field       | type        | notes                                                   |
|-------------|-------------|---------------------------------------------------------|
| `version`   | int         | protocol version                                        |
| `id`        | string      | matches the request                                     |
| `status`    | string      | `"submitted"`, `"ok"` (query), `"rejected"`, or `"error"` |
| `job_id`    | int\|null   | set when `status=submitted`                             |
| `message`   | string      | human-readable; the reject/error text, or a query's captured **stderr** |
| `exit_code` | int         | what the stub should exit with                          |
| `stdout`    | string      | a read-only query's captured **stdout** (`status=ok`); empty otherwise |

The stub maps the response to the shadowed command's behaviour:
- `submitted` → stdout `Submitted batch job <job_id>`, exit `0`
- `ok` (query) → replay `stdout` to stdout and `message` to stderr, exit `exit_code`
- `rejected` / `error` → stderr `<tool>: error: <message>`, exit `exit_code` (non-zero)

## Timeouts & failure

- The stub polls for its `resp-` file up to `HUSK_SLURM_TIMEOUT` seconds
  (default 120). On timeout it exits non-zero with an error on stderr — it
  **fails closed** (no job is considered submitted).
- If the spool dir does not exist / is not writable, the stub errors out rather
  than silently bypassing the broker.

## Security invariants (do not regress)

1. **Script body is snapshotted inline** — broker never submits an agent-owned path.
2. **Broker force-overrides** dangerous options (`-o/--output`, `-e/--error`,
   `-D/--chdir`, `--export`, …) and **strips** `SBATCH_*`/`SLURM_*` env — these
   are acted on by slurmd *outside* the job sandbox (e.g. `-o ~/.bashrc`).
3. **Responses are broker-only.** A forged `resp-` only fools the agent's own
   stub; it grants nothing. The stub treats the broker as the sole authority.
4. **The stub is untrusted plumbing.** It runs in agent context; all policy
   lives in the broker. The broker validates every field as hostile input.

## Scope vs deferred

- **Implemented:** `sbatch` (validate + force-safe + re-sandbox + submit) and
  Tier-1 read-only queries (broker runs the command, returns `stdout`/`message`/
  `exit_code`); spool in the project dir.
- **Deferred:** `srun`/`salloc` (interactive/pty — harder), state-changing verbs
  and verb-gated read-only introspection (`scancel`, `scontrol`, `sacctmgr` —
  Tier 2), spool relocation, richer policy (queue/QoS routing), broker GC tuning,
  multi-session isolation.
