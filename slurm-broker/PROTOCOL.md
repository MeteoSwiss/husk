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

- **Location (decided 2026-06-11):** a dedicated subdir of the project
  directory, `./.husk-slurm-spool/`. The stub finds it via the
  `HUSK_SLURM_SPOOL` env var (set by the outer wrapper), falling back to
  `$PWD/.husk-slurm-spool`. The location may be revisited in a later version.
- **Files:** `req-<uuid>.json` (stub → broker), `resp-<uuid>.json`
  (broker → stub). `<uuid>` pairs a response to its request.
- **Atomicity:** every file is written to `.<name>.tmp` in the same directory
  and then `rename()`d into place, so a reader never sees a partial file.
- **Lifecycle:** the stub owns its pair — it deletes both `req-` and `resp-`
  after reading the response. The broker removes the staged `job-<id>.sh` right
  after `sbatch` returns (sbatch has copied the script into SLURM's own spool by
  then), and, at the start of each scan, GCs orphaned `resp-*.json`/`job-*.sh`/
  `.*.tmp` older than a cutoff (a stub or broker that died before cleanup) — it
  never touches `req-*.json`.

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
  "cwd": "/users/cmueller/project",
  "argv": ["--time=01:00:00", "--nodes=1", "job.sh", "42"],
  "script": { "source": "file", "name": "job.sh", "body": "#!/bin/bash\nsrun hostname\n" },
  "job_args": ["42"],
  "env": { "SBATCH_OUTPUT": "/users/cmueller/.bashrc" }
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
