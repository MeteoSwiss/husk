# husk — Claude Code on HPC supercomputers

Claude Code is an AI coding assistant that runs in your terminal. On a shared
supercomputer login node it needs some extra care: the agent runs as your user
account, so without restrictions it could read your SSH keys, reach internal
cluster services, or submit SLURM jobs without asking. This repository provides
**husk**, the tooling to run Claude safely in that environment.

Developed and tested on CSCS supercomputers (Balfrin, Santis).

## Install from a release (recommended)

Install on the cluster from a **published release tarball** — not by cloning and
building. A release carries the prebuilt, architecture-correct `seccomp-wrapper`
binaries, so nothing is compiled on Balfrin or Santis. (Building from a clone is
only for development.)

Releases are published at:

> https://github.com/MeteoSwiss/husk/releases

A single tarball works on **both** Balfrin (x86_64) and Santis (aarch64) — it
ships both binaries and the installer picks the right one for the machine.

1. **Download** the latest release tarball and its checksum file (on any machine
   with a browser or network — e.g. your laptop):
   - `husk-<version>.tar.gz`
   - `husk-<version>.SHA256SUMS`

2. **Upload** both to the cluster with `scp` (Balfrin shown; repeat for Santis,
   or copy once if your `$HOME` is shared between them):

   ```bash
   scp husk-<version>.tar.gz husk-<version>.SHA256SUMS balfrin:~/
   ```

   > If the login node itself has outbound HTTPS, you can skip the laptop and
   > `wget` the two files directly from the releases page instead.

3. **Verify and unpack** on the cluster:

   ```bash
   sha256sum -c husk-<version>.SHA256SUMS   # must print: OK
   tar xzf husk-<version>.tar.gz
   cd husk-<version>
   ```

4. **Install** — continue with [Getting started](#getting-started) below, running
   `./install-husk.sh` from the unpacked release directory.

## Getting started

> **Prerequisite:** Claude Code must already be installed and authenticated.
> `husk` wraps your existing `claude` CLI — it does not install Claude
> for you. See [Requirements](#requirements).

Run the install script once from the unpacked release directory (or a
development clone):

```bash
./install-husk.sh
```

> The script will show you exactly what it will add to `~/.claude/settings.json`
> and ask for confirmation before making any changes.

### SLURM: record the partition (per machine)

On a machine with SLURM, the broker forces **every** brokered job onto one
partition, recorded at install time. The built-in default is `preemptible`, so
installing bare on a site without that partition leaves the broker forcing one
that does not exist — submissions then fail at the scheduler with
`invalid partition specified`.

**Balfrin** — use `preemptible`. It is also the built-in default, so a bare
install works here:

```bash
./install-husk.sh --slurm-partition preemptible
```

**Santis** — has **no** `preemptible` partition, so it must be set explicitly.
`debug` and `shared` both work (`debug` for short test jobs, `shared` when nodes
are free):

```bash
./install-husk.sh --slurm-partition debug
```

On any other site, list what exists with `sinfo -s` and pick accordingly.

Prefer a low-priority or preemptible queue where the site has one, so an
unattended agent's jobs can be killed and do not consume your allocation's
priority. The partition is **not** auto-detected: which queue an unattended
agent submits to is an operator decision, not something to infer from cluster
state. To change it later, re-run the installer with the new value.

If `~/.local/bin` is not yet on your PATH, add this to `~/.bashrc` or
`~/.bash_profile`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then start Claude Code with `husk` instead of `claude`:

```bash
husk
```

The sandbox is now active for all your projects.

To remove everything later — the installed binaries and the settings blocks it
added (your other settings are preserved) — run:

```bash
./install-husk.sh --uninstall
```

**Optional — per-project restrictions:** For tighter control over what Claude
can do within a specific project (network access, MCP servers), copy the
template into your project and commit it:

```bash
mkdir -p .claude
cp /path/to/agentskills-internal/project-config/settings.json .claude/settings.json
```

See [Per-project setup](#per-project-setup) for details.

## What it restricts

**Filesystem:** Claude can only read and write files inside the current project
directory. All home directories — yours and other users' — are not visible to
the agent. Data on shared filesystems outside the home directories
(e.g. `/scratch/`) is readable but not writable.

**SLURM:** `husk` handles SLURM automatically. On a cluster it routes job
submission through a **fail-closed broker** — the agent can submit batch jobs and
run read-only queries (`squeue`/`sinfo`/`sacct`/…), but the real commands run
*outside* the sandbox, submitted jobs are re-sandboxed on the compute node, and the
agent never gets the credentials to submit directly. The broker is spawned **only
when SLURM is detected**; on a laptop there's no broker and no trace, and a
sandboxed `sbatch` has nothing to talk to. See
[Running SLURM jobs (the broker)](#running-slurm-jobs-the-broker).

**Network access** *(per-project config):* `ssh`, `curl`, `wget`, and similar
tools are blocked by default. This is a conservative starting point for shared
login nodes; relax it per project if your workflow needs it.

**Credential files:** `.env` files, private keys (`*.pem`, `*.key`), and
credential files are blocked from being read or modified.

**MCP servers** *(per-project config):* All MCP tool calls are blocked by
default. Enable specific servers you trust in your project config.

## Per-project setup

The install script applies machine-wide defaults. For project-specific
restrictions, copy the template into your project:

```bash
mkdir -p .claude
cp /path/to/agentskills-internal/project-config/settings.json .claude/settings.json
```

Commit `.claude/settings.json` so the restrictions apply to everyone on the
project. See [`project-config/README.md`](project-config/README.md) for what
each entry does and which ones you may want to relax.

## How it works

The sandbox is built from three layers that stack on top of each other:

**Process isolation (seccomp-wrapper):** A thin wrapper around the Claude
process that installs a syscall deny-list — blocking low-level operations like
attaching to other processes, loading kernel modules, and manipulating user IDs.
This is the outermost layer and covers the entire Claude process tree.

**Filesystem isolation (bubblewrap):** A sandboxing tool installed system-wide
on CSCS supercomputers. Claude Code uses it to run each agent subprocess in an
isolated view of the filesystem, where only the project directory is present.
This is what keeps your home directory invisible to the agent.

**Additional filter (apply-seccomp):** A binary from Anthropic that blocks
two specific escape paths: reaching host services via Unix domain sockets, and
bypassing filters through `io_uring`. This runs inside the filesystem sandbox.

Settings are split into two files:
- `~/.claude/settings.json` — written by the install script; applies to all
  your projects; covers machine-wide security defaults.
- `.claude/settings.json` in your project — copied from `project-config/`; 
  covers workflow decisions that vary per project (network access, MCP servers).

## Requirements

- **Claude Code itself** — the `claude` CLI, installed and authenticated.
  `husk` wraps your existing Claude Code install; it does not install or
  update Claude for you. Install it (e.g. `npm install -g
  @anthropic-ai/claude-code`, or the native installer) and sign in first; see
  the [Claude Code docs](https://code.claude.com/docs).
- x86\_64 or aarch64 Linux, kernel ≥ 4.14
- bubblewrap installed system-wide (present on all CSCS supercomputers; check
  with your administrators on other HPC systems)
- `gcc`, `make`, `wget`, `python3` (standard on HPC login nodes)

## Running SLURM jobs (the broker)

On a cluster, just run **`husk`** — it detects SLURM and starts a small,
**fail-closed broker** that lets an unattended agent submit and monitor jobs — days
long, with no human to approve prompts — **without ever handing the agent the
credentials to do so**. On a machine with no SLURM, `husk` runs the plain sandbox,
with no broker and no trace. (There's no separate command — `husk` does both.)

**Activate your uenv (or modules) first.** The broker inherits the software
environment of the shell that launched it, and the agent cannot mount one from
inside the cage. So `uenv start <image>` (or load your modules) *first*, then `husk`.

### How it works

Inside the sandbox, `sbatch` and the read-only query commands are shadowed by a
stub. The stub hands each request to the trusted broker running **outside** the
sandbox — the only place MUNGE and the network exist. The broker:

1. **validates** the request as hostile input (see policy below);
2. **re-sandboxes** the job on the compute node — the job runs inside the same
   kind of cage as the login session (other users' homes hidden, credential
   files masked, auto-exec files write-protected, network unshared), so a
   prompt-injected job cannot read another user's data or escape the node; and
3. submits it under policy and returns the job id.

Because only the trusted broker holds MUNGE and the network path, the agent
**cannot bypass it** to submit directly — a sandboxed `sbatch` has nothing to
talk to.

### What the agent can do

- **Submit batch jobs** — `sbatch --partition=<site> job.sh`. The partition **must**
  be the site's configured one — `preemptible` by default, set per machine at install
  with `--slurm-partition` (Balfrin uses `preemptible`; Santis has no such partition,
  so e.g. `debug`). Any other is rejected with a message telling the agent how to
  resubmit (so design jobs to checkpoint and tolerate preemption). Risky options
  (`--output`/`--error`/`--chdir`/`--export`/`--wrap`) are forced to safe values, and
  the script is snapshotted at submit time (no edit-after-validate window).
- **Monitor jobs (read-only)** — `squeue`, `sinfo`, `sacct`, `sstat`, `sprio`,
  `sreport`, `sshare`. The broker runs them and returns their output; they change
  no scheduler state.
- **Everything else is rejected** — state-changing commands (`scancel`,
  `scontrol update`, …), interactive `srun`/`salloc`, and any unknown command.

The submitted job still runs *your* script with *your* allocation — but now
inside a cage, so an agent that tampers with its own job script is contained to
that job's sandbox rather than turned loose unsandboxed on the node. If you want
belt-and-suspenders, still keep the job script and its imports read-only to the
agent (an absolute path outside the project) and pass the agent's choices as
**validated data**, not as a code path.

> **Scope in this release (v0.4):** single node, no MPI. Multi-process / multi-node MPI
> (`srun`), a network allowlist for compute jobs (they currently run with the
> network unshared), interactive `srun`/`salloc`, and read-only
> `scontrol show`/`sacctmgr list` are on the roadmap — see
> [`ROADMAP.md`](ROADMAP.md) and [`slurm-broker/BROKER.md`](slurm-broker/BROKER.md).
>
> **Already built on the `experimental` branch, shipping in v0.5:** brokered `srun` and
> single-node multi-rank MPI — ICON runs on Balfrin across 4 GPUs inside the cage. The
> network allowlist is the last feature before that release.

## Known limitations

- **Network access:** Full network isolation (restricting Claude to only reach
  Anthropic's servers) is not yet implemented. `curl`, `wget`, `ssh`, and
  friends are blocked in the project config template as a compensating control.
- **SSH to compute nodes:** Blocked by default. Remove `Bash(ssh *)` from your
  project's deny list if you regularly need Claude to assist on compute nodes.
- **SLURM:** on a cluster `husk` auto-brokers; the broker
  supports **single-node batch jobs** (`sbatch`, re-sandboxed on the compute
  node) and **read-only queries** (`squeue`/`sinfo`/`sacct`/…) — see
  [Running SLURM jobs (the broker)](#running-slurm-jobs-the-broker). Not yet:
  multi-process / multi-node **MPI** (`srun`), a **network allowlist** for
  compute jobs (they run with the network unshared), interactive `srun`/`salloc`,
  and read-only `scontrol show`/`sacctmgr list` (see [`ROADMAP.md`](ROADMAP.md)).
  The compute-node cage is a *subset* of the login cage — notably its credential
  auto-scan uses a built-in pattern set rather than your `Read()` deny globs.
- **Large projects on Lustre:** on very large trees (many build directories) on
  Lustre filesystems, the sandbox can stall for up to ~a minute while it sets up
  its per-command filesystem rules. This is in the bundled sandbox and not
  currently configurable; launch the agent from a leaner working directory (not
  the build-heavy project root) to avoid it.

## Acknowledgements

husk builds on Anthropic's open-source
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (Apache-2.0):
the login sandbox installs and runs its `apply-seccomp` helper, and the broker's
compute-node filesystem cage is a Rust reimplementation adapted from its Linux
model (read/write policy, credential masking, bubblewrap argument construction).
See [`NOTICE`](NOTICE) for details.

## License

BSD 3-Clause — see [`LICENSE`](LICENSE) for details.
