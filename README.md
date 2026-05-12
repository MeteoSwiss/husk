# Claude Code on HPC supercomputers

Claude Code is an AI coding assistant that runs in your terminal. On a shared
supercomputer login node it needs some extra care: the agent runs as your user
account, so without restrictions it could read your SSH keys, reach internal
cluster services, or submit SLURM jobs without asking. This repository provides
the tooling to run Claude safely in that environment.

Developed and tested on CSCS supercomputers (Balfrin, Santis).

## Getting started

Run the install script once from this repository:

```bash
./install-claude-safe.sh
```

If `~/.local/bin` is not yet on your PATH, add this to `~/.bashrc` or
`~/.bash_profile`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then start Claude Code with `claude-safe` instead of `claude`:

```bash
claude-safe
```

The sandbox is now active for all your projects.

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
directory. Your home directory — SSH keys, API tokens, configuration files — is
not visible to the agent. Data on shared filesystems outside your home directory
(e.g. `/scratch/`) is readable but not writable.

**SLURM:** Read-only commands (`sinfo`, `squeue`, `sacct`, etc.) run freely.
Job submissions (`sbatch`, `srun`, `salloc`) and cancellations (`scancel`)
require your explicit confirmation — they affect the shared queue and consume
allocation.

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

- x86\_64 or aarch64 Linux, kernel ≥ 4.14
- bubblewrap installed system-wide (present on all CSCS supercomputers; check
  with your administrators on other HPC systems)
- `gcc`, `make`, `wget`, `python3` (standard on HPC login nodes)

## Known limitations

- **Network access:** Full network isolation (restricting Claude to only reach
  Anthropic's servers) is not yet implemented. `curl`, `wget`, `ssh`, and
  friends are blocked in the project config template as a compensating control.
- **SSH to compute nodes:** Blocked by default. Remove `Bash(ssh *)` from your
  project's deny list if you regularly need Claude to assist on compute nodes.

## License

BSD 3-Clause — see [`LICENSE`](LICENSE) for details.
