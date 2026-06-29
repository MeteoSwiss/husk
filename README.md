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

**SLURM:** SLURM commands don't run inside the sandbox at all — it blocks the
local authentication socket (MUNGE) they rely on and removes the network path
to the scheduler. Run them yourself in your own shell. For the one (heavily
restricted) way to let an *unattended* agent submit a job, see
[Running SLURM jobs from an unattended sandbox](#running-slurm-jobs-from-an-unattended-sandbox).

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

## Running SLURM jobs from an unattended sandbox

> **⚠️ This is a deliberately crippled last resort, not a recommended workflow — read the whole section before using it.** If a human is around to run SLURM commands, do that and let the agent only edit code.

SLURM commands do not work inside the sandbox: it blocks the local socket
SLURM's authentication (MUNGE) needs and removes the network path to the
scheduler. In an **unattended** run — days long, with no human to approve
prompts — there is currently exactly one way to let the agent submit a job:
**exempt a single, exact, immutable command from the sandbox.** That is enough
to, say, drive a weeks-long hyperparameter search that re-submits the *same*
training job with different numeric settings. It does not let the agent submit
anything else.

The safety of this rests entirely on three things you must get right by hand:

**1. The job script — and everything it touches — must not be editable by the agent.**

Put the script at an **absolute path outside your project directory**, owned
by you (the sandbox makes your home read-only to the agent's shell, and the
file-editing tools prompt or refuse outside the project). This applies to the
**whole chain**: every file the script sources, every module it imports, every
program it runs. An agent-writable `train.py` imported by a read-only
`train.sh` reopens the hole completely.

```
~/slurm-jobs/train.sh     # the script you submit — read-only to the agent
~/slurm-jobs/train.py     # and everything it imports — also read-only
```

**2. Allow exactly one command string, exempted from the sandbox.**

In `~/.claude/settings.json`, exempt that one command and allow only its exact
string — **no `*` wildcard**, the match must be exact:

```json
{
  "sandbox": {
    "excludedCommands": ["sbatch --partition=preemptive --time=2:00:00 /home/you/slurm-jobs/train.sh"]
  },
  "permissions": {
    "allow": ["Bash(sbatch --partition=preemptive --time=2:00:00 /home/you/slurm-jobs/train.sh)"]
  }
}
```

Keep `allowUnsandboxedCommands: false` so this is the *only* command that ever
leaves the sandbox. Any other `sbatch` stays sandboxed and simply fails —
harmlessly. (If your Claude Code only matches `excludedCommands` by program
name, use `"sbatch"` there instead — the exact `allow` rule is what restricts
execution to the single command.)

**3. The agent may dial parameters, never inject code.**

The agent's only influence on the run must be **pure data through a strictly
validated channel** — numbers within ranges, choices from a fixed list. Have
your read-only script read the agent's settings from a data file and validate
them hard before using them:

```
# the agent may edit ./params.json in the project:  {"lr": 0.01, "batch": 64, "loss": "mse"}
# train.sh checks: lr and batch are numbers in range; loss is one of a fixed
# enum {"mse", "cross_entropy"}; anything else aborts the job.
```

The data/code boundary is the hard part, and it is sharper than it looks.
"Let the agent choose the loss function" sounds like data, but a loss *name*
usually maps to imported code — a free-form string there is a code-injection
channel. Only a **closed enum** is safe. The same caution applies to anything
that can name a file, a module, a Python object, or a shell fragment.

> **⚠️ The submitted job runs completely unsandboxed on the compute node.**
> None of the sandbox's protections reach it. The exact-command rule pins
> *which command runs*, not *what it does* — and what it does is decided
> entirely by the script and everything it reads as code. If any link in that
> chain is writable, or if one "parameter" can smuggle in code, the agent has
> arbitrary, unsandboxed execution with your full credentials.

This works, but it is narrow, brittle, and easy to get subtly wrong — the tool
gives you no help verifying the chain is immutable or that the parameters are
truly data-only; that is all on you. It exists only because there is no better
option yet. A proper mechanism — a small broker that validates structured job
requests outside the sandbox and re-sandboxes the job on the compute node — is
planned but not yet available. Until then, prefer to **run SLURM yourself** and
let the agent assist with code, or accept that an unattended agent cannot
submit jobs.

## Known limitations

- **Network access:** Full network isolation (restricting Claude to only reach
  Anthropic's servers) is not yet implemented. `curl`, `wget`, `ssh`, and
  friends are blocked in the project config template as a compensating control.
- **SSH to compute nodes:** Blocked by default. Remove `Bash(ssh *)` from your
  project's deny list if you regularly need Claude to assist on compute nodes.
- **SLURM:** SLURM commands don't work inside the sandbox at all (it blocks the
  local authentication socket they use and the network path to the scheduler).
  Run them in your own shell; for unattended submission see
  [Running SLURM jobs from an unattended sandbox](#running-slurm-jobs-from-an-unattended-sandbox).
  A submitted job runs *unsandboxed* on its compute node — a SLURM gateway (a
  broker that re-sandboxes the job on the compute node) is planned for an
  upcoming v0.2.x release.
- **Large projects on Lustre:** on very large trees (many build directories) on
  Lustre filesystems, the sandbox can stall for up to ~a minute while it sets up
  its per-command filesystem rules. This is in the bundled sandbox and not
  currently configurable; launch the agent from a leaner working directory (not
  the build-heavy project root) to avoid it.

## License

BSD 3-Clause — see [`LICENSE`](LICENSE) for details.
