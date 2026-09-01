# husk — sandboxing AI coding agents on HPC supercomputers

**husk confines an AI coding agent on a shared supercomputer, from the outside.** The agent
runs inside a cage it cannot inspect, disable or negotiate with; every SLURM command it
issues is validated by a trusted broker running beyond its reach; and its cooperation is
never required for any of it.

That is worth doing because the agent runs as *you*. On a login node an unconfined assistant
holds your SSH keys and credentials, your compute allocation, the other home directories on
the shared filesystem, and the cluster's internal services — not because it is malicious, but
because it inherited your account. husk makes those unreachable rather than discouraged, and
tells the agent what it just refused so it stops guessing and works around the boundary.

It wraps **Claude Code** today; the confinement contract itself is agent-agnostic by design
(`doc/sandbox-interface.md`).

Developed and tested on CSCS supercomputers (Balfrin, Santis).

## Getting started

On a Balfrin or Santis login node. Nothing is compiled, nothing needs root.

**1. Claude Code, if you don't have it.** To check `command -v claude`.

```bash
curl -fsSL https://claude.ai/install.sh | bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
claude          # log in once, then exit
```

**2. Install husk.** One tarball works on both machines — it ships binaries for each and the
installer picks the right ones.

```bash
curl -fLO https://github.com/MeteoSwiss/husk/releases/download/v0.5/husk-v0.5.tar.gz
tar xzf husk-v0.5.tar.gz && cd husk-v0.5
./install-husk.sh --slurm-partition <partition> --slurm-account <project>
```

The installer prints exactly what it will add to `~/.claude/settings.json` and asks before
changing anything. The two flags are recorded in `~/.husk/config.json` on a first install —
see [below](#slurm-record-the-partition-per-machine) if you need to change them later.

**3. Use it.** Run `husk` where you would have run `claude`:

```bash
cd ~/my-project
husk         # husk --resume also works
```

Repeat step 2 on each machine whose `$HOME` is not shared. Releases are listed at
https://github.com/MeteoSwiss/husk/releases — verify the tarball with the published
`SHA256SUMS` if you want to.

<details>
<summary>Installing somewhere other than Balfrin or Santis, or building from source</summary>

husk needs `bubblewrap` (`bwrap`) system-wide, `wget`/`python3`/`tar`/`sha256sum` on `PATH`,
and outbound HTTPS once to fetch Anthropic's `apply-seccomp`. It also needs `socat`; if that
is missing the installer builds it, which then needs `gcc` and `make`. All of this is already
in place on CSCS machines.

Building from source is for developing husk, not for using it. It needs a Rust toolchain and
must be done separately on each architecture — there is no cross-compilation:

```bash
git clone https://github.com/MeteoSwiss/husk && cd husk
(cd seccomp-wrapper && ./build_and_test.sh)   # -> seccomp-wrapper-$(uname -m)
(cd slurm-broker    && ./build-release.sh)    # -> husk-slurm-{broker,wrapper}-$(uname -m)
./install-husk.sh --slurm-partition <partition> --slurm-account <project>
```

`make` alone is not a substitute for `build_and_test.sh`: it writes `seccomp-wrapper`, and the
installer only ever reads `seccomp-wrapper-<arch>`.

</details>

### SLURM: record the partition (per machine)

On a machine with SLURM, the broker forces **every** brokered job onto one
partition, recorded at install time. The built-in default is `preemptible`, so
installing bare on a site without that partition leaves the broker forcing one
that does not exist — submissions then fail at the scheduler with
`invalid partition specified`.

```bash
./install-husk.sh
```

The partition and account live in **`~/.husk/config.json`**, which is the interface:
edit the file, no reinstall. The installer only ever *seeds* it on a first install
and never clobbers an existing one — accounts and partitions change far more often
than the installation does.

```json
{ "partitions": ["preemptible"], "accounts": ["<your project>"] }
```

**Balfrin** — `preemptible` (also the built-in default). **Santis** — has **no**
`preemptible` partition; use `debug` (short test jobs) or `shared` (when nodes are
free). On any other site, list what exists with `sinfo -s` and pick accordingly. A
per-system override is `~/.husk/config.<system>.json`, which wins outright — `$HOME`
is shared between some machines and their partitions differ.

Prefer a low-priority or preemptible queue where the site has one, so an
unattended agent's jobs can be killed and do not consume your allocation's
priority. The partition is **not** auto-detected: which queue an unattended
agent submits to is an operator decision, not something to infer from cluster
state.

**To change it later, edit `~/.husk/config.json`.** Re-running the installer with a
new value does *not* change it: a config file that names partitions wins over the
install-time flags by design, and the installer never clobbers one that exists. It says
so when you try — *"…but you passed `--slurm-account`/`--slurm-partition`, and the config
file OVERRIDES them"* — and then prints what is in effect. A flag that does nothing must
not do it quietly.

> **One edge, worth knowing because the warning is wrong there.** The config wins only
> where its list is **non-empty**. On a config that reads `{"partitions": [], "accounts":
> []}` the broker falls back to `HUSK_SLURM_PARTITION`, which the installer *does*
> rewrite on every run — so `--slurm-partition` takes effect while the installer is still
> printing that the file overrides it. Put the value in the file and the ambiguity goes
> away.

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
cp <unpacked-release>/project-config/settings.json .claude/settings.json
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
cp <unpacked-release>/project-config/settings.json .claude/settings.json
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

All of these are already in place on Balfrin and Santis — this list is for other systems.

- **The `claude` CLI**, installed and authenticated. husk wraps it; it does not install or
  update it. See [Getting started](#getting-started) for the one-liner, or the
  [Claude Code docs](https://code.claude.com/docs).
- x86\_64 or aarch64 Linux, kernel ≥ 4.14.
- **bubblewrap** (`bwrap`) installed system-wide. husk cannot sandbox without it.
- `wget`, `python3`, `tar`, `sha256sum` on `PATH`, and outbound HTTPS once, to fetch
  Anthropic's `apply-seccomp`.
- **`socat`.** If it is missing the installer builds it from source, which then needs `gcc`
  and `make`. Check with `command -v socat`.

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
  be the site's configured one — `preemptible` by default, set per machine in
  `~/.husk/config.json` (Balfrin uses `preemptible`; Santis has no such partition,
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

> **Scope in this release (v0.5):** single-node batch jobs, brokered `srun`, and
> **single-node multi-rank MPI including GPU jobs** — ICON runs on Balfrin across 4 GPUs
> inside the cage with CMA enabled, and a production KENDA assimilation experiment has run
> green through husk. Compute jobs get an allowlisted, `CONNECT`-only egress proxy where an
> allowlist is configured, instead of no network at all.
>
> **Not in v0.5:** multi-*node* MPI, which husk **refuses** — `--nodes` other than 1 is
> rejected with a message saying so, rather than silently downgraded to one node. Shipping it
> as a named weaker profile is a decision on the roadmap, not code that exists (see
> [`ROADMAP.md`](ROADMAP.md) Track D). Also not in v0.5: interactive `srun`/`salloc`; and
> read-only `scontrol show`/`sacctmgr list`. See [`ROADMAP.md`](ROADMAP.md) and
> [`slurm-broker/BROKER.md`](slurm-broker/BROKER.md).

## Known limitations

- **Network access:** the shipped user settings carry an **enforced** domain allowlist
  (`strictAllowlist: true`) rather than a prompt hint — but only where that flag is
  actually deployed. **Check yours:** without `strictAllowlist`, an allowlist is a prompt
  hint and unlisted hosts auto-approve in auto mode, and at least one CSCS machine has
  been found running exactly that (measured during the v0.5 review). Brokered
  compute jobs reach the network only through husk's own `CONNECT`-only proxy, and get no
  network at all where no allowlist is configured.
  **The shipped `sandbox.network.allowedDomains` holds one entry,
  `opendatadocs.meteoswiss.ch:443` — that is an example, not a recommendation.** Replace it
  with the hosts your work needs; an empty list means no network at all. Entries are `host`,
  `host:port` or `*.two.labels`, and SLURM's own ports are always refused.
  What is *not* implemented is confining
  the agent to Anthropic's servers specifically. `curl`, `wget`, `ssh` and friends stay
  blocked in the project config template as a second, independent control.
- **SSH to compute nodes:** Blocked by default. Remove `Bash(ssh *)` from your
  project's deny list if you regularly need Claude to assist on compute nodes.
- **SLURM:** on a cluster `husk` auto-brokers. v0.5 supports **single-node batch jobs**
  (`sbatch`, re-sandboxed on the compute node), **brokered `srun` with single-node
  multi-rank MPI and GPUs**, the **compute-job network allowlist**, and **read-only
  queries** (`squeue`/`sinfo`/`sacct`/…) — see
  [Running SLURM jobs (the broker)](#running-slurm-jobs-the-broker). All of it has run on
  both CSCS machines. Not yet: multi-**node** MPI,
  interactive `srun`/`salloc`, and read-only `scontrol show`/`sacctmgr list` (see
  [`ROADMAP.md`](ROADMAP.md)).
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
