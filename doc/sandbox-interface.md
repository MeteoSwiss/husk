# Sandbox interface spec

> **⚠ STALE — read with care (flagged 2026-08-05).** This describes a v0.2/v0.3 contract
> and cites harm IDs against a threat model that has since moved (H10/H11 added, the
> bash-vs-native-tool asymmetry closed by `--tools Bash`). It is nonetheless the
> **acceptance criterion for ROADMAP 6b** — the test is that the string `claude` appears
> nowhere in it except as one integration among others — so it is worth rewriting *before*
> 6a rather than after. Until then, treat [PRINCIPLES.md](PRINCIPLES.md),
> [threat-model.md](threat-model.md) and [constraints.md](constraints.md) as authoritative
> where they disagree with it.

This document defines the contract between the HPC agent sandbox and the
agent it wraps. An agent that satisfies the requirements below can be
wrapped by the sandbox without modification to the sandbox layer.

The sandbox is agent-agnostic. It wraps any process. The first integration
wraps Anthropic's Claude Code (see integrations/husk/); future
integrations are added by writing a launcher that invokes the sandbox
with the agent binary as its target.

Threat model: doc/threat-model.md. Harm IDs (H1, H2, …) referenced below
are defined there.

## What the sandbox provides

Three independent layers applied to the wrapped process tree:

1. Filesystem isolation (bubblewrap).
   The wrapped process sees a mount namespace where:
     - One or more explicit paths (typically the project directory) are
       writable.
     - Paths outside any denyRead region are visible read-only via the
       root bind mount.
     - Paths inside denyRead regions are invisible. On CSCS the default
       denyRead is /users — all home directories on the cluster.
     - Configuration files inside protected regions may be replaced with
       /dev/null inside the namespace.
   Defends H2, H4 (operationally), H7, H8, H9-in.

2. Network isolation (bwrap --unshare-net + host-side proxy).
   The wrapped process has no network namespace of its own. Its only
   network path is a Unix socket bind-mounted into the sandbox connecting
   to a host-side proxy. The proxy:
     - Exposes one HTTP CONNECT endpoint (port 3128) and one SOCKS5
       endpoint (port 1080) inside the sandbox.
     - Enforces a domain allowlist from a user-maintained config file.
       The agent can read the file but cannot write it. The proxy reloads
       on file change.
     - Optionally logs requests for audit.
   There is no other network path. Direct socket() / connect() reaches
   nothing. Defends H5, H5', H6.

3. Syscall isolation (seccomp).
   A deny-list of "exotic" syscalls is installed before the wrapped
   process starts:
     - Blocked: ptrace, bpf, io_uring family, AF_UNIX socket creation,
       kexec_load, pivot_root, personality (ABI-switch forms), plus ~20
       more. Full list in the seccomp-wrapper source.
     - Coverage includes secondary ABIs (x86 on x86_64, arm on aarch64).
     - Enforcement: SCMP_ACT_KILL_PROCESS. An offending child is killed;
       the parent agent receives the exit code and can recover.
   Standard syscalls (read, openat, write, mmap, futex, …) work normally.
   Defends H1 (narrows kernel attack surface).

## Wrapping a closed-binary agent (namespace inheritance)

The sandbox treats the agent as opaque — it never patches the agent. When the
wrapped agent is itself a closed binary that sets up its OWN inner bwrap per
tool call (as Claude Code does — a single compiled binary, unpatchable), the
sandbox can still inject filesystem policy from the OUTSIDE: create the mount
namespace and apply bind-mounts BEFORE launching the agent, and the agent's
inner bwrap — which re-binds the host filesystem from the namespace it runs
in — inherits them.

The v0.2.1 SLURM shim uses exactly this: an outer wrapper bind-mounts a
controlled stand-in over sbatch/srun/salloc/scancel before exec'ing the
agent, and every sandboxed tool call inherits the shimmed binary. This is how
an unmodifiable agent is contained without any API into it — the general
pattern for closed integrations.

## Sandbox-to-agent context channel

The sandbox communicates its state and configuration to the agent via two
mechanisms:

  1. Environment variables (SANDBOX_* namespace) — structured facts the
     agent reads programmatically. Minimum set:
       SANDBOX_ACTIVE              "1" when the sandbox is wrapping
       SANDBOX_PROJECT_DIR         absolute path to the writable working
                                   directory
       SANDBOX_DENY_READ           paths invisible to the wrapped process
                                   (comma-separated)
       SANDBOX_ALLOWLIST_PATH      file the user maintains for both
                                   network and filesystem allowlist policy
       SANDBOX_NETWORK_KEY         key within ALLOWLIST_PATH for network
                                   allowedDomains
       SANDBOX_FILESYSTEM_KEY      key within ALLOWLIST_PATH for filesystem
                                   allowRead
       SANDBOX_POSTURE             "strict" or "permissive" (network)
       SANDBOX_INFO_PATH           absolute path to the reference document
                                   described below

  2. A reference document at $SANDBOX_INFO_PATH — human-readable, written
     for an LLM agent to consume. Describes the rules in prose plus
     recommended user-facing phrasing for each failure mode the agent will
     encounter.

The agent decides how to consume the channel. LLM agents typically inject
relevant content into a system prompt; script-based agents read the
document when handling errors. The contract is that the sandbox provides
these — the agent is free to ignore them, but a polished integration uses
them to give the user actionable guidance instead of a bare error code.

### Failure modes the reference document should cover

The document should walk the agent through at least these cases, with
sample user-facing phrasing for each:

  - Network HTTP 403. The requested domain is not in the allowlist. The
    user can add it by editing $SANDBOX_ALLOWLIST_PATH under
    $SANDBOX_NETWORK_KEY.

  - Filesystem ENOENT / EACCES on a path inside $SANDBOX_DENY_READ. The
    path is invisible to the agent because it falls inside a denied
    region. Typical case: the user's ~/miniconda3/ lives under /users and
    is not in allowRead. The user fixes by adding the path to
    $SANDBOX_ALLOWLIST_PATH under $SANDBOX_FILESYSTEM_KEY (same file,
    different key).

  - Subprocess killed by SIGSYS. The subprocess hit a blocked syscall.
    The agent should pick a different approach and not retry; this is a
    structural limit, not user-fixable.

  - Network connection refused / DNS resolution failed for a domain that
    IS on the allowlist. Infrastructure issue (proxy down, upstream
    unreachable), not a sandbox policy issue; the agent should surface
    the actual error rather than blame the sandbox.

## SLURM gateway (optional)

Where the host scheduler (e.g. SLURM) is unreachable from inside the sandbox by
design — the credential socket (MUNGE/AF_UNIX) and the network are both cut — an
agent still needs a controlled way to submit jobs that do not escape onto
unsandboxed compute nodes. The sandbox can provide a GATEWAY:

  - It SHADOWS the submit binary (e.g. sbatch) inside the sandbox with a thin
    stub, and exposes a request channel (a bind-mounted drop dir or fifo) whose
    path it advertises in the context channel (e.g. SANDBOX_SLURM_BROKER).
  - The stub serializes a structured job request (script, partition, resources)
    to the channel — plain file I/O, so it works even with AF_UNIX blocked.
  - A BROKER process running OUTSIDE the sandbox (where the scheduler IS
    reachable) validates the request against policy, forces safe options, and
    submits a job whose payload runs re-sandboxed (the same syscall + bwrap
    layers) on the compute node.

The split is deliberate: the real submit binary and the scheduler credentials
never enter the sandbox, so the agent has no path to submit directly — a stub
that submitted from inside would be bypassable. The broker, the request schema,
and the compute-side re-sandboxing are agent- and sandbox-agnostic; only the two
delivery responsibilities above (shadow the binary, expose the channel) belong
to the sandbox, which keeps the gateway portable across integrations.

## What the agent must accept

An agent is wrappable if:

1. It writes only to its configured working directory or to other
   explicitly allowed paths. The home directory may be read-only or
   hidden depending on denyRead policy.

2. Network traffic is configurable to go through the sandbox proxy. The
   agent accepts HTTP_PROXY / HTTPS_PROXY / SOCKS_PROXY env vars, or
   exposes an equivalent configuration mechanism. Direct DNS, raw
   sockets, and io_uring-based networking will not work.

3. It does not depend on blocked syscalls. Most agents satisfy this by
   default. The notable trap is io_uring, which some modern async I/O
   libraries use opportunistically; the agent must run in a mode that
   uses epoll / poll / select instead.

4. Tools that affect the system run as subprocesses, not in-process.
   The sandbox layers apply to the entire process tree, but only to
   processes that ARE in the tree. A tool the agent implements by opening
   a file descriptor in its own process bypasses bwrap entirely. Such
   tools cannot be sandboxed by this mechanism — they must be implemented
   as subprocesses, or the agent must accept they are unsandboxed.

   This is the most important requirement. It is the structural finding
   that drove this spec: existing agents that mix in-process tools with
   subprocess tools (the Claude Code situation) leave a hole the sandbox
   cannot close. The bash-vs-native-tool asymmetry called out in
   threat-model.md is exactly the symptom of failing this requirement.

   Corollary: an agent that fully satisfies this requirement does not need
   per-tool permission deny rules to protect credentials or config — the OS
   filesystem boundary (denyRead) covers every tool uniformly. Such rules
   (Read/Edit/Write deny patterns) are a compensation for in-process tools,
   the Claude Code case; on a fully wrappable agent the policy lives in
   denyRead and in the property that neither agent nor sandbox can modify the
   allowlist. They may be kept as cheap defense-in-depth, but they stop being
   load-bearing.

5. It runs as a normal user. No setuid, no CAP_SYS_ADMIN, no assumption
   of root.

## Out of scope for the sandbox

These are the agent's responsibility, not the sandbox's:

  - Agent loop, planning, tool dispatch, model API calls.
  - Per-tool permission policy ("ask before sbatch", H3).
  - Per-file content policy (don't read .env, fine-grained H2).
  - User interaction, prompts, confirmations.
  - Session transcripts and other agent-level audit.
  - Choice of model and model provider.

The network allowlist policy is the user's responsibility, not the
sandbox's or the agent's. The user maintains the allowlist file directly;
the sandbox enforces it; the agent cannot modify it. An agent that could
expand its own network permissions would bypass H6 entirely.

## Compliance checklist

  [ ] Confines writes to a configurable working directory.
  [ ] Accepts proxy configuration via standard env vars or config.
  [ ] Does not require io_uring or any other blocked syscall.
  [ ] Implements system-affecting tools as subprocesses (no in-process
      file or network access).
  [ ] Runs as an unprivileged user.
  [ ] Does not attempt to detect or bypass the sandbox.

An agent meeting all six is fully wrappable. An agent meeting 1, 2, 3, 5,
6 but failing 4 (in-process tools) is a best-effort integration: those
specific tools are documented as known asymmetries, and their behavior
depends on agent-level policy rather than sandbox-level enforcement. The
current Claude Code integration is this case.
