# Constraints

**Level 3 of four.** Every control husk applies, where it is enforced, and how much
weight it carries. Organised by **enforcement surface**, not by configuration file —
most of husk's security now lives in Rust, and organising by settings key hides that.

Rationale lives one level up. Where a control exists *because* of a principle, this
file cites it (`P5`) and describes only the mechanism. Harm and vector IDs are
defined in [`threat-model.md`](threat-model.md). Findings are [`review-v0.5/`](review-v0.5/).

Each control declares:

- **defends** — harm/vector IDs
- **weight** — **load-bearing** (part of the guarantee) or **depth** (must never be
  the last line)
- **principle** — the L1 entry it instantiates, if any
- **asserted by** — the test that would fail on regression, or `— prose only`, which
  is itself a finding

Status: v0.5. Last reconciled against source 2026-08-05.

---

## Surface 0 — launcher and tool allowlist

`husk` → `husk-slurm-wrapper` → `seccomp-wrapper claude --tools Bash`. The wrapper
brokers iff it detects SLURM; on a laptop there is no broker and no trace.

### C0.1 — tool allowlist (`--tools Bash`)
defends H2, H4, H7, H8 · **load-bearing** · `P5` · asserted by *— prose only*

The runtime's `Read`/`Edit`/`Write` execute in the agent process on the host, beside
the cage — no mount table applies. Their only leash is a path-pattern permission
list a human can answer "yes" to. Everything they do, bash does, through the door
that *is* locked. So the agent gets an allowlist of tools, not a deny-list.

This closed the bash-vs-native-tool asymmetry that dominated every previous revision.
Costs real ergonomics — every file touch is a sandboxed command, slow on Lustre.
Revisit when the login side gets its own outer cage.

husk's flags are placed **first**, so an explicit user flag still wins: the human
launching husk is the trusted party.

### C0.2 — fail-closed wrapper
defends meta · **load-bearing** · `P6`

Absent broker binaries → plain cage, never an unbrokered SLURM path. The installer
errors rather than silently omitting `seccomp-wrapper`. `SandboxReady` is a witness
type mintable only by a verified bind, so "we checked" is carried by the type.

---

## Surface 1 — syscall filtering

### C1.1 — `seccomp-wrapper`
defends H1 · **load-bearing** · asserted by `make check`, `build_and_test.sh` (incl. a bwrap gate)

Static per-arch binary, installed before `claude` starts. Deny-list — `ptrace`,
`bpf`, `io_uring`, `kexec_load`, `pivot_root`, ~20 more — via
`SCMP_ACT_KILL_PROCESS`: the offending subprocess dies, the session survives, the
agent observes the exit code. `SCMP_ARCH_X86` / `SCMP_ARCH_ARM` registered so
secondary-ABI numbers are covered. `personality(2)` uses argument filtering — the
`0xffffffff` query allowed, ABI-switch forms killed.

**Deliberately not blocked:** `mount`, `umount2`, `pivot_root`, `capset` — bwrap
needs them; blocking `capset` killed bwrap on aarch64. Bounded: inside bwrap's user
namespace only bind-mounts of owned paths and pseudo-filesystems are possible, and an
unprivileged `NO_NEW_PRIVS` process has an empty permitted capability set.

Narrows the surface; does not eliminate it. A CVE in `read()` or `openat()` is not
caught here.

### C1.2 — `apply-seccomp` (vendored)
defends H1, H6 · **depth**

Blocks `socket(AF_UNIX, …)` and `io_uring`, nests a user+PID+mount namespace, uses
`SCMP_ACT_ERRNO`. Stacked, not relied upon. **Login-side only** — AF_UNIX is open on
compute by necessity (socat relay, CUDA), so cross-uid protection there rests on
directory ownership and mode instead.

### C1.3 — `SECCOMP_WRAPPER_DEBUG`
n/a — development escape hatch

Swaps `KILL_PROCESS` for `ERRNO(ENOSYS)` for one session. A human may set it for
profiling; the agent cannot, because the agent is the threat model.

---

## Surface 2 — the login cage

From `user-config/settings.json`, written to `~/.claude/settings.json` by the
installer, which preserves keys outside the managed blocks. Vendored runtime today;
husk owns it at ROADMAP 6a.

### C2.1 — `sandbox.enabled`, `allowUnsandboxedCommands: false`
defends meta · **load-bearing**

Without the first, nothing else applies. The second hard-blocks any request to run
outside the cage — in an unattended run such a request is never legitimate.
`autoAllowBashIfSandboxed: true` is the corollary: the cage is the guard, so
prompting inside it is friction with no safety value.

### C2.2 — `filesystem.denyRead` / `allowRead`
defends H2, H7, H8, H9-in · **load-bearing**

`denyRead: ["/users"]` hides every home on CSCS. `allowRead: ["./"]` re-exposes the
project directory. `allowRead` entries become bwrap `--ro-bind`; paths outside any
`denyRead` region are already readable through the root bind, so `allowRead` is only
needed to punch back through a `denyRead` region. `/scratch` needs no entry; a path
under `~` does. Adding scientific inputs to `allowRead` is the H9-in pattern.

### C2.3 — `filesystem.denyWrite`
defends meta, H7 · **load-bearing** · `P8`

`~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`,
`~/.local/lib/husk`, `.Rprofile`, `.hg/hgrc`.

`settings.local.json` is the critical entry — project-local settings **outrank** user
settings, so an agent writing `"sandbox":{"enabled":false}` there disables the cage
next session. `.Rprofile` and `.hg/hgrc` were added after the review found the login
cage masked neither while the compute cage did; the fix was `LOGIN_AUTO_EXEC_DENY`,
asserted in both directions against the shipped config, not two new entries.

### C2.4 — credential deny globs
defends H2 · **depth** (was load-bearing before C0.1)

~25 `Read`/`Edit` patterns on the `//**/` anchor: `.env*`, `*.env`, `*.pem`, `*.key`,
`*.cer`, `*.crt`, `*.p12`, `*.pfx`, `*.jks`, `credentials`, `.netrc`,
`.git-credentials`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.ssh/**`, `.aws/**`,
`.kube/**`, `.config/gcloud/**`, `.gnupg/**`.

**These now guard tools the agent does not have.** The OS layer — `/users` tmpfs plus
the mandatory-deny scan — is what stops credential reads. Kept as the fallback if
`--tools` is ever widened.

Two things worth not rediscovering: the Config-tab warning ("glob patterns not fully
supported on Linux") describes the **bwrap boundary only** — bwrap binds concrete
paths and cannot express a glob — while the permission layer still matches; and
**deny beats allow**, so a filesystem-wide `//**/*.key` cannot be re-allowed for one
file.

### C2.5 — `enableAllProjectMcpServers: false`, `mcp__*` deny
defends H6, H8 · **depth**

Stops a cloned project's `.mcp.json` activating servers. **User-level MCP servers in
`~/.claude/` are not covered** — review separately.

### C2.6 — `Bash(nc *)`, `Bash(socat *)` deny
defends H6 · **depth**

Compensating only; the architectural control is `--unshare-net` plus the proxy. socat
is on `PATH` because the installer builds it as a runtime dependency.

### C2.7 — `permissions.allow` for read-only SLURM verbs
n/a — prompt suppression

`sinfo`, `squeue`, `sacct`, `scontrol show`, `sprio`, `sreport`. **In v0.5 these work
inside the cage** — the stub forwards them to the broker. Earlier revisions stated
they could not; that was true before brokering. State-changing verbs are refused by
the broker regardless, so the allow list is convenience, not policy.

### C2.8 — known limitation: Lustre stalls
n/a — availability

Stalls up to ~a minute in large trees. Cause: the vendored runtime performs an
in-process deny-set walk, then bind-mounts the result over Lustre — finding is fast,
mounting is not. Not configurable (`mandatoryDenySearchDepth` is not honoured by the
shipped binary). Workaround: launch from a leaner cwd, keep build trees out of the
working directory (also shrinks H4 blast radius).

**The 6a fix is a design constraint, not tuning: express policy as mounts, not as a
scanned deny-set.** The compute cage already is.

---

## Surface 3 — the submission gate

The broker, outside the cage, holding MUNGE and the network. `sbatch` and the query
verbs are shadowed by a stub that serialises a request; the agent never holds the
credentials to submit.

### C3.1 — construct, re-emit, reject unknown
defends H3, H10, AV8, and every compute-side control · **load-bearing** · `P5` ·
asserted by `sbatch::REGISTRY` tests, `interpret_cli`

The broker builds the invocation: security-relevant options forced, benign resource
options parsed → validated → re-emitted canonically, everything unrecognised
rejected. Glued shorts, `--wrap`, unknown flags and next year's new sbatch option
fail closed by construction.

`Ignored` means **dominated** — husk emits the safe value on the CLI — never
**dropped**, because a dropped option leaves `#SBATCH` as an ungated channel.

**Reason about the sink, not the source.** The design enumerates the security-relevant
decisions slurmd makes and, for each, every channel that can influence it. That grid
is closeable and lives in [`slurm-broker/`](../slurm-broker/); a list of dangerous
options is not.

Resource validators check **shape, not magnitude** (`v_array` accepts `1-100000`) —
magnitude is bounded by C3.4.

### C3.2 — the guard is the execution, not a file
defends every compute-side control · **load-bearing** · `P3`

husk submits its own fixed wrapper **on stdin** as the batch entry point and runs the
agent's body as **data read inside the cage**. The agent authors none of the bytes
slurmd executes, and there is no staged path to substitute.

### C3.3 — confine, do not merely forbid
defends H7 · **load-bearing** · `P3`

`--output`/`--error`/`--chdir` cannot be forced to constants without breaking the
workflows husk exists to serve. So husk validates, canonicalises, and emits its own
option from a confined value: the agent influences the value, contributes no bytes to
slurmd's parser.

Two things make that safe:

1. **The boundary is one the job already has** — the working-directory subtree,
   already bound writable. Only a choice of *where within* the existing blast radius.
2. **Nothing is validated that someone else re-expands.** SLURM expands `%j`, `%x`
   *after* husk checks the string, so `%` is refused in directory components and the
   specifier allowlist excludes `%x`.

slurmd writes these files **as the user, outside the cage** — an unconfined output
path is an uncaged arbitrary-write primitive. Residual TOCTOU and its three
mitigations are in threat-model §9.

Out-of-subtree requests are **rejected with a teaching message**, not silently
replaced (`P11`). Refusal messages carry no host facts — no target path, no errno, no
absent-vs-present tell — because the message is otherwise an existence oracle. See
C6.3 for how the two constraints are reconciled.

**Native `sbatch` is the reference.** Where husk diverges without a security
argument, husk is wrong.

### C3.4 — the forced partition carries the resource envelope
defends H3 · **load-bearing** *given a correctly chosen partition*

Every brokered job is forced onto one partition (`HUSK_SLURM_PARTITION`, recorded at
install under `~/.local`, agent-inaccessible). A **preemptible** partition makes the
property structural: the job is interrupted by any job on any other partition, so the
agent cannot block the machine. The scheduler enforces it continuously, for free.

Default `preemptible`, so an install that configures nothing lands on the guarantee.
Balfrin: `preemptible`. Santis: no such partition — `debug` or `shared` must be set.

**Two consequences in the threat model:** the guarantee is a property of the
configured partition and nothing in husk checks it (§7.2); and preemption becomes a
correctness risk, H11 (§7.4).

*Roadmap:* an operator-recorded allow-**set** the agent may choose from — the
option-registry pattern applied to a value.

### C3.5 — `scancel` gated on provenance
defends H10 · **load-bearing** · `P5` · asserted by `spool.rs::cancel`

The gate cannot be permission — SLURM correctly grants it, since agent jobs and
production jobs share one uid. So the broker refuses every id it did not itself
submit this session. Array tasks and steps map back to their base id first.

- **Default-deny on the option surface:** any argument starting with `-` refused
  outright; the code enumerates nothing, so a future `--filter` fails closed.
- **Grammar, not sanitising:** `<digits>[_<digits>|.<digits>]`, ≤20 digits.
- **All-or-nothing:** one unowned id refuses the whole request, so ownership cannot be
  probed by watching which of a batch died.

### C3.6 — read-only queries are constructed, not forwarded
defends H2 · **load-bearing** · `P5` · asserted by `policy::query_spec`

"Read-only" describes what a command does to the **scheduler**, not the filesystem.
`sacct --completion --file=X` reads X; `--batch-script` prints any job's stored
script. Forwarding the agent's argv made husk a read oracle running outside the cage
as the user. Per-verb option allowlist, values charset-checked with **no slash**,
re-emitted as canonical `--long=value`.

### C3.7 — submission environment built from an allowlist
defends H2, AV7 · **load-bearing** · `P5`

Constructed from an allowlist, not inherited and stripped of four names. The
four-name denylist leaked `GH_TOKEN` and a live `SSH_AUTH_SOCK` into every job.
The drop list is **printed loudly with the remedy** — an allowlist is wrong on every
new site until measured there (Balfrin dropped 82 login variables including
`$SCRATCH`; Santis then dropped Lmod's serialised module table, which Balfrin does
not set).

### C3.8 — watchdog on every external invocation
defends availability · **depth** · `P6`

`run_sbatch` runs under a watchdog and its own process group, as `run_query_cmd`
already did. Without it a hung submission wedged the single-threaded broker
indefinitely, including `scancel`. `#SBATCH --wait` reaches this.

---

## Surface 4 — the compute cage

Applied by the guard husk submits. Base shape: `--ro-bind / /`, `--tmpfs /users`,
`--bind <trusted project dir>` plus `allowWrite` roots, credential denies, env
masking, symlink guard, `--dev-bind-try /dev/nvidia*`, `--unshare-net`,
`--die-with-parent`.

### C4.1 — the writable root comes from a trusted origin
defends meta, H4, H7 · **load-bearing** · `P2` · asserted by two tests that previously
pinned the broken behaviour and had to flip

The write root is the directory **husk was launched from**, captured before the agent
ran — not `req.cwd`. `is_workdir_allowed` is applied to the value that becomes the
bind, and paths are **normalised before** any floor comparison (raw string compares
let `//`, `..`, `/./` walk the predicates). The egress proxy resolves its allowlist
from the trusted project dir, not `$PWD`.

### C4.2 — write model and floor filtering
defends H2, H4 · **load-bearing**

`allowWrite`/`denyWrite`, default-deny. Config values are floor-filtered **before**
becoming mounts: a `denyWrite` under the floor was previously emitted as a
`--ro-bind`, which *exposes* its source — `denyWrite: ["/users"]` re-exposed every
home. `allowWrite: ["/"]` is refused with a message stating what it would have cost.

### C4.3 — credential and auto-exec masking (F1, F3, F4, F5, F6a, F6b)
defends AV1, AV2, AV5 · **load-bearing** · `P5` (F6b)

- **F1/F3** — declared credential files and `denyRead` files → `/dev/null`
- **F4** — declared `credentials.envVars` → `--unsetenv`
- **F5** — symlinked carve-outs dropped. Bind-*source* symlinks are the only ones
  that escape; runtime symlinks the job creates are namespace-confined, and the
  `/users` tmpfs neutralises any pointing into a home.
- **F6a** — bounded credential auto-scan: **workdir only**, depth- and
  file-count-capped, fail-safe. Compute rebuilds per **job** with binds frozen
  mid-job, so it is structurally scan-once; login rebuilds per **command** and
  re-scans.
- **F6b** — auto-exec files write-protected, **masked by shape**: a real repo gets
  hooks masked and config protected; a `.git` *file* (ordinary worktree) is bound
  read-only, because a tmpfs under a file made bwrap fail and took the cage down;
  anything absent is masked whole.

Two rules learned expensively, generalising beyond git:

1. **Protected-if-present is not protection.** `--ro-bind-try` silently skips a
   missing file, so every auto-exec file not normally present stayed plantable.
   Anything harmless when empty is now masked with an empty file.
2. **Do not create the thing you are defending.** bwrap creates the mountpoints it is
   given, so a mask aimed *inside* a `.git` brought that `.git` into existence — which
   created the repository the v0.5 plant needed.

The mask remains a denylist; recorded as residual in threat-model §9.

### C4.4 — the unit of confinement is the job on a node
defends AV8, H1 · **load-bearing** · `P1`

All ranks of one MPI job are one trust domain, so the job gets **one shared user
namespace**. Only the user namespace is shared; mount and network namespaces stay per
task.

The **job** cage takes `--unshare-pid`. A **rank** must not — it would put each rank
in its own namespace, unable to name its peers. A rank joins via
`bwrap --userns <holder>/ns/user --pidns <holder>/ns/pid`.

**Joining must be fail-closed** — the one genuinely new risk the design introduces.
With a cage per task, failing to build it means the task does not run; when a task
*joins*, a bug could let it run **outside**, silently. Two guards, both tests: the
task refuses to start if the holder's namespace is unreadable, and `bwrap --userns`
exits rather than inventing a namespace.

**Scope of the CMA concession, exactly:** a rank can read the memory of the other
ranks of its own job and nothing else — not the broker, not an uncaged process, not
another job's ranks (separate holder → siblings → `EPERM`). The exemption is
`--profile=single-node` only, and a smoke test pins that it cannot leak into
`--profile=login`. Verified from both sides: `cma.peers` and `cma.outside`.

### C4.5 — cage lifecycle
defends availability, AV4 · **load-bearing** · `P6`

`--die-with-parent` on both cages; the `/dev/shm` directory owned and released via
`Drop`; the holder reaps by disposition or `SIG_IGN`; the cached holder pid
liveness-checked before reuse; `TunnelSlot` returns its slot however the thread ends.

The `/dev/shm` ownership check is **symlink-safe**. It was not: `[ -O "$_d" ]` follows
symlinks, so a co-tenant's planted `/dev/shm/husk-<jobid>` symlink landed a victim
directory read-write in every rank — read a secret and wrote back, end to end. **The
only cross-user break the v0.5 review found.**

The holder is torn down with `SIGKILL`, not `SIGTERM`: from an ancestor namespace
those are the only two signals a handler-less PID 1 cannot ignore. A `SIGTERM`,
including one delivered by `PDEATHSIG`, is discarded — which left the holder
outliving its parent on every job until it was measured.

### C4.6 — announce the boundary
defends diagnostic correctness · **depth, but treat as a requirement** · `P11`

The cage states its own boundary inside the job: a banner listing every writable path,
and `HUSK_WRITABLE` in the environment. A **list**, not a root — `allowWrite` adds
paths beyond the project dir, and announcing one root would be a new way to mislead.

The banner names the **gaps and the shape of each**, because reads are not literally
unrestricted and the three exceptions fail differently: a masked home or `denyRead`
path is an **empty directory**; a credential file reads **empty or `EACCES`** depending
on how it was bound; a path under a hidden home is **`ENOENT`**. An agent promised
unrestricted reads diagnoses all three as "the file isn't there" and looks elsewhere.
*The banner previously claimed reads were unrestricted; that claim is what made this
expensive.*

Two things deliberately **not** done:

- **No `LD_PRELOAD` to attribute `EROFS`** — fails for static binaries and under MPI
  launchers, and means injecting code into the cage to improve an error message.
- **No preflight scan of the script for write targets** — that secures our *model* of
  shell rather than shell itself, and a false negative reads as approval.

The partition guard is the standard to match: names the constraint, names the fix,
fires at submit time before compute is burned.

---

## Surface 5 — egress

```
rank/job cage (--unshare-net: no route at all)
  socat TCP-LISTEN:3128 ──► /tmp/husk-<uid>-<jobid>/net.sock ──► husk proxy ──► internet
        (dumb relay)          (a FILE, not a route; ro-bind)     (outside the cage)
```

### C5.1 — one hole, of a shape husk chooses
defends H6, H5′, AV6 · **load-bearing** · asserted by `selftest.sh` — `net.live` plus
three negative arms

Off by default. When configured, the single hole is a **unix socket**, which crosses
the network namespace because it is a filesystem object — the same reasoning that
makes the `/run/munge` mount mask load-bearing rather than a syscall filter.

It lives in a short, node-local, owner-only directory rather than the step spool: a
unix address must fit `sun_path` (108 bytes, kernel-fixed) and the spool path spent
enough of that budget that a slightly deeper project would have lost its network with
no explanation; and the spool is inside the workdir, which the cage binds writable, so
the job could replace its own socket. The directory is bound read-only —
`connect(2)` still works through a read-only bind. `/tmp` is world-writable and job
ids are public, so husk **creates** the directory rather than accepting one, and the
proxy re-checks owner and mode before binding.

Three properties asserted, not assumed:

1. **The hole is the only hole** — a direct connection from inside must still fail.
   If it ever succeeds, the allowlist is decoration.
2. **An unlisted host is refused with a 403**, not a timeout (`P11`).
3. **SLURM daemon ports are refused, including under `*`** — AV8 as a test.

### C5.2 — policy outside, relay inside
**load-bearing** · `P2`

The allowlist is enforced outside the cage, read from files the agent cannot write.
The relay inside carries no policy: one proxy per node, one relay per rank, and **what
must never be duplicated is the decision**.

Accepts **host-or-IP plus port** — a self-hosted model endpoint is an internal address
with no SNI. `*` available for sites choosing open egress; scheduler ports refused
regardless. The agent can surface a denial but cannot widen the list.

**Known limitation, by design:** `CONNECT` only, so `https://` works and plain
`http://` does not — serving an absolute-URI `GET` means a second HTTP parser, exactly
the shape `P5` exists to avoid. The refusal names `https://` so it is actionable.

**What this does not give:** control over *what* a job says, only *where*. Content
control needs TLS termination — ROADMAP 6b, where it also buys credential injection so
an agent can use an API key it never sees.

### C5.3 — layers must be independent
design constraint

`--unshare-net` will be relaxed. **The filesystem cage must therefore protect
confidentiality on its own, assuming exfiltration is possible.** No secret's safety
may depend on "there is no network."

---

## Surface 6 — audit

### C6.1 — session transcripts
defends forensic coverage of H2, H3, H4, H7, H8 · **depth**

Per-session JSONL at `~/.claude/projects/<encoded-path>/<session-id>.jsonl`: every
prompt, tool call with arguments, result, and model response. No admin cooperation
needed.

**Does not cover:** subprocess-level activity; the wire (the relay does not log by
default); real-time alerting — review is forensic only.

**Sensitivity.** Transcripts contain verbatim prompts and anything pasted into them.
Over time this is a comprehensive behavioural record — writing style usable as a
stylometric biometric, research direction, occasionally a secret the user did not
realise they pasted. Treat the directory as sensitive personal data. The installer
displays a notice.

### C6.2 — broker log
**load-bearing for provenance** · `P2`

Lives under `$HOME`, **not** in the agent-writable spool — the audited party must not
be able to rewrite its own audit trail. Records forced argv, refusals with reasons,
submitted ids, and the broker's build stamp (a session keeps the broker it started
with, so a reinstall does not touch a running session; the crate version alone could
not distinguish a stale broker from a current one).

### C6.3 — split the audience
defends H2 · **load-bearing** · `P11` + `P2`

The confined party gets the teaching message; the operator gets the detail, on a
channel the confined party cannot read. This resolves the A7-1 tension directly: a
confinement refusal that quoted the resolved host path was an existence oracle for the
paths the cage exists to hide — `~/.ssh` present, `~/.gnupg` absent, one probe each.
Both constraints are real; the split is what satisfies them at once.

---

## Operational constraints

Threat-model §7, in the form of things to do.

| do | why | check |
|---|---|---|
| Choose a write root you know the contents of | the AV2 mask is a denylist; husk refuses a home but cannot audit yours | read the banner husk prints |
| Confirm the partition is actually preemptible | H3 rests on it; nothing in husk verifies it | `scontrol show partition <name>` + QOS preempt settings |
| Activate uenv/modules **before** `husk` | the broker inherits the launching shell's environment; the agent cannot mount one from inside the cage | — |
| Keep precious data outside the writable set | H4 has no in-cage defence — the project dir *is* the working surface | paths outside `/users` are readable via the root bind with no `allowRead`; paths inside `~` need one |
| Back up before an unattended run | the cage takes no snapshot | — |
| Maintain the egress allowlist yourself | the agent cannot, deliberately | — |
| Keep job scripts and their imports read-only to the agent | belt and braces: pass the agent's choices as **validated data**, not as a code path | absolute path outside the project dir |
| Read the env drop list on a new site | an allowlist is wrong until measured there | printed at submit |

---

## Controls asserted by prose only

A control with no test is a claim (`P9`). Listed so the list can shrink.

- **C0.1** tool allowlist — nothing asserts that only `Bash` is exposed
- **C3.4** partition preemptibility — unverifiable in husk by construction; belongs in
  an install-time warning rather than a test
- **C6.3** audience split — no arm asserts that a refusal reaching the agent contains
  no host fact

The v0.5 review found **five tests that passed while unable to detect the thing they
covered** (`P9`, `P10`). Every fix now lands with an arm that has a **demonstrated
failing state** — a planted marker, a sent signal, a generated table.
