# C1 — findings: the real remaining delta to dropping Anthropic's runtime

**Pass 1 (discovery). Code-only, laptop. Comparison target: `sandbox-runtime/` (vendored,
`295f0e1`, package version 0.0.67) vs husk at `f5fd395`.**

## Summary

The delta is **not** "fs telemetry plus login plumbing". It is larger and more specific:
**husk has no login-node cage of its own at all.** The compute side is genuinely
reimplemented — mount table, allowlist, egress proxy, shared namespaces — but on the login
node husk contributes exactly three things (a session-wide syscall deny-list, a
bind-mounted `sbatch` stub, and a JSON file written into `~/.claude/settings.json`), and
*everything that actually confines a Bash command* — the `--ro-bind / /` root, the
`--unshare-net` + socat bridge, the PID namespace, `--new-session`, the AF_UNIX block, the
mandatory deny set — is built by the Claude-Code-bundled runtime from that JSON. Six
delta items are boundaries and block 6a; four are features; nine are not needed. The
sharpest structural result is that 6a deliverable (iii) — a **session**-level wrap — is in
direct tension with the one control that is inherently **per-command** (AF_UNIX blocking),
so that deliverable is not a plumbing swap. The trap check comes back positive in an
unexpected place: husk's *own* trusted layer already runs a Lustre directory walk
(`scan_credentials`), so "dropping their runtime fixes the freeze" is only half true.

---

## THE LIST

`B` = boundary, `F` = feature. "Blocking" = blocks 6a. "CC" = Claude-coupled (also a 6b
problem). Login and compute are scored separately where they differ, because *every*
missing row is missing on the login side only.

### A. Policy source and schema

| # | Their component | Their file | Status | B/F | Blocking | CC | Ours |
|---|---|---|---|---|---|---|---|
| 1 | Policy schema (`sandbox.filesystem/network/credentials/seccomp`) + loader | `src/sandbox/sandbox-config.ts`, `src/utils/config-loader.ts`, `src/cli.ts` (`~/.srt-settings.json`) | **MISSING** (login). Compute parses a *subset* of the same schema | B | **yes** | **yes** — path `.claude/settings.json`, schema is theirs | `slurm-broker/broker/src/settings.rs:278` (`SETTINGS_SOURCES`), `user-config/settings.json`, `scripts/merge-claude-settings.py` |
| 2 | Mandatory write-deny set (`DANGEROUS_FILES`, `.git/hooks`, `.claude/commands`, `.claude/agents`, `.vscode`, `.idea`) | `src/sandbox/sandbox-utils.ts:11-40`, `src/sandbox/linux-sandbox-utils.ts:269` | **MISSING** (login). Compute has a *superset*, expressed as mounts | B | **yes** | partial (`.claude/*`) | `slurm-broker/broker/src/settings.rs:131` (`AUTO_EXEC_DIRS`), `:145` (`AUTO_EXEC_RO_FILES`) |
| 3 | Default write paths + `TMPDIR` override (`/tmp/claude`, `~/.npm/_logs`, `~/.claude/debug`, `/dev/{null,tty,stdout,stderr}`) | `src/sandbox/sandbox-utils.ts:399`, `:443` | **MISSING** | F (compat) | no — but the "naked Claude" check will hit it | **yes** (`/tmp/claude`, `~/.claude/debug`, `CLAUDE_CODE_TMPDIR`) | none; compute cage uses `--tmpfs /tmp` (`settings.rs:602`) |
| 4 | `safe.directory` git-config env under a userns | `src/sandbox/sandbox-utils.ts:675`, `:741` | **MISSING** | F (functional) | no, but git breaks silently under any userns wrap | no | none |
| 5 | Glob expansion of policy paths (`readdirSync recursive`) | `src/sandbox/sandbox-utils.ts:825` | **NOT NEEDED — must not be adopted** (see trap) | — | — | — | husk policy paths are literals |

### B. Mount table and namespaces

| # | Their component | Their file | Status | B/F | Blocking | CC | Ours |
|---|---|---|---|---|---|---|---|
| 6 | bwrap fs arg construction (ro-root, write binds, tmpfs denies, `/dev/null` file masks, symlink/nonexistent-deny handling) | `src/sandbox/linux-sandbox-utils.ts:899` (`generateFilesystemArgs`) | replicated (compute) / **MISSING** (login) | B | **yes** | no | `slurm-broker/broker/src/settings.rs:597` (`bwrap_args`) |
| 7 | `--new-session` and `--die-with-parent` | `src/sandbox/linux-sandbox-utils.ts:1467` | **MISSING everywhere in husk** (0 occurrences repo-wide) | B | **yes** | no | none — cage line is `slurm-broker/broker/src/policy.rs:894` |
| 8 | `--unshare-pid` + `--proc /proc` | `src/sandbox/linux-sandbox-utils.ts:1647-1657` | replicated (compute, job cage) / **MISSING** (login) | B | **yes** | no | `slurm-broker/broker/src/settings.rs:631` |
| 9 | `--unshare-user --cap-drop ALL` | `src/sandbox/linux-sandbox-utils.ts:1657` | **NOT NEEDED** — only defends a root parent; bwrap auto-creates the userns and drops caps when EUID≠0. Keep the *inverse* rule (never root-map) | — | — | — | `slurm-broker/broker/src/cage.rs:106` (`identity_map`), `husk-slurm-wrapper.rs:292` |
| 10 | The wrap mechanism itself (per-Bash-command bwrap) | `src/sandbox/linux-sandbox-utils.ts:1404` | **already replaced in husk** — session-level user+mount ns exists and is fail-closed | — | — | no | `slurm-broker/broker/src/bin/husk-slurm-wrapper.rs:292` (`enter_user_mount_ns`), `:262` (`SandboxReady`) |

### C. Network

| # | Their component | Their file | Status | B/F | Blocking | CC | Ours |
|---|---|---|---|---|---|---|---|
| 11 | HTTP CONNECT proxy + allowlist decision point | `src/sandbox/http-proxy.ts`, `sandbox-manager.ts:185` (`filterNetworkRequest`) | replicated (compute) / **MISSING** (login) | B | **yes** | no | `slurm-broker/broker/src/netproxy.rs`, `netallow.rs` |
| 12 | Host pattern grammar, `:port` suffix, control-char + `inet_aton` canonicalization | `src/sandbox/domain-pattern.ts` | replicated (deliberately, per its own header) | B | no | no | `slurm-broker/broker/src/netallow.rs:22-29` |
| 13 | `--unshare-net` + socat bridge + in-cage listeners + `HTTP_PROXY`/`NO_PROXY`/`GIT_SSH_COMMAND` env generation | `src/sandbox/linux-sandbox-utils.ts:599` (`initializeLinuxNetworkBridge`), `:781` (`buildSandboxCommand`), `sandbox-utils.ts:443` | replicated (compute, incl. the socat-in-cage bind) / **MISSING** (login) | B | **yes** | no | `slurm-broker/broker/src/policy.rs:643-760` |
| 14 | SOCKS5 proxy (git-over-ssh, non-HTTP protocols) | `src/sandbox/socks-proxy.ts` | **MISSING** | F | no — husk deliberately refuses non-CONNECT | no | none (`netproxy.rs` header states the refusal) |
| 15 | HTTP/SOCKS mux on one port + `listenInRange` | `src/sandbox/mux-proxy.ts`, `listen-in-range.ts` | **NOT NEEDED** — husk's proxy listens on a unix socket, not a loopback TCP port | — | — | — | `slurm-broker/broker/src/netproxy.rs` |
| 16 | Per-session proxy auth token | `sandbox-manager.ts:127`, `sandbox-utils.ts:453` | **NOT NEEDED** — same reason as 15 (fs permissions replace the token) | — | — | — | — |
| 17 | Upstream/parent proxy chaining + `NO_PROXY` CIDR rules | `src/sandbox/parent-proxy.ts` | **MISSING** | F | no *unless* CSCS requires a site egress proxy — **unverified, worth one question to CSCS** | no | none |
| 18 | TLS termination / MITM CA / leaf minting | `src/sandbox/tls-terminate-proxy.ts`, `mitm-ca.ts`, `mitm-leaf.ts` | **MISSING** | F | no (explicitly out of scope; 6b / C2) | no | none |
| 19 | `filterRequest` per-request hook, `body-substitution.ts` | `src/sandbox/request-filter.ts`, `body-substitution.ts` | **NOT NEEDED** (both require TLS termination) | — | — | — | — |

### D. Credentials

| # | Their component | Their file | Status | B/F | Blocking | CC | Ours |
|---|---|---|---|---|---|---|---|
| 20 | Env-var deny/mask + sentinel registry + proxy re-injection | `src/sandbox/credential-mask-env.ts`, `credential-sentinel.ts`, `sandbox-manager.ts:897` | **MISSING** (login), deny-only degradation (compute) | F — see finding 8: this is **new capability**, not replication | no for parity; yes for the stated 6a deliverable (ii) | no | `slurm-broker/broker/src/settings.rs:400-418` (mask→deny) |
| 21 | Whole-file credential masking (`--ro-bind <fake> <real>`, read-only store dir) | `src/sandbox/credential-mask-files.ts`, `linux-sandbox-utils.ts:1256`, `:1349` | **MISSING**; husk denies instead of masking | F | same as 20 | no | `settings.rs:504` (`split_file_denies`), `:868` (`scan_credentials`) |
| 22 | AWS SigV4 re-signing + linked credential pairs | `src/sandbox/aws-sigv4.ts`, `credential-aws-pairs.ts` | **NOT NEEDED** | — | — | — | — |
| 23 | JWT decode / claim masking / extract patterns | `src/sandbox/credential-decode.ts`, `credential-extract.ts` | **NOT NEEDED** | — | — | — | — |

### E. Seccomp

| # | Their component | Their file | Status | B/F | Blocking | CC | Ours |
|---|---|---|---|---|---|---|---|
| 24 | AF_UNIX + io_uring BPF, applied **per Bash command** | `vendor/seccomp-src/seccomp-unix-block.c:99-121`, baked into `apply-seccomp` | **MISSING** at that granularity — see finding 3 | B | **yes** | no | `seccomp-wrapper/src/seccomp_wrapper.c:55-61` (says so itself); wrapper blocks io_uring at session scope (`:179`) but **not** AF_UNIX |
| 25 | Nested user+PID+mount ns, `PR_SET_DUMPABLE=0`, fresh `/proc`, ambient-cap clear, `NO_NEW_PRIVS` | `vendor/seccomp-src/apply-seccomp.c:685-843` | **MISSING** (login). Compute equivalent is the cage holder + `--unshare-pid` | B | **yes** | no | `slurm-broker/broker/src/cage.rs`, `settings.rs:631` |
| 26 | USER_NOTIF write-intent observer + violation store + `<sandbox_violations>` stderr annotation | `apply-seccomp.c:92-119`, `src/sandbox/linux-violation-monitor.ts`, `sandbox-violation-store.ts`, `sandbox-manager.ts:2010` | **NOT NEEDED as a control** (fail-open telemetry, by their own header). Wanted as a **feature**. husk does not receive it today anyway — finding 4 | F | no | no | none |
| 27 | apply-seccomp binary discovery (npm roots, argv0 multicall) | `src/sandbox/generate-seccomp-filter.ts` | **NOT NEEDED** — husk installs to a fixed path | — | — | — | `install-husk.sh:284` |
| 28 | Broad syscall deny-list (ptrace, bpf, kexec, pivot_root, personality ABI switch, …) | *(they have none — this is husk-only)* | husk **exceeds** them here | — | — | — | `seccomp-wrapper/src/seccomp_wrapper.c` |

### F. Platform / support

| # | Their component | Their file | Status |
|---|---|---|---|
| 29 | macOS seatbelt backend | `src/sandbox/macos-sandbox-utils.ts` | **NOT NEEDED** |
| 30 | Windows WFP / `srt-win` / ACL backend | `src/sandbox/windows-sandbox-utils.ts`, `src/cli.ts:52-131` | **NOT NEEDED** |
| 31 | ripgrep invoker | `src/utils/ripgrep.ts` | **NOT NEEDED — must not be adopted** |
| 32 | POSIX shell quoting | `src/utils/shell-quote.ts` | replicated — `slurm-broker/broker/src/settings.rs` (`sh_quote`) |

**Score:** 6 blocking boundaries (rows 1, 2, 6, 7, 8, 11, 13, 24, 25 — nine rows, six
distinct subsystems: policy source, mount table, bwrap hardening flags, login PID
isolation, login egress, per-command AF_UNIX). 4 features (3, 4, 14, 17, 20/21, 26).
9 not-needed.

---

## Findings

### 1. The login cage is 100% theirs, and nothing in husk says so — CONFIRMED

`install-husk.sh` installs **one** binary from their runtime (`apply-seccomp`,
`install-husk.sh:264-298`) and writes a settings file. Everything else at login is built by
the Claude-Code-bundled runtime from `~/.claude/settings.json`
(`scripts/merge-claude-settings.py:105-107`). Concretely, husk currently *inherits* from
them, at login, with no husk-side code for any of it: the `--ro-bind / /` root, the
`--tmpfs /users` read-deny, `--unshare-net` plus the socat bridge pair and the mux proxy
enforcing `allowedDomains`, `--unshare-pid --proc /proc`, `--new-session
--die-with-parent`, the mandatory deny set, `TMPDIR=/tmp/claude`, and the AF_UNIX block.
The repo's own framing ("husk builds on … the login sandbox installs and runs its
`apply-seccomp` helper", `README.md:296`) understates this by a wide margin — it names the
one piece husk *ships* and omits the six subsystems husk *depends on*.

**Why this is the answer to the brief's question, not just background:** the believed
remaining delta ("fs telemetry plus login plumbing") is scoped as if husk already had a
login boundary that needed accessories. It does not have one. 6a is "build the login
cage", not "finish the login cage".

### 2. `--new-session` is a two-word boundary nobody has written down — CONFIRMED

Their wrapper opens with `const bwrapArgs = ['--new-session', '--die-with-parent']`
(`linux-sandbox-utils.ts:1467`) — unconditional, un-configurable, never mentioned in their
README's security section. `grep -rn 'new-session\|die-with-parent\|TIOCSTI'` over
`slurm-broker/`, `seccomp-wrapper/` returns **zero hits**.

`--new-session` calls `setsid()` so the sandboxed process has no controlling terminal.
Without it, a process inside the cage can `ioctl(fd, TIOCSTI, …)` on an inherited tty fd
and push characters into the *user's* terminal input queue — they execute in the user's
shell, outside the cage, after the agent exits. `dev.tty.legacy_tiocsti` defaults to 0 only
from kernel 6.2; **Balfrin runs 5.14** (recorded in `ROADMAP.md`, holder-dumpable note), so
this is live there, not theoretical. It is exactly the class of thing a reimplementation
loses silently, because it is not in any config file and produces no error.

`--die-with-parent` is the lifecycle half (B1's territory): without it a bwrap cage
outlives the agent that made it.

**Closeable as:** two flags on the 6a login cage, plus one selftest arm that asserts the
process has no controlling tty inside the cage.

### 3. 6a deliverable (iii) is in tension with the AF_UNIX block, not merely a plumbing swap — CONFIRMED

The AF_UNIX block is **inherently per-command**. `seccomp_wrapper.c:52-61` says so in its
own words: `PROFILE_LOGIN` cannot block AF_UNIX because "the husk launcher wraps the whole
agent SESSION … and the agent runtime legitimately uses unix sockets for its own IPC (MCP
servers, IDE integration)". Their design resolves this by applying the filter *inside* each
Bash command, after socat has already opened its sockets (`linux-sandbox-utils.ts:781-812`,
`apply-seccomp.c` process layout).

6a's stated deliverable (iii) is "a **session-level** wrap rather than their
per-Bash-command bwrap". Those two statements cannot both hold as written: a session-level
wrap has exactly the granularity that `seccomp_wrapper.c` says makes the block impossible.
The comment's own resolution — "When ROADMAP step 5 drops their runtime, this profile takes
that block over at the same granularity" — presupposes husk keeps a per-command hook it
would no longer have.

Three ways out, all of which are design decisions rather than plumbing, and none of which
is currently written down:
(a) husk keeps a per-command wrap for Bash only (a `husk-exec` helper the agent's Bash tool
is pointed at) — closest to theirs, but requires an agent-side hook, which is CC;
(b) drop the block and rely on destination masking (the reasoning the compute side already
adopted — `seccomp_wrapper.c:404-412`: the MUNGE *mount* mask was the load-bearing control
and AF_UNIX blocking cost GPU support). At login the relevant destination is the ssh-agent
socket, the Docker socket, and any daemon in `/run` — maskable by mounts;
(c) accept the loss and record it as a residual.

**This is the single highest-leverage item in the brief**: (b) is probably right and is
consistent with the project's own hard-won principle, but choosing it means 6a *reduces*
the login syscall boundary, and that should be a deliberate, recorded decision rather than
a discovery after the runtime is gone.

### 4. Two unpinned, mutually inconsistent version couplings to their runtime — CONFIRMED

`install-husk.sh:188` pins `SANDBOX_RUNTIME_VERSION="0.0.49"` and extracts `apply-seccomp`
from that tarball, with a SHA-512 lock. Meanwhile:

- The USER_NOTIF observer landed in `apply-seccomp.c` at **0.0.57** (`git show
  1640f71:package.json`). A 0.0.49 binary ignores `SRT_OBSERVE_SOCK` entirely. So the fs
  telemetry the brief calls "a feature husk may want" is a feature **husk is already
  configured for and silently does not receive** — the newer bundled runtime sets the env
  var and binds the socket (`linux-sandbox-utils.ts:1500-1517`), the older binary drops it,
  and every failure path there is fail-open. Nothing reports the mismatch.
- `user-config/settings.json:23` ships `"opendatadocs.meteoswiss.ch:443"`. The `:port`
  suffix grammar landed at **0.0.67**, 2026-07-24 (`f869f5a`). Before that,
  `domainPatternSchema` **rejects any value containing `:`** (`git show
  f869f5a~1:src/sandbox/sandbox-config.ts:16-21`). So husk's shipped allowlist requires
  ≥0.0.67 while its shipped binary is 0.0.49.

Checked against the Claude Code build on this laptop (2.1.220, 2026-07-25): the bundle
contains `hostPattern` and `lastIndexOf(":")` — `hostPattern` has **zero** occurrences
pre-0.0.67 — so this build does carry the port grammar and the entry works *here*. It also
contains `SRT_OBSERVE_SOCK`, confirming the observer half of the mismatch is real.

The finding is not "it is broken today"; it is that **husk's policy file is written against
a third-party schema version husk neither pins nor checks**, and both failure modes are
silent: a dropped allowlist entry looks like a network fault, a dropped observer looks like
"no violations". Dropping the runtime removes this coupling entirely — a real, previously
unstated benefit of 6a.

### 5. The session-level wrap already exists, and its design note will become stale the day the runtime goes — CONFIRMED

`husk-slurm-wrapper.rs:292` (`enter_user_mount_ns`) already unshares `CLONE_NEWUSER |
CLONE_NEWNS` for the whole session, identity-maps uid/gid, bind-mounts the stub over
`sbatch`, verifies it by dev+inode, and gates the agent `exec` on a `SandboxReady` witness
(`:262`). `doc/sandbox-interface.txt:57-72` documents the inheritance property this relies
on. So 6a (iii) is **mechanism-complete**: what is missing is the policy mounts, not the
namespace, not the fail-closed exec path.

Two attached notes:
- The identity map is not merely good hygiene, it is a **workaround for a behaviour of
  their runtime**: `husk-slurm-wrapper.rs:283-289` records that a root map makes their
  runtime take its `--cap-drop ALL` branch, emptying the bounding set so `apply-seccomp`
  cannot write `uid_map`. When the runtime goes, that *specific* causal chain goes with it —
  but the rule must stay for its own reasons (least surprise, file ownership). The comment
  will read as stale justification for a rule that is still correct. Worth rewriting at 6a,
  not deleting.
- The wrapper's namespace is entered **only on the SLURM path** (`exec_plain`,
  `husk-slurm-wrapper.rs:334`, takes no namespace). A 6a login cage must move the unshare
  ahead of the SLURM branch.

### 6. Trap check: husk's own trusted layer already runs a Lustre directory walk — CONFIRMED

The brief asks whether a proposed 6a design would reintroduce the deny-set walk. It is
already here, in husk, today:

`settings.rs:868` `scan_credentials` → `scan_credentials_rec` does a recursive
`std::fs::read_dir` of the project directory, `SCAN_MAX_DEPTH = 4`, `SCAN_MAX_ENTRIES =
20_000` (`:821-822`). It runs from `FsPolicy::resolve` (`:523`), called at
`main.rs:465` — **broker startup, on the login node** — and again at `main.rs:427` for each
step-broker on a compute node.

It is materially better than theirs (once per session, not once per Bash command; hard
entry budget; symlinks not followed; truncation reported, `:535`), and it is not what
caused the observed freeze. But the shape is identical to `linuxGetMandatoryDenyPaths`
(`linux-sandbox-utils.ts:269`, `--max-depth 3`), and a 20 000-entry `read_dir` walk over
Lustre at `husk` startup is exactly the operation the freeze taught us to distrust. **The
claim "dropping their runtime fixes the Balfrin lag" is therefore only true for the
per-command half.** Recommend a bounded-time budget (not just an entry budget) as the
closing condition, and an explicit note in the 6a design that this is the one walk husk
knowingly keeps and why.

### 7. What the ripgrep walk actually buys is small and precisely nameable — CONFIRMED

`linuxGetMandatoryDenyPaths` (`linux-sandbox-utils.ts:269-387`) builds its deny list in two
halves. The first is **static**: `DANGEROUS_FILES.map(f => path.resolve(cwd, f))` plus
`getDangerousDirectories()` plus `cwd/.git/hooks` and `cwd/.git/config` (`:282-310`) — no
scan involved. The second is the ripgrep call (`:333-346`), whose *entire* marginal value is
dangerous files in **subdirectories** of cwd, to depth 3, excluding `node_modules`.

So a 6a policy layer that emits the static half as mounts loses exactly one thing: a nested
`.git/hooks/`, `.claude/commands/`, `.vscode/` or `.gitconfig` inside a subdirectory of the
project. husk's compute cage already answers this the right way — mask the *directory*
relative to each writable root with a fresh tmpfs (`settings.rs:101-136`), which is
absent-safe and needs no enumeration. The residual (nested repos / nested `.claude`) is
small, statable, and can be closed later by masking the directory names at each level of
the writable roots rather than by searching for them.

**This is the concrete form of the "mounts, not a scanned deny-set" rule for 6a**, and it
comes with a named residual rather than a hand-wave.

### 8. 6a deliverable (ii) is new capability, not replication — CONFIRMED

`user-config/settings.json` declares **no** `sandbox.credentials` block. Their credential
machinery (`credential-mask-env.ts`, `credential-mask-files.ts`, `credential-sentinel.ts`,
~1 200 lines) is therefore entirely dormant in husk's login configuration: at login,
credential protection is `denyRead: ["/users"]` plus Claude Code's *permission-layer* globs
(`user-config/settings.json:41-80`), which bind the `Read`/`Edit` tools and **not** `cat`
inside a Bash command. Nothing is lost by dropping their runtime here.

The asymmetry is worth stating on its own: **husk's compute cage is currently stricter about
credentials than its login cage** — `scan_credentials` auto-denies `.env`/`*.pem`/… in the
workdir on a compute node (`settings.rs:517-528`), with no login-side equivalent. 6a
deliverable (ii) closes that gap in husk's favour; it is not a parity item and should not be
scored as blocking.

### 9. `TMPDIR` / default write paths are a functional dependency the "naked Claude" check will hit — PLAUSIBLE

`getDefaultWritePaths()` (`sandbox-utils.ts:399`) unconditionally adds `/tmp/claude`,
`~/.npm/_logs`, `~/.claude/debug` and the `/dev` character devices to the writable set, and
`generateProxyEnvVars` sets `TMPDIR=/tmp/claude` whenever a write policy exists
(`:461-467`). A session-level husk cage that mounts a read-only root without these will
break every tool that writes a temp file, and the failure will look like a tool bug rather
than a policy denial. The compute cage sidesteps this with `--tmpfs /tmp`
(`settings.rs:602`); the login cage will need the same, plus a decision about `~/.claude`
(which husk otherwise wants write-denied — `user-config/settings.json:15-19`, and
`AUTO_EXEC_DIRS` masks `.claude` wholesale on compute). Marked PLAUSIBLE because the exact
set of paths Claude Code needs writable at login is not derivable from this repo; it is
precisely what the ROADMAP's "naked Claude" check should measure.

---

## Notes for triage

- Rows 7, 24, 25 are the ones a reproducer can settle cheaply on a laptop: `bwrap
  --ro-bind / / -- sh -c 'tty'` with and without `--new-session`; `socket(AF_UNIX)` inside
  `seccomp-wrapper` vs inside `apply-seccomp`.
- Finding 4's version arithmetic is fully checkable from the vendored git history and
  `install-husk.sh` — no cluster needed.
- Finding 3 is a design question, not a bug. Triage should test the *claim* (that a session
  wrap cannot supply per-command AF_UNIX blocking), not the recommendation.
- Upstream is moving under the snapshot: a `transparent network capture` feature (`63e64be`,
  0.0.64) exists on a branch that is **not** an ancestor of the vendored HEAD, and the
  `remove-bwrap-socat` branch is already noted elsewhere. Neither changes the delta, but the
  vendored clone should not be treated as "the" runtime.
