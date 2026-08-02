# C3 — agent neutrality: the 6a acceptance test

**Pass 1 (discovery). Code-only, laptop, no cluster access. No source file was modified.**
Scope = the 44 tracked husk files (`git ls-files`). `sandbox-runtime/` and `uenv/` are
untracked local clones of third-party repos and are not husk; they are excluded.

---

## Summary — the acceptance test, answered

**husk fails the test, and not narrowly.** The test asks whether `claude` appears anywhere
except one row of a three-column table (binary to exec · config dir to allow · API hosts to
allowlist). It appears in **9 of 44 tracked files and in ~100 lines**, of which roughly 60 are
comments or docs (correctly weightless) — but **13 distinct shipped-code couplings sit outside
the three columns**, spread over 8 files. Worse, the table itself does not describe the real
shape: column 2 is not "a config dir to allow", it is **a vendor JSON schema that husk parses
as its policy source, in three files, with a merge order, plus a directory name that is
load-bearing as a security mask**; and **column 3 is empty** — husk does not manage the login
agent's API egress at all today (that is C2's gap), so there is no hosts list to swap. The
single genuinely one-row item is column 1: the literal binary name, hardcoded at three `exec`
sites in the generated launcher rather than parameterised.

The honest headline is stronger than "more coupled than the axiom implies": **on the login
node, husk does not implement a filesystem boundary at all.** It configures the confined
party's own runtime to implement one (`user-config/settings.json` → `~/.claude/settings.json`),
and for the agent's *native* file tools that boundary is a **prompt**, not an enforcement
(`doc/constraints.txt:100-108`). The compute side is genuinely husk's and is genuinely
agent-neutral in mechanism — `rank.rs`'s environment handling is the model — but it still reads
its policy out of the vendor's schema and defends the vendor's directory name by hardcoded
string.

Two couplings are the ones that would actually bite during 6b, and neither is findable by
grepping for `claude`: **`STRIPPED_SUBMIT_ENV`** (`spool.rs:391-396`) is a four-name denylist,
so a second agent's API token rides into every compute job by default; and
**`AUTO_EXEC_DIRS`** (`settings.rs:131-136`) is a four-name denylist of config directories, so
a second agent's config directory is left writable-and-persistent inside the cage, reopening
AV2 for that agent.

---

## THE CLASSIFIED HIT LIST

Classification per the brief: **T** = table row (one of the three legitimate columns) ·
**V** = vendor artefact (a path/schema husk did not choose) · **I** = incidental (comment,
doc, fixture — noted, not weighted) · **R** = real coupling (logic that behaves differently
because the agent is Claude).

### Shipped code

| file:line | hit | class | note |
|---|---|---|---|
| `install-husk.sh:372-377` | `command -v claude` preflight + 3 error lines | **T** | column 1, but hardcoded |
| `install-husk.sh:419` | `exec seccomp-wrapper claude "$@"` (no-broker path) | **T** | column 1, site 2 |
| `install-husk.sh:427` | `exec "${args[@]}" -- seccomp-wrapper claude "$@"` | **T** | column 1, site 3 |
| `install-husk.sh:188,194,205` | `SANDBOX_RUNTIME_VERSION=0.0.49`, npm URL, pinned SHA-512 | **R** | husk downloads a vendor binary… |
| `install-husk.sh:289-296` | extracts `package/vendor/seccomp/${ARCH}/apply-seccomp`, installs 0755 | **R** | …and puts it on the enforcement path |
| `install-husk.sh:84,103-110` | `CLAUDE_SETTINGS="${HOME}/.claude/settings.json"` (uninstall) | **R** | husk *writes* the vendor config |
| `install-husk.sh:500-506` | same, install side; invokes `merge-claude-settings.py` | **R** | the whole install mechanism |
| `install-husk.sh:2,5,13-14,18,24,29-41,139-155,363-369,515-533` | prose | **I** | 22 comment/echo lines |
| `scripts/merge-claude-settings.py` (whole file) | filename, `MANAGED_KEYS` | **R** | see next row |
| `scripts/merge-claude-settings.py:23` | `MANAGED_KEYS = ["enableAllProjectMcpServers","sandbox","permissions"]` | **R** | three vendor schema keys |
| `scripts/merge-claude-settings.py:78-80` | injects `sandbox.seccomp.applyPath` | **R** | vendor schema key |
| `scripts/merge-claude-settings.py:105-107` | wholesale overwrite of the three keys | **R** | install = mutating vendor config |
| `user-config/settings.json:1-85` | the entire shipped login policy | **R** | vendor schema **and** vendor enforcement |
| `user-config/settings.json:2` | `enableAllProjectMcpServers: false` | **V** | backstop cited by `settings.rs:138-145` |
| `user-config/settings.json:3-6` | `sandbox.{enabled,autoAllowBashIfSandboxed,allowUnsandboxedCommands}` | **R** | toggles *inside* the confined runtime |
| `user-config/settings.json:15-17` | `denyWrite` of the three `.claude` settings files | **V**/**R** | the twin of `SETTINGS_SOURCES` |
| `user-config/settings.json:27-83` | `permissions.allow/deny` with `Bash()/Read()/Edit()` rule syntax | **R** | vendor rule *language*, vendor-enforced |
| `user-config/settings.json:37-39` | `Edit(~/.claude/settings.json)` etc. | **V** | vendor paths |
| `project-config/settings.json:2-11` | `permissions.deny` incl. `mcp__*` | **R** | vendor rule language (no literal `claude`) |
| `slurm-broker/broker/src/settings.rs:278-282` | `SETTINGS_SOURCES` — 3 `.claude/settings*.json` paths | **R** | the policy source, not a "dir to allow" |
| `slurm-broker/broker/src/settings.rs:372-418` | `Settings/SandboxCfg/FsCfg/CredentialsCfg` serde structs | **R** | vendor schema, `rename_all="camelCase"` |
| `slurm-broker/broker/src/settings.rs:131-136` | `AUTO_EXEC_DIRS = [".claude", ".git/hooks", ".vscode", ".idea"]` | **R** | vendor-name-keyed **security mask** |
| `slurm-broker/broker/src/settings.rs:145` | `AUTO_EXEC_RO_FILES = [".mcp.json"]` | **R** | vendor file name |
| `slurm-broker/broker/src/settings.rs:490-503` | `resolve(home, project_dir)` — hierarchy + merge order | **R** | vendor layering semantics |
| `slurm-broker/broker/src/settings.rs:1,119,490,537` | prose | **I** | |
| `slurm-broker/broker/src/settings.rs:1592,1602,1611,1614,1616` | `.claude` in tests | **I** | fixtures asserting the mask |
| `slurm-broker/broker/src/netallow.rs:304-318` | `sandbox.network.allowedDomains` serde | **R** | vendor schema |
| `slurm-broker/broker/src/netallow.rs:24-29` | "pattern language matches Anthropic's `sandbox-runtime`, deliberately" | **I** | a *deliberate* compat choice, implementation is husk's |
| `slurm-broker/broker/src/netallow.rs:364` | `assert!(!a.permits("api.anthropic.com", 443))` | **I** | sample hostname in a default-deny test |
| `slurm-broker/broker/src/spool.rs:391-396` | `STRIPPED_SUBMIT_ENV` incl. `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` | **R** | credential denylist, vendor spellings |
| `slurm-broker/broker/src/spool.rs:133,383-390` | prose | **I** | |
| `slurm-broker/broker/src/spool.rs:475,483,582,584` | test fixtures | **I** | |
| `slurm-broker/broker/src/policy.rs:537` | "where `.claude/` lives" | **I** | comment only; the code uses `project_dir` |
| `slurm-broker/broker/src/bin/husk-slurm-wrapper.rs:283-291` | identity uid-map *because* the vendor runtime branches on EUID==0 | **R** | **behavioural**; zero `claude` strings |
| `seccomp-wrapper/src/seccomp_wrapper.c:52-62` | `PROFILE_LOGIN` permits AF_UNIX for "the agent runtime… MCP servers, IDE integration" | **R** | **behavioural**; the floor is agent-tuned |
| `seccomp-wrapper/src/seccomp_wrapper.c:4-8,15-16,156-158,293,546-548` | prose | **I** | 9 comment lines, no code |
| `slurm-broker/sbatch-stub.py`, `srun-stub.py` | — | — | **zero hits.** Genuinely neutral |
| `slurm-broker/broker/src/rank.rs` | — | — | **zero hits.** The neutral shape |

### Tests, probes, fixtures (noted, not weighted)

| file:line | class |
|---|---|
| `slurm-broker/selftest.sh:850-853, 972-973, 1117-1118, 1565-1574` | **I** — fixtures asserting the `.claude` mask |
| `slurm-broker/broker/tests/golden/guard-net-{on,off}.sh:204,95` | **I** — golden output; `--tmpfs '/work/project/.claude'` is *generated* from `AUTO_EXEC_DIRS` |
| `slurm-broker/resume-probe.sh:5-10, 24, 27-28, 63, 85-90` | **I** — but see F5; it documents Node/libuv + transcript-path coupling |
| `slurm-broker/verify-sbatch-inheritance.sh:4-17, 103-106` | **I** — but see F6; it exists to test nested-bwrap |
| `slurm-broker/discover-writable-spool.sh:17` | **I** |

### Docs (noted, not weighted)

`README.md` (30), `doc/constraints.txt` (43), `doc/context.txt` (31), `ROADMAP.md` (11),
`seccomp-wrapper/README.md` (20), `project-config/README.md` (12), `NOTICE` (4),
`slurm-broker/{THREAT-MODEL,BROKER,BRINGUP,CAGE-PROFILES,PROTOCOL,SRUN-MPI-DESIGN}.md` (15),
`doc/sandbox-interface.txt` (5), `doc/threat-model.txt` (2) — all **I**.
`README.md:1` (`# husk — Claude Code on HPC supercomputers`) is the project's own framing and is
the one doc hit worth knowing about: the README does not claim agent neutrality.

**Tally outside the three columns: 13 shipped-code couplings across 8 files.**

---

## THE ASSUMPTION ANALYSIS

### 1. Policy source — "what is the neutral equivalent, and what breaks when the vendor changes it?"

husk has **no policy source of its own**. Every policy input the broker acts on is read out of
`.claude/settings*.json` in the vendor's schema:

- **paths** — `SETTINGS_SOURCES` (`settings.rs:278-282`), three files, home-then-project-then-local.
- **schema** — `settings.rs:372-418`, `#[serde(rename_all = "camelCase")]`,
  `sandbox.filesystem.{allowRead,denyRead,allowWrite,denyWrite,allowGitConfig}`,
  `sandbox.credentials.{files,envVars}`, and separately
  `sandbox.network.allowedDomains` (`netallow.rs:304-318`).
- **merge semantics** — `resolve()` (`settings.rs:494-503`) reproduces the vendor's layering.

What breaks on a vendor schema change splits cleanly, and the two halves fail in opposite
directions:

- **Renaming a `filesystem`/`credentials`/`network` key fails SAFE.** `serde` ignores unknown
  keys and `unwrap_or_default()` yields an empty policy (`settings.rs:423-424`); an empty
  allowlist permits nothing (`netallow.rs:360-365`). The compute cage gets *tighter*, silently.
  That is the right direction but it is silent: a schema drift would present as "my
  `allowWrite` stopped working", not as an error.
- **Renaming `permissions.deny` fails OPEN.** The pairing test
  (`settings.rs:946-981`) asserts that everything in `SETTINGS_SOURCES` is covered by
  `sandbox.filesystem.denyWrite` in the shipped config — and its own comment (lines 954-956) is
  explicit that this is *"enforced by the bwrap filesystem cage… policy ours, enforcement the
  runtime's today, ours after 6a"*. So the property "the agent cannot edit its own cage" is
  today a property of the vendor runtime honouring husk's `denyWrite` entries. The test asserts
  the two *husk-owned lists* agree with each other; nothing asserts the runtime still obeys.

The neutral equivalent would be a husk-owned file at a husk-owned path with a husk-owned
schema. Nothing in the tree is a partial step toward one — there is no `husk.toml`, no
`~/.husk/policy.*` (`~/.husk/log/` exists, but only for logs:
`husk-slurm-wrapper.rs:205-224`, `policy.rs:846-847`).

### 2. Process shape — single long-lived process? Node? re-exec per command?

Four separate assumptions, all real, none named `claude`:

- **One exec'able binary, argv forwarded verbatim.** The launcher is
  `exec seccomp-wrapper claude "$@"` (`install-husk.sh:419,427`), so **husk's CLI surface *is*
  the agent's CLI surface** — every flag the user types is the agent's. There is no husk-owned
  argument namespace.
- **Session-level on the outside, per-command on the inside.** The login side wraps the whole
  session once (seccomp + the userns/bind for `sbatch`), and then *relies on the agent
  re-sandboxing itself per Bash command*. `seccomp_wrapper.c:52-62` states this outright:
  `PROFILE_LOGIN` is the default "precisely because it must stay today's behaviour" and does not
  block AF_UNIX, because the agent runtime needs unix sockets for MCP/IDE IPC — AF_UNIX is
  blocked *"by Anthropic's apply-seccomp, applied per BASH COMMAND rather than to the runtime
  process."* So the login side's granularity is the vendor's, not husk's. The compute side is
  the opposite shape (one cage per node that tasks join) and is husk's own.
- **Tools are descendant processes in husk's mount namespace.** The `sbatch` shadow is a
  `MS_BIND` in the namespace the wrapper unshares before `exec`ing the agent
  (`husk-slurm-wrapper.rs:277-301`, bind+verify at `263`, read-only shadows at `374-386`). It
  confines only processes that inherit that namespace. An agent that dispatched tool calls to a pre-existing daemon, a container, or an
  SSH hop would not see the stub at all.
- **Not Node *per se*, but Node-shaped failures are already on record.** `resume-probe.sh:5-10`
  diagnoses `--resume` dying under the io_uring block as libuv fs I/O, and the proposed fix
  direction at line 86 is `export UV_USE_IO_URING=0` — a libuv-specific environment variable in
  the husk launcher. That is not in the shipped launcher today, but it is the recorded remedy.

### 3. Filesystem conventions — a config directory at all, and under `$HOME`?

Yes to both, in two independent places, and the second is a security mask rather than a lookup:

- **Lookup.** `SETTINGS_SOURCES` (`settings.rs:278-282`) assumes (a) a config *directory*
  exists, (b) it is literally `.claude`, (c) there is one under `$HOME` **and** one under the
  project dir, (d) with a `.local.json` override layer, (e) all JSON. `resolve(home, …)` takes
  home from `$HOME` (`main.rs:463`, `policy.rs:363`, `netallow.rs:338`).
  Minor edge, noted not weighted: with `$HOME` unset, `unwrap_or_default()` gives an empty
  `PathBuf`, so `home.join(".claude/settings.json")` becomes a *relative* path resolved against
  the broker's cwd — i.e. the "global" layer silently re-reads the project layer. `union()`
  dedups, so it is harmless today.
- **Mask.** `AUTO_EXEC_DIRS` (`settings.rs:131-136`) tmpfs-masks `.claude` inside **every**
  writable root of the compute cage (applied at `settings.rs:762-766`). Its own doc comment
  (lines 115-122) argues the directory-level mask is "future-proof… a new agent-config feature
  is covered the day it ships, with no list to keep in sync" — which is true *within one
  vendor* and false across vendors. The list is still a denylist; it is future-proof against
  new Claude features and not against a different agent. Same for `AUTO_EXEC_RO_FILES =
  [".mcp.json"]` (`settings.rs:145`).

There is no notion of "the agent's config directory" as a *variable* anywhere in the tree.

### 4. Credential names — keyed on specific names, or on a declared set?

**Both, and the declared set is empty by default.** Three mechanisms:

| mechanism | file:line | shape |
|---|---|---|
| submission-time strip | `spool.rs:391-396`, applied `402-404` | **hardcoded denylist**, 4 names |
| cage `--unsetenv` | `settings.rs:364-368,404,414`, `806-810` | **declared set** — `sandbox.credentials.envVars` |
| workdir file scan | `settings.rs:824-853` | **hardcoded heuristic denylist**, ~20 basename patterns |

The declared set is the neutral one and it is the only one that is agent-agnostic — but
`user-config/settings.json` ships **no `sandbox.credentials` block at all** (lines 3-26 contain
only `filesystem` and `network`). So out of the box, `unset_env` is empty and the *only*
env-credential protection on the submission path is the four-name list in `spool.rs`, two of
whose entries are one vendor's spelling. See F1.

`matches_credential` (`settings.rs:831-853`) is agent-neutral (SSH keys, `.netrc`, `.npmrc`,
keystores) — it is a *general secret* heuristic, not an agent one, and its own comment already
concedes it should be sourced from the user's actual `Read()` globs.

Contrast with the neutral shape the brief points at: `rank.rs:35-52` refuses whole *namespaces*
(`SLURM_`, `SBATCH_`, `PMI_`, `PMIX_`, `PALS_`, `HUSK_`) and whole *categories* (`PROXY_ENV`, with
the stated rule "values that describe a NAMESPACE do not travel across one"), and validates the
name *charset* structurally (`is_valid_env_name`, 62-67) so an option-shaped name is
unrepresentable. `rank.rs` never names a vendor. `spool.rs` names two.

### 5. Behavioural coupling — does anything depend on how the agent *behaves*?

Yes. Five distinct cases, in descending order of how load-bearing they are:

1. **The login filesystem boundary is the agent's own permission layer, and for native tools it
   is a prompt.** `doc/constraints.txt:100-116` records it plainly: *"Native file tools — Read,
   Edit, Write (run in the Claude Code process): These run OUTSIDE bwrap entirely and bypass its
   filesystem restrictions. denyRead: ["/users"] and allowRead: ["./"] cause Claude Code to
   PROMPT the user before proceeding, but do not hard-block access."* The mitigation
   (`constraints.txt:118-125`) is `permissions.deny` rules — i.e. more of the same layer. This
   is the axiom inverted: the confiner is relying on the confined party's cooperation and on a
   human answering a prompt. `user-config/settings.json:36-82` is entirely this layer.
2. **husk's namespace design is constrained by a branch inside the vendor runtime.**
   `husk-slurm-wrapper.rs:283-291`: the uid map must be identity, not `0 -> uid`, because with
   EUID==0 *"the sandbox-runtime treats us as a 'root parent' and adds `bwrap --cap-drop ALL`,
   which empties the capability BOUNDING set"* and `apply-seccomp` then cannot write `uid_map`.
   A trusted-boundary design decision, taken to accommodate observed vendor behaviour.
3. **The seccomp floor is calibrated to one agent's syscall usage.** `seccomp_wrapper.c:4-5`:
   *"a deny-list for syscalls a Claude Code agent provably does not need"*, with
   `SCMP_ACT_KILL_PROCESS` (line 285-ish, `install_filter`). `PROFILE_LOGIN` deliberately leaves
   AF_UNIX open for the vendor runtime's IPC (52-62), and `mount`/`umount2`/`pivot_root`/`capset`
   are left unblocked because the vendor's bwrap needs them (`156-158`, `106-115`). A second
   agent needing anything on the list does not degrade — it is killed.
4. **The vendor's per-command bwrap must nest inside husk's outer userns.**
   `verify-sbatch-inheritance.sh:14` exists to prove exactly this: *"It also incidentally proves
   claude's inner bwrap can start AT ALL while nested."* `ROADMAP.md:153-154` lists it as an
   open question: *"confirm Claude runs correctly wrapped per-session (its per-command sandbox
   should be a security layer, not a functional dependency)"* — the project's own admission that
   this is currently unproven.
5. **Teaching messages assume the agent reads stderr and acts on prose.** `policy.rs:538-557`
   (`cage_banner`), the refusal strings in `settings.rs:204-266` and `netallow.rs:57-82`. This
   one is **not** load-bearing — the enforcement is the mount table either way — so it is a
   coupling to behaviour that costs nothing if the behaviour is absent. Worth recording as the
   one behavioural dependency that degrades gracefully.

---

## FINDINGS

### F1 — `STRIPPED_SUBMIT_ENV` is a four-name denylist, so a second agent's API token rides into every compute job by default — **CONFIRMED**

`slurm-broker/broker/src/spool.rs:391-396`

```rust
const STRIPPED_SUBMIT_ENV: &[&str] = &[
    "SECCOMP_WRAPPER_DEBUG",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CSCS_INFERENCE_API_KEY",
];
```

Applied at `spool.rs:402-404` (`cmd.env_remove(k)`) on the `sbatch` invocation. The broker
inherits the launching session's environment and forces `--export=ALL` (module comment,
`spool.rs:375-380`), so anything *not* on this list reaches slurmd's copy of the job
environment. `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`,
`OPENROUTER_API_KEY`, `HF_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK` — none are stripped.

The declared-set fallback does not cover it: the cage's `--unsetenv` comes from
`sandbox.credentials.envVars` (`settings.rs:404,414` → `806-810`), and
`user-config/settings.json:3-26` ships **no `credentials` block**, so `unset_env` is empty in
the default install. Confirmed by reading the shipped config.

This is the same class the project already named — *a cleanup that enumerates is a denylist* —
applied to credentials. Note the deliberate asymmetry the code documents (`spool.rs:383-386`):
`ANTHROPIC_BASE_URL`/`ANTHROPIC_MODEL` are excluded on the argument that they are useless
without a token. That argument holds only while the token list is complete.

**Re-runnable as a test:** assert `STRIPPED_SUBMIT_ENV` contains no vendor-specific spelling,
or that it is derived from a declared set rather than a literal. The existing test at
`spool.rs:469-486` asserts the opposite — it pins the vendor names in place.

### F2 — `AUTO_EXEC_DIRS` masks one vendor's config directory by name; another agent's config dir is left unmasked inside the cage — **CONFIRMED**

`slurm-broker/broker/src/settings.rs:131-136`, applied at `settings.rs:762-766`

```rust
const AUTO_EXEC_DIRS: &[&str] = &[".claude", ".git/hooks", ".vscode", ".idea"];
```

This is the AV2 mask: a fresh tmpfs over each of these inside **every** writable root, so a
compute job cannot plant a hook/skill/settings file that fires later in a login session. The
comment at `settings.rs:115-122` argues the *directory*-level mask is future-proof — true within
one vendor's feature set, false across vendors. For a second agent (`.codex/`, `.aider/`,
`.cursor/`, `.gemini/`, `.opencode/`), the directory is inside a writable bind, unmasked, and
writes there **persist to the real filesystem** after the job ends.

The generated evidence is visible in the golden fixtures:
`slurm-broker/broker/tests/golden/guard-net-off.sh:95` and `guard-net-on.sh:204` both emit
`'--tmpfs' '/work/project/.claude'` and nothing else agent-shaped.

Same shape at `settings.rs:145` — `AUTO_EXEC_RO_FILES = [".mcp.json"]`, one vendor's
project-level MCP config filename.

**Re-runnable as a test:** plant a file under `<workdir>/.notclaude/` in the golden-guard
harness and assert it is masked. It will not be.

### F3 — husk has no policy source of its own; all four policy inputs are the vendor's schema — **CONFIRMED**

`settings.rs:278-282` (paths) · `settings.rs:372-418` (fs + credentials schema) ·
`netallow.rs:304-318` (network schema) · `settings.rs:490-503` (hierarchy and merge order)

6a's first deliverable is "husk's own policy source". Today there is none, and the coupling is
deeper than a filename: it is three paths, a camelCase key schema across four sub-objects, a
three-layer additive merge, and — per `settings.rs:954-956` — an enforcement dependency, since
`denyWrite` (the thing that stops the agent editing its own cage) is enforced by the *runtime's*
bwrap on the login side.

Failure directions differ and both are silent (see Assumption 1). The `filesystem`/`network`
half fails safe-but-quiet; the `permissions` half fails open if the vendor stops honouring it.

### F4 — the login-side filesystem boundary is implemented by the confined party, and for native tools it is advisory — **CONFIRMED**

`user-config/settings.json:3-26` and `27-83` · `doc/constraints.txt:87-125` ·
`scripts/merge-claude-settings.py:23,105-107`

husk's login-side "sandbox" is 85 lines of vendor JSON, merged into `~/.claude/settings.json` by
`merge-claude-settings.py`, and enforced by the agent runtime. Two of the three managed keys
(`sandbox`, `permissions`) are the boundary itself; the third
(`enableAllProjectMcpServers: false`) is cited elsewhere as a backstop (`settings.rs:138-145`).

`doc/constraints.txt:100-108` records the measured behaviour: native `Read`/`Edit`/`Write` run
outside bwrap and *prompt* rather than block. So on the login node, for the agent's own file
tools, the boundary is (i) implemented by the confined party and (ii) defeasible by a human
approving a prompt. `constraints.txt:110-116`'s summary table shows `Elsewhere in ~/` as
"writable, prompts" for native tools.

This is the finding that makes the acceptance test the wrong instrument: it would pass a
codebase that hardcoded nothing and still delegated its whole boundary. Recorded here because
the brief asks for design decisions that would have to be reversed — this is the one, and
ROADMAP already calls it 6a.

### F5 — husk's install pipeline downloads a vendor binary and places it on the enforcement path — **CONFIRMED**

`install-husk.sh:188` (`SANDBOX_RUNTIME_VERSION="0.0.49"`), `194` (npm URL), `205` (pinned
SHA-512), `289-296` (extract `package/vendor/seccomp/${ARCH}/apply-seccomp`, `install -m 0755`),
`505-506` (wired in via `sandbox.seccomp.applyPath`, `merge-claude-settings.py:78-80`)

`apply-seccomp` is the component that blocks AF_UNIX and io_uring per Bash command — the thing
`seccomp_wrapper.c:55-60` explicitly defers to for AF_UNIX on the login side. It is fetched from
`registry.npmjs.org/@anthropic-ai/sandbox-runtime`, pinned by hash, and installed to
`$PREFIX/lib/husk/apply-seccomp`. The install fails hard on hash mismatch (line 290-291), so
supply-chain integrity is handled; the coupling is that a version bump of one vendor's npm
package is a change to husk's login enforcement, and there is no second-agent path that does not
go through it.

Note for triage: `MEMORY`/`anthropic-fs-model` records that `apply-seccomp`'s own header calls
itself telemetry rather than enforcement. Whether that reclassifies this finding is a C1
question, not a C3 one. Either way the *dependency* is in `install-husk.sh` and is real.

### F6 — the identity uid-map is a design decision taken to accommodate a branch inside the vendor runtime — **CONFIRMED**

`slurm-broker/broker/src/bin/husk-slurm-wrapper.rs:277-301` (decision at 283-291, code at 298)

The comment is the evidence: mapping to root *"broke the agent's OWN Bash sandbox: with EUID==0
the sandbox-runtime treats us as a 'root parent' and adds `bwrap --cap-drop ALL`… so every Bash
command died with `apply-seccomp: write /proc/self/uid_map: Operation not permitted`"*. The
chosen mapping is defensible on its own merits (the comment argues that too — CAP_SYS_ADMIN
comes from creating the userns, and identity is less surprising), but the *reason it was
changed* is vendor behaviour, and nothing records the constraint as a constraint. It is a
comment on one function, not a test.

Contains zero occurrences of `claude` or `anthropic` — this is the class of finding the
mechanical half of the brief cannot see.

### F7 — the seccomp floor and the login profile are calibrated against one agent's syscall usage, and the failure mode is SIGKILL — **CONFIRMED** (calibration) / **PLAUSIBLE** (that a second agent trips it)

`seccomp-wrapper/src/seccomp_wrapper.c:4-5, 52-62, 106-115, 156-168`; action at
`seccomp_wrapper.c:297-299` (`SCMP_ACT_KILL_PROCESS` unless `SECCOMP_WRAPPER_DEBUG=1`)

Three separate accommodations to one agent's implementation are written into the filter:
`capset` unblocked (bwrap's userns setup, 106-115), `mount`/`umount2`/`pivot_root` unblocked
("Claude Code's sandbox invokes bwrap as a child process", 156-168), and AF_UNIX left open under
`PROFILE_LOGIN` for the runtime's MCP/IDE IPC (52-62). The stated header claim is "syscalls a
Claude Code agent provably does not need" (line 4-5).

**CONFIRMED** that the floor is agent-calibrated — it says so, and the exemption table
(`SINGLE_NODE_EXEMPT`, 246-251) is the same pattern applied to Cray MPICH.
**PLAUSIBLE** that a second agent trips it, but with strong precedent rather than speculation:
`resume-probe.sh:5-10` documents *the current agent* being killed by the io_uring block on the
`--resume` path, and line 44-51 shows the diagnosis machinery already needed for it
(`159 = 128+31 = SIGSYS`). A Go, Rust or Python harness has a different syscall footprint than
libuv's, and the failure is a process kill with no attribution from husk.

### F8 — column 1 (`binary to exec`) is hardcoded at three exec sites, not parameterised — **CONFIRMED**

`install-husk.sh:372-377` (preflight `command -v claude` + 3 message lines), `419`
(`exec seccomp-wrapper claude "$@"`), `427`
(`exec "${args[@]}" -- seccomp-wrapper claude "$@"`), `527-533` (post-install messages)

Notable because the layer *underneath* is already neutral: `husk-slurm-wrapper.rs:86,147-151`
takes the agent as `agent: Vec<String>` after `--`, defaults to `"husk"`, and execs it
generically (`exec_agent` 311-328, `exec_plain` 334-338). `seccomp-wrapper` is `execvp(cmd[0],
cmd)` (`seccomp_wrapper.c:549`). So the only thing that knows the agent's name is the generated
launcher heredoc, at three sites plus a preflight — the shortest distance to column 1 being a
single variable, and it is not one today.

### F9 — column 3 (`API hosts to allowlist`) does not exist — **CONFIRMED**

`user-config/settings.json:21-25` (`allowedDomains: ["opendatadocs.meteoswiss.ch:443"]`) ·
`netallow.rs:289-318` · `spool.rs:388-390`

There is no Anthropic API host anywhere in the shipped configuration, and the allowlist code
that exists governs **compute-job egress**, not the login agent's model traffic. `spool.rs:388-390`
states the gap: *"Preventing the AGENT from redirecting its own model traffic —
`ANTHROPIC_BASE_URL` pointed at a host husk did not intend — needs husk to own the login
environment, which is ROADMAP step 6a."*

This matters for the acceptance test's own framing: two of the three columns are not what the
table says they are (column 2 is a schema, not a directory), and the third is empty. Overlaps
C2; recorded here because the test cannot be evaluated as written without it.

### F10 — the login-side confinement granularity is the vendor's, and husk has no proof it is not a functional dependency — **PLAUSIBLE**

`seccomp_wrapper.c:52-62` · `verify-sbatch-inheritance.sh:4-17, 103-106` · `ROADMAP.md:153-154`

husk wraps the session; the vendor runtime wraps each Bash command; husk's own comments defer to
that ("When ROADMAP step 5 drops their runtime, this profile takes that block over at the same
granularity"). Two things follow that are not established anywhere in the tree:

- husk's outer user+mount namespace must permit the vendor's inner bwrap + `apply-seccomp` to
  nest. `verify-sbatch-inheritance.sh:14` treats this as something to *prove incidentally*, and
  its `INCONCLUSIVE` branch (line 106) is "claude's inner sandbox likely failed to start
  nested" — so the nesting is known to be fragile enough to need a verdict for.
- `ROADMAP.md:153-154` records the open question directly: whether the agent runs correctly
  wrapped per-session, i.e. whether its per-command sandbox is "a security layer, not a
  functional dependency". Unanswered.

Marked PLAUSIBLE rather than CONFIRMED because both halves need a cluster to settle, which this
brief did not have. The reproducer is named in ROADMAP; it is a login-node run, not a job.

### F11 — the install mechanism itself is agent-specific and is not separable from husk's install — **CONFIRMED**

`scripts/merge-claude-settings.py:23,78-80,105-107` · `install-husk.sh:84,103-110,500-506`

`MANAGED_KEYS = ["enableAllProjectMcpServers", "sandbox", "permissions"]` — three vendor schema
keys, overwritten wholesale on install and restored from a manifest on uninstall. The uninstall
path (`install-husk.sh:103-110`) reverses edits to `~/.claude/settings.json` specifically. There
is no branch, flag or variable in either file for a non-Claude install; `install-husk.sh:29-30`
states the prerequisite as *"The `claude` CLI installed and signed in"*.

Recorded separately from F4 because F4 is about *what enforces*, this is about *what the
installer does*: even an agent that needed no policy translation would still get the vendor
config written.

---

## What is genuinely neutral (the counter-list)

Worth recording, because it is the evidence that 6b is an extension rather than a rewrite for
the parts that matter most:

- `slurm-broker/broker/src/rank.rs` — zero hits. `RESERVED_ENV_PREFIXES` (35-36) refuses by
  *namespace*, `PROXY_ENV` (49-52) by *category* with a stated rule, `is_valid_env_name` (62-67)
  by *charset* so an option-shaped name is unrepresentable. The brief's chosen exemplar earns it.
- `slurm-broker/sbatch-stub.py`, `slurm-broker/srun-stub.py` — zero hits. The stub forwards
  `argv[0]` and lets the broker decide (`tool_name()`, 26-32).
- `husk-slurm-wrapper.rs:86,147-151,311-338` — the agent is a `Vec<String>` after `--`.
- `seccomp_wrapper.c:549` — `execvp(cmd[0], cmd)`; the wrapper is a generic exec shim.
- The compute cage's construction — `settings.rs:597-815`, `policy.rs`, `profile.rs` — is
  mount-table-shaped and does not consult the agent's identity anywhere. `AUTO_EXEC_DIRS` and
  `SETTINGS_SOURCES` are the only vendor strings that reach it.
- `netallow.rs` — the *pattern language* deliberately matches the vendor's (24-29), but the
  implementation is husk's and the reasoning given is explicitly that vendor code must not be on
  the enforcement path.

---

## Note for triage

Every entry above is a static claim about a file at a line; all of it is re-runnable on a
laptop with no cluster. The two that are worth building as actual arms rather than greps are
**F1** (assert the strip list is not a vendor-name literal, or plant a non-Anthropic token and
show it reaches the job env) and **F2** (plant a file under a non-`.claude` config directory in
the golden-guard harness and show it survives the cage). **F6** and **F7** are the two findings
the mechanical half of this brief would have missed entirely — neither contains the string
`claude` at the line that matters.
