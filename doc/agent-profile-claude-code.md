# AgentProfile — Claude Code CLI

**What this is.** The concrete instance of [`sandbox-interface.md §5`](sandbox-interface.md),
for the one agent husk currently wraps. §5 says an integration must *declare* what its agent
needs so an operator can decide before launch; this file is that declaration, plus the
Claude-Code-specific facts husk had to measure in order to write it.

**Why it exists as a file.** Two reasons, and the second is the load-bearing one:

1. It is the honest cost of agent-neutrality — every harness has quirks and finding them is
   work that cannot be automated away (§5).
2. **It is the specification for 6a.** Today these facts are used to *choose flags*; when husk
   wraps the CLI itself they are used to *build the outer cage*. Same facts, different consumer.
   Anything wrong here becomes wrong in the cage.

**Status of every claim below:** measured on 2026-08-10 unless marked otherwise, on the laptop's
Claude Code build, with the **filesystem as the oracle**. Nothing here is pinned by a test in
this repo — see [Version coupling](#version-coupling), which is the most important section.

---

## 1. Invocation

```
husk → husk-slurm-wrapper → seccomp-wrapper claude --tools <allowlist> [user flags]
```

- The wrapper brokers **iff** it detects SLURM; on a laptop there is no broker and no trace.
- **husk's flags go first**, so an explicit user flag still wins. The human launching husk is
  the trusted party; the agent inside is not.
- Absent broker binaries → plain cage, never an unbrokered SLURM path (`C0.2`).

## 2. Egress

| channel | routed through husk? | note |
|---|---|---|
| the agent's own model API traffic | **no** | the `claude` process is not inside bwrap; its sockets are the host's. Structural, and it is *why* the agent runs at all |
| `WebFetch` / `WebSearch` | **no** | host-side, beside the cage — which is why they are excluded from the tool allowlist |
| network from a `Bash` command | **yes** | netns + per-node proxy + `network.allowedDomains` |
| network from a job / MPI rank | **yes** | second cage on the compute node |

**The operator-visible consequence:** husk's network allowlist governs what the *agent's
commands* may reach, not what the *agent* may reach. An empty allowlist still yields a working,
degraded agent (§5 requires this) — because the model endpoint was never in the allowlist's
scope to begin with.

*Unverified:* whether a corporate proxy or `HTTPS_PROXY` in the launching environment changes
the first row. It is inherited from the login shell, so assume it does.

## 3. Filesystem

### 3.1 The two `.claude` trees are different objects

The single most confusing thing about this agent, and the source of three separate bugs.

| | `~/.claude` (home) | `<project>/.claude` |
|---|---|---|
| husk `denyRead: /users` | **tmpfs-masked — does not exist inside the cage** | not covered |
| vendor built-in write-deny | — | `.claude/commands`, `.claude/agents` |
| husk `denyWrite` | `~/.claude/settings.json` | `.claude/settings.json`, `.claude/settings.local.json` |
| **effective, to caged Bash** | invisible | **read-only** — measured 2026-08-10: a heredoc into `.claude/workflows/` fails `Read-only file system`, and the LETKF log reports the same for `config` |
| husk `allowWrite` | `~/.claude/projects` | (the project dir is writable anyway) |
| compute cage | under `HIDDEN_FLOOR` | `AUTO_EXEC_DIRS` tmpfs |

### 3.2 Home state directory — inventory

Measured on the laptop; **the cluster inventory is unverified** and worth one `ls` when
convenient.

| path | written by | needed? |
|---|---|---|
| `projects/<slug>/*.jsonl` | harness | transcript — works masked, harness is host-side |
| `projects/<slug>/memory/` | **the agent** | agent memory — see §5.3, this is the trap |
| `skills/` | operator/installer | husk installs its own skill here |
| `settings.json` | operator (husk-managed, 3 keys) | policy input — `denyWrite`, `P2` |
| `.credentials.json` | harness | auth |
| `history.jsonl`, `sessions/`, `file-history/`, `paste-cache/`, `session-env/`, `todos/` | harness | session bookkeeping |
| `plugins/`, `cache/`, `downloads/`, `backups/`, `.cc-writes/` | harness | — |

### 3.2a The vendored `sandbox-runtime/` is NOT the running code

**Measured 2026-08-13, and it invalidates a method rather than a fact.** A plain `config/`
directory in the project root is bind-mounted read-only — reproduced, `grep config /proc/mounts`
shows the bind, and a write into it fails. **Nothing in the vendored `sandbox-runtime/` source
explains it**: `DANGEROUS_FILES` and `getDangerousDirectories()` contain `.git/config` and
nothing named `config`.

So the shipped implementation has rules the open-source copy does not, and every conclusion in
this file drawn from reading that tree is *indicative only*. An agent reported this directory
in a friction log; it was dismissed on the strength of a grep through the vendored source, and
the dismissal removed a true warning from the shipped skill. **Read the tree for hypotheses;
settle them against `/proc/mounts` in a live session.**

### 3.3 Project-scope paths the agent must not own

`.claude/settings*`, `.claude/commands`, `.claude/agents`, `.claude/hooks`, `.mcp.json`,
`.git/hooks`, `.git/config`, `.vscode`, `.idea`, `.Rprofile`, `.hg/hgrc`.

The vendor covers some, husk covers others, and **the split is not the same on login and
compute** — which is why `LOGIN_AUTO_EXEC_DENY` exists as a pairing assertion rather than a
second list nobody compares.

## 4. Subprocesses and delegation

`Agent` tool parameters: `description`, `prompt`, `subagent_type`, `model`,
`run_in_background`, `isolation ∈ {worktree, remote}`.

- **Tool inheritance holds.** The parent's `--tools` wins over the agent definition's own
  `tools:` field. Verified against a project-local `.claude/agents/*.md` declaring
  `Bash, Write, Read, Edit` — a file the caged agent could author — which still yielded Bash
  only, with no file landing. **This is the property that makes swarms safe**, and it is the
  one to re-check on upgrade.
- **Second, independent barrier on the server:** the vendor write-denies `<project>/.claude/agents`,
  so a caged agent cannot author a definition at all. It does **not** follow into a worktree root.
- `isolation: "worktree"` → `<project>/.claude/worktrees/agent-<id>`. Created by the harness
  host-side, so it appears despite `<project>/.claude` being read-only to caged Bash. **Open
  question, and a strong prediction: a worktree-isolated subagent probably cannot WRITE in
  its own worktree**, because that path is under the read-only mount and its only tool is
  Bash. The worktree probe only ran read-only commands, so this is untested.
- `isolation: "remote"` → **gated off; degrades to a local worktree, silently.** Same hostname,
  kernel and `$HOME`. This is a *dated assumption, not a control*: if the gate opens, context
  leaves the machine and nothing husk has would notice.
- Background agents report completion by push notification; no polling tool is required.

**Not admitted, and why:** `EnterWorktree`/`ExitWorktree` are separate tools and stay out.
A worktree is a fresh project root, so the auto-exec protections do not apply inside it.

## 5. The host-side / caged split

**The single most useful table in this file.** husk's boundary is in the path of `Bash` and
nothing else, so every capability sorts by who performs it.

| operation | performed by | meets the cage? |
|---|---|---|
| a `Bash` command | wrapped child process | **yes** — bwrap argv per command |
| `Read`/`Write`/`Edit`/`Glob`/`Grep` | agent process, host-side | no → excluded from the allowlist |
| `WebFetch`/`WebSearch` | agent process, host-side | no → excluded |
| **skill loading** | harness, host-side | no → **works despite the masked home** |
| **memory injection / recall** | harness, host-side | no → works |
| **memory writing** | **the agent, via `Write`** | — → **broken unless done with Bash** |
| transcript writing | harness, host-side | no → works |
| worktree creation | harness, host-side | no |
| settings load | harness, host-side, at session start | no |

### 5.3 Memory is the trap this table exists to explain

Memory *reads* work and memory *writes* do not, for reasons that have nothing to do with each
other. Injection is the harness (host-side, unaffected by the mask); writing is the **agent**,
and its instructions name the `Write` tool, which husk removed. The agent therefore experiences
"memory is unavailable", concludes correctly from a false premise, and writes durable state into
the project directory instead — which is what the LETKF session did.

**MEASURED 2026-08-11, and it kills the fix:** `allowWrite: ~/.claude/projects` *does* fire —
the mount table shows a `rw` bind — and **the harness then binds the same source over the same
target read-only, as a child of our own mount.** Deny beats allow, and this deny is not husk's:
it is not in `denyWrite`, and the mandatory list is cwd-scoped. The harness is protecting its own
state directory, which is defensible — a writable transcript directory would let an agent forge
its own transcript.

So agent memory is **not writable, by any route husk controls**, and the shipped carve-out is
inert. **This is a property of the SANDBOX, not of husk** — any Claude Code session with
`sandbox.enabled: true` has an unwritable memory directory, and husk only turns the sandbox
on. There is therefore nothing here for husk to fix, and the inert `allowWrite` entry should
be **removed** once the cluster measurement agrees: a control that does not control is worse
than none, because the next reader takes it for a working carve-out.

**Decision, 2026-08-11: agent memory is project-local under husk.** That raises the value of
the friction-log habit — a lesson that cannot ride in memory across sessions has to be
written into the project or it is lost.

**Worth reporting upstream**, same shape as the CPython ACL report: a shipped feature that
silently does not work under a shipped mode, with no message saying so.

**Not yet measured on the cluster, and the code path there is different:** `/users` gets a
`denyRead` tmpfs, and the vendor re-binds `allowWrite` paths *after* it
(`pushReadDenyDirMounts`). Whether the harness's read-only bind still lands on top of that is
unknown. Measure before concluding — the two sites can genuinely differ here.

## 6. Mediated binaries

`sbatch`, `srun`, `squeue`, `scancel`, `sinfo`, `sacct` — substituted by husk's stubs, which
talk to the out-of-cage broker over a spool. `scontrol`/`sacctmgr` reach the controller only for
the read-only verbs husk allows; from inside a job they cannot resolve it at all.

Also mediated: `seccomp-wrapper` wraps `claude` itself, and `apply-seccomp` is **telemetry, not
enforcement** (fail-open).

## 7. Tool surface

**Admission rule:** a tool is admissible when *every* effect it can have routes through a cage
husk controls — bwrap mounts, or the netns/egress proxy. One rule, both axes.

### 7.1 Every selectable tool, with its disposition

Enumerated 2026-08-10 by passing every candidate name to `--tools` and reading back what the
session exposed. **A list of what we admit is a bug list; this is the decision record.** A tool
absent from this table is excluded by default — that is what an allowlist means — but it is
also a signal that the table is stale.

| tool | disposition | why |
|---|---|---|
| `Bash` | **admitted** | it *is* the caged door |
| `Skill` | **admitted** | loads instructions host-side; no I/O of its own; skill files are not agent-writable |
| `Agent` | **admitted** | delegation inherits the allowlist — *measured*, see §4 |
| `TaskCreate` `TaskUpdate` `TaskList` `TaskGet` `TaskStop` | **admitted** | in-session bookkeeping by their schemas: create/update/list/read, and stop. `TaskCreate` makes a `pending` record and starts nothing. `TaskStop` earns its place beyond symmetry — an agent that spawned background work on a *shared* login node must be able to stop its own runaway, or the only remedy is a human with `kill` |
| `TaskOutput` | excluded | observation only, and safe — but marked **DEPRECATED**, and it duplicates a path that already works: background output lands in a file and `cat` reads it (measured). A deprecated name would also be silently dropped on the upgrade that removes it |
| `ListAgents` | **excluded** | reads harmless — both parameters are disabled in this build — but its own description says it lists cloud sessions and Remote Control sessions **on other machines**. That makes it the DISCOVERY half of the family whose ACTION half (`SendMessage`, `RemoteTrigger`) is already excluded. Enumerate-then-act is one capability, not two |
| `ToolSearch` | admissible, not enabled | **measured: cannot escape the allowlist.** `select:Write,Edit,Read` returned *"No matching deferred tools found"* and no file landed — it searches only what `--tools` already granted. Becomes *necessary* if the admitted set ever grows enough to defer |
| `Read` `Write` `Edit` `NotebookEdit` | **excluded** | host-side filesystem, beside the cage — the two-door problem |
| `Glob` `Grep` | **excluded** | host-side traversal and file-content reads; same door as `Read` |
| `EnterWorktree` `ExitWorktree` | **excluded** | host-side filesystem writes; and a worktree is a fresh project root, where the auto-exec protections do not apply |
| `WebFetch` `WebSearch` | **excluded** | host-side network — `network.allowedDomains` never sees them, exactly as the mount table never sees a `Write` |
| `PushNotification` `RemoteTrigger` `SendMessage` | **excluded** | effects outside the machine or outside the session; neither cage applies |
| `CronCreate` `CronDelete` `CronList` | **excluded** | **scheduled execution that outlives the session and the cage.** The sharpest item on this list: husk's boundary is per-session, and a cron entry is not |
| `ScheduleWakeup` | **excluded** | same family — schedules a future session |
| `DesignSync` | **excluded** | unknown effects; the allowlist's default, and the reason it is a default |
| `LSP` `Monitor` | **excluded, pending measurement** | both plausibly spawn or poll host-side; neither has been measured, so neither is admitted |
| `ReportFindings` | **excluded, pending measurement** | destination unknown |
| `Workflow` | **excluded, and this blocks ultracode — see §7.3** | tool inheritance is *unmeasured* |

**Not selectable at all in this build**, though `BashOutput`, `KillShell` and `TodoWrite` are
real tool names elsewhere: passing them to `--tools` silently drops them. `--tools default` is
also *not* the full set — it omits `Glob` and `Grep`, which are selectable by name.

### 7.1b The enumeration has a blind spot, and it is structural

**Everything above was enumerated headlessly, and headless mode cannot see interactive-only
tools.** `AskUserQuestion`, `Artifact`, `EnterPlanMode`/`ExitPlanMode` and `EndConversation`
exist in a live session and appear in **no** `-p` probe — not in `--tools default`, and not
even when passed by name. The table is therefore complete *for what a `-p` session can reach*,
which is not the same as complete.

This was found the way such things are found: an agent hit `AskUserQuestion` being absent while
holding two decisions for its operator, and asked why.

| tool | disposition | why |
|---|---|---|
| `AskUserQuestion` | **admitted** | renders a choice to the human and returns the answer — no filesystem, no network, no execution, and the operator is the trusted party. Its absence cost an agent a clean hand-off |
| `Artifact` | **excluded — and this one is egress** | it *publishes a page to claude.ai*. Content leaves the machine, past the proxy and the allowlist, exactly as `WebFetch` would. It is in `permissions.deny` rather than merely absent from `--tools`, because absence is not durable (§7.1a) and this is the one where that matters |
| `EnterPlanMode` / `ExitPlanMode` | admissible, not enabled | session mode, no effects |
| `EndConversation` | **excluded** | ends the session; harmless to husk, but a reviewer ending its own run mid-brief wastes a cycle |

**`Artifact` is the finding here, not `AskUserQuestion`.** An exfiltration channel sat outside
the analysis for as long as the analysis was built from headless probes only — and the earlier
conclusion that "the allowlist holds" was measured against a tool set that never contained it.
Whenever this table is revisited, **at least one pass must be made from a live session.**

### 7.1a `--tools` is not durable — and what is

**Measured 2026-08-11, and it changes what C0.1 is worth.** The restriction lives on the
invocation, not the session. `claude --continue` without the flag restores `Read`/`Write`/`Edit`
in full; Christoph saw the same after `/compact`, twice. The tool is genuinely back — not
imagined — because a model can only emit calls for tools present in the request schema.

The durable form is a **bare tool name in `permissions.deny`**. It removes the tool from the
registry (the call reaches no permission prompt, and `ToolSearch` cannot find it), and it
survives re-entry because settings are re-read per session. husk now ships both, and the deny
list is derived from the table above.

**Cost, stated plainly:** the deny is a *denylist*, so on the re-entry path an unknown new tool
is allowed. That is the `P5` failure husk avoids everywhere else, accepted here only because
the alternative is no durable control at all. It makes §7.1 load-bearing rather than
documentary — a tool added upstream is a hole until it appears there.

### 7.2 `--tools` semantics

Names come from the built-in set. An unmatched name is **dropped, not fail-open**
(`--tools TypoBash` yields no `Write`). `""` disables all. The restriction **propagates to
subagents** and **is not escapable via `ToolSearch`**. `run_in_background` is a `Bash`
*parameter*, which is why no output-management tool is needed.

### 7.3 Open: `Workflow`, and therefore ultracode

**ultracode drives the `Workflow` tool, which is not in the allowlist — so ultracode does not
run under husk today.** Enabling it needs the same measurement `Agent` got, and that has not
been possible headlessly:

- a **dynamic** (inline-script) workflow hits an approval gate — *"Review dynamic workflow
  before running"* — which under husk means a human approves each one. That is a reasonable
  control and it also breaks unattended swarms.
- a **named** workflow cannot be planted from inside the cage: `<project>/.claude` is
  **read-only to the caged agent**, so the write fails with `Read-only file system`. Good
  hardening, and it is why the probe could not be completed from inside.

So the measurement has to be driven from *outside* the cage — the same rule that says the
trusted layer runs the probe. Until then `Workflow` stays out, and that is a known functional
gap rather than a decision.

## 8. Lifecycle

- **A session keeps the cage it started with.** Settings are read at session start, so editing
  `settings.json` mid-session changes nothing until relaunch. This has cost real debugging time
  twice; check a session's start time against the file's mtime before concluding anything.
- The broker's `project_dir` is `std::env::current_dir()` **at broker startup** — the session's
  directory, not the caller's. A subagent working in a worktree therefore cannot shift the
  policy root, which is what keeps `F17` closed under delegation.
- `nohup … &` processes are killed between tool calls; `run_in_background` is the supported way.

## Version coupling

**Everything in sections 4, 5 and 7 is upstream Claude Code behaviour, and no test in this
repository pins any of it.** A rename, a default change, or a new tool on auto-update moves
husk's boundary silently. That is the largest unmanaged risk in the profile.

| assumption | measured | how it fails |
|---|---|---|
| `--tools` propagates to subagents | 2026-08-10 | silently, toward more capability |
| unmatched tool name is dropped | 2026-08-10 | silently, toward more capability |
| `isolation: remote` is gated off | 2026-08-10 | silently, toward off-machine egress |
| host-side tools bypass bwrap | 2026-08-04, from SRT source | this one is structural, not a version accident |

**Re-check on every Claude Code upgrade, and once on each cluster's installed version.** The
probes are cheap and headless; the pattern that matters is that each one uses the *filesystem*
as the oracle. **Never ask the agent what tools it has** — asked to enumerate them while holding
none, it recited the full canonical list, and believing it produced a false fail-open alarm.

## What 6a needs from this file

At 6a husk wraps `claude` itself, and this profile stops being a list of flags and becomes the
cage's specification. Three entries change character:

- **§2 row 1 becomes a hole husk must decide about.** The agent's model API traffic is
  currently outside every cage by construction. Inside an outer bwrap it becomes husk's
  problem — and the acceptance test (`ROADMAP` Track B) does not currently mention it.
- **§3.2 becomes the mount list.** The outer cage must permit exactly what the harness needs to
  function, and the inventory above is that list — including the parts nobody thinks about
  (`.credentials.json`, `sessions/`, `paste-cache/`).
- **§7 mostly disappears.** With the agent inside the cage, `--tools` can be deleted, host-side
  tools become safe, and the largest usability cost husk imposes goes away. The acceptance test
  is exactly that deletion.
