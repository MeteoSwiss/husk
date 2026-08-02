# B3 — mount-table construction: findings

**Pass 1 (discovery). Code-only, laptop, no cluster access.**
Instrument: the real builder (`FsPolicy::bwrap_args`) driven from a *scratchpad copy* of the
crate with a dump harness appended — no repo source was modified. Every ordering claim below
was then re-checked against **bwrap 0.6.1** (`/usr/bin/bwrap` on this laptop, the same version
the code's own comments say was measured), using `/home` as a stand-in floor.

---

## Summary

The static mount table is well-constructed in its interior: the hide/allow ops are
depth-sorted so a carve-out is always applied after the mask it carves, and every rule that
must beat the writable bind (`denyRead` re-hide, auto-exec masks, credential `/dev/null`
binds, the guard's `_husk_extra`) is emitted after it. The problems are all at the *edges of
the input*, and they share one root cause: **the floor is defended by three string
predicates that only some of the inputs pass through.** `is_workdir_allowed` guards
`req.cwd` but not the value that actually becomes the write bind; `drop_floor_overlapping_allows`
filters `allowRead`/`allowWrite` but not `denyWrite`; `path_under_floor` is a raw prefix test
that `..` and `//` walk straight through. The result is four distinct ways to get a mount
emitted **after** `--tmpfs /users` whose destination resolves *onto* `/users` — the F18 shape,
four times, on paths F18's fix does not reach. Separately, and independent of the floor: the
**rank cage carries no MUNGE mask at all**, because that mask lives only in the job guard's
`_husk_extra` and bwrap mount namespaces do not propagate — so the second, network-independent
wall that `profile.rs` calls "what keeps the escape-relevant destination unreachable" exists in
the job cage and is simply absent from every rank.

---

## The annotated mount table

Generated, not transcribed. Two tables: the **static** one from
`settings::FsPolicy::bwrap_args` (`slurm-broker/broker/src/settings.rs:597-815`), and the
**appended** one added at run time by the guard (`policy.rs::wrap_script`) or the rank script
(`rank.rs::exec_line`). bwrap applies the concatenation left to right; later wins.

Legend — **src**: `const` = fixed in the source; `cfg` = from the settings hierarchy
(`sandbox.filesystem.*` / `sandbox.credentials.*`, trusted human input, agent cannot write it);
`sess` = from the session/host (project dir, job id, resolved binary paths); `agent` = supplied
by the confined side.

### A. Static args — `FsPolicy::bwrap_args(workdir, kind)`

| # | entry | src | opens / closes | ordering dependency |
|---|---|---|---|---|
| 1 | `--ro-bind / /` | const | Opens the whole host filesystem **read-only**. This is the base plane: everything after it is a delta. | Must be **first**. Everything else assumes a populated, read-only root. |
| 2 | `--dev /dev` | const | Closes the host `/dev` — replaces it with a minimal devtmpfs (null/zero/random/tty/pts). Also closes host `/dev/shm` for both kinds. | Must precede every `--dev-bind-try` and the `/dev/shm` mounts, or they land in the tree it replaces. |
| 3 | `--proc /proc` | const | Opens a fresh procfs. For `Job` (which has `--unshare-pid`) this is what turns the namespace into visible isolation; for `Rank` it shows the *job's* pidns. | Must follow `--dev`/precede nothing in particular; must exist or the pidns is invisible. |
| 4 | `--tmpfs /tmp` | const | Closes the node's `/tmp` (world-writable, shared with other users' jobs). Also *creates* the private `/tmp` that the socat and egress-socket binds later land in. | Must precede the `_husk_extra` binds to `/tmp/husk-socat` and `/tmp/husk-<uid>-<jobid>/net.sock`, which rely on it being a writable tmpfs so bwrap can create the mountpoints without touching the host. |
| 5 | `--tmpfs /dev/shm` | const, **Job only** | Opens a private POSIX-shm namespace for the job. | After `--dev` (which removed `/dev/shm`). |
| 6 | `--unshare-pid` | const, **Job only** | Closes the node's process table: the job cannot name, signal or `process_vm_readv` the un-caged step-broker or egress proxy. | Order-independent (not a mount), but pointless without #3. |
| 7 | `--dev-bind-try /dev/cxi{0..7}` | const, **Rank only** | Opens the Slingshot fabric NICs. `/dev/cxi_sbl` deliberately excluded (0600 root). | After `--dev`. `-try` here is a **feature** degrade (no fabric on a node without one), not a boundary. |
| 8 | `--dev-bind-try /dev/nvidia*`, `/dev/gdrdrv` (18 entries) | const | Opens GPU/NVLink device nodes. Device nodes only — does not widen the filesystem policy. | After `--dev`. `-try` = feature degrade. |
| 9 | `--tmpfs <p>` for `p ∈ HIDDEN_FLOOR ∪ denyRead(absolute)` | const + **cfg** | **The floor.** Closes `/users` — every home, own and others'. Config `denyRead` adds to it. De-duplicated so `/users` in both is mounted once. | Emitted inside one depth-sorted op list with the allows (#10): shallowest first, so a deeper `allowRead` carve-out lands after the mask it carves out of. **This is the only ordering the code states, and it is correct — but it only orders #9 against #10, not against #11-#13.** |
| 10 | `--ro-bind <p> <p>` for `p ∈ allowRead(absolute)` | **cfg** | Re-opens a specific subtree read-only through the floor (the miniconda case). `./` and `.` are skipped (that is the workdir); relative entries are silently skipped. | Sorted with #9 by slash-count. At **equal** depth the stable sort puts hides first, so an `allowRead` that names the same path as a `denyRead` **wins** — undocumented. |
| 11 | `--bind <workdir> <workdir>` | **sess** (`policy.rs:290` → `main.rs:464` `current_dir()`) | Opens the project dir **read-write**. The one writable region every job gets. | **After** #9/#10 — so it beats the floor. That is intentional for a scratch workdir and catastrophic for a workdir under the floor (finding 1). |
| 12 | `--bind <p> <p>` for `p ∈ allowWrite` | **cfg** | Opens each configured root read-write. | **After** #9/#10/#11 — beats the floor and beats the workdir bind (finding 4). |
| 13 | `--ro-bind <p> <p>` for `p ∈ denyWrite(absolute)` | **cfg** | Intended: re-closes writes inside a writable root. Actual: a read-only **bind**, i.e. a *mount that exposes its source*. | Deliberately after #12 so it beats `allowWrite`. Also after #9, which is the bug (finding 3). Relative entries silently dropped (finding 8). |
| 14 | `--tmpfs <abs(p)>` for `p ∈ denyRead` where `abs(p)` is under the workdir or an `allowWrite` root | **cfg** | Re-closes a `denyRead` that #11/#12 just re-opened. F22. Relative entries resolved onto the workdir. | **Must be after #11/#12.** This is the one re-application the code does, and it covers `denyRead` only — not `HIDDEN_FLOOR`. |
| 15 | `--tmpfs <root>/{.claude,.git/hooks,.vscode,.idea}` for every writable root | const × **cfg/sess** | Closes the agent-config and auto-exec **directories** inside every writable root — AV2 (plant a payload that fires on the login side later). tmpfs, not `-try`, so it covers *absent* paths too. | **Must be after #11/#12.** Not absent-safe on the *destination*: kills the cage when `<root>/.git` is a file (finding 7). |
| 16 | `--ro-bind-try <root>/.mcp.json`, `<root>/.git/config` | const × **cfg/sess** | Closes *rewrites* of two files that must stay readable. | After #11/#12. **`-try` means these are skipped when absent — a boundary that degrades silently** (finding 6). `.git/config` omitted when `allowGitConfig`. |
| 17 | `--ro-bind /dev/null <abs(f)>` for `f ∈ credentials.files ∪ denyRead(files) ∪ workdir scan` | **cfg** + scan | Closes each credential file — the job reads empty. `~`-prefixed entries are dropped (left to the floor); relative resolved onto the workdir. | **Must be after #11/#12** so a secret inside the writable workdir is re-denied. Not absent-safe outside the writable set (finding 9). |
| 18 | `--unsetenv <NAME>` for `credentials.envVars` | **cfg** | Drops secrets from the inherited env. | Order-independent vs mounts; must not be followed by a `--setenv` of the same name (rank path filters that — `rank.rs:105-113`). |
| 19 | `--unshare-net` | const | Closes IP. Both kinds. | Not a mount; position irrelevant. |

### B. Appended at run time — the JOB guard (`policy.rs::wrap_script`, golden `guard-net-on.sh:204`)

Everything here is appended **after** #19 via `${_husk_extra[@]}`, so it beats every static
entry — that is the stated and load-bearing ordering.

| entry | src | opens / closes | note |
|---|---|---|---|
| `--tmpfs /run/munge` (and `/var/run/munge`, de-duplicated via `readlink -f`) | const, resolved on the compute node | **Closes MUNGE.** Decouples "the job has a route" from "the job can submit un-caged jobs" (AV8). Resolved on the node because `--tmpfs DEST` is neither absent- nor symlink-safe. | Guarded by `[ -d "$_d" ]`, so absent ⇒ skipped, which is correct (nothing to mask). **Job cage only** — finding 2. |
| `--ro-bind <socat> /tmp/husk-socat` | sess | Opens husk's socat inside the cage at a fixed path in the cage's own tmpfs. | Read-only bind, not a copy, so the job cannot replace its own relay binary. Lands in #4's tmpfs ⇒ nothing on the host to clean up. |
| `--ro-bind <net.sock> <net.sock>` | sess (`/tmp/husk-<uid>-<jobid>/net.sock`) | Opens the one route out. Read-only bind so the job cannot delete or replace the socket; `connect(2)` still works. | Bound only after a bounded wait proves the proxy bound it — otherwise `HUSK_NET_SOCK` is unset and the job runs with no egress. Correct direction. |
| `--ro-bind <srun-stub> <real srun>` | sess | Replaces `srun` with the brokering stub. | "Convenience, not containment" — the guard says so out loud when it cannot do it. |

### C. Appended at run time — the RANK script (`rank.rs:181-206`, `rank.rs:258-283`)

`bwrap --userns 9 --pidns 8 <static rank args> --bind "$_d" /dev/shm --bind-try "$_s" "$_s" [--ro-bind-try <socat> /tmp/husk-socat --ro-bind-try <sock> <sock>] --`

| entry | src | opens / closes | note |
|---|---|---|---|
| `--userns 9` | sess (holder pid) | Joins the job's user namespace — the single share that legalises rank-to-rank CMA. | Fail-closed: the script refuses to run if `/proc/<holder>/ns/user` is unreadable. |
| `--pidns 8` | sess | Joins the job's PID namespace. | Ranks see each other, not the node. Note: `settings.rs:1194-1200` asserts in prose that this is impossible (finding 12). |
| `--bind "$_d" /dev/shm` | sess (`/dev/shm/husk-$SLURM_JOB_ID`) | Opens the per-job shared-memory dir **read-write** as `/dev/shm`. Replaces the private tmpfs the job cage gets — a per-rank tmpfs hangs same-node MPI. | `mkdir -m 700` + `[ -O ]`, because `/dev/shm` is world-writable and job ids are public in `squeue`. Correct. |
| `--bind-try "$_s" "$_s"` | sess (`<SlurmdSpoolDir>/mpi_cray_shasta/<jobid>.<stepid>`) | Opens the per-step apinfo directory **read-write**. | Read-write for a path the ranks only read (finding 10). |
| `--ro-bind-try <socat> /tmp/husk-socat`, `--ro-bind-try <sock> <sock>` | sess | Per-rank egress relay. Each rank binds its own — bwrap namespaces do not propagate. | `-try` = honest degrade to "no network". |
| *(nothing)* | — | **No `/run/munge` mask.** | Finding 2. |

**Job vs Rank delta, confirmed against generated output:** in the *static* args the only
differences are exactly the two documented ones (`--tmpfs /dev/shm` + `--unshare-pid` for Job;
the eight `/dev/cxi*` for Rank). In the *full* command line the delta is much larger: a rank
additionally gets `--userns`/`--pidns`, a shared read-write `/dev/shm`, a read-write apinfo
bind — and **loses** the MUNGE mask and the private `/dev/shm`. The test named
`rank_cage_keeps_every_containment_property_of_the_job_cage` (`settings.rs:1221`) checks three
properties and is therefore satisfiable while its own name is false.

---

## Findings

### 1. The cage's writable root is never validated — launching husk from `$HOME` binds the home writable *through* the floor · **CONFIRMED**

`main.rs:464`: `let project_dir = std::env::current_dir()`. `policy.rs:290,354`:
`root = project_dir` → `fs.compute_bwrap_args(&root)` → entry #11, `--bind <root> <root>`,
emitted **after** `--tmpfs /users`. `settings::is_workdir_allowed` exists and rejects exactly
this (`settings.rs:290-298`, "Jobs must run from a scratch/project path", F15/F19) — but it is
called only on the agent-supplied `req.cwd` (`policy.rs:97`, `step.rs:278`), never on the value
that becomes the bind. Nothing in `install-husk.sh` or the wrapper constrains the launch
directory either.

Generated table for `workdir=/users/me`:

```
 66  --tmpfs /users
 68  --bind /users/me /users/me          <- floor undone, read-WRITE
 71  --tmpfs /users/me/.claude
```

and for `workdir=/` (husk launched from `/`):

```
 66  --tmpfs /users
 68  --bind / /                          <- entire host filesystem, read-WRITE
```

Confirmed against bwrap 0.6.1:

```
$ bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /home \
        --bind /home/christoph /home/christoph -- ls -a /home/christoph
.git  .ssh  ...                     # visible
# /proc/self/mountinfo inside: /home/christoph rw,nosuid,nodev,relatime
```

Scenario: a user does `cd ~ && husk`. Every brokered job then has read-write access to the
whole home. Three things break at once:

* `~/.ssh`, `~/.aws`, `~/.netrc` are readable (the `~`-prefixed `credentials.files` entries are
  *deliberately* dropped by `abs_for_cage` on the grounds that "the floor already hides them",
  `settings.rs:322-323` — so with the floor gone they are unmasked, not doubly masked);
* `~/.bashrc`, `~/.profile`, `~/.zshrc` are writable — none of them is in `AUTO_EXEC_DIRS` —
  which is AV2 with the cage bypassed;
* `$HOME/.husk/log/job-<id>.log` becomes writable by the job. The guard's own comment
  (`guard-net-on.sh:37-42`) justifies putting the log there precisely because "`$HOME` is
  tmpfs-masked inside the cage, so this file is out of the job's reach entirely". With the home
  as the workdir, the audited party can author the audit trail.

The narrower and much more common case — `cd ~/myproject && husk` — exposes only that subtree,
which is arguably the intent; but it is the same code path, so there is no line where the safe
case and the unsafe case diverge. Suggested shape of the fix: run `project_dir` through
`is_workdir_allowed` at broker startup and refuse to start, naming the reason.

### 2. Rank cages carry no MUNGE mask · **CONFIRMED (absence)**

`CREDENTIAL_SOCKET_DIRS` (`settings.rs:99`) is referenced in exactly two non-test places:
`policy.rs:615`, which bakes it into the **job guard**'s `_husk_extra`. `step.rs:315` and
`rank.rs` never apply it. Verified by generating the complete rank argv (see table C above):
there is no `--tmpfs /run/munge` anywhere in it.

The rank cage starts from its own fresh `--ro-bind / /`; the job cage's mount namespace does
not propagate into it (the code knows this — it is the stated reason each rank re-binds socat
itself, `rank.rs:143-150`). So `/run/munge/munge.socket.2` is present in every rank cage, and
`connect(2)` through a read-only bind works — the guard's own comment asserts that as measured
fact (`guard-net-on.sh:119-121`). `Profile::SingleNode::seccomp_profile` adds **no** syscall
rules (`profile.rs:73-85`), explicitly because "the MUNGE mount mask is what keeps the
escape-relevant destination unreachable". For a rank, it does not.

Why it matters rather than being pure defence-in-depth: `settings.rs:94-98` states the purpose
is to "DECOUPLE 'the job has a network route' from 'the job can submit un-caged jobs' (AV8)…
a second, independent wall that survives if multi-node MPI ever forces the netns to be
relaxed." Ranks are precisely the code path where the netns will be relaxed for multi-node.
Today `--unshare-net` still holds in a rank, so this is a missing wall rather than a live
escape — which is why it is finding 2 and not finding 1 — but it is the wall that was built to
survive the removal of the other one, and it is missing on the side that will lose the other
one first.

Reproducer for triage (no cluster needed to see the absence; one arm to prove reachability):
assert `--tmpfs /run/munge` is present in the rank argv, and/or a selftest arm that runs
`munge -n` inside a rank and expects failure.

### 3. `denyWrite` is not filtered against the floor, and a `denyWrite` is a *bind* — so `denyWrite: ["/users"]` re-exposes every home · **CONFIRMED**

`drop_floor_overlapping_allows` (`settings.rs:558-561`) retains on `allow_read` and
`allow_write` only. `deny_write` is never floor-filtered, never symlink-filtered
(`drop_symlinked_carveouts`, `settings.rs:551-554`, also covers only the two allow lists), and
is emitted at #13 as `--ro-bind p p` — a mount that *exposes its source at that destination*.
Entry #13 comes after entry #9.

```
===== denyWrite=["/users"] =====
 66  --tmpfs /users
 71  --ro-bind /users /users            <- the floor, back, read-only
drop_floor_overlapping_allows leaves deny_write = ["/users"]
drop_symlinked_carveouts  leaves deny_write = ["/users"]
```

Confirmed against bwrap 0.6.1 (`--tmpfs /home` … `--ro-bind /home /home` → `/home` lists real
contents, exit 0).

This is F18 exactly, on the one filesystem field F18's fix does not cover. It is also the most
*plausible misconfiguration* of the four floor bypasses, because `denyWrite: ["/users"]` reads
in English as "jobs must not write to homes" — and its actual effect is to make every home in
the cluster readable inside the cage. A deny that grants.

### 4. `allowWrite: ["/"]` survives the floor filter and mounts the host root read-write · **CONFIRMED**

`path_under_floor` (`settings.rs:303-308`) trims trailing slashes, so `"/"` normalises to `""`,
which is neither equal to `/users` nor prefixed by `/users/` — `"/"` is *not* dropped. It is
then emitted at #12, after the floor:

```
===== allowWrite=["/"] =====
 66  --tmpfs /users
 68  --bind /work/project /work/project
 71  --bind / /                          <- host root, read-WRITE
after drop_floor_overlapping_allows: allow_write=["/"]
```

Confirmed against bwrap 0.6.1 — `/proc/self/mountinfo` inside shows `/ rw,…` and `/home` lists
real contents.

The instructive part is the **asymmetry**: `allowRead: ["/"]` is harmless, because `"/"` has a
slash-count of 0 and therefore sorts to the *front* of the op list, landing at index 66 *before*
`--tmpfs /users` at 69. The identical value is safe on one field and total on the other, purely
because one is inside the depth-sorted op list and the other is not. This is the brief's
"a rule correct in isolation undone by what follows it", with the two halves visible side by
side.

### 5. The floor predicates are raw string tests — `..` and `//` walk through them · **CONFIRMED**

`path_under_floor` does one `trim_end_matches('/')` and two string comparisons. No
normalisation, no `..` handling, no duplicate-slash handling. `is_workdir_allowed` checks for
`..` components but not for `//`. Measured:

```
path_under_floor("/users")        = true
path_under_floor("//users")       = false      <- floor filter bypassed
path_under_floor("/./users")      = false      <- floor filter bypassed
is_workdir_allowed("//users")     = true       <- workdir gate bypassed
```

Consequences, each confirmed in a generated table:

* `allowWrite: ["//users/me"]` is kept by `drop_floor_overlapping_allows` and emitted as
  `--bind //users/me //users/me` at index 71, after the floor. bwrap 0.6.1 treats `//x` as
  `/x` (verified: `--bind //home/christoph //home/christoph` lists the real home).
* `allowRead: ["/scratch/a/../../users"]` is kept (`drop_floor` leaves it; `drop_symlinked_carveouts`
  does not flag it, since `lstat` of a path ending in `..` resolves the `..` and the path need
  not exist at all) and is emitted at **depth 5**, i.e. after the depth-1 floor mask.
  Verified against bwrap 0.6.1:

  ```
  $ bwrap --ro-bind / / --tmpfs /home \
          --ro-bind /home/christoph/../../home /home/christoph/../../home -- ls -a /home
  .  ..  christoph
  ```

  bwrap's `mkdir_with_parents` + `mount()` both let the kernel resolve `..`, so the destination
  lands on `/home` — on top of the tmpfs.
* `is_workdir_allowed("//users/x") == true` means the step-broker (`step.rs:278`) accepts
  `req.cwd = "//users/victim"` from the **agent** and passes it verbatim to `srun --chdir`
  with no canonicalisation. Today the impact is nil (the rank cage still tmpfs-masks `/users`,
  so that directory does not exist inside the cage and bwrap falls back). But the function's
  own docstring describes it as the gate on a path that gets "bound WRITABLE into the compute
  cage" — so the next caller who uses it that way inherits a live hole. `policy.rs:97` is safe
  only because `confine_under_any` canonicalises downstream.

The fix is one line of shape: canonicalise (or at minimum normalise `//` and reject `..`)
before every floor test, and apply the floor test to `deny_write` too.

### 6. The auto-exec mask set is not the superset it claims to be, and its two file entries are `-try` · **CONFIRMED (mount table); the AV2 chain is PLAUSIBLE**

`settings.rs:112-113` states the intent: "The set mirrors what the login-side runtime masks …
keep it a SUPERSET — it protects the login side, we protect the job side." The login runtime's
mandatory set is in `sandbox-runtime/src/sandbox/sandbox-utils.ts:11-27` and
`linux-sandbox-utils.ts:277-322`:

| login runtime denies | husk compute cage |
|---|---|
| `.gitconfig`, `.gitmodules`, `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`, `.ripgreprc` | **not masked** |
| `.mcp.json` | `--ro-bind-try` — skipped when absent |
| `.vscode`, `.idea` | `--tmpfs` ✅ |
| `.git/hooks`, `.git/config` (top level) | `--tmpfs` ✅ / `--ro-bind-try` |
| `**/.git/hooks/**`, `**/.git/config`, `**/.vscode/**`, `**/.idea/**` (every subdirectory, via ripgrep) | **top level of each writable root only** |
| — | `.claude` ✅ (husk adds this; the runtime handles settings files at its own call site) |

Two concrete gaps in the emitted table:

* **Nested repos.** `<workdir>/subrepo/.git/hooks/` is writable in the cage. So is
  `<workdir>/.git/modules/<submodule>/hooks/` — a submodule's `$GIT_DIR`, whose hooks git runs
  on `submodule update`/`checkout`. Neither matches any emitted mask.
* **The `-try` degrade is a boundary, not a feature.** Confirmed:
  `bwrap … --ro-bind-try /definitely/not/here /tmp/mcp.json -- …` exits 0 with nothing
  mounted. In a project with no `.mcp.json`, the job can create one. That is acknowledged and
  backstopped by `enableAllProjectMcpServers: false` in the shipped config
  (`user-config/settings.json:2`) — but that backstop is a *settings key*, not the mount table,
  i.e. exactly the class of "policy prose standing in for the enforcement boundary" this brief
  is about. `.git/config` has the same shape with a weaker backstop: in a **non-git** workdir
  bwrap creates a real `.git/` (see finding 7's second half), `.git/hooks` is a tmpfs so writes
  there evaporate — but `.git/config` is *creatable and persists*, and `core.hooksPath` can then
  point at any unmasked directory inside the workdir. Whether a later login-side `git` command
  actually fires it depends on someone running git there, hence PLAUSIBLE for the chain,
  CONFIRMED for the table permitting it.

### 7. `--tmpfs <root>/.git/hooks` kills the whole cage when `.git` is a file, and fabricates a `.git` when it is absent · **CONFIRMED**

Entry #15 is emitted unconditionally for every writable root. The login runtime guards both
cases explicitly (`linux-sandbox-utils.ts:210-216` `hasFileAncestor`, and `:288-292`
`dotGitIsDirectory` — "In git worktrees, `.git` is a file … denying it would cause bwrap to
fail"). husk does not. Measured on bwrap 0.6.1:

```
# .git is a file (git worktree, or a submodule checkout)
bwrap … --bind $W $W --tmpfs $W/.claude --tmpfs $W/.git/hooks -- true
bwrap: Can't mkdir parents for …/.git/hooks: Not a directory
exit=1

# .git absent
exit=0 ; and on the HOST afterwards:  $W/.claude/  and  $W/.git/hooks/  now exist
```

So: **every brokered job whose project dir (or any `allowWrite` root) is a git worktree or a
submodule checkout fails to start at all**, with a bwrap diagnostic and no husk attribution —
the identical failure mode the MUNGE constant documents at length (`settings.rs:75-83`,
"both killed the cage outright"). It is fail-*closed*, so not a containment hole, but it is an
unattributed denial (B2's property 2) on a completely ordinary repo layout.

The absent-`.git` half leaves a real, empty `.git/hooks/` on the host in a directory that was
not a repository. `settings.rs:125-126` calls this "at most an empty directory, which is
harmless"; it is not quite harmless, because a bogus `.git` truncates git's upward repository
discovery for that directory.

Same class, worth listing together because they share the cause (non-`-try` mounts on
input-derived destinations, evaluated on the login node):

* `allowRead` / `allowWrite` / `denyWrite` naming a path that does not exist on the **compute**
  node → `bwrap: Can't find source path …` → job dies. (`--ro-bind`/`--bind`, not `-try`.)
* `denyRead` naming a directory absent on the compute node → `--tmpfs` under the read-only root
  → `bwrap: Can't mkdir /x: Read-only file system` → job dies.
* `HIDDEN_FLOOR` itself: `--tmpfs /users` on a site without `/users` takes every job down.
  (Fail-closed and arguably right, but it means the floor constant is also a hard site
  dependency.)

### 8. Relative `denyWrite` is silently dropped on compute — F22, unfixed on this one field · **CONFIRMED**

F22 (`settings.rs:310-328`, `abs_for_cage`) fixed relative entries for `denyRead` and
`credentials.files`, on the stated grounds that "a relative `denyRead` … was previously dropped
on compute while the login cage honored it, so the two cages drifted and a relative deny failed
OPEN". `deny_write` at `settings.rs:726` still uses the raw `if p.starts_with('/')` test.
Measured, same policy, same workdir:

```
relative denyRead  honoured : true    ->  --tmpfs /work/project/secrets
relative denyWrite honoured : false   ->  (nothing emitted)
```

The shipped config's own `denyWrite` list is `["~/.claude/settings.json",
".claude/settings.json", ".claude/settings.local.json", "~/.local/lib/husk"]` — **all four are
relative or `~`-prefixed, so none of them is emitted into the compute cage at all.** In this
specific case nothing is lost (the whole `.claude` directory is tmpfs-masked by entry #15, and
`~/…` is behind the floor). But `settings_sources_are_all_write_denied_by_the_shipped_config`
(`settings.rs:946`) asserts the pairing "the broker reads policy from X, the shipped
`denyWrite` protects it" — and on the compute side that protection comes from a *different*
mechanism than the one the test names. The test passes for the wrong reason, and any operator
who adds a relative `denyWrite` gets login-side enforcement and compute-side silence.

### 9. The comment that says `--ro-bind /dev/null <absent dest>` is safe is false under a read-only root · **CONFIRMED**

`settings.rs:791-793`: "`--ro-bind /dev/null <dest>` also works when the path is absent (bwrap
creates an empty file there), so no stat is needed." True only when the destination lives on a
writable mount. Measured on bwrap 0.6.1 under `--ro-bind / /`:

```
--ro-bind /dev/null /etc/husk-b3-absent.pem  ->  Can't create file at …: Read-only file system, exit 1
--ro-bind /dev/null /nodir/deep/secret.pem   ->  Can't mkdir parents for …: Read-only file system, exit 1
--ro-bind /dev/null /etc/ssl                 ->  Can't create file at …: Is a directory, exit 1
```

So a `sandbox.credentials.files` entry naming an absolute path **outside** the writable set
that is absent on the compute node (a login-only path, a stale entry, a host-specific
`/etc/...` credential) takes down every brokered job — and the code comment says explicitly
that no stat is needed. The F6a auto-scan is unaffected (it only ever produces paths inside the
workdir, which is writable). Fail-closed, but it is a landmine sitting under a comment that
says there is no landmine.

### 10. The rank's apinfo bind is read-write for a path ranks only read · **PLAUSIBLE**

`rank.rs:196,200` — `--bind-try "$_s" "$_s"` where `_s=<SlurmdSpoolDir>/mpi_cray_shasta/<jobid>.<stepid>`.
Under `--ro-bind / /` this is the only thing making that path writable inside the rank cage,
and it is a directory in slurmd's own spool. The apinfo file is produced by slurmd's
cray_shasta plugin and consumed by the PMI/PALS bootstrap; nothing in a rank writes it.
Whether a rank can actually write there depends on host DAC (if slurmd creates it root-owned,
it cannot), which is why this is PLAUSIBLE and not CONFIRMED — it needs one `touch` inside a
rank on real hardware to settle. Least privilege says `--ro-bind-try`. It is also a writable
region that `HUSK_WRITABLE` does not announce, which matters for A7/A8's "does the announced
writable set match the real one".

### 11. Two unstated precedence rules in the op list · **CONFIRMED (documentation gap)**

Both fall out of the depth sort at `settings.rs:686-691` and neither is written down:

* **`allowRead` beats `denyRead` at equal depth.** The sort key is slash-count and the sort is
  stable, so for the same path the hide (pushed first) is emitted before the allow. Generated:
  `--tmpfs /capstor/secret` at 68, `--ro-bind /capstor/secret /capstor/secret` at 70 → readable.
  This is the *opposite* convention from `denyWrite`, which the code deliberately emits after
  `allowWrite` so that deny wins (`settings.rs:722-724`). Read denies lose to read allows; write
  denies beat write allows. One of those is a decision and one is an accident, and the file does
  not say which.
* **An `allowRead` inside a writable root is shadowed by the write bind.** Generated with
  `allowRead: ["/work/project/vendor"]`, workdir `/work/project`: the `--ro-bind` lands at 68,
  the `--bind /work/project` at 71 — so the path the human asked to be read-only is read-write.
  Harmless today (the region was writable anyway), but it is a rule silently undone by what
  follows it, and it is the mirror image of the F22 re-application that *does* exist for
  `denyRead`.

### 12. Stale prose: the file asserts ranks cannot join a PID namespace, and `rank.rs` gives them one · **CONFIRMED**

`settings.rs:1194-1200` (the rationale on
`only_the_job_cage_unshares_pids_because_a_rank_must_still_name_its_peers`) states: "`bwrap
--pidns FD` is parent-only (with `--unshare-pid` it makes the given namespace the parent of a
fresh one; without it bwrap fails outright, 'Can't send pid: Invalid argument', measured on
0.6.1), so ranks cannot join a shared PID namespace the way they join the shared user
namespace." `rank.rs:181-206` emits `bwrap --userns 9 --pidns 8 …` with no `--unshare-pid`, and
`bwrap 0.6.1 --help` documents `--pidns FD` as "Use this user namespace (as parent namespace
**if using** `--unshare-pid`)" — i.e. plain `setns` when `--unshare-pid` is absent, which is
what the shipped rank does. The prose is a superseded measurement left in the file that most
needs to be trustworthy. Correctness of the *behaviour* is B4's; the finding here is that the
mount-table oracle's own commentary now contradicts the shipped table.

---

## What I tried that did NOT break it

* **The depth sort against ancestor/descendant carve-outs.** `denyRead: ["/a"]` +
  `allowRead: ["/a/b"]`, and the reverse, both order correctly: the shallower rule is emitted
  first, the deeper one wins. `allowRead: ["/scratch/x"]` under `denyRead: ["/scratch"]` behaves
  as intended. The sort key (slash count) is the right key for this relation.
* **`denyRead` under a writable root.** F22's re-application (#14) is correct and correctly
  placed: absolute and relative `denyRead` entries landing inside the workdir or an `allowWrite`
  root are re-`--tmpfs`'d after the write binds. Verified for `secrets`, `./nested/creds`, and
  `/work/project/inner` (the last is emitted twice — once in the op list, once after the bind —
  which is redundant but correct).
* **`credentials.files` after the workdir bind.** `--ro-bind /dev/null <secret>` is emitted
  after every write bind, so a secret inside the writable workdir is genuinely re-masked.
  Verified for absolute, workdir-relative and `~`-prefixed forms.
* **`allowWrite` that is a parent, a child, or a sibling of the workdir.** All three produce
  correct tables; the auto-exec masks are emitted after *both* binds in every case, so an
  `allowWrite: ["/work"]` with workdir `/work/project` does not leave `/work/project/.claude`
  exposed by the later `/work` mount.
* **`denyWrite` naming the workdir itself.** `--ro-bind /work/project /work/project` lands after
  the `--bind`, making the workdir read-only — coherent, if unusual.
* **`allowRead: ["/"]`.** Sorts to the front (slash count 0), lands *before* the floor, harmless.
  (Its `allowWrite` twin is finding 4.)
* **`allowRead: ["./"]` / `["."]`.** Explicitly skipped rather than emitted as a bind over a
  relative path.
* **The private `/dev/shm` in the job cage, and its absence in the rank cage.** `--dev /dev`
  does not create `/dev/shm`, so a rank has no `/dev/shm` at all until the final
  `--bind "$_d" /dev/shm` — the host `/dev/shm` is never visible in either cage. The
  `mkdir -m 700` + `[ -O ]` ownership check on the per-job directory correctly handles the
  pre-creation race that world-writable `/dev/shm` plus public job ids would otherwise allow.
* **Env masking vs env forwarding.** `--unsetenv` from `credentials.envVars` is emitted inside
  the static rank args, and `rank::env_args` filters those names out of the forwarded delta, so
  a forwarded variable cannot undo the mask despite being appended later.
* **`_husk_extra` ordering in the job guard.** Appended after every static argument including
  `--unshare-net`, so the MUNGE mask, the socat bind and the egress-socket bind all beat the
  workdir bind — the stated dependency holds, and the golden files pin it.
* **The `-try` device binds.** `/dev/nvidia*`, `/dev/cxi*`, the egress socket and socat: every
  one of these degrades a *feature*, not a boundary. `/dev/cxi_sbl` is correctly excluded.
* **`HIDDEN_FLOOR` completeness for the two sites we run on.** Every absolute path in
  `bringup-balfrin-*.txt` and `bringup-santis-*.txt` is under `/users` (homes),
  `/scratch/mch/<user>` (Balfrin scratch) or `/capstor/scratch/cscs/<user>` (Santis scratch).
  No second home root appears in any bring-up log, doc or threat model. So `["/users"]` looks
  complete *for homes* on both clusters — I cannot prove it from the laptop, and the residual
  is worth stating explicitly rather than treating as covered: **personal scratch is not
  floor-covered**, and dotfiles, SSH keys and `.netrc` copies routinely live there.
  `THREAT-MODEL.md:15` already accepts this ("confidentiality rests on the `/users` mask …
  not on read scoping"), so it is a documented residual, not a finding — but findings 1 and 3
  both become materially worse if a second home-like root ever appears.
