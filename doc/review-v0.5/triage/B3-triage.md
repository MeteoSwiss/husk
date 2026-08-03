# B3 triage — mount-table construction (pass 2)

**Code-only, laptop, no cluster. No repo source file was modified.**

Instruments, all built for this pass:

* `scratchpad/broker/` — a copy of `slurm-broker/broker` with two extra binaries appended
  (`src/bin/b3dump.rs`, `src/bin/b3rank.rs`) and a `pub mod b3 { … }` shim appended to the
  end of the *copy's* `settings.rs` to reach the private predicates. Nothing above the
  append point was touched, so all line numbers below are the repo's.
  * `b3dump <home> <project_dir> <workdir> job|rank` drives the **real**
    `FsPolicy::resolve()` over real settings files on disk (so `split_file_denies`,
    `drop_symlinked_carveouts`, `drop_floor_overlapping_allows` and the F6a credential scan
    all run) and prints the numbered mount table.
  * `b3rank` emits the **complete** rank command line via the real
    `rank::wrap_command` + `FsPolicy::rank_bwrap_args`.
* The **shipped release binary**, built from the repo and invoked by explicit path —
  `slurm-broker/broker/target/release/husk-slurm-broker` — driven end-to-end in `--dry-run`
  against a hand-written `req-*.json`, inside a `bwrap --tmpfs /` scaffold that gives this
  laptop a real `/users` so `confine_under_any`'s `canonicalize` has something to resolve.
  The gitignored prebuilt `slurm-broker/husk-slurm-broker-x86_64` was never used.
* `bwrap 0.6.1` (`/usr/bin/bwrap`), with `/home` as the stand-in floor.

Every table below is generated. Every ordering claim was re-run through real `bwrap`.

## Summary

| ID | outcome | my severity | one line |
|---|---|---|---|
| **F1** | **CONFIRMED**, impact narrative corrected | **HIGH** | The write root really is unvalidated, and I drove a **submitted** job whose cage carries `--tmpfs /users --bind /users/me /users/me` through the shipped binary. But the finder's headline scenario is wrong in an important direction: `cd ~ && husk` and `cd ~/proj && husk` **reject every submission** for an honest agent. The live exposure comes from (a) the `//` bypass of F5, or (b) launching from `/` or a shared scratch parent, which needs no trick at all. |
| **F5** | **CONFIRMED**, and it is F1's live delivery mechanism | **HIGH** | `path_under_floor("//users")==false`, `is_workdir_allowed("//users")==true`; bwrap 0.6.1 resolves `//x`, `/./x` and `a/../x` onto the floor. Demonstrated end-to-end: `req.cwd="//users/me"` turns "rejected" into "submitted, home bound read-write". |
| **F6** | **CONFIRMED**, and the AV2 chain is no longer "plausible" — **I executed it** | **HIGH** | With the *shipped default* table and no config change, a job wrote `<workdir>/.git/config` with `core.hooksPath` plus an executable payload; both persisted on the host; a later `git init && git commit` ran the payload as the user, outside every cage. Also confirmed: nested `.git/hooks`, submodule `$GIT_DIR/hooks`, nested `.claude`, `.bashrc`/`.gitmodules`/`.profile` all persist. |
| **F3** | **CONFIRMED** | **MEDIUM** | `denyWrite:["/users"]` emits `--ro-bind /users /users` **after** `--tmpfs /users`; verified against bwrap that the real homes come back, read-only. Config-dependent: the **shipped default config does not contain it** and its emitted table is byte-identical to the empty-policy one. |
| **F4** | **CONFIRMED**, and worse than stated | **MEDIUM** | `allowWrite:["/"]` survives the floor filter and emits `--bind / /` last. It does not merely re-open the floor — measured, it also undoes `--dev`, `--proc`, `--tmpfs /tmp` and `--tmpfs /dev/shm`, restoring the host `/dev` (280 nodes vs 14) and the host `/proc` (host PID 1 readable despite `--unshare-pid`). Not in the shipped config. |
| **F2** | **CONFIRMED (absence)** | **MEDIUM** | No `--tmpfs /run/munge` anywhere in the generated rank argv, and nothing else covers it: `Profile::SingleNode` adds no syscall rules and `seccomp_wrapper.c` deliberately does *not* block AF_UNIX. `netallow.rs:15` asserts the mask holds "in every cage" and calls it "the load-bearing one" — that sentence is false for ranks. |
| **F7** | **CONFIRMED**, both halves | **MEDIUM** | `.git` as a file (an ordinary `git worktree`) kills the cage with a bare bwrap diagnostic and no husk attribution; `.git` absent leaves a fabricated `.git/hooks/` on the host — which is the *enabling step* of F6's demonstrated chain, so `settings.rs:125-126`'s "harmless" is wrong. |
| **F11** | **CONFIRMED**, and sharpened | **LOW** | Both precedence rules reproduce. Sharper: the same `denyRead`+`allowRead` pair resolves in **opposite directions** depending on whether the target is a *file* or a *directory* at resolve time on the login node — file ⇒ deny wins (`/dev/null` bind is last), directory ⇒ allow wins. |
| **F8** | **CONFIRMED**, one sub-claim recharacterised | **LOW** | Relative `denyWrite` really is dropped on compute while relative `denyRead` is honoured — measured side by side under one policy. The shipped `denyWrite` list emits **nothing** into the compute cage. But the cited test is not vacuous: it asserts two written lists against each other and can fail. What is false is the *comment* above it. |
| **F9** | **CONFIRMED**, plus two findings of my own | **LOW** | All three bwrap failures reproduce verbatim. Two additions: an absent credential path *inside* the writable workdir leaves a persistent 0-byte file in the user's project, and a `/dev/null` credential mask reads back **EACCES, not empty** — the opposite of what `settings.rs:360` and `:788` promise. |
| **F10** | **UNRESOLVED — NEEDS HARDWARE** | — | Code confirms `--bind-try` (read-write) for a path ranks only read. Whether a rank can write there is host DAC. Exact command below. |
| **F12** | **FLAGGED — overlaps B4** | — | The prose/behaviour contradiction is real (`bwrap 0.6.1 --help` says `--pidns FD` is "parent namespace **if using** `--unshare-pid`"), but per the protocol I do not resolve it. |

**One thing the finder did not claim that I want on the record:** the *shipped* default
`user-config/settings.json` produces a compute mount table **identical** to the empty
policy — `/users` deduped to one `--tmpfs`, `allowRead:["./"]` skipped, all four `denyWrite`
entries dropped. So F3 and F4 are footguns in a configuration surface, not defects in the
default install; F1, F5, F6, F7 need no configuration at all.

---

## F1 — the cage's writable root is never validated · CONFIRMED (HIGH), with the impact narrative corrected

### What I did

Read the chain: `main.rs:464` `let project_dir = std::env::current_dir()` →
`policy.rs:290` `let root = project_dir.to_string_lossy()` → `policy.rs:354`
`fs.compute_bwrap_args(&root)` → entry `--bind <root> <root>`, emitted after the floor.
`settings::is_workdir_allowed` (`settings.rs:290`) is called at `policy.rs:97` on `req.cwd`
and at `step.rs:278` on the step's cwd — never on `root`. I then attacked the *reachability*
rather than the code reading, because that is what severity turns on.

Read the shipped launch path in full: the `husk` launcher is written inline by
`install-husk.sh` (the heredoc at lines 361-428). It resolves `claude`, locates the
wrapper/broker/stub, reads the recorded partition and account, and `exec`s
`husk-slurm-wrapper -- seccomp-wrapper claude`. **It never inspects the current directory.**
`husk-slurm-wrapper.rs` uses `current_dir()` only to name the spool. So nothing upstream
constrains where husk is launched.

Then I drove the real release binary end-to-end. Scaffold (so `/users` exists on this
laptop):

```
bwrap --tmpfs / --ro-bind /usr /usr --ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 \
      --ro-bind-try /bin /bin --ro-bind-try /sbin /sbin --ro-bind /etc /etc \
      --proc /proc --dev /dev --tmpfs /tmp \
      --bind $SCRATCH/users /users --ro-bind <repo> /repo -- /users/e2e.sh <broker-cwd> <req.cwd>
```

where `e2e.sh` starts `/repo/slurm-broker/broker/target/release/husk-slurm-broker
--dry-run --poll-ms 50` with that cwd and drops one `req-*.json`.

### What happened

| broker cwd (`root`) | agent's `req.cwd` | result |
|---|---|---|
| `/users/me` | `/users/me` | **rejected** — "Working directory \"/users/me\" is not allowed…" |
| `/users/me/proj` | `/users/me/proj` | **rejected** — same message |
| `/users/me` | `/users/me/./` | **rejected** |
| `/users/me` | `//users/me` | **SUBMITTED** |
| `/` | `/scratchdir/x` | **SUBMITTED** |

The staged script for the `//users/me` case contains, verbatim:

```
'--tmpfs' '/users' '--bind' '/users/me' '/users/me' '--tmpfs' '/users/me/.claude' …
```

and the forced options are `--chdir=/users/me --output=/users/me/slurm-%j.out
--error=/users/me/slurm-%j.err` — i.e. slurmd, running as the user **outside** the cage,
also writes into the home.

For the `/`-launched case the staged script contains `'--tmpfs' '/users' '--bind' '/' '/'`
and `HUSK_WRITABLE='/'`.

Against bwrap 0.6.1:

```
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /home \
      --bind /home/christoph /home/christoph -- sh -c 'ls /home; ls /home/christoph/.ssh; touch …'
  -> /home lists only `christoph`; .ssh readable; WRITE-OK; exit 0
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /home --bind / / -- …
  -> / is rw in mountinfo; /home lists real contents; writes into the home succeed
```

### Verdict

**CONFIRMED.** The mechanism is exactly as stated — `is_workdir_allowed` exists, rejects
exactly this shape, and is never applied to the value that becomes the bind — and that is
the thing a fix must be built on, so the finding's *reason* is right.

**Three corrections to the impact narrative, all material to how a fix is scoped:**

1. **"a user does `cd ~ && husk`. Every brokered job then has read-write access to the whole
   home" is not what happens for an honest agent.** Every submission is *rejected*, because
   `req.cwd` is also under the floor and `policy.rs:97` catches it. Same for the case the
   finder called "narrower and much more common", `cd ~/myproject && husk` — it does not
   "expose only that subtree", it exposes nothing, because nothing runs. That is a real
   usability cliff (husk is unusable for any project under a home) but it is **fail-closed
   and attributed**, which is the opposite of the finding's framing.
2. **The live exposure needs a second ingredient.** Either the `//` bypass of F5 — which I
   demonstrated turns "rejected" into "submitted with the home bound read-write" — or a
   launch directory that is over-broad without being under the floor. The second needs no
   trick: `cd / && husk`, and equally `cd /scratch/mch && husk` or
   `cd /capstor/scratch/cscs && husk`, are all accepted by every gate in the system and make
   the entire named tree writable inside the cage.
3. **Blast radius is asymmetric between the variants.** `--tmpfs /users` followed by
   `--bind /users/me /users/me` re-exposes *only* `/users/me` (measured: `ls /home` shows
   one entry). So the home variant exposes the launching user's own home; the `/` and
   shared-scratch variants expose other users' data, bounded only by host DAC — and CSCS
   dotfiles are routinely mode 644.

The three consequences the finder lists all hold once a job does run: `~/.ssh` etc. are
unmasked (`abs_for_cage` deliberately returns `None` for `~`-prefixed `credentials.files`,
`settings.rs:322-323`, on the grounds the floor covers them); `~/.bashrc`/`~/.profile` are
writable and are in none of `AUTO_EXEC_DIRS`; and `$HOME/.husk/log/job-<id>.log` becomes
job-writable, which is the audited party authoring the audit trail.

One more piece of evidence for severity that pass 1 missed: **the existing test suite pins
the broken behaviour.** `allowread_carveout_is_reexposed_after_the_hide` (`settings.rs:1127`)
and `credential_file_is_devnull_bound_after_the_workdir` (`settings.rs:1295`) both call
`compute_bwrap_args("/users/x/proj")` and assert `--bind /users/x/proj /users/x/proj` is
present. A fix that validates `root` has to rewrite those tests.

### Severity: HIGH

Live in the shipped install with no configuration change; two independent reachable routes;
the worst reachable outcome (`cd / && husk`) is the whole host tree writable *plus* the loss
of `--dev`/`--proc`/`/tmp` isolation (see F4, same mechanism). Not CRITICAL because both
routes require either an unusual launch directory or a deliberately malformed `req.cwd`, and
the ordinary mistake fails closed.

---

## F5 — the floor predicates are raw string tests · CONFIRMED (HIGH)

### What I did

Ran every hostile spelling through the real predicates via `b3dump`, then generated the
tables, then re-ran each shape through bwrap 0.6.1, then chained it into the shipped binary.

### What happened

```
path_under_floor("/users")            = true      is_workdir_allowed = false
path_under_floor("//users")           = false     is_workdir_allowed = true    <-- both gates
path_under_floor("///users/me")       = false     is_workdir_allowed = true    <-- both gates
path_under_floor("/./users")          = false     is_workdir_allowed = true    <-- both gates
path_under_floor("/users/")           = true      is_workdir_allowed = false
path_under_floor("/scratch/../users/me") = false  is_workdir_allowed = false   (`..` caught)
```

Generated tables (indices are `b3dump`'s):

* `allowWrite:["//users/me"]` → kept by `drop_floor_overlapping_allows`, emitted at index 71
  as `--bind //users/me //users/me`, after `--tmpfs /users` at 66.
* `allowRead:["/./users"]` → emitted at 68 (slash-count 2, so it sorts *after* the depth-1
  floor), `--ro-bind /./users /./users`.
* `allowRead:["/scratch/a/../../users"]` → kept (`path_has_symlink_component` `lstat`s each
  accumulated prefix and returns `false` for anything that does not exist), emitted at 68.

bwrap 0.6.1 resolves all three onto the floor:

```
bwrap --ro-bind / / --tmpfs /home --bind //home/christoph //home/christoph -- …    -> real home, WRITE-OK
bwrap --ro-bind / / --tmpfs /home --ro-bind /./home /./home -- ls /home            -> christoph
bwrap --ro-bind / / --tmpfs /home --ro-bind /var/../home /var/../home -- ls /home  -> christoph
```

And the chain into F1, through the shipped release binary: with the broker's cwd at
`/users/me`, `req.cwd="/users/me"` is **rejected** and `req.cwd="//users/me"` is
**submitted**, with `--chdir=/users/me` and the home bound read-write in the cage.

### Verdict

**CONFIRMED**, and I would rank it above where pass 1 filed it. This is not a latent
predicate weakness — it is the one input the *agent* controls that flips F1 from a
configuration mistake into an exploitable one, and I have it working end-to-end against the
shipped binary. The finder's own note that "today the impact is nil" for the `step.rs:278`
caller is correct in isolation and misses that the *same* predicate on the `policy.rs:97`
caller is what admits the request in the first place.

Two additions:

* `is_workdir_allowed` rejects `..` but `path_under_floor` does not, so `..` walks through
  the two `allowRead`/`allowWrite` filters even though it is caught on the workdir path.
  The two predicates disagree about what a path is, which is the actual defect.
* `drop_symlinked_carveouts` is not a backstop here: `path_has_symlink_component`
  (`settings.rs:928`) returns `false` for a non-existent path, and it walks
  `Path::components()`, which silently normalises `//` and `.` away — so it cannot see the
  very forms that beat `path_under_floor`.

### Severity: HIGH

No configuration required, adversary-controlled input, demonstrated to change the broker's
answer from "rejected" to "submitted with the home writable". The fix is small
(canonicalise, or normalise + reject `..`, before every floor test, and apply the floor test
to `deny_write`), which does not lower the severity, only the cost.

---

## F6 — the auto-exec mask set is not a superset, and its `-try` files are a boundary · CONFIRMED (HIGH). The AV2 chain is **executed**, not plausible

### What I did

Read the login runtime's real sets — `sandbox-runtime/src/sandbox/sandbox-utils.ts:11-27`
(`DANGEROUS_FILES`, `DANGEROUS_DIRECTORIES`, `getDangerousDirectories`) and
`linux-sandbox-utils.ts:264-322` (the ripgrep `--iglob` pass) — and compared them against a
generated husk table. Then, instead of arguing the chain, I built the exact shipped table
over a scratch workdir and ran it.

### What happened

Coverage comparison, re-derived from the sources:

| login runtime denies | husk compute cage |
|---|---|
| `.gitconfig` `.gitmodules` `.bashrc` `.bash_profile` `.zshrc` `.zprofile` `.profile` `.ripgreprc` (in cwd **and**, via `--iglob <name>`, at any depth) | **nothing** |
| `.mcp.json` | `--ro-bind-try` — skipped when absent |
| `.vscode` `.idea` | `--tmpfs` ✅ |
| `.claude/commands`, `.claude/agents` | `--tmpfs .claude` ✅ (husk is a superset here) |
| `.git/hooks`, `.git/config` — **and only when `.git` is a directory** | `--tmpfs` / `--ro-bind-try`, **unconditionally** (see F7) |
| `**/.git/hooks/**`, `**/.git/config`, `**/.vscode/**`, `**/.idea/**`, `**/.claude/commands/**`, `**/.claude/agents/**` | **top level of each writable root only** |

Experiment 1 — what survives a job (exactly the shipped table, `--bind $W $W --tmpfs
$W/.claude --tmpfs $W/.git/hooks --tmpfs $W/.vscode --tmpfs $W/.idea --ro-bind-try
$W/.mcp.json … --ro-bind-try $W/.git/config … --unshare-net`):

```
survived on the host:
  <workdir>/.mcp.json                          (-try skipped an absent source)
  <workdir>/.bashrc  <workdir>/.gitmodules  <workdir>/.profile
  <workdir>/sub/.claude/settings.local.json    <-- the C3 nested-.claude gap, from the B side
  <workdir>/subrepo/.git/hooks/post-checkout
  <workdir>/.git/modules/sub/hooks/post-checkout
discarded (tmpfs):
  <workdir>/.git/hooks/pre-commit
```

Experiment 2 — the full AV2 chain, in a **non-git** workdir, shipped default config:

```
# inside the cage
printf '#!/bin/sh\necho PWNED …\n' > $W/payload/pre-commit; chmod +x …
printf '[core]\n\thooksPath = $W/payload\n' > $W/.git/config
# after the cage exits, on the host:
$W/.git/config           <- persists, contains the redirect
$W/payload/pre-commit    <- persists, executable
# later, on the login side:
git -C $W init -q ; git -C $W config core.hooksPath   -> $W/payload    (init PRESERVES it)
git -C $W commit --allow-empty -m x
   PWNED: planted hook executed as christoph
   [master 577f3c4] x
```

### Verdict

**CONFIRMED**, and the finder's `PLAUSIBLE` on the chain is too conservative — the chain
runs. Three mechanisms compose, and each is on its own in the "annotated table":

1. `--tmpfs <root>/.git/hooks` **fabricates** `<root>/.git` when it is absent (F7's second
   half), so a non-repo project dir acquires a `.git` the job can write into;
2. `--ro-bind-try <root>/.git/config` skips an absent source, so `.git/config` is creatable
   and **persists**;
3. `.git/hooks` being a tmpfs is irrelevant once `core.hooksPath` points elsewhere — the
   redirect is the bypass, and `git init` preserves it.

In an *existing* repo the same outcome is reached through `<workdir>/subrepo/.git/hooks/`
or `<workdir>/.git/modules/<sub>/hooks/`, both demonstrably unmasked.

Two honest narrowings I owe the record:

* The nested `.claude` gap is real (I reproduced C3's result from the mount side) but it is
  the weakest link in this list: Claude Code reads `.claude/settings*.json`,
  `.claude/agents`, `.claude/commands` at the **project root**, and `SETTINGS_SOURCES`
  (`settings.rs:278`) likewise reads `<project>/.claude/…` only. The chain is
  "job plants `<workdir>/sub/.claude/settings.local.json`; a human later launches husk from
  `<workdir>/sub`" — indirect, but it ends with the agent having authored its own cage, which
  is the F17 failure by another route.
* The missing `DANGEROUS_FILES` mostly bite when the workdir *is* `$HOME` (a project-level
  `.bashrc` is inert) — except `.gitmodules`, which git reads from the worktree root, and
  `.ripgreprc`, which fires whenever `RIPGREP_CONFIG_PATH` points at it.

The `enableAllProjectMcpServers: false` backstop for `.mcp.json` is real (I checked
`user-config/settings.json:2`) and the finder is right that it is a settings key rather than
the mount table. `.git/config` has no equivalent backstop at all.

### Severity: HIGH

Shipped default configuration, no operator error required, no adversarial input required,
and it terminates in code execution as the user outside every cage. It is the same class as
F18 (policy says one thing, mount table says another) but on the control whose stated purpose
in `settings.rs:101-113` is precisely to stop this.

---

## F3 — `denyWrite:["/users"]` re-exposes every home · CONFIRMED (MEDIUM)

### What I did

Traced the filter coverage: `drop_floor_overlapping_allows` (`settings.rs:556-561`) retains
on `allow_read`/`allow_write` only; `drop_symlinked_carveouts` (`settings.rs:551-554`) the
same two. `deny_write` is emitted at `settings.rs:725-731` as `--ro-bind p p`. Generated the
table and ran the shape through bwrap.

### What happened

```
== resolved policy ==   deny_write = ["/users"]     (survives both filters)
  66  --tmpfs /users
  68  --bind /work/project /work/project
  71  --ro-bind /users /users            <- the floor, back, read-only
```

```
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /home --bind /tmp /tmp \
      --ro-bind /home /home -- sh -c 'ls /home; ls /home/christoph/.ssh; touch …'
  -> real home contents listed, .ssh readable, write refused (Read-only file system), exit 0
```

### Verdict

**CONFIRMED.** A `denyWrite` is emitted as a *bind*, and a bind exposes its source at its
destination; entry order puts it after the floor. This is F18's shape on the one filesystem
field F18's fix does not reach, and the English/effect inversion is real: "jobs must not
write to homes" makes every home in the cluster readable inside the cage.

Attempts to refute it that failed: the `~`-prefixed `credentials.files` masks would not
save you (`abs_for_cage` drops them precisely *because* the floor is expected to hold);
the F6a auto-scan only covers the workdir; and `drop_symlinked_carveouts` never sees
`deny_write` either, so a symlinked `denyWrite` is a second, independent version of the same
hole.

The one thing that does hold it back: **the shipped `user-config/settings.json` does not
contain it.** I generated the table for the shipped file verbatim and it is byte-identical
to the empty-policy table.

### Severity: MEDIUM

Requires an operator edit — but an edit that reads as *tightening* the policy, made in the
file that already contains `denyRead: ["/users"]`, so the symmetric addition is the obvious
next thing an operator types. Blast radius is every user's home, read-only, cluster-wide;
higher than F1's home variant in breadth, lower in depth. Not HIGH only because it is not
the shipped state.

---

## F4 — `allowWrite:["/"]` mounts the host root read-write · CONFIRMED (MEDIUM), and it does more than that

### What I did

Read `path_under_floor`: `"/".trim_end_matches('/')` is `""`, which is neither `"/users"`
nor prefixed by `"/users/"`, so `"/"` survives `drop_floor_overlapping_allows`. Generated
both the `allowWrite:["/"]` and the `allowRead:["/"]` tables to check the asymmetry claim.
Then measured what `--bind / /` actually undoes.

### What happened

```
allowWrite=["/"] :  66 --tmpfs /users   68 --bind /work/project …   71 --bind / /
allowRead =["/"] :  66 --ro-bind / /    69 --tmpfs /users           71 --bind /work/project …
```

The asymmetry is exactly as described: `"/"` has slash-count 0 so the *read* form sorts to
the front of the depth-sorted op list and lands harmlessly before the floor, while the
*write* form is emitted outside that list, after it.

Measured against bwrap, baseline job cage vs. the same cage with `--bind / /` appended:

```
baseline :  /dev=14   /proc=5 numeric entries   /tmp=0 entries
+ --bind / / : /dev=280  host /proc (cat /proc/1/cmdline -> "/sbin/init")  /tmp=21 entries
```

### Verdict

**CONFIRMED**, and the finder understated it. `--bind / /` is not "the floor, undone" — it
is *the whole prefix*, undone. Entries 2, 3, 4 and 5 of the annotated table (`--dev`,
`--proc`, `--tmpfs /tmp`, `--tmpfs /dev/shm`) are all mounted inside the tree that the final
`--bind / /` replaces, so the cage reverts to the host filesystem with the user's own DAC:
the full host `/dev` (280 nodes, not the 14-node minimal devtmpfs), the host `/tmp` shared
with other users' jobs, and a host `/proc` through which the job can read the node's process
table **despite** `--unshare-pid` — which is the one control `settings.rs:610-631` describes
as "structural" rather than a credentials check.

That correction matters beyond F4, because F1's `cd / && husk` variant produces the
identical `--bind / /` with no configuration at all.

The finder's framing of this as "the brief's *a rule correct in isolation undone by what
follows it*, with the two halves visible side by side" is right and is the most useful
sentence in the pass-1 document.

### Severity: MEDIUM

Config-dependent and a less natural mistake than F3's (`allowWrite:["/"]` reads as
"everything", not as a tightening). Raised from LOW by the collateral loss of `--dev`,
`--proc` and the PID isolation, and by its identity with F1's most severe variant.

---

## F2 — rank cages carry no MUNGE mask · CONFIRMED as an absence (MEDIUM)

### What I did

Grepped every non-test reference to `CREDENTIAL_SOCKET_DIRS` (`settings.rs:99`): exactly
one, `policy.rs:615`, which bakes it into the **job guard's** `_husk_extra`. Then generated
the complete rank command line with `b3rank` and searched it. Then went looking for a
different mechanism that might cover it.

### What happened

The generated rank argv (single-node profile, egress on) is

```
sh -c '… exec 9</proc/<pid>/ns/user … exec 8</proc/<pid>/ns/pid … mkdir -m 700 /dev/shm/husk-$JOBID …
 exec seccomp-wrapper --profile=single-node bwrap --userns 9 --pidns 8 \
   --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp  <8×/dev/cxi*>  <18×/dev/nvidia*> \
   --tmpfs /users --bind /work/project /work/project  <4 auto-exec tmpfs>  <2 ro-bind-try> \
   --unshare-net --bind "$_d" /dev/shm --bind-try "$_s" "$_s" \
   --ro-bind-try /usr/bin/socat /tmp/husk-socat --ro-bind-try <sock> <sock> -- …'
```

`grep munge` → nothing.

Refutation attempts, all failed:

* **Inheritance from the job cage?** No. The rank starts from its own `--ro-bind / /` and
  bwrap mount namespaces do not propagate — the code relies on exactly this fact when it
  re-binds socat per rank (`rank.rs:141-150`).
* **A syscall rule instead?** No. `profile.rs:73-85` says `SingleNode` adds no rules, and
  `seccomp-wrapper/src/seccomp_wrapper.c:387-413` records that the AF_UNIX block was
  **reverted** because CUDA needs unix sockets. So `connect(2)` to
  `/run/munge/munge.socket.2` is unfiltered in a rank.
* **DAC?** The socket is world-connectable by design; the guard's own comment
  (golden `guard-net-on.sh:119-121`) records connect-through-a-read-only-bind as measured
  fact.

The severity argument the finder makes is understated in one place and I want it recorded:
`netallow.rs:9-20` states the network design's guarantee as *two* independent walls, and
names the mask as "the load-bearing one", asserting it "stays masked **in every cage**".
That sentence is false today for ranks — and ranks are the one cage that also receives the
egress relay. So on the code path where the network exists, the allowlist is the *only*
wall, in a module whose own doc comment says it must not be.

### Verdict

**CONFIRMED (absence).** Not a live escape: the rank cage still carries `--unshare-net`
(present in the generated argv), the egress proxy refuses `SCHEDULER_PORTS`
(`netallow.rs:39`) at configuration time, and MUNGE without a route is inert. It is the
second wall — the one explicitly built to survive the loss of the first — missing on the
side that loses the first one first.

Related, and worth folding into whatever fixes this: the test named
`rank_cage_keeps_every_containment_property_of_the_job_cage` (`settings.rs:1221`) checks
three strings against the **static** rank args only. It cannot fail for the missing MUNGE
mask (which is in neither cage's static args), nor for the extra rank binds. It can fail —
it is not vacuous — but it cannot fail for the property its name promises. Protocol rule 7
applies.

### Severity: MEDIUM

No exploitable path today; a documented invariant that is false; and the gap sits exactly
where the design says the remaining wall must hold.

**Hardware arm (to prove reachability rather than absence):**
submit through husk a one-node job whose script runs
`srun -n1 sh -c 'ls -l /run/munge/munge.socket.2; munge -n >/dev/null 2>&1; echo rank_rc=$?'`
and, in the same script but outside `srun`,
`ls -l /run/munge/munge.socket.2; munge -n >/dev/null 2>&1; echo job_rc=$?`.
Expected today: the job arm shows the masked (empty tmpfs) directory and a non-zero
`job_rc`; the rank arm shows the real socket and `rank_rc=0`. On Balfrin `short` and
`pp-short`. Read the errno: a `159` would be seccomp (ours), not the mask.

---

## F7 — `--tmpfs <root>/.git/hooks` kills the cage when `.git` is a file, fabricates one when absent · CONFIRMED (MEDIUM)

### What I did

Ran the shipped table shape against both layouts, and checked that a real `git worktree`
does produce a file `.git`.

### What happened

```
# .git is a FILE
bwrap … --bind $W $W --tmpfs $W/.claude --tmpfs $W/.git/hooks … -- true
  bwrap: Can't mkdir parents for …/.git/hooks: Not a directory      exit=1

# .git ABSENT
… exit=0
host afterwards: <workdir>/.claude  <workdir>/.vscode  <workdir>/.idea
                 <workdir>/.git  <workdir>/.git/hooks

# a real worktree
git worktree add ../wt ; file wt/.git  ->  ASCII text
```

The login runtime guards both cases explicitly and by name
(`linux-sandbox-utils.ts:210-237` `hasFileAncestor`; `:288-305` `dotGitIsDirectory`, with
the comment "In git worktrees, `.git` is a file … denying it would cause bwrap to fail").
husk has neither guard.

I also checked whether the guard attributes the failure: it does not. The generated guard
captures `_husk_rc=$?` after the `bwrap` line and has branches for signals (143/137) and for
seccomp traces, but no branch for "the cage failed to start". A user gets a bare
`bwrap: Can't mkdir parents …` in the job's stderr with no husk prefix.

### Verdict

**CONFIRMED**, both halves. Fail-closed, so not a containment hole — but it is an
unattributed denial on an ordinary repository layout (`git worktree` and submodule
checkouts), which is the exact failure mode `settings.rs:75-83` documents at length for
MUNGE and then does not apply here.

The second half is **not** the cosmetic issue `settings.rs:125-126` calls it. The fabricated
`.git/` is what makes `<workdir>/.git/config` creatable in a non-repo project, which is step
one of the AV2 chain I executed under F6. "At most an empty directory, which is harmless"
should be struck.

The finder's three "same class" sub-cases are correct and I confirmed the first two by
inspection of the emitted flags (`--ro-bind`/`--bind` for `allowRead`/`allowWrite`/
`denyWrite`, not `-try`; `--tmpfs` for an absent `denyRead` under a read-only root). They
are all evaluated on the **login** node against the **compute** node's filesystem, which is
the structural cause.

### Severity: MEDIUM

Denial-of-service on a common layout, no attribution, plus its role as the enabler of F6's
chain. It would be LOW as a pure availability bug.

---

## F8 — relative `denyWrite` silently dropped on compute · CONFIRMED (LOW), one sub-claim corrected

### What I did

Generated one table from one policy carrying both forms, and separately generated the table
for the shipped `user-config/settings.json` verbatim. Then read the cited test.

### What happened

```
policy: denyRead ["secrets"], denyWrite ["build", "./out", "~/.claude/settings.json"]
  71  --tmpfs /work/project/secrets          <- relative denyRead honoured (F22)
  (nothing for build, ./out, ~/…)            <- relative denyWrite dropped
```

Shipped config: `deny_write = ["~/.claude/settings.json", ".claude/settings.json",
".claude/settings.local.json", "~/.local/lib/husk"]` → **zero** emitted entries; the
resulting table is identical to the empty-policy table.

### Verdict

**CONFIRMED** for the mechanism: `settings.rs:725` still uses the raw
`if p.starts_with('/')` test that F22 replaced everywhere else with `abs_for_cage`, so the
login cage honours a relative `denyWrite` and the compute cage silently does not — the exact
drift F22's own comment (`settings.rs:310-318`) says it exists to prevent.

**One sub-claim recharacterised.** The finder says
`settings_sources_are_all_write_denied_by_the_shipped_config` (`settings.rs:945`) "passes for
the wrong reason". Read in full, the test asserts the *shipped JSON array* contains a string
for each `SETTINGS_SOURCES` entry; it can fail, and it fails for the thing it is named for
(someone removing a deny while adding a policy source). What is wrong is the **comment above
it** — "denyWrite is enforced by the bwrap filesystem cage, which THREAT-MODEL.md counts as
load-bearing" — which is false on compute for all four of those entries. Their compute-side
protection is entirely `AUTO_EXEC_DIRS`'s `.claude` tmpfs and the `/users` floor.

No live gap today: `.claude/…` is inside the `.claude` tmpfs, `~/…` is behind the floor.

### Severity: LOW

Latent. It becomes real the moment an operator adds a relative `denyWrite` for anything not
already covered by the `.claude` mask or the floor, and it fails **open** and **silently**,
which is the property that makes it worth fixing rather than documenting.

---

## F9 — the "no stat is needed" comment is false under a read-only root · CONFIRMED (LOW), plus two additions

### What I did

Ran all three shapes from `settings.rs:791-793`'s claim, then ran the writable-destination
control the comment implicitly relies on.

### What happened

```
--ro-bind /dev/null /etc/husk-b3-absent.pem  -> Can't create file at …: Read-only file system   exit 1
--ro-bind /dev/null /nodir/deep/secret.pem   -> Can't mkdir parents for …: Read-only file system exit 1
--ro-bind /dev/null /etc/ssl                 -> Can't create file at …: Is a directory           exit 1
--ro-bind /dev/null <workdir>/absent.pem     -> exit 0
```

### Verdict

**CONFIRMED.** A `sandbox.credentials.files` entry naming an absolute path outside the
writable set that is absent on the compute node takes every brokered job down, under a
comment stating no stat is needed. The F6a auto-scan is indeed unaffected (it only ever
yields paths inside the workdir).

**Two things I found that pass 1 did not, both from the same experiment:**

1. **The writable-destination case leaves litter in the user's project.** After the cage
   exits, `<workdir>/absent.pem` exists on the host as a 0-byte `-r--r--r--` file. This is
   precisely the failure `settings.rs:123-126` cites as the reason `AUTO_EXEC_DIRS` uses a
   tmpfs instead of per-file `/dev/null` binds ("that leaves an EMPTY `settings.json` behind
   on the host — i.e. invalid JSON in the user's project") — the same mechanism is still in
   use for `credentials.files`. Declare a not-yet-existing `.env` prophylactically and every
   job creates it.
2. **The mask does not deliver what it promises.** `settings.rs:360-362` and `:788-790` both
   say the job "reads EMPTY". Measured, inside the cage the masked path is a character device
   `1,3` owned by `nobody:nogroup` and `cat` returns **EACCES**, for both an existing and an
   absent destination, while `/dev/null` under `--dev /dev` in the same cage reads fine
   (rc=0, empty). Safer than promised, but it is a different observable: a program that
   tolerates an empty credential file will not tolerate `Permission denied`.

### Severity: LOW

Fail-closed, config-dependent, and the two additions are correctness/usability rather than
containment. Listed because the comment actively tells a future reader not to check.

**Hardware arm for addition 2:** on Balfrin, run a brokered job with
`sandbox.credentials.files` naming a file in the workdir on the real scratch filesystem and
have the job run `cat <file>; echo rc=$?` — record whether it is `rc=0` with empty output or
`rc=1` with `Permission denied`, because the answer depends on the mount flags of the
workdir's filesystem and this laptop is not that filesystem.

---

## F10 — the rank's apinfo bind is read-write · UNRESOLVED — NEEDS HARDWARE

### What I did

Confirmed from the generated rank argv that the flag is `--bind-try "$_s" "$_s"` (read-write),
`_s=<SlurmdSpoolDir>/mpi_cray_shasta/${SLURM_JOB_ID}.${SLURM_STEP_ID}` (`rank.rs:188,196`),
and that under `--ro-bind / /` this is the only thing making that path writable in the rank
cage. Also confirmed the second half of the finding by inspection: `HUSK_WRITABLE` is
exported by the **job guard** and names the workdir plus `allowWrite` roots only; a rank
additionally has this directory and `/dev/shm/husk-<jobid>` writable and announces neither.

### Verdict

**UNRESOLVED — NEEDS HARDWARE.** Whether the bind grants anything depends on host DAC: if
slurmd creates that directory root-owned, the rank cannot write it and the finding reduces
to "the flag overstates the need". That cannot be settled here.

**Exactly what would settle it**, on Balfrin (and repeat on Santis, whose spool path differs):

```
scontrol show config | grep -i SlurmdSpoolDir          # confirm the base path
# then, in a brokered single-node job:
srun -n1 sh -c 'd=$(ls -d <SlurmdSpoolDir>/mpi_cray_shasta/${SLURM_JOB_ID}.* 2>/dev/null | head -1);
                ls -ld "$d";
                touch "$d/husk-b3-probe" && echo APINFO-WRITABLE || echo apinfo-not-writable;
                rm -f "$d/husk-b3-probe"'
```

`APINFO-WRITABLE` ⇒ least privilege says change `--bind-try` to `--ro-bind-try` and add the
path to `HUSK_WRITABLE` until then. `apinfo-not-writable` ⇒ downgrade to a tidiness note.
(Note for whoever runs it: `--ro-bind-try` must be verified not to break the PMI/PALS
bootstrap in the same run — one arm each way.)

---

## F11 — two unstated precedence rules · CONFIRMED (LOW), and sharper than stated

### What I did

Generated both cases, then generated a third the finder did not: the same
`denyRead`+`allowRead` pair where the target is a real **file** rather than a directory.

### What happened

```
denyRead+allowRead ["/capstor/secret"]  (absent -> treated as a directory)
  68 --tmpfs /capstor/secret     70 --ro-bind /capstor/secret /capstor/secret   -> ALLOW WINS

allowRead ["<workdir>/vendor"], workdir <workdir>
  68 --ro-bind …/vendor …/vendor 71 --bind <workdir> <workdir>                  -> WRITE BIND WINS

denyRead+allowRead of a real FILE and a real DIRECTORY, one policy:
  68 --tmpfs <dir>               73 --ro-bind <dir> <dir>                        -> ALLOW WINS
  70 --ro-bind <file> <file>     93 --ro-bind /dev/null <file>                   -> DENY WINS
```

### Verdict

**CONFIRMED**, with a sharpening that makes it more than a documentation gap: the outcome of
an identical `denyRead`/`allowRead` conflict **inverts** depending on whether the path is a
file or a directory, because `split_file_denies` (`settings.rs:568`, driven by a real `stat`
in `resolve`) routes files into `deny_files`, which is emitted last. And the classification
is made on the **login** node at broker startup, so a path that does not exist yet is
classified as a directory and gets the allow-wins behaviour.

The finder's observation that read-denies lose to read-allows while write-denies beat
write-allows is correct, and the file/directory inversion means husk has *three* precedence
conventions where the file documents one.

### Severity: LOW

Requires a self-contradictory configuration to bite. Filed as a correctness trap and a
documentation debt on the one file the brief calls the oracle, not as an exploitable defect.

---

## F12 — stale prose about `--pidns` · FLAGGED, overlaps B4 — not resolved

Per the task instruction and protocol rule 3, I did not adjudicate this. Recording only
what is cheap and non-overlapping:

* The contradiction is textual and real. `settings.rs:1188-1200` states `bwrap --pidns FD`
  is parent-only and that "ranks cannot JOIN a shared PID namespace"; `rank.rs:187,194` emit
  `bwrap --userns 9 --pidns 8 …` with no `--unshare-pid`.
* `bwrap 0.6.1 --help` on this laptop prints:
  `--pidns FD  Use this user namespace (as parent namespace **if using** --unshare-pid)`,
  which reads as plain `setns` when `--unshare-pid` is absent.
* **Whether the shipped rank behaviour is correct is B4's**, and I ran no behavioural test.
  The B3-side observation is narrower: the mount-table oracle's own commentary now
  contradicts the shipped table, in the same file the review treats as authoritative.

---

## What I attacked and could not break

Independently re-derived, not inherited:

* **The depth sort.** Ancestor/descendant carve-outs order correctly in every combination I
  generated. Slash-count is the right key for the nesting relation, and the stable sort's
  hide-before-allow tie-break is the only thing that surprised me (F11).
* **F22's re-application of `denyRead` inside writable roots.** Correct and correctly
  placed, for absolute, `./`-relative and bare-relative forms.
* **`credentials.files` after the workdir bind.** Emitted last, so a secret inside the
  writable workdir is genuinely re-masked (modulo F9's EACCES-not-empty note).
* **`_husk_extra` ordering.** Appended after every static argument including
  `--unshare-net`, so the MUNGE mask, the socat bind and the egress-socket bind all beat the
  workdir bind, and both golden files pin it.
* **`--unsetenv` vs the rank's forwarded env.** `rank::env_args` filters the unset names out
  of the forwarded delta, so a forwarded variable cannot undo the mask despite being appended
  later.
* **`allowRead:["./"]`/`["."]`** are skipped rather than emitted as a bind over a relative
  path; **empty `credentials.files` paths** are dropped rather than emitted as a bind over
  `/`.
* **The shipped default config.** Its generated compute table is identical to the empty
  policy's. Nothing in `user-config/settings.json` widens the cage.
* **`/dev/cxi_sbl`** is correctly excluded from `FABRIC_DEVICES`; the `-try` device binds all
  degrade a feature, not a boundary.
* **The Job/Rank static delta** is exactly the two documented items. The *full* command-line
  delta is much larger, as pass 1 says — and that is F2's territory, not a second finding.

## Residual I could not settle here

**`HIDDEN_FLOOR` completeness.** Independently grepped every bring-up log for home-like
roots: `/users/cmueller` and `/users/victim` are the only ones that appear, and no second
home root appears anywhere in the docs or threat model. That is consistent with `["/users"]`
being complete, but it is evidence of absence from a laptop, not proof.
**Settling command, both clusters:** `getent passwd | cut -d: -f6 | sed 's|/[^/]*$||' | sort -u`
— anything outside `/users` that is a home root is an F18 with no fix, and F1 and F3 both get
materially worse if one exists. Note also that **personal scratch is not floor-covered**
(`THREAT-MODEL.md:15` accepts this explicitly), and dotfiles and key copies routinely live
there.

## Coverage note

All twelve findings were reached. F10 is the only one blocked on hardware; F12 is
deliberately unresolved as an overlap. The C3 cross-reference (auto-exec masks applied at the
top level of each writable root only) is folded into F6 and independently reproduced from
the mount side.
