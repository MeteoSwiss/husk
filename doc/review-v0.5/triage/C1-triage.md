# C1 — triage (pass 2): the remaining delta to dropping Anthropic's runtime

**Triaged at `2b8a8e1`** (pass 1 wrote against `f5fd395`; nothing in the intervening commits
touches the code cited). Comparison target: vendored `sandbox-runtime/` at `295f0e1`,
package version 0.0.67. Laptop only, kernel 6.8.0-136-generic, `dev.tty.legacy_tiocsti = 0`.
No cluster access. **No source file was modified.**

## Summary

| # | Finding | Outcome | My severity | One line |
|---|---|---|---|---|
| 2 | `--new-session` missing everywhere in husk | **RECHARACTERISED** | **none as a bug today; HIGH as a 6a boundary item** | The flag really is absent and really is a boundary — but every cage husk itself builds runs inside a batch job with no controlling terminal, and the one cage that *does* sit at the user's terminal is theirs and has the flag. Not live on Balfrin. |
| 3 | 6a (iii) is in tension with the AF_UNIX block | **CONFIRMED** | **HIGH (design decision, not a bug)** | A session-scoped seccomp filter provably cannot discriminate; and the escape hatch the finder ranks first is *forbidden* by ROADMAP's own axiom, so the option set is smaller than stated. |
| 6 | husk's own trusted layer runs a Lustre walk | **RECHARACTERISED** | **LOW now / MEDIUM as a 6a constraint** | The walk exists exactly as described, but it is a background child off the interactive path, and it issues no per-entry `stat` (measured). It cannot reproduce the freeze; what survives is "the budget bounds count, not time". |
| 1 | The login cage is 100% theirs and nothing says so | **RECHARACTERISED** | **MEDIUM (docs) / HIGH (reframing)** | The enumeration is right and valuable; "nothing in husk says so" is not — three places say part of it, and one says the *opposite* of the truth. The sharpest form of the point is missing from the finding. |
| 4 | Two unpinned version couplings | **RECHARACTERISED** | **LOW–MEDIUM** | Both version facts verified, but they are not two instances of one defect and they are not "mutually inconsistent": only the observer is a binary/TS skew, and the allowlist half fails *closed*. |
| 5 | Session wrap already exists; its design note will go stale | **CONFIRMED** | **LOW (positive finding)** | All citations verified. The stale-justification comment exists in a second place the finding does not name (`cage.rs:100-105`). |
| 7 | What the ripgrep walk buys is small and nameable | **CONFIRMED** | **informational** | The static/scanned split is exactly as described; their own comment above the function is the evidence for the per-command cadence. |
| 8 | 6a (ii) is new capability, not replication | **CONFIRMED** | **informational (lowers the 6a score)** | No `sandbox.credentials` block ships; the compute cage really is stricter than the login cage about workdir secrets. |
| 9 | `TMPDIR` / default write paths | **CONFIRMED** as a work item | **functional, not security** | Citations verified. Note `/dev/tty` is in their writable set yet unopenable inside their own cage — measured. |

**Net effect on the brief's score.** Pass 1 scored six blocking boundaries. I agree with the
*list* but not with the framing that any of them is a live hole. Every "MISSING" row is
missing **on the login side only**, and the login side is currently supplied by their
runtime, which is installed and configured. C1 produces **zero security bugs now** and a
clean 6a work list — which is the right outcome for a substitution-gap brief. The one thing
I would move *up* the list is not on it: see finding 1.

---

## 2. `--new-session` — RECHARACTERISED

### What I did

**The grep.** Reproduced and widened it:

```
grep -rn 'new-session\|die-with-parent\|TIOCSTI\|setsid\|SETSID' \
  slurm-broker/ seccomp-wrapper/ scripts/ install-husk.sh user-config/ tools/
```

Zero hits. The only hits repo-wide are `sandbox-runtime/src/sandbox/linux-sandbox-utils.ts:1467`
and one of their tests. The claim is accurate.

**Their side.** `linux-sandbox-utils.ts:1467` is
`const bwrapArgs: string[] = ['--new-session', '--die-with-parent']` — the first statement
after the early-out, so it is unconditional *given that bwrap runs at all*. bwrap is skipped
only when the policy is completely empty (`:1449-1457`: no network, read, write, env or
git-config restriction). husk's shipped `user-config/settings.json` supplies all three of
`denyRead`, `denyWrite` and `network.allowedDomains`, so that early-out can never be taken
under husk. Combined with `"allowUnsandboxedCommands": false` (`:6`), **every** Bash command
at login goes through a bwrap that carries `--new-session`.

**Is anything else providing the `setsid()`?** No.
`grep -n 'setsid\|TIOCSTI\|TIOCNOTTY' sandbox-runtime/vendor/seccomp-src/apply-seccomp.c`
returns nothing, so their nested-namespace helper does not detach the terminal either —
`--new-session` is the sole provider. And husk's own filter does not filter `ioctl` at all
(`seccomp_wrapper.c` has no `ioctl` rule), so nothing in husk substitutes for it.

**The mechanism, reproduced locally.** Under a pty (`script -qec … /dev/null`):

```
bwrap --ro-bind / / --dev-bind /dev /dev -- sh -c 'ps -o pid,sid,tty -p $$'
    →  SID 47401  TT pts/2        # the *user's* terminal is the controlling terminal
bwrap --new-session --ro-bind / / --dev-bind /dev /dev -- …
    →  SID 47407  TT ?            # detached
```

and with a C probe (`open("/dev/tty"); ioctl(fd, TIOCSTI, &c)`):

```
uncaged                 CTTY=yes  TIOCSTI=FAIL errno=5 (EIO)
bwrap (no flag)         CTTY=yes  TIOCSTI=FAIL errno=5 (EIO)
bwrap --new-session     CTTY=no   (open /dev/tty: No such device or address)
```

Reading the errno per protocol rule 5: `EIO`, not `EPERM`, is the **6.2+
`dev.tty.legacy_tiocsti=0` gate** (`tiocsti()` returns `-EIO` when the sysctl is off and the
caller lacks `CAP_SYS_ADMIN`). It is *not* the controlling-terminal check, which returns
`EPERM`. So this laptop confirms the *mechanism* (`--new-session` removes the controlling
terminal so hard that `/dev/tty` cannot even be opened) and simultaneously proves it cannot
confirm the *exploit* — my kernel has the gate on.

### Where I break the finding: the scope

The finding scores this row "MISSING everywhere in husk" and then writes "Balfrin runs 5.14,
so this is live there, not theoretical." A reader will take that as a live hole. It is not,
and the reason is that **TIOCSTI needs a controlling terminal to aim at, and none of husk's
own cages has one**:

- **Every bwrap husk constructs is inside a SLURM job.** The three invocation sites are
  `policy.rs:894` (job cage, in the generated batch script), `rank.rs:187/194` (rank cage,
  under `srun` inside the job) and `step.rs:315` (the rank args feeding it). There is no
  husk-built bwrap on the login node — I grepped for `bwrap` across
  `slurm-broker/broker/src/`, `seccomp-wrapper/src/`, `install-husk.sh` and `scripts/`.
- **A batch job has no controlling terminal.** `slurmd`/`slurmstepd` `setsid()`s the job and
  redirects stdin from `/dev/null`; the broker reinforces this on its own side —
  `spool.rs:320` and `step.rs:358` both spawn with `Stdio::null()` stdin and files/pipes for
  output. No fd to the user's pty is ever passed toward a compute node.
- **husk actively refuses the one SLURM feature that would put a pty in a job.**
  `srun.rs:150` classifies `--pty` as `Rejected`, and `srun.rs:180-186` rejects a
  command-less (interactive) `srun`. `salloc` is not brokered at all and is an explicit
  roadmap decision (`ROADMAP.md:110-111`).
- **The one process that *does* sit at the user's terminal is the agent itself**, wrapped by
  `seccomp-wrapper claude` (`install-husk.sh:419/427`). That process must own the terminal —
  it is an interactive CLI. TIOCSTI buys it nothing it cannot already do by `fork`+`exec`,
  because at login the agent *process* is not filesystem-caged at all (see finding 1).

So the correct statement is: **`--new-session` is a boundary flag husk will have to supply
the day it builds its own login cage, and today does not need because it builds no cage at a
terminal.** That is a 6a work item of real value — precisely because it is the class of
control a reimplementation loses in silence — and not a defect in shipped husk.

### `--die-with-parent`

Separate mechanism, and husk is less exposed than the row implies: the compute cage's
lifetime is bounded by the SLURM step teardown (a kernel-coupled reaper, not a cooperative
one), and husk's own daemons already use `PR_SET_PDEATHSIG` (`main.rs:75-85`,
`die_with_parent`). I would not carry this on the same row as `--new-session`; they close
differently. **Suspected overlap with B1 (resource lifecycle / RAII) — flagging, not
resolving.**

### Severity

- **As a bug in shipped husk: none.** No cage husk builds is reachable from a controlling
  terminal.
- **As a 6a deliverable: HIGH.** Two flags, no config surface, no error if omitted. The
  finding's closing recommendation — the flags plus **a selftest arm asserting the cage has
  no controlling tty** — is exactly right, and the arm must be written so it *could* fail
  (protocol rule 7): assert `open("/dev/tty")` fails with `ENXIO`, not that `tty` prints
  something, because `tty(1)` still reports `/dev/pts/N` from an inherited fd 0 even after
  `setsid()` — I hit that in the first version of my own probe.

### UNRESOLVED — NEEDS HARDWARE (two cheap questions, one job)

1. **Is the gate present on Balfrin?** On a Balfrin login node:
   `uname -r; sysctl dev.tty.legacy_tiocsti; grep -i legacy_tiocsti /boot/config-$(uname -r)`
   A missing sysctl confirms the knob does not exist on 5.14 (so TIOCSTI is unconditional,
   subject only to the controlling-terminal check) and settles the finding's kernel claim.
2. **Does a brokered job really have no controlling terminal?** This is the scope claim
   above, and it is the one I am asserting from code plus SLURM semantics rather than
   measurement. Build the probe (source in this triage; ~20 lines) and run it *through
   husk*, so it goes down the real path:
   ```
   # inside a husk session on Balfrin, in a scratch workdir
   gcc -O1 -o tiocsti_probe tiocsti_probe.c
   ./tiocsti_probe                      # expect CTTY=yes  (uncaged login shell)
   #   then, from the agent's Bash tool (their bwrap):
   ./tiocsti_probe                      # expect CTTY=no  ← their --new-session
   #   then, in a brokered job:
   printf '#!/bin/bash\n%s/tiocsti_probe\n' "$PWD" > probe.sh && sbatch probe.sh
   cat slurm-*.out                      # expect CTTY=no  ← no ctty in a batch job
   ```
   If the third line ever prints `CTTY=yes`, this finding is upgraded to a live hole and the
   flag goes on the job cage immediately. I expect `CTTY=no`.

---

## 3. 6a deliverable (iii) vs the AF_UNIX block — CONFIRMED

### The claim, tested rather than re-argued

The finding asks triage to test the *claim* (a session wrap cannot supply per-command AF_UNIX
blocking), not the recommendation. Both halves check out and the mechanism is not
recoverable:

**husk's side says it.** `seccomp_wrapper.c:51-64`, verbatim: `PROFILE_LOGIN` is the default
"precisely because it must stay today's behaviour: the husk launcher wraps the whole agent
SESSION (`seccomp-wrapper claude`), and the agent runtime legitimately uses unix sockets for
its own IPC (MCP servers, IDE integration)", and "When ROADMAP step 5 drops their runtime,
this profile takes that block over **at the same granularity**." The comment does presuppose
a per-command hook husk would not have.

**Their side resolves it by granularity.** `linux-sandbox-utils.ts:800-803`, verbatim:
"apply-seccomp runs after socat so socat can still create Unix sockets" — the filter is the
innermost layer of each Bash command, after the plumbing that needs `AF_UNIX` has finished
using it. `resolveApplySeccompPrefix` (`:763-775`) makes that a per-command argv prefix.

**Why no session-scoped filter can do this.** seccomp filters are inherited across `fork`
and `exec` and cannot be removed or relaxed; the kernel applies every filter in the stack and
the most restrictive answer wins. A filter installed on the session leader therefore applies
identically to the agent runtime and to everything it spawns. seccomp can discriminate on
scalar syscall arguments — which is how their rule works, `SCMP_A0(SCMP_CMP_MASKED_EQ,
0xffffffff, AF_UNIX)` on `socket()` (`seccomp-unix-block.c:92-101`) — but it cannot
discriminate on *caller identity*. There is no mechanism to exempt one process in the tree.
The two statements cannot both hold. **Confirmed.**

### Where I go further than the finding

**Option (a) is not merely Claude-coupled — it is forbidden.** The finding lists "husk keeps
a per-command wrap for Bash only (a `husk-exec` helper the agent's Bash tool is pointed at)"
as the option "closest to theirs", costed only as `CC`. `ROADMAP.md:12-16` is the project's
design axiom and rules it out in as many words:

> husk uses a **per-session, kernel-enforced (bwrap + seccomp), external wrap** — never a
> per-command hook the agent has to invoke. A per-command hook makes containment only as
> correct as the untrusted orchestrator's code that calls it.

So the real option set is (b), (c), or a fourth the finding does not list.

**(d), for completeness: a `SECCOMP_RET_USER_NOTIF` supervisor** that decides per-call by
inspecting the calling pid's ancestry. It is external, kernel-mediated and needs no
cooperation from the agent, so it does not violate the axiom. I would not recommend it — it
adds a supervisor process on the enforcement path whose death is a fail-open, which is
exactly the property that disqualified their observer as a control — but it belongs on the
list so the decision record shows it was considered and rejected for a stated reason.

**Option (b)'s destination list is missing the load-bearing entry.** The finding names
"the ssh-agent socket, the Docker socket, and any daemon in `/run`". On a SLURM login node
the destination that matters is **MUNGE** (`/run/munge/munge.socket.2`) — it is the
credential that lets a process authenticate to `slurmctld`, i.e. the AV8 broker-bypass. And
husk has already made this exact call once, on the compute side — the mask list is
`settings.rs:100`, `CREDENTIAL_SOCKET_DIRS = ["/run/munge", "/var/run/munge"]` — and written
down why (`seccomp_wrapper.c`, the `PROFILE_SINGLE_NODE` block):

> The point of the block was that a caged job must not authenticate to slurmctld via MUNGE.
> That is enforced by MASKING /run/munge in the cage (`CREDENTIAL_SOCKET_DIRS`, verified on
> hardware) … The mount mask was the load-bearing control; this was defence in depth, and it
> cost GPU support.

That is the same reasoning finding 3 recommends, already adopted, already hardware-verified,
already costed. Option (b) is therefore not a new proposal — it is the extension of a
decision the project has made, and its precedent should be cited in the 6a decision record.

**The premise has never been measured.** "The agent runtime legitimately uses unix sockets"
is an assertion in a comment, not a measurement anywhere in this repo. Three things make it
less certain than it reads:

- their rule is `ERRNO(EPERM)` on `socket()`, not `KILL`, and it does **not** cover
  `socketpair()` — so Node's own `child_process` IPC and anything using socketpairs is
  unaffected;
- husk's own test explains that glibc NSS *self-heals* on `EPERM` and falls back
  (`seccomp-wrapper/test/test_af_unix.c:6-12`), which removes the usual reason a login-node
  process must have `AF_UNIX` (sssd/nscd);
- `user-config/settings.json:2` ships `"enableAllProjectMcpServers": false`.

So the honest position is that a session-scoped block *might* be survivable, and the
ROADMAP already has the instrument to find out: the "naked Claude" check
(`ROADMAP.md:153-154`). **That check should be extended to measure this**, because it turns
finding 3 from a three-way judgement call into a measurement plus a one-way judgement call.

### Severity

**HIGH, as a design decision that must be recorded before the runtime goes — not as a bug.**
I agree with the finding that this is the highest-leverage item in the brief, and for its
stated reason: whichever way it goes, 6a changes the login syscall boundary, and the failure
mode of *not* deciding is discovering the change after the thing that provided it is gone.
Nothing is broken today.

---

## 6. The Lustre walk in husk's own trusted layer — RECHARACTERISED

### What is exactly as described

`settings.rs:868` `scan_credentials` → `:874` `scan_credentials_capped` → `:882`
`scan_credentials_rec`, a recursive `std::fs::read_dir`. `SCAN_MAX_DEPTH = 4`,
`SCAN_MAX_ENTRIES = 20_000` (`:821-822`). Symlinks are skipped without following (`:903-905`).
Truncation is reported (`:535-543`). It runs from `FsPolicy::resolve` (`:523`), and I
confirmed both call sites: **`main.rs:465`, broker startup on the login node**, from
`current_dir()` (the trusted project dir, F17), and **`main.rs:427`, once per step-broker on
a compute node**. The finder's reading of the code is accurate in every particular.

### Where I break the impact claim

**(1) It is not on the interactive critical path.** `husk-slurm-wrapper.rs:416` spawns the
broker with `spawn_broker()`, which is `Command::…spawn()` — a background child with its
stdio redirected to the session log — and the wrapper then proceeds immediately to
`enter_user_mount_ns()` (`:419`), `SandboxReady::establish()` (`:420`) and `exec_agent()`
(`:431`). The scan runs **concurrently with the agent starting**. It cannot produce the
symptom the freeze taught us to fear (the agent stalling at a tool call), because nothing the
user sees waits on it. The worst case is a race on the *first* `sbatch`: the stub polls with
a 120 s deadline and then fails closed with a named error (`sbatch-stub.py:184-189`), and the
`srun` stub has no timeout at all and simply waits (`srun-stub.py:124-125`). That is a
latency and diagnosability cost, not a containment one.

**(2) The walk issues no per-entry `stat` — measured.** This is the part I expected to
confirm the finding and did not. `std::fs::DirEntry::file_type()` on Linux consumes `d_type`
straight from the `getdents64` record and only falls back to `lstat` on `DT_UNKNOWN`. Built a
200-file directory and straced a Rust `read_dir` + `file_type()` loop:

```
$ strace -f -c -e trace=getdents64,statx,newfstatat,lstat ./dt
  71.01%  0.000049   2 calls  getdents64
  28.99%  0.000020   5 calls  newfstatat     ← process startup, not per entry
```

Two `getdents64` for 200 entries and **zero** per-entry stats. So on a filesystem that
populates `d_type`, the walk costs one RPC round per *directory*, not per *entry*, and the
20 000 budget is far less frightening than it reads. Local baseline for the same shape:
`find … -maxdepth 5` over a 20 121-entry tree = **22 ms**.

**(3) The two walks are not the same shape.** Theirs (`linux-sandbox-utils.ts:333-346`) is a
`ripGrep` **subprocess** with `--files --hidden --max-depth 3`, ten-plus `--iglob` patterns
and an ignore-rule engine — it stats, it reads `.gitignore`s, it forks a process — and their
own comment above the function (`:264-266`) is the smoking gun for the cadence:

> With --max-depth limiting, this is fast enough to run on each command without memoization.

Per Bash command, in-process-blocking, with a process spawn. That is a categorically
different cost profile from one `getdents64`-only walk per broker process. **"Dropping their
runtime fixes the Balfrin lag is only half true" overstates it**: the halves are not
comparable, and the half husk keeps is the cheap one.

### What survives, and is worth acting on

The finder's actual recommendation is right and I would keep it verbatim: **the budget bounds
*count*, not *time*.** A single `read_dir` against a degraded MDT blocks with no ceiling, and
20 000 entries is a bound on iterations, not on wall clock. Two closing conditions:

- a **deadline** alongside `SCAN_MAX_ENTRIES`, reported through the same `truncated` path
  that already exists (`:859-862`, `:535-543`) so the operator learns the scan was
  incomplete for a *second* reason;
- an explicit line in the 6a design saying this is the one walk husk knowingly keeps, why
  (it translates credential *globs* into concrete `/dev/null` binds — a thing mounts cannot
  express without enumeration), and that it is scan-once by construction. The reasoning
  already exists in `THREAT-MODEL.md:528-537` ("Scan cadence = `ScanMode { PerConstruction,
  CacheOnce }`" and the re-scan rule); it is simply not in the 6a section where a reader
  looking for the "mounts, not a scanned deny-set" rule would find it.

### Severity

**LOW as a now-issue** (background startup latency; worst case a 120 s fail-closed first
`sbatch` with a named error). **MEDIUM as a 6a constraint**, because the project's rule is
stated absolutely — "express policy as MOUNTS, never as a scanned deny-set" — and an
undocumented exception to an absolute rule is how the rule gets quietly widened later. The
finder is right that this belongs in writing; I disagree only about how alarming it is.

### UNRESOLVED — NEEDS HARDWARE (one command)

Whether Lustre populates `d_type` decides between "O(directories) RPCs" and "20 000 RPCs".
On a Balfrin login node, in a large real project on Lustre:

```
cd /path/to/a/large/project/on/lustre
strace -f -c -e trace=getdents64,newfstatat,statx,lstat \
  /usr/bin/time -f 'wall %e s' \
  ~/.local/bin/husk-slurm-broker --once --dry-run --spool /tmp/husk-scan-probe
```

Read it as: `newfstatat`/`statx` count **≈ number of files** → Lustre returns `DT_UNKNOWN`,
the walk is one MDS RPC per entry, and the time budget is required, not optional.
`newfstatat` count **≈ 0** → the walk is one round per directory and the entry budget is
already sufficient. Either way the `wall` figure is the number to put in the 6a note. Use an
explicitly-built binary and pass `--broker`/an absolute path — `slurm-broker/husk-slurm-broker-x86_64`
is a gitignored prebuilt that can shadow `target/release` (protocol rule 6).

---

## 1. The login cage is 100% theirs — RECHARACTERISED

**The dependency list is right.** I verified the load-bearing pieces independently:
`install-husk.sh:264-296` extracts exactly one binary (`apply-seccomp`) from the tarball —
and *skips the download entirely if the destination already exists* (`:285-286`), so it never
upgrades; `merge-claude-settings.py:105-107` writes `enableAllProjectMcpServers`, `sandbox`
and `permissions` into `~/.claude/settings.json` and nothing else; every bwrap husk
constructs is inside a SLURM job (grep for `bwrap` across the husk trees). The `--ro-bind /
/` root, `--unshare-net` + socat, the PID namespace, `--new-session`, the mandatory deny set
and `TMPDIR` at login are all built by the bundled runtime from that JSON. **6a is "build the
login cage", not "finish it" — that reframing is correct and is the answer the brief asked
for.**

**"Nothing in husk says so" is not right, and I have to say so.** Three places say part of it:

- `README.md:180-183` — "**Filesystem isolation (bubblewrap):** … *Claude Code* uses it to
  run each agent subprocess in an isolated view of the filesystem". The fs layer *is*
  credited to them.
- `README.md:284-289` — the Lustre stall is attributed to "the bundled sandbox and not
  currently configurable".
- `THREAT-MODEL.md:524-527` — "Only the `Compute` profile is wired now; the `Login` profile
  is config, not a rewrite, when husk owns login."

What is genuinely undocumented is the *specific* list: the network namespace + socat bridge +
allowlist proxy, the PID namespace, `--new-session`/`--die-with-parent`, and the mandatory
deny set appear nowhere. The Acknowledgements (`README.md:292-297`) and `NOTICE` name only
`apply-seccomp`, which is the understatement the finding correctly identifies.

**And the docs are wrong in the other direction too**, which the finding misses.
`README.md:269-271` under Known limitations: "**Network access:** Full network isolation
(restricting Claude to only reach Anthropic's servers) is not yet implemented" — while
`user-config/settings.json:21-25` ships `network.allowedDomains:
["opendatadocs.meteoswiss.ch:443"]`, which their runtime enforces with `--unshare-net` plus
the allowlisting proxy for every Bash command. So the login network cage both *exists* and is
*documented as absent*. A reader cannot currently derive what the login side does from the
docs in either direction.

**The sharpest form of the point, which is not in the finding.** At login the agent
*process* is confined by the seccomp deny-list and the `sbatch` bind, and nothing else — no
filesystem cage, no network namespace. Those exist only for commands **the agent's own code
chooses to route through bwrap**. That is precisely the "per-command hook the agent has to
invoke" that `ROADMAP.md:12-16` names as architecturally weaker and says husk must never rely
on. So today's login side is a live exception to husk's own design axiom, and 6a is not only
a substitution — it is what brings the login side into compliance with the axiom. That is a
stronger and more actionable framing than "the docs understate a dependency", and I would put
it at the top of the 6a rationale.

**Severity:** MEDIUM as documentation accuracy (a wrong "not implemented" is worse than a
missing mention — it invites a compensating control nobody needs, and hides one that will
disappear at 6a). HIGH as a reframing of the roadmap step.

---

## 4. Version couplings — RECHARACTERISED

**Every version fact checks out**, from the vendored history, no cluster needed:
`install-husk.sh:188` pins `0.0.49` with a SHA-512 lock; `1640f71` ("feat(linux): passive
seccomp USER_NOTIF observer") is at `package.json` version **0.0.57**, 2026-06-22;
`f869f5a` (the `:port` suffix) is **0.0.67**, 2026-07-24; and `git show
f869f5a~1:src/sandbox/sandbox-config.ts` shows `domainPatternSchema` rejecting any value
containing `:` outright. I also confirmed the configuration really does pair them:
`merge-claude-settings.py:79-80` writes `sandbox.seccomp.applyPath` pointing at husk's
0.0.49 binary, so the shipped combination is "newest bundled TS runtime + 0.0.49 helper", not
a hypothetical.

**Where the finding's framing is wrong.** These are not two instances of one defect and they
are not "mutually inconsistent":

- The `:port` grammar lives **entirely on the TS side** and never reaches `apply-seccomp`.
  The helper is invoked as `<binary> bash -c <cmd>` (`linux-sandbox-utils.ts:763-775`,
  `:800-803`) — an argv stable across all these versions. So "husk's shipped allowlist
  requires ≥0.0.67 while its shipped binary is 0.0.49" is a category error: the binary does
  not parse domain patterns. The real statement is "husk's policy file is written against a
  schema owned by *whatever Claude Code version the user installed*, which husk neither pins
  nor checks" — which is the finding's own conclusion, and is correct.
- Only the observer is an actual binary/TS skew, and it is real: the newer TS binds the
  socket and sets `SRT_OBSERVE_SOCK` (`:1500-1517`), the 0.0.49 binary ignores it, every path
  there is fail-open, and nothing reports it.

**And the two failure directions differ in a way that matters for severity.** A rejected
allowlist entry fails **closed** — the domain is simply not reachable. That is an
availability and diagnosability problem (it looks like a network fault), not a widening.
The dropped observer is telemetry that their own header disclaims as an enforcement boundary.
Neither is a loss of containment.

**Severity: LOW–MEDIUM.** Worth one line in the release notes and worth a startup assertion
if 6a slips; not worth a fix round. The finding's real value is its last sentence, which I
agree with and which is a genuine, previously unstated argument *for* 6a: dropping the
runtime deletes this coupling class entirely.

---

## 5. The session wrap already exists — CONFIRMED

Verified every citation: `husk-slurm-wrapper.rs:292-301` `enter_user_mount_ns` unshares
`CLONE_NEWUSER | CLONE_NEWNS` and writes identity uid/gid maps; `:262-275`
`SandboxReady::establish` binds the stub and proves it by `dev`+`ino`, and the token is the
only way to reach `exec_agent` (`:311-328`); `doc/sandbox-interface.txt:57-72` documents the
inheritance property. 6a (iii) is mechanism-complete — what is missing is the policy mounts.
I agree, and this is the most useful *positive* result in the shard.

Two corrections to the attached notes:

- **The stale-justification comment exists in two places, not one.** The finding names
  `husk-slurm-wrapper.rs:283-289`; `cage.rs:100-105` carries the same causal chain ("`0 <uid>
  1` … flips the agent runtime into its `--cap-drop ALL` branch"). Both need the rewrite at
  6a, and the rule itself stays for its own reasons.
- The `exec_plain` gap (`:334-339`, no namespace) is real, but note it is the **no-SLURM**
  path — a laptop, where there is no `sbatch` to shadow and nothing to broker. The 6a work is
  as stated (move the unshare ahead of the SLURM branch); it is not a cluster exposure today.

**Severity: LOW** — a positive finding plus two comment-maintenance items.

---

## 7. What the ripgrep walk buys — CONFIRMED

Read `linuxGetMandatoryDenyPaths` (`linux-sandbox-utils.ts:269-387`) end to end. The split is
exactly as described: `:282-310` is static (`DANGEROUS_FILES.map(path.resolve(cwd, …))`,
`getDangerousDirectories()`, and `.git/hooks`/`.git/config` gated on `.git` being a real
directory), and `:333-346` is the single `ripGrep` call whose entire marginal value is
matches in **subdirectories** of cwd to `--max-depth 3`, excluding `node_modules`. So a 6a
policy layer that emits the static half as mounts loses exactly one thing: a nested
`.git/hooks/`, `.claude/commands/`, `.vscode/` or `.gitconfig` below the project root. husk's
compute answer — mask the directory *name* relative to each writable root with a fresh tmpfs
(`AUTO_EXEC_DIRS`, `settings.rs:131-136`) — is absent-safe and needs no enumeration, and generalises to each
level. I agree this is the concrete form of the "mounts, not a scanned deny-set" rule for 6a,
and I agree the residual is small, named and closeable later.

**Severity: informational** (design guidance, no defect).

---

## 8. 6a deliverable (ii) is new capability — CONFIRMED

`user-config/settings.json` (read in full, 85 lines) declares no `sandbox.credentials` block,
so their `credential-mask-env.ts` / `credential-mask-files.ts` / `credential-sentinel.ts`
machinery is entirely dormant under husk. Login credential protection is `denyRead:
["/users"]` (`:8-10`) plus the permission-layer `Read()`/`Edit()` globs (`:41-80`), which bind
the tools and not `cat` inside a Bash command. The compute side really is stricter:
`settings.rs:517-528` folds `scan_credentials` hits into `deny_files`, which become
`--ro-bind /dev/null <path>` masks (`:796-802`), with no login equivalent.

The asymmetry is precisely located: a `.env` **inside the project directory** is readable by
`cat` at login and masked on compute. (Home-directory secrets are covered at login too, by
the `/users` tmpfs.) So 6a (ii) closes a gap in husk's favour and is not a parity item.
I agree it should not be scored as blocking.

**Severity: informational** — this *lowers* the 6a blocking count by one.

---

## 9. `TMPDIR` / default write paths — CONFIRMED as a work item

`getDefaultWritePaths()` (`sandbox-utils.ts:399-415`) unconditionally adds `/tmp/claude`,
`~/.npm/_logs`, `~/.claude/debug` and the `/dev` character devices; `generateProxyEnvVars`
(`:443-467`) sets `TMPDIR` (from `CLAUDE_CODE_TMPDIR`/`CLAUDE_TMPDIR`, default `/tmp/claude`)
whenever a write policy exists. husk's compute cage sidesteps it with `--tmpfs /tmp`
(`settings.rs:602`). The login cage will need the same plus a decision about `~/.claude`,
which husk otherwise write-denies (`user-config/settings.json:14-19`). The finding is right
that the exact set is not derivable from this repo and that the "naked Claude" check
(`ROADMAP.md:153-154`) is the instrument.

One detail worth keeping, because it connects to finding 2: `/dev/tty` is in their default
*writable* set, yet `--new-session` makes `/dev/tty` unopenable inside their own cage — I
measured `open("/dev/tty") → ENXIO` there. So that entry is vestigial (or macOS-only) on
Linux, and a 6a reimplementation should not copy it as if it were load-bearing.

**Severity: functional, not security.** Getting it wrong produces "tool bug" symptoms rather
than policy denials, which is the finding's real point and is worth carrying into the 6a
acceptance criteria.

---

## Coverage and overlaps

**Nothing in the shard went untriaged.** All nine findings and the rows they rest on were
checked against source; four of the table's "NOT NEEDED" rows (9, 15, 16, 27) I read but did
not re-derive in depth, since nothing hangs on them.

**Suspected overlaps — flagged, not resolved (protocol rule 3):**

- Finding 2's `--die-with-parent` half is a lifecycle/RAII question and looks like **B1**
  territory.
- Finding 3's option (b) changes the login *syscall* boundary; if another shard covers
  seccomp scope at login, this is the same decision from the other side.
- Finding 6 touches broker startup, which any shard auditing the broker's own trusted-side
  behaviour will also reach.

**One thing I could not settle and did not try to:** whether CSCS requires a site egress
proxy (row 17). That is a question for CSCS, not for the code, and the finding says so.

**Artefacts** (scratchpad, not committed): `tiocsti_probe.c` — the 20-line probe used above
and referenced in the hardware task list for finding 2.
