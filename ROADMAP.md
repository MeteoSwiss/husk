# husk roadmap

**Where husk is going.** Its sibling [`doc/context.md`](doc/context.md) holds where husk *is*
— together they are the ⟂ time axis of the [documentation stack](doc/README.md), and both are
expected to rot on purpose. Nothing here re-argues *why*: the design premise lives in
[`doc/threat-model.md §1`](doc/threat-model.md), the reasoning that outlives any scheduler in
[`doc/PRINCIPLES.md`](doc/PRINCIPLES.md), and the agent contract in
[`doc/sandbox-interface.md`](doc/sandbox-interface.md). If a paragraph here explains a rule
rather than scheduling work, it is in the wrong file.

**Strategy, unchanged:** reimplement the vendor runtime's pieces in Rust incrementally, each
independently useful, until the marginal cost of dropping it is ~zero — then own it and
generalise. Never big-bang.

---

## Shipped

**v0.4 (2026-07-27)** — single-node broker: `sbatch`, compute-side re-sandbox, the fs cage
(F1–F6), GPU carve-outs, read-only SLURM queries. Submission surface default-deny by
construction. Balfrin-verified.

**Steps 1–3b (2026-07-31, branch `experimental`, unreleased)** — `srun` brokering end to end
(recursive stub/step-broker pairs, step option allowlist, per-rank cages, single-node
multi-rank MPI); network egress (allowlist, one proxy per node, per-rank relays, `CONNECT`
only by design). **ICON ran to completion with CMA enabled**, and a **production KENDA
assimilation experiment ran green** — the first real production workload through husk.

**v0.5 fix round (2026-08-05)** — the security review's whole above-LOW set plus the eight LOW
code fixes, hardware-green on Balfrin *and* Santis, ICON running again. Details in
`doc/review-v0.5/`.

---

## Track A — release v0.5 — **DONE**

Everything else assumes a released baseline.

1. **Santis at HEAD.** It was green at `2f1a0b0`, before both the Lmod env fix and the
   ghost-file TOCTOU fix. Re-run.
2. **The A1 file-descriptor question — ANSWERED 2026-08-19, and the grep test was wrong.**
   The empty grep was read as "guard enforces, CRITICAL closed"; it was actually "the fail-open
   branch never fired", which is not the same claim. A1's re-run settled it directly: for an
   `--output` swapped OUTSIDE the set, the guard's `$$` fd1 is the real file and it refuses
   (job-5138292 log) — content holds. F2 (output into a PROTECTED path inside the set) was the
   real CRITICAL and is sealed; F1's residual is bounded empty-file creation, accepted for v0.6.
3. **Pen-test re-run — FULL round, decided 2026-08-20.** Not just R1/R2: every remaining brief
   (R3, R4, N1–N9, A10, A11) in one pass, findings batched, one fix pass, then release. A5/A1
   done. See `doc/review-v0.5/RE-RUN-PLAN.md`.
   A5 first: it never actually ran (the cage-build collision killed 3 of its 4 jobs), so its
   hop 2–4 verdicts came from laptop triage rather than the cluster. Then A1, then the new
   briefs aimed at the code the fix round added — two of which are a *gate* nobody has
   attacked.
4. **→ RELEASE v0.5.** An agent on a CSCS system, externally confined, running its own
   single-node 4-GPU jobs. A daily-work tool, not a demo.

---

## Track B — own the boundary (6a, then 6b)

**6a is the keystone, and it is not only a security milestone.** Today the vendor runtime owns
the login-side boundary and wraps each *command*; husk wraps the *harness* only on compute.
Three consequences close together when husk owns the outer cage:

- **The two-door problem disappears.** In-process file tools stop being a hole — not because
  the tools changed, but because a path that is not mounted is unreachable by any of them
  ([`sandbox-interface.md §4.1`](doc/sandbox-interface.md)).
- **the `--tools` allowlist can be deleted**, which is the single largest usability win available:
  native file tools come back at full speed instead of every touch being a sandboxed command
  on Lustre.
- **husk can own policy** (§6 of the contract), because it owns what is mounted.

### 6a also retires the `~/.claude` mask list — and the spelling matters

The shipped `denyRead` enumerates the `~/.claude` children by hand
(`.credentials.json`, `history.jsonl`, `sessions`, …) because a **top-level** `denyRead` on
`~/.claude` is silently ignored: the vendor runtime binds that directory back read-only
over the home mask, and its bind wins. So the list is a denylist, which means it is a bug
list (P5) — measured 2026-08-25, `cache/`, `bridge-spawn/`, `telemetry/` and two
`settings.json.bak.*` files our own installer leaves are all unmasked, and every directory
Anthropic adds in future arrives readable.

**Inverting it is feasible before 6a, and was deferred to 6a deliberately.** The mechanism,
read out of `sandbox-manager.ts` (~line 1596): on **Linux specifically**, a `denyRead` entry
containing glob characters is expanded with `expandGlobPattern` at config-build time. So
`~/.claude/*` expands to the concrete children and self-maintains, and `allowRead` — which
overrides `denyRead` — brings back the ones that must stay readable (`projects`).

**THE TRAP, and it is silent.** `removeTrailingGlobSuffix` strips only a trailing `/**`:

- `~/.claude/**` → stripped to `~/.claude` → no glob chars remain → pushed as the
  **top-level deny the runtime ignores** → masks NOTHING, with no error;
- `~/.claude/*` → not stripped → expanded → works.

Since `//**` is the spelling husk uses elsewhere for filesystem-wide coverage, the natural
thing to write here is the one that silently does nothing. Whoever does this must verify by
**actual read** (`stat` showing `/dev/null` or an empty tmpfs), never by the config —
exactly the lesson `husk-verify.sh` exists to enforce.

At 6a this becomes moot in the good way: husk owns the login cage, builds `$HOME` from an
empty base like the compute cage already does, and simply never binds the credential
directories. No denylist, no glob, nothing to drift.

### 6a GIVES TOOLS BACK — the deny list is collateral, not policy

Christoph, 2026-08-28: *"Once 0.6 hits we can allow all of these again, because then we
control if SendMessage is used to revive a subagent in the same session, or signaling a
different agent in a different session. One will work, one will not."*

That is the strongest argument for 6a and it is not a security argument.

**Today the tool allowlist is a DESCRIPTION-level control** — husk denies the NAME of a
capability because it cannot deny the capability. `P4` says plainly that this is the weaker
form: control what executes, not a description of it. The 29 denied names are not 29 security
judgements; they are **collateral damage from a boundary husk cannot currently express**, and
only 8 of them ever had a measured disposition (`review-v0.5/TOOL-DENY-TRIAGE.md`).

The cost is real and it is invisible to us. `SendMessage` is denied, so an operator cannot
resume a subagent after a usage limit — which is the recovery step the whole sequential-agent
pattern depends on. Nobody would connect that failure to husk.

**After 6a the same tool splits along the line that actually matters.** `SendMessage` is
dangerous only because it reaches OUT — other sessions on this machine, and remote ones via
Remote Control. Both paths are things an outer cage already knows how to close: a sibling
session is on the far side of the namespace, Remote Control is on the far side of the egress
proxy. A subagent spawned INSIDE the cage is reachable, because it is inside. So:

    resume my own subagent      -> works
    signal another session      -> fails, at the OS layer, with no tool rule involved

That is the difference between a boundary and a list of names, and it is why every entry on
that list is provisional. **The 6a acceptance test already says "delete the `--tools`
allowlist entirely"; this is the other half — the `permissions.deny` bare names go too, and
the tools come back.** What remains denied afterwards should be denied because the channel is
gone, not because the name is on a list nobody can keep complete (`W3-DRIFT`: an unknown name
only warns, and a new upstream tool is admitted by default).

*Acceptance test for 6a:* land the outer cage, **delete the `--tools` allowlist entirely, and
verify `/users` is still unreachable from the agent's own file tools.** Note what the test does
NOT yet cover: the agent's own model-API egress, which is outside every cage today by
construction ([`agent-profile-claude-code.md §2`](doc/agent-profile-claude-code.md)) and becomes
husk's problem the moment the outer cage exists. If it holds, the workaround was
redundant; if not, husk does not own the boundary it claims.

*Free input, already collected:* the vendor's `DANGEROUS_FILES` / `getDangerousDirectories()`
are **a draft of husk's own mask list**, and every friction report against them is a decision
husk inherits rather than a quirk that disappears. `.gitmodules` is the worked example: at 6a
husk decides whether to mask it, and the answer is already argued — it is *tracked content*
rather than configuration, so denying the write breaks ordinary merges mid-transaction, and the
threat it guards (a hostile submodule URL) is realised at `git submodule update`, not at write
time. Same for `.git/config`, `.claude/*` and the rest. **Stop attributing these to Anthropic;
start reading them as our own backlog.** The attribution work is what 6a makes worthless — the
analysis is what it consumes.

**The condition on that, so it is a decision and not a drift (Christoph, 2026-08-13):** this
holds only while 6a stays close. *If husk ends up depending on the vendor sandbox materially
longer than currently planned, revisit and start attributing* — build the machinery that names
the vendor layer in the error, and file the reports properly rather than drafting and parking
them. The trigger is calendar, not opinion: if 6a has not landed by the time the vendor's
protected paths have cost a **third** production session, the trade has flipped and the cheap
answer is no longer the right one. Two have gone so far — the `config` directory in the LETKF
build, and this `.gitmodules` merge.

*Another one for the 6a list, found 2026-08-19 — and the tally is the argument.* A write into a
hidden path returns `rc=0`, reads back correctly, and is discarded: `denyRead` produces an empty
per-command tmpfs, not a refusal. An agent asked to put a file in a home directory did exactly
that and reported success with an `ls -l` as proof. **husk cannot fix the login half** — that
argv is the vendor's, and there is no config for "hidden AND read-only" — so it joins agent
memory, `.gitmodules` and the `config/` mount as things that are only fixable by owning the
layer. At 6a it is one `--remount-ro` after each `--tmpfs`, and the behaviour finally matches
the banner, which already promises `Read-only file system` for writes outside the writable set.

**The compute cage can have it sooner**, since husk builds that argv itself — worth doing after
the pen test, and worth knowing it only closes half the problem.

*Output ownership — the clean end of the A1 story (2026-08-19).* A1 showed `--output` is a
write primitive slurmd executes UNCAGED, following symlinks, on an agent-influenced path. v0.5
fixes it in layers — refuse protected targets (F2), name-check the emitted paths at run time
(F1 option 2), reap the leaked spool — and one residual survives: slurmstepd creates an empty
file at the swapped target before husk's guard runs. **v0.6 retires the whole class instead of
the instance.** Because husk owns the agent's mount namespace at 6a, it can:
- emit its OWN fixed output path in `~/.husk/out/<jobid>` — masked from the agent in every cage,
  so there is no pending window and no directory the agent controls; slurmstepd opens a fresh
  regular file husk owns, and the empty file is never created (prevention, not detection);
- bind that file READ-ONLY into the agent's view at the conventional `<workdir>/slurm-<jobid>.out`,
  so convention is preserved — the v0.5 reserved-directory option moves the output, this moves
  only the agent's *view* of it.

The categorical win: `confine_output_pattern` is a two-machine TOCTOU *by construction* — it
validates an agent-influenced path husk checks at T1 and slurmd opens at T2. At v0.6 the agent's
path never reaches slurmd; husk emits a fixed unreachable one and the agent's requested name is a
label on a read-only view. **No agent-controlled path reaches `open()`, so there is no check to
race** — F1, the untested directory-swap sibling and the `%`-specifier corner are absent, not
patched. It is the SLURM broker's own logic one primitive over: emit husk's submission rather
than filter the agent's, now for output rather than for options.

*Prerequisite, now measurable:* user namespaces must **nest** — husk's cage will sit around a
runtime that creates its own. `husk-site-check.sh` tests it.

**6b** — the contract is written and passes its own acceptance test (the vendor's name appears
once, in the integration table). What remains is husk's own policy schema plus a vendor
adapter. **Deliberately unspecified: the field names** — the property is the commitment, the
encoding is 6a's to choose. husk's own non-conformance is tracked in
[`sandbox-interface.md §8.1`](doc/sandbox-interface.md), and those rows are deleted when
closed, never reworded.

---

## Track C — more machines

Parallel to everything; blocks nothing. The architecture already ports (no root, no site
cooperation, per-arch binaries, degrades without uenv). The details are where the work is.

**Run [`slurm-broker/husk-site-check.sh`](slurm-broker/husk-site-check.sh) first, on every
candidate.** It answers the one fatal, binary question — are unprivileged user namespaces
available — in five seconds, before anyone invests a week. It also emits the draft site
profile.

**Targets, chosen for what they teach rather than for coverage:**

| target | new axis | note |
|---|---|---|
| **LUMI** | AMD GPUs (`/dev/kfd`) | Cray EX, so Slingshot and the OS are familiar — one new variable, well isolated. Highest information per unit effort. |
| **Euler (ETH)** | InfiniBand fabric, non-Cray OS | second device family and a different module system |
| **DKRZ Levante** | — | mostly confirms what LUMI and Euler already teach; do it later, cheaply |

**Known work:** AMD (`/dev/kfd`) and InfiniBand (`/dev/infiniband`) are listed as of
2026-08-09 — `--dev-bind-try` skips what a node lacks, so they were an omission rather than a
blocker and cost nothing here. What remains is enumeration: `/dev/nvidia0…7` is a static eight,
and `/dev/dri` must be conditional on the node actually being AMD. Both are `F2` work. The env allowlist needs one measured bringup per site — that is `P5`'s documented tax,
and it is now routine: read the "not forwarded" line.

---

## Track D — multi-node MPI — **ANSWERED 2026-08-06: weeks, not days** (currently REFUSED)

The experiment ran (`fabric-probe.sh` C10, Balfrin, real 2-node allocation, job 5019306).
**Exactly one thing blocks multi-node: `--unshare-net` per rank.** `cs_2node4rank_nonet`
gives a real 4-rank communicator — the ICON shape, intra-node shared memory and the
inter-node NIC at once — while `cs_2node4rank_netns` fails with `_pmi_set_af_in_use:
Unable to obtain IP address`. `cray_shasta` PMI is TCP, and a rank alone in a netns has no
IP to bind.

Everything else is clear: the **fabric is orthogonal** (proven twice — the no-unshare arm
failed identically, and `C11` shows a caged job really is on CXI, not degraded to TCP);
**`/dev/shm` must be shared per node** (private tmpfs *hangs*; the per-job-subdir design is
now measured); AF_UNIX can stay blocked at no functional cost; steps run concurrently.
**The escape hatch is closed** — `pmix_2rank_UNCAGED` is also wrong-size, so this MPICH does
not speak Slurm pmix at all, and `pmi2` fails the same at two nodes.

**The open decision, and it is a real one.** Dropping `--unshare-net` gives those ranks the
HOST network, so the egress proxy and allowlist stop applying — on the largest jobs. Three
shapes: (1) accept it and document it as a capability difference between cage profiles, the
way `single-node` and `multi-node` already differ; (2) **one netns per job-on-a-node** rather
than per rank, with an address PMI can bind — consistent with `P1`, looks right on principle,
needs its own measurement; (3) treat the fabric as the checked hole VNIs already make it.

**(4) — added 2026-08-06, Christoph: let the endpoint pre-exist the boundary.** Rather than
carrying PMI *through* the netns, arrange that the connection it needs already exists when the
cage is built — the spirit of the egress relay, where the real socket lives outside and the
caged side only holds a handle. Two mechanisms do this without any address rewriting:

- **an inherited fd** — `PMI_FD` exists precisely so a launcher can hand a bootstrapped
  connection to the process it spawns, and husk already passes fds through bwrap
  (`--userns 9 --pidns 8`);
- **a Unix socket path** — `PMIX_SERVER_URI` names a *filesystem* rendezvous, and a filesystem
  path crosses a netns natively. husk already bind-mounts exactly this shape for egress.

**What does NOT work, and it is worth writing down so nobody spends a day on it:** "let MPI
bootstrap, then wrap it." bwrap execs, and exec destroys the in-process MPI state, not merely
its sockets. The in-process variant — the workload calling `unshare(CLONE_NEWNET)` on itself
after `MPI_Init` — is mechanically fine but requires the confined side to cooperate, which is
the one thing husk's axiom forbids.

**ANSWERED 2026-08-06 (jobs 5021103/5021116), and the answer is the expensive one.** Neither
cheap mechanism exists on this stack: `C12` measured **zero AF_UNIX socket/connect calls** in a
caged 2-rank run, so the rendezvous is not a Unix socket; and the rank's environment offers
neither `PMIX_SERVER_URI` nor `PMI_FD`, so there is no filesystem path and no inherited fd to
adopt. What is offered is `PMI_CONTROL_PORT` + `SLURM_STEP_RESV_PORTS`, and the netns failure
is `_pmi_set_af_in_use: Unable to obtain IP address` — PMI determining **its own** address.
That is the hardest sub-case: an address used as identity cannot be rewritten the way an HTTP
proxy target can, so option 4 would have to supply a *bindable* address, not merely
reachability.

### DECIDED 2026-08-06: ship it as a named, weaker profile; real support is v0.7

Dropping `--unshare-net` for multi-node is **unsatisfying, and that is the point** — so it
gets advertised as what it is rather than hidden. A `MultiNode` profile whose boundary is
explicitly weaker: ranks share the host network, so **the egress proxy and its allowlist do
not apply**, and AV8 (broker bypass) is reachable from a rank. Everything else — the
filesystem cage, the seccomp profile, the resource envelope — is unchanged.

Two constraints on how it ships, both from `P7` and from this project's own history:

- **It must be LOUD.** `Profile::select` currently *rejects* multi-node rather than silently
  downgrading to one node, for exactly the right reason (a wrong answer that looks like a
  right one is the worst outcome available). The same rule applies here: a job that gets the
  weaker boundary must say so, in the banner and in the job log, every time. An operator who
  discovers the difference by reading the roadmap has been failed.
- **It must be opt-in at the operator level**, not something an agent reaches by asking for
  `--nodes=2`. The agent picks from what the operator allows; it does not pick its own
  boundary.

**Real multi-node containment is v0.7**: per-rank routable addressing (veth + bridge +
routes), which is real container networking and the first thing husk would have built that
needs it. Not before the v0.6 boundary work — owning the login cage is worth more.

**MEASURED 2026-08-06 (job 5022735), and it settles the boundary question.** Instrumented
`mpi_hello` dumped its own fd table after `MPI_Init` in an uncaged 2-node run:

```
rank=0 host=nid001227 fd=3 local=0.0.0.0:27702        peer=0.0.0.0:0      st=0A  <- LISTENING
rank=0 host=nid001227 fd=4 local=…97.54:27702  peer=…97.74:56708  st=01
rank=1 host=nid001237 fd=4 local=…97.74:56708  peer=…97.54:27702  st=01
```

**Each rank LISTENS and they cross-connect directly across nodes.** So option 4 is out for
this stack: there is no pre-existing connection to inherit when the rank itself creates the
listener, and an inherited fd cannot cover a listener plus N inbound.

**The decision that follows is robust to what that traffic actually is:** either way a rank
must bind a listener and advertise an address another node can dial, and loopback is not
advertisable — which is exactly what `_pmi_set_af_in_use` reports. **Multi-node therefore means
dropping the per-rank netns, or building real container networking (veth + bridge + routes).**

**Still genuinely open, and it decides how big the fix is, not whether one is needed:** is
27702 the PALS/PMI control plane or MPI's own transport? It is NOT `PMI_CONTROL_PORT` (that was
22125/22275, always the first of `SLURM_STEP_RESV_PORTS`), and both ranks listen on the same
number, which reads as a derived service port rather than an ephemeral data socket. The
discriminator is one run with the TCP provider disabled and CXI forced: if 27702 survives it is
control, if it vanishes it was transport.

**Not answered: whether PMI accepts an address it is handed.** The `pmi_addr_hint` arm came
back inconclusive because the caged run died at `pals_init2() failed: 2` — the PALS launcher
failing UPSTREAM of the address lookup, so `MPICH_INTERFACE_HOSTNAME` was never reached.

Superseded, kept for the reasoning: the refinement worth measuring was the PEER of that
connection: does a rank talk
to its LOCAL stepd, or to a remote node? Local-only would mean a per-node relay is enough;
remote means full inter-node routing. `C13` does not answer it yet — it inspects a `sh -c`,
which never calls `MPI_Init` and so never opens the socket. It needs to dump the fd table from
inside the probe's own `mpi_hello` after `MPI_Init`, which is a small change to a binary the
probe already builds.

**Also now measured, and it narrows the problem a lot:** intra-node ranks in separate netns
wire up **fine** — `cs_1node2rank_netns_shm` and `cs_1node2rank_netns_jobdir` both form real
2-rank communicators, twice, reproducibly. PMI finds its same-node peer through the filesystem.
So the netns boundary is not broken by PMI in general, only by the **inter-node** hop.

Historic framing kept for the record:
`_pmi_set_af_in_use: Unable to obtain IP address` is a real failure mode naming a real IP
lookup, not merely a variable being set; and "obtain **its own** address" is the harder
sub-case, because an address used as *identity* cannot be rewritten the way an HTTP proxy
target can. `fabric-probe.sh` **C13** settles which of the three transports is actually in use
by dumping what a rank is offered *and* what it holds open — the environment says what was
offered, the fd table and `ss` say what was taken. One 2-node run, no new experiment.

**Security item surfaced by the same run:** `SLINGSHOT_VNIS` is in the step environment and
steers which VNI a process uses, while `SLINGSHOT_` is not in `RESERVED_ENV_PREFIXES` — so a
caged rank can set it. Whether the NIC validates it against Slurm's grant is the
AV8-over-fabric question, which needs a libfabric program rather than shell. Reserve the
prefix regardless.

---

## Track E — usability

Not a phase — a lens. The evidence so far says usability is mostly **precision work**, not
"make husk weaker": in each case the control's blast radius exceeds its target, and tightening
the aim costs no security.

| symptom | control | actual target | shape of the fix |
|---|---|---|---|
| ~~agent memory does not persist~~ | `denyRead: /users` masks the whole home | the agent's own state dir | **DONE 2026-08-09** — `allowWrite: ~/.claude/projects`, bound back inside the mask. Cross-project until 6a can scope it; see below |
| cannot read another user's data tree (e.g. operations data) | the `/users` floor | credentials in home *roots* | **NOT DECIDED — see below** |
| every file touch is a slow sandboxed command | the `--tools` allowlist | the two-door problem | dissolves with 6a |
| per-site setup needs undocumented knowledge | — | — | site profile + `husk-site-check` |
| SLURM queries fail inside a job, blaming the controller | nothing — the stubs were never bound on the compute side | the write verbs (`sbatch`, `scancel`) | **bind the Tier-1 stubs in the compute cage too — see below** |

**Read-only SLURM inside a job — Tier 1 shipped for one cage, not two.**

Reported 2026-08-29: `sinfo -p normal -h -o "%c"` inside a job returns *"Unable to contact
slurm controller"*. The flags are not the problem — `-p`, `-o` and `-h` are all in `sinfo`'s
`QuerySpec` and the broker would have accepted that exact invocation. The request never
reached a broker. On the LOGIN side the Tier-1 verbs are shadowed by husk stubs; in the
COMPUTE cage husk binds a stub over `srun` and nothing else, so `squeue`/`sinfo`/`sacct`
are the REAL binaries, with no MUNGE and no route (measured independently in
`findings_round2/N4.md`, job 5169678).

So this is not a control with too wide a blast radius — it is a control that was never
there. Nothing decided that a job may not ask what its own node looks like; the write verbs
needed brokering and the read verbs came along by omission.

**Why it cost a session, in the reporter's words: "it's insidious because interactive
verification says it's fine."** The same command, in the same session, on the same cluster,
answers correctly on the login node and fails inside the job — `sinfo -p normal -h -o "%c"`
returns `288` interactively and "Unable to contact slurm controller" in a runscript. Every
check a person naturally runs before submitting is run in the wrong cage.

That is a general hazard and not a fact about `sinfo`: **husk has two cages with different
contents, and the one you verify in is not the one you run in.** Anything the docs, this
file, or a teaching message calls "brokered" is per-cage, and saying it unqualified is what
made the reporter reasonably suspect the flags. `husk-verify.sh` shares the shape — it
checks the cage it runs in. Wherever a capability is named, name the cage.

**Where it goes: the step-broker, not the login broker.** There is already an UN-CAGED
helper on the compute node — the step-broker husk starts for `srun`, which needs MUNGE and
the daemon route and therefore already has exactly the reach a query needs. Its protocol
already carries a `tool` field and today rejects everything that is not `srun` (`step.rs`).
That rejection is the extension point. Routing to the login broker instead would mean a
cross-node spool, added latency, and a second caller on a deliberately single-threaded
process — all to reach a machine that is further from the answer.

**The constraint that matters: ONE policy, two transports.** The query allowlist and the
construct-and-re-emit path live in `policy.rs` and must be *reused*, not restated in
`step.rs`. A second list is the failure this project keeps paying for — twice in one day on
2026-08-29 alone (`GRACEFUL_ERRNO_SYSCALLS` had no tie to `BLOCKED_SYSCALLS`; `DOC-STATUS`'s
glob silently did not cover `HARDWARE-RUN.md`). Whatever the shape, it needs the same
startup assert: every tool the step-broker will answer resolves to a spec in the one table.

Also inherited, and worth naming so it is not rediscovered: the stubs are bound over a
`command -v`-resolved path, so the `which()`-first-match residual applies here **seven more
times**, once per verb. And a job must not be able to hammer `slurmctld` — the same
`QUERY_TIMEOUT_SECS` bound as the login path, plus the step-broker's existing concurrency
cap.

**Scope:** read-only Tier 1 only (`squeue`, `sinfo`, `sacct`, `sstat`, `sprio`, `sreport`,
`sshare`). Whether `scancel` of the job's own id belongs here is a separate decision — a job
cancelling itself is legitimate, a job cancelling its siblings is not, and that distinction
needs the same care the login side gave it.

**Cheap and separable first step: attribution before capability.** Today the real binary
answers with a message that names SLURM, so a reader concludes the controller is down or the
flags are wrong — which is exactly what happened, and it cost a debugging session. A stub
that only explains ("husk does not broker SLURM queries inside a job yet; run it on the login
side") closes the teaching failure without building the feature, and is strictly less work.
Third instance of an unattributed denial in one day (`P13`), alongside the broker's
dropped-variable log and the guard's strace advice.

**Agent memory, and why it waits for 6a.** `~/.claude` is not read-only — `denyRead: /users`
tmpfs-masks the entire home, so the agent cannot see its state dir at all. That is *better*
than read-only for this purpose: the tree is already an allowlist, so restoring memory means
binding one object back inside the mask rather than punching a hole in a deny list, and the
auto-exec siblings (`hooks`, `commands`, `agents`, `skills`) stay invisible because they were
never visible. The vendor runtime supports exactly this — it re-binds `allowWrite` paths after
the `denyRead` tmpfs, by design.

**SHIPPED 2026-08-09, deliberately unscoped.** `allowWrite: ~/.claude/projects` restores agent
memory for every project at once. Per-project opt-in was considered and rejected as incoherent:
husk installs per user, so "enable memory for this one directory" is not a thing a user should
have to say.

**What that costs, recorded so it is a decision and not a drift.** It is husk's *first
cross-project write channel*. Until now writes were confined to the current project dir, so a
session could already plant instructions for a later session in the SAME project (a project
`CLAUDE.md` is agent-writable and always was) but not in a different one. Now it can: a
compromised session in a throwaway project can write a memory file that a future session in a
production project loads as its own established context. Same user, same machine, no escape and
no cross-user reach — the blast radius is the operator's own, which is why it is acceptable —
but it is a genuinely new capability and the first of its kind.

**It is removable, and should be removed.** At 6a husk builds the login bwrap args itself,
knows the project dir, and binds exactly `~/.claude/projects/<this-project>`. This entry should
be deleted the day that lands; leaving it would keep a cross-project channel that has stopped
being necessary.

**The blocker was scoping, not mechanism.** The memory path is per project
(`~/.claude/projects/<mangled-cwd>`), and before 6a the only lever is the vendor's
*user-global* settings file, which cannot express "this project". The broad form
(`allowWrite: ~/.claude/projects`) would create the surface and make it cross-project in one
step: a session in one project could plant content a later session in another reads as its own
established context. With 6a husk builds the login bwrap args itself, knows the project dir,
and binds exactly one path — the same move the compute cage already makes.

An opt-in `install-husk.sh --enable-memory <dir>` would scope it at install time if this
blocks work before 6a. **The workaround is a state file in the project dir**, which is what
both friction logs did, and it works.

**Worth a pen-test brief either way:** agent memory is the sharpest case of the confined side
writing what a later confined side reads as trusted context. A transcript is turn-by-turn and
self-evidently the agent's own; a memory file is instruction-shaped and survives the session
boundary that currently resets everything.

**Introspection is one problem wearing three hats**, and it has cost real time: a stale
prebuilt binary reported the A1 escape as still open; a stale in-session broker cost a whole
diagnosis round on ICON (a session keeps the broker it started with, so reinstalling does
nothing); `exit` backgrounds a session rather than ending it, producing a phantom DRIFT. The
build stamp fixed one instance. **`husk status`** would generalise it: which build, which
broker, which session, which policy, which partitions, is the boundary actually up.

---

## Track F — break up the two functions that carry the bug history

**The module structure survived 213 commits; the function structure did not.** Measured
2026-08-06, on the code that ships v0.5:

| | |
|---|---|
| `wrap_script` | 624 lines |
| `decide` | 454 lines |
| **together** | **1,078 of `policy.rs`'s 1,563 code lines — 69%** |

The dependency graph is still a clean DAG with no cycles, and the seven modules added since
v0.4 (`rank`, `step`, `srun`, `netproxy`, `netallow`, `profile`, `cage`) all landed as proper
layers rather than as extensions of existing files. That is the part that usually rots first
under incremental growth, and it held.

What drifted is inside those two functions, and **they are the two most security-critical in
the project**: `decide` is the submission gate (F13/F14/F24/F26/F27 and the `#SBATCH` CRITICAL
all lived there), `wrap_script` is the guard generator (B5's *4 of 7 shipped guard bugs were
quoting, interpolation or scoping*, plus the 2026-08-06 silent hang).

That is not coincidence. **Both of this project's recurring bug classes are the failure mode of
a 500-line linear sequence of conditionals** — in a function that long, "is this handled on
every path" is not visible by reading, so it does not get checked. The srun hang was a nested
`if` with no `else` at line ~1375 of a 624-line emitter. The `#SBATCH` outage was a branch that
validated body directives and then failed to re-emit them.

Three ordered steps. **The order is the point:** each one makes the next checkable. F0 below is
not a step — it is what the steps are *for*.

### F0 — the five concepts, and the sweep rule

**Christoph, 2026-08-10.** The bugs of the last three weeks are not five bugs. They are five
*concepts that do not exist in the code*, each showing up in three or four places. Fixing
instances one at a time is what we have been doing, and it is why the same shape keeps arriving
under a new name. The redesign's job is to give each concept a type, and then **sweep every
instance in the same pass** — the [fix-the-sibling rule](doc/PRINCIPLES.md), which cost an
afternoon the one time it was ignored.

Each entry below already clears L1's two-instance entry bar several times over. The instances
are the evidence, and they are also the sweep list.

> **CORRECTED 2026-09-01 — the five concepts survive; F0's split does not.** Round 3 sent three
> independent passes at this section (`C3`, `E1`, `F1`) and they agree: **every concept is real
> and F0 under-counted all five** — 47 instances found in that round alone (C1 = 8, C2 = 10,
> C3 = 8, C4 = 14, C5 = 7), against "three or four each". C4 is under-counted threefold and is
> the one concept with no type-shaped fix. What does not survive is the sentence at the end of
> this section, *"C1, C2 and C3 are already Rust"*. **That is a category error: it reads
> *written in Rust* as *has a type*.** The measurement that decides it — `C3` counted the
> crate's type declarations: **46 types, zero path domains, zero policy dispositions.**
> `FsPolicy`, the struct F0 names as where C1 lives, was five `Vec<String>`, so a policy
> pattern, a home-relative entry, a workdir-relative entry and a resolved absolute path were
> all the same type — which is F0-C1's own definition of the bug, in the struct F0 offered as
> the answer to it.
>
> The forgery experiment is the sharpest form, run twice independently (`B5-1`, `C3`) and
> reproduced by `D1`: `SandboxReady::establish(..).unwrap_or(SandboxReady)` **compiled, with no
> new warnings and 328/328 green**, and launched the agent with the bind failed; the identical
> forgery against `netallow::Entry`, 1,200 lines away in the same crate, was **`error[E0451]:
> fields … are private`**. One module boundary and one private field separate a control the
> compiler enforces from a control that is a comment. **So the correct split is not `C1–C3` vs
> `C4–C5`. It is *has a type* versus *does not*.**
>
> **And several of the types this section asked for have since been built** (round 3's fix
> batches, `d7f3f84`…`8c4109c`), which makes the track smaller than the paragraphs below
> assume:
>
> | concept | what now exists | where |
> |---|---|---|
> | C1 | **`Floor`** with private `hidden`/`masked` — the first path domain in the crate, and the split is the type, not a convention | `settings.rs` |
> | C2 | **`Disposition`** (`Applied` / `Redundant` / `CoveredByFloor` / `Refused`) with `PolicyEntry`. Its own doc comment says it is *"`C2` — one disposition per input line — as a type rather than a `bool` inside a `retain`"*. Measured before it: **21 of 27** entries in the shipped config produced no bwrap argument and no line of output, and the 2 that did speak were wrong | `settings.rs` |
> | C3 | **`mod witness`** — the three witnesses moved into a module with private fields, so the two-word forgery no longer compiles, plus a test that refuses a fourth `pub` item, any trait `impl`, `Default` and `Deserialize`. **`Readiness`** replaced the broker's dead/silent/ready bool pair | `bin/husk-slurm-wrapper.rs` |
> | C4 | **`SpoolArtifact`** — one table of the names husk writes into a spool, with the `gc_while_live` exception carried *on the entry* instead of a second literal in `spool.rs` that had drifted in both directions | `lib.rs` |
> | C5 | **`InheritedEgress`** — the step's inherited egress as a value with one construction site rather than four `var()` reads | `step.rs` |
>
> That is C1 and C2 existing *somewhere* for the first time, and C3's type made real rather
> than nominal. It is not the sweep: `FsPolicy`'s other fields, the guard, the Python stubs and
> the C wrapper still hold live instances. **Track F is larger in concept work and smaller in
> rewrite work than this section states**, and its prior art is **two shipping, tested modules**
> — `netallow.rs` and `netproxy.rs`, both new since `v0.4`, ~670 non-blank non-comment
> production lines between them at `8c4109c` (`E1` sized the same prior art at ~390 at an
> earlier commit; the figure is not reproducible here and the point does not rest on it) —
> **plus the five types above. Not a rewrite.**

**C1 — a configured path is not a string; it is a path in a named domain.**
Absolute, home-relative, workdir-relative, unresolvable — and the same string means different
things to the login cage and the compute cage.

| instance | what went wrong |
|---|---|
| `~/.claude/projects` (2026-08-10) | refused on compute *with the wrong reason* — the operator was told to copy it to scratch |
| F22 relative `denyWrite` | honoured on login, silently dropped on compute; a deny that failed **open** |
| `.git/hooks` leaf shape | checked one level too shallow |
| `--output logs/x.out` | relative resolution had to be added by hand, per call site |

`normalize_abs` returns `Option<String>`, and `path_under_floor` turns `None` into `true`. So
"I cannot resolve this" and "this is under a hidden home" become the same bool — which is
exactly why the `~` entry got an error message about scratch directories. **Two different facts
must not collapse into one bool.**

**C2 — every input line gets exactly one stated disposition.**
Not "applied or not". `Applied | Refused{reason} | NotApplicableHere{cage, why}`, total, and
enumerable. F3 already wants this for the sbatch registry (*"every option claimed by exactly
one rule"*); it is the same property for filesystem-policy entries, `#SBATCH` directives and
`Class::Ignored`. Instances: symlinked carve-outs dropped in silence (F20), non-existent
carve-outs dropped in silence, the `~` entry refused with a wrong reason, directives validated
and then not re-emitted (the `#SBATCH` CRITICAL). **This makes "silently dropped" and "dropped
with a plausible wrong reason" both unrepresentable** — and the second one is the more
dangerous, because it sends the operator confidently in the wrong direction (`P13`).

**C3 — a check is evidence only where and when it was taken.**
The two-machine TOCTOU, generalised. Instances: A1's CRITICAL (right check, wrong *time*), the
`.git` shape stat'd on login and acted on at compute, the ghost `/dev/null` placeholders that
appear during any login-cage Bash command, `kill -0` succeeding on a zombie. The shipped answer
is witness types (`SandboxReady`, `BrokerReady`); the generalisation is that a *checked path*
should carry its provenance too, rather than decaying to a `String` the moment it is validated.
**Corollary, and the useful half: if the witness cannot be minted where it is consumed, the
check belongs there instead.** That single rule decides every row of F2's compute-node table.

**C4 — when a comment names a class, the code must iterate the class.**
This project's signature defect, now four for four: `.git` where the comment said auto-exec
directories; "the job" where the comment said the task (array bodies); a nested `if` with no
`else` where the comment described the failure path; `/dev/nvidia0…7` hardcoded to eight where
the comment said GPUs. Plus my own roadmap claiming LUMI was blocked on F2. The fix is
structural, not vigilance: **derive from one table and assert the table is the only source.**

**C5 — the owner of a resource is its LAST user, not its first.**
Instances: an array's staged body deleted by task 1 while tasks 2..N still needed it, spool
leaks on the abnormal-exit path, the preemption cleanup leak, `trap` coverage that is correct
only while maintained. This is B1's resource-lifecycle criterion, and it is the one concept
that genuinely *is* blocked on F2 — `Drop` runs on every path including unwind, and no
discipline about `trap` gets there. **Both halves of that sentence are corrected below**: only
the *shell* half is blocked on F2, and `Drop` does **not** run on every path in the shipped
binary — see the struck paragraph at the end of this section and F2's narrowed table row.

**What is actually blocked by the shell, and what is not.** ~~Only C4 and C5 need F2. C1, C2
and C3 are already Rust (`settings.rs`, `sbatch.rs`, `spool.rs`) and could be done without
touching the guard at all.~~ **Struck 2026-09-01 — wrong in both directions** (`C3`, `E1`,
`F1`; see the correction at the top of F0):

- **C1–C3 are not "done without touching the guard."** They have live instances in the
  generated shell, in the Python stubs and in the C wrapper — three languages the guard
  rewrite does not reach either way.
- **C5's Rust half needs no guard rewrite at all.** **Two `impl Drop` in the entire crate** —
  `netproxy::TunnelSlot` and `BrokerHandle`, re-counted at `8c4109c`, still two — against
  **17 hand-placed releases whose failure is discarded**. That half could land today in
  `spool.rs`, `main.rs`, `step.rs`, `lib.rs`. Only the *shell* half is blocked on F2.
- **The order inside the type work is the reverse of the one this list implies.** `C3 §7` gives
  the mechanism: a C1 fix does not fix C2, while building the disposition ledger (C2) surfaces
  every C1 instance for free. So **C2 before C1**.

What is true and unchanged: the work waits for the release because refactoring now discards
the hardware verification and sends reviewers at a ghost — not because the bash blocks it.

### F1 — split `guard.rs` out of `policy.rs`

`policy.rs` does two unrelated jobs that share a name and nothing else: a **gate** (decide what
is permitted) and a **code generator** (emit the guard). Separating them halves the file and
gives the guard a defined input type instead of eight captured locals.

Mechanical, and **verifiable byte-for-byte against `tests/golden/guard-net-{on,off}.sh`** —
"prove the bytes are identical." Do it FIRST, because F2 retires that oracle: a program emits
no bytes to compare. This is the last moment the goldens can check a refactor of this code.

**Two corrections, 2026-09-01 (`B1`, `B2 §6`, `C2`, adjudicated by `F1 §4.1`).**

1. **The reason is right and the scope is too narrow.** The guard goldens embed `bwrap_args`'
   complete output verbatim, and `settings.rs` — the file that emits the entire compute-cage
   mount table, and which has gone **1,241 → 6,134 lines since `v0.4`** (measured at
   `8c4109c`; `F1` said `+2,263`, which was already stale when it was written) — **had zero
   tests that executed anything**. So F2
   retires the mount table's only end-to-end oracle at the same moment it retires the guard's,
   for a file this step does not mention. **Ruling: `R1`'s `bwrap` harness is a named
   precondition of F2**, not a nice-to-have after it. One number bounded how much of the green
   was real when `C2` measured it: **18 of 328 tests executed the artefact**, and no test in
   the repository had ever run `bwrap`. **Partly overtaken, verified at `8c4109c`:**
   `settings.rs` now has **three tests that run a real `bwrap` on the emitted argument list**
   (first in `a37caa4`, factored into a helper and extended in `c7f888c` closing `M-1`). **Two
   of the three** go through a `bwrap_verdict` helper that *says out loud* when it
   skips — *"SKIPPED THE ONLY REAL ORACLE … which is exactly how `M` shipped with `M-1` in
   it."* **The third does not**: `settings.rs:3413` is an inline duplicate of the same probe
   whose skip arm is a bare `if matches!(…)` with no `else`, so on a machine without user
   namespaces it goes green having tested nothing — the exact defect `bwrap_verdict`'s message
   exists to prevent, sitting eighteen lines above it. That is a live `P8` instance and it is in
   `LOW-BACKLOG.md`. So: the harness exists in one file, for one function, and in two of the
   three places it is used. It is not the harness F2 needs, which has to cover
   `compute_bwrap_args` as a whole, but it is the pattern and the precedent, and the next step
   is widening it rather than building it.
2. **"Halves the file" is optimistic in the direction that matters.** `B1` performed the move
   and measured a **prod-only** split leaving `policy.rs` at **3,687 of 4,781 lines**, because
   the bulk of the file is `mod tests` and 24 of its then-81 tests (1,224 lines) are *guard*
   tests that a prod-only split strands.
   **Re-measured at `8c4109c`, because `B1`'s absolute numbers no longer hold and the ratio
   got worse:** `policy.rs` is **6,894 lines**, `mod tests` starts at `:2494`, so prod is 2,493
   and tests are **4,401 — 64% of the file** — across **97** tests. Moving `B1`'s ~1,094 prod
   lines out now leaves ~5,800, which is no longer *the* largest file (`settings.rs` is 6,134)
   but is still the second, and still four fifths of what we started with. The conclusion is
   unchanged and is the point: **prod and tests move together, or the split buys less than it
   costs.**

### F2 — the guard becomes a program

**Decided 2026-08-06: the job guard should be compiled Rust, not generated bash.** This
supersedes the "deferred typed shell builder" that `review-v0.5/B5-guard-generation.md` left
open — that option is now judged to be aimed at the wrong bug class.

**Why the builder is not enough.** B5's own verdict: the emitted shell is auditable, the
generator is not, and *4 of 7 shipped guard bugs were quoting, interpolation or scoping*. But
it also found that a builder "would not have caught the two most severe findings, which are
semantic, not syntactic." 2026-08-06 confirmed that from the other direction: srun hung in
five or six jobs because a nested `if` had no `else` and a backgrounded child was never
checked. Both semantic. A builder that owns quoting would have shipped both.

**Why a binary, specifically.** Not for speed and not for elegance — for the acquisition-side
twin of [`PRINCIPLES.md` P6](doc/PRINCIPLES.md): *make the unverified state unrepresentable*.
husk already does this on the login side, where `SandboxReady` (`husk-slurm-wrapper.rs`) can
only be minted by a verified bind, so the agent exec cannot be reached without proof. The
compute side has no such thing, because a shell cannot carry a proof. In Rust the guard's
sharp edges become types:

| today, in shell | as a program |
|---|---|
| `mkdir -p … \|\| _husk_spool=` — error becomes an empty string | a `Result` that must be handled |
| broker started, never checked; `if` with no `else` | entering the cage needs a `StepBrokerReady` witness |
| the rank's socat relay, backgrounded then `exec`'d past, with `>/dev/null 2>&1` | same witness, one level down — **measured as a real flake on Santis 2026-08-11**: `steps.egress` failed, then passed on re-run, with no code on that path changed |
| `trap` per exit path, correct only while maintained | `Drop` — **narrowed 2026-09-01: RAII *plus a reaper*.** The row used to say "runs on every path including unwind". `Cargo.toml:27` sets `panic = "abort"` on the release profile, and `B8-9` measured that cargo does **not** apply it to the test profile — so a test proving a `Drop` fires on the panic path proves it for a strategy the shipped binary does not have. In the shipped binary a panic aborts and **no `Drop` runs**; and on a partition husk *forces* to be preemptible, `SIGKILL` is the normal exit, not an edge case. RAII is still the right move and is still most of the win — it just cannot be the whole argument |
| a resource released in one branch and not another | acquiring *is* registering the release |

**A whole category of deferred work becomes cheap, and that is the strongest argument for
F2.** Several things must be decided **on the compute node**, because the login node does not
know the answer — login ≠ compute. Today each one is either shell-by-necessity or a submit-time
guess with a two-machine race in it. As a program they are all just Rust running in the right
place:

| deferred item | why it must be decided on the node | today |
|---|---|---|
| **`.git` / `.hg` mask shapes** | the login cage creates and destroys `/dev/null` placeholders on *every Bash command*, so a path's shape changes under a queued job | read at SUBMIT time; a shape that changes in between still kills the cage in bwrap setup — cost 3 of 4 concurrent jobs (A3/A5/A8) and a whole project directory (2026-08-09) |
| **GPU node COUNT** | `/dev/nvidia0…7` is a static list of eight; a bigger node silently gets half | needs enumeration, not more entries — the one real glob |
| **`/dev/dri`** | present with any integrated graphics, so it must be bound only where it is the compute path | `-try` cannot express "only if `/dev/kfd` exists" |
| **credential-socket masks** | `--tmpfs DEST` dies if DEST is absent, and again if two entries resolve to the same dir | already resolved at run time, in generated shell — the pattern works, and is the thing F2 replaces |

The `.git` one is the sharpest, because it is the only one that is currently *wrong* rather
than merely limited: `settings.rs` reads the shape with `symlink_metadata` on the login node
and emits static bwrap arguments a compute node acts on later. The 2026-08-09 fix made husk
mask what is actually there at submit time, which closes the persistent case and leaves the
race. **Closing the race means resolving the shape where bwrap runs**, and in a program that is
the same `match` moved, not a new mechanism.

**The GPU and fabric lists are NOT blocked on F2** — that was an overstatement, corrected
2026-08-09. Both are bound with `--dev-bind-try`, which skips a device the node does not have,
so listing AMD's `/dev/kfd` and `/dev/infiniband` costs nothing on a Slingshot/NVIDIA machine.
Their absence was an omission, not a design limit, and both are listed now.

What genuinely wants run-time resolution is narrower: **`/dev/nvidia0…7` is hardcoded to
eight**, so a node with more GPUs silently gets half — that is the real glob argument, and it
is about node counts rather than portability. And **`/dev/dri` is conditional**: it exists on
anything with integrated graphics, so binding it unconditionally would widen the device surface
on machines with no use for it, and `-try` cannot express "only if `/dev/kfd` exists".

**The feasibility question is settled and was never actually asked.** No document anywhere
argues the guard must be bash. The recorded constraint is different: late-binding facts (GPU
devices, MUNGE sockets, credential dirs) can only be resolved on the compute node — which is
why guard *logic* exists, not why it is *shell*. And the binary is already there: the same
artifact runs on compute nodes as `--step-broker`, which is how the step pair works at all.
Observed on Balfrin 2026-08-06: `/users/hpcuser/.local/bin/husk-slurm-broker --net-proxy`
running on nid001231. SLURM needs a script as the entry point; that script can be one `exec`
line. There is also a recorded decision *against* adding more compute-side guard shell, on
fragility grounds — which points the same way.

**The oracle changes, and this is the part to get right before starting.** The goldens
(`tests/golden/guard-net-{on,off}.sh`) were built specifically to make this rewrite checkable
— "prove the bytes are identical" instead of "hope the refactor was faithful". **That works
for a builder and not for a binary**, which emits no bytes to compare. A Rust guard needs a
*behavioural* oracle: drive both implementations through the same scenarios and compare what
is observable — mount table, processes, exit status, messages, what survives cleanup. Building
that harness is the first deliverable, not the second; without it this is the act of faith the
goldens exist to prevent.

**Start with `rank.rs`, not `wrap_script` (`B3 §8`, added 2026-09-01).** The roadmap does not
record that there is a cheap first slice, and there is. `rank.rs` (1,553 lines, 30 tests) has
**no byte-golden and needs none**: **six** of its tests *execute* the generated shell — `B3`
counted three of 26, and re-counted at `8c4109c` it is six of 30 — **two of them under both
`bash` and `dash`**, one with hostile symlinked paths. Rewriting it therefore **expires no
oracle and has no split-first precondition** — the exact opposite shape to `guard.rs`, whose
whole difficulty is that its only oracle is the bytes. It is a real slice of the guard, in the
right language, with a behavioural oracle already in place, and it is where the pattern gets
proved before the expensive half.

### F3 — `decide` becomes a sequence of named rules

A different argument from F2's, and worth keeping distinct: this one is not about types or
RAII, it is about **making a property checkable that is currently only hoped for**.

454 lines of inline conditionals decide, among other things, which options reach sbatch. The
`#SBATCH` CRITICAL was an option that no rule re-emitted, and nothing could have told you that
by reading — there is no place where "every option is decided by exactly once rule" is
expressible. As a sequence of named rules over a request, it becomes a test: enumerate the
registry, assert each entry is claimed by exactly one rule, fail on an option that is claimed
by none or by two.

That directly retires the shape of F13/F14/F24/F26/F27 and the `#SBATCH` outage, none of which
were quoting bugs and none of which F2 would catch either.

### Sequencing for the whole track

**RE-ORDERED 2026-09-01 (`E1 §5`, `F1 §4.3`). The track's first step is now its fourth.** Two
oracles come first, and the argument for putting them there is that they are **additive**: they
expire nothing, change no shipped byte, and are what turn F1→F2 from a one-way door into an
ordinary refactor. They are also where the round's whole yield is concentrated — `C2` measured
**14 of 14** neuterings of a production *predicate* caught by the suite against **9 of 22**
disconnections of that predicate's *call site* invisible to all 328 tests, and `C1` measured
**63 of 109** entries in the shipped `settings.json` deletable with the suite green, split
exactly on whether a set-comparison assert exists. More unit tests and more list entries do not
help; one harness that runs the assembly and one that compares sets do.

| new step | content | today |
|---|---|---|
| **F−1** | **The two oracles.** ~~Run `cargo test` from the release gate at all~~ — **done, verified at `8c4109c`**: `4f1c9ed` made `make-release.sh:379` gate the tarball on `build-release.sh --test-only` (`B8-5`; before it, the broker could be built, bundled, checksummed and shipped with a red suite), and there is still no CI and no `.github/`, so that gate is the only one. What remains: run the emitted **guard** under `bash`, and widen the three real-`bwrap` tests in `settings.rs` to the whole mount table | **absent from this file** |
| **F0′** | Give the existing types their privacy and sweep the pattern backwards — **largely done**: `mod witness` landed, and `Floor`/`Disposition`/`SpoolArtifact`/`InheritedEgress`/`Readiness` with it | F0, reframed |
| **F1′** | **The type work, in Rust, guard untouched.** The disposition ledger **before** the path domains, then the rest of C5's Rust half (`OwnedDir`, `OwnedSocket`; `SpoolArtifact` has landed) — none of it blocked on F2 | "C1–C3 already Rust" |
| **F2′** | **Split**, prod **and** its 24 guard tests, then `settings.rs` | F1 above |
| **F3′** | **The guard becomes a program — starting with `rank.rs`** | F2 above |
| **F4′** | `decide` as named rules | F3 above |

Not in the track and not blocked by it: **install durability** (`D1` ranks it the highest single
severity in the round's set) and **the instruments** — the first is post-tag and first, the
second is before the *second* hardware round.

**After v0.5 ships.** The guard is hardware-verified at 91/0/0 on Balfrin and 92/0/1 on Santis
at `7505d67`, and the pen-test briefs were refreshed against exactly this code; refactoring now
discards that verification and sends reviewers at a ghost. F2 likely lands with or before 6a,
since both are "husk owns this layer rather than driving someone else's". F1 is cheap and
should not wait long after the release — it is the one step whose oracle expires.

---

## Cross-cutting — profiles as first-class

Today site knowledge is scattered across install flags, Rust constants, env vars and a shipped
JSON; agent knowledge is scattered similarly, and some of it (the agent's state directory) does
not exist as a concept at all. The proposal is to make both **data with a schema**, so the cage
becomes a function of `(site, agent, operator policy, workdir)` rather than of constants —
which also makes it testable against a synthetic LUMI without a LUMI.

**Three kinds of data, and naming the third is what stops profiles becoming a dumping ground:**

- **SiteProfile** — devices, scheduler, module system, site path vars, socket path budget.
  First draft already exists: the `[site]` block `husk-site-check.sh` emits.
- **AgentProfile** — state directory, egress needs, config paths, mediated binaries. This is
  [`sandbox-interface.md §5`](doc/sandbox-interface.md) made real, and for Claude Code it now
  exists: [`doc/agent-profile-claude-code.md`](doc/agent-profile-claude-code.md).
- **husk's own catalogues** — auto-exec surfaces, blocked syscalls, the sbatch option registry.
  These vary with the *ecosystem*, not with site or agent, and must ship with husk: `.Rprofile`
  executes everywhere, and re-discovering that per site would be strictly worse.

**The AgentProfile is no longer hypothetical — 2026-08-10 measured its first fields.** Widening
the tool allowlist (C0.1) required knowing, for Claude Code specifically: which tools have
effects outside husk's two cages, where the agent keeps state, and which of its own features
reach off-machine. That list *is* an AgentProfile, and **it is also the specification husk needs
at 6a**, where husk wraps the CLI itself rather than driving it — the same facts, used to build
an outer cage instead of to choose a flag.

`AgentProfile.state_dir` now has three bugs behind it rather than a symmetry argument, all the
same shape — *the harness puts something load-bearing under `.claude`, and husk's policy hides
it*:

| the harness puts | husk does | outcome |
|---|---|---|
| agent memory in `~/.claude/projects` | `denyRead: /users` | masked; restored by an `allowWrite` entry, and refused by the COMPUTE cage with a misleading message |
| skills in `~/.claude/skills` | `denyRead: /users` | invisible — and husk installs its own skill there and points the banner at it |
| worktrees in `<project>/.claude/worktrees` | compute-side `AUTO_EXEC_DIRS` tmpfs | harmless *today* — the PROJECT `.claude` is a different object from the masked HOME one: see below |

**The worktree case shows why the profile must model the directory rather than mask it — and
why `~/.claude` and `<project>/.claude` are two different objects.** The HOME copy is invisible
on the server: `denyRead: /users` tmpfs-masks every home, so `~/.claude/projects` and
`~/.claude/skills` do not exist inside the cage at all. The PROJECT copy is not masked; the
vendor write-denies `.claude/commands` and `.claude/agents` (`getDangerousDirectories()`) plus
`.claude/settings*` via husk's `denyWrite`, and nothing denies the rest.

**What makes that survivable is the same asymmetry that caused the two-door problem, running in
our favour:** host-side features read the *real* filesystem, so the mask does not apply to them.
Skill loading and memory injection happen in the uncaged agent process and work despite the
tmpfs; only paths reached through *Bash* meet the cage. That is why `Skill` in the allowlist
genuinely fixes the skill pointer even though `cat ~/.claude/skills/husk/SKILL.md` still fails,
and why agent memory needed an `allowWrite` carve-out specifically for the Bash write path.

Worktrees land in the PROJECT copy (`<project>/.claude/worktrees/`), which is why swarms on the
login node work untouched. Carving `worktrees` out of the COMPUTE mask would still be strictly
harmful: a worktree is a fresh project root, so unmasking it exposes an agent-writable
`<worktree>/.claude/settings.json` — **the confined side supplying its own boundary, F17** — for
a capability no job needs. Note also that the vendor's write-deny on `.claude/agents` does *not*
follow into a worktree root, which is a second reason not to open one.

What that leaves for the profile is the real statement: **auto-exec masking applies per project
root, and worktrees create new roots at run time.** Enumerating them is a compute-node question
(`F2`), not a submit-time one — the same category as the `.git` shape.

*Note the tangle this exposes:* `AUTO_EXEC_DIRS` currently mixes axes — `.claude` is
agent-specific, `.vscode`/`.idea` are ecosystem. Invisible today, obvious under the split.

**The discipline, mirroring L1's entry bar:** *a field enters a profile when a **second** site
or agent disagrees about it.* Until then it stays a constant. On today's evidence that admits
four fields, not a rewrite — `GPU_DEVICES` (LUMI is AMD), `SUBMIT_ENV_ALLOW_SITE` (Santis ≠
Balfrin), `DEFAULT_PARTITION` (Santis has no preemptible), `FABRIC_DEVICES` (on checking
Euler) — plus one *new* `AgentProfile` field driven by a real bug rather than by symmetry: the
state directory.

**Warning: a profile is a policy input.** It inherits `P2` (must live where the agent cannot
write it) and `P8` (must join the `SETTINGS_SOURCES ↔ denyWrite` pairing test). Get that wrong
and this has built a fresh way for the confined side to supply its own boundary — which is
F17, the bug that started the whole write-root saga.

*Migration:* start from the site-check's schema → move the four earned constants → add
`AgentProfile.state_dir` and fix memory with it → leave everything else alone until a second
instance appears.

---

## uenv as the third allowlist — what is actually left

`~/.husk/config.json` already accepts and validates a `uenvs` set, label-only. What is missing
is the **resolver**, not a security prerequisite:

1. **`policy.rs` resolution** — take the requested label, match it against `session.allowed_uenvs`,
   re-emit husk's own copy of the entry, refuse an unlisted one naming the set. Identical in
   shape to the partition and account resolvers; the third instance, so **factor it** rather
   than writing it again (`resolve_against_operator_set`).

   **Read from the uenv source, 2026-08-14, and it is not what the prose suggested:**
   - `--uenv` is `<file>[:mount-point][,<file:mount-point>]*` — **a comma-separated LIST**, and
     each element may carry a mount point. So the resolver faces a list, not a value. Decide
     deliberately: resolve each element against the set (a workflow legitimately wants two
     images), or refuse multiples as `--partition` does. The mount point is a second field the
     job would be choosing — pin it.
   - `--view` is `[uenv:]view-name[,<uenv:view-name>]*` — also a list, and each element may be
     qualified by uenv name.
   - **`--no-default-view` exists**, and is a third member of this family. It is not in husk's
     registry, so it is refused by default-deny today — correct, and worth knowing rather than
     rediscovering when someone reports that it does not work.
   - `--uenv-passthrough` likewise absent, likewise refused.
2. **`--view`: DECIDED 2026-08-14 — allow all views of an allowed image.** Christoph's domain
   call, and the reasoning is the part to keep: *views differ in HOW software is loaded, not in
   WHAT the image contains.* So a view is not a content choice, and constraining it would buy
   nothing while making the config harder to write. `--uenv` is the boundary; `--view` is a
   selector inside it.
3. **Harden how the guard reaches its own tools** — *should-do, and NOT a condition on 1 or 2.*
   Measured 2026-08-14: `bwrap` and `husk-slurm-broker` are both dynamically linked, the guard
   resolves `bwrap` and `seccomp-wrapper` through `PATH`, and it scrubs no `LD_*`. A uenv view
   therefore influences both which binary builds the cage and which libraries it loads — and
   the library lever is the likelier one, because **every** view sets `LD_LIBRARY_PATH` by
   design while few images would carry a `bwrap`.

   **This is the situation TODAY**, with a login-side uenv: husk already execs `bwrap` under
   whatever the operator's view set. The allowlist does not create it and must not be blocked
   on it — that mistake was already made once on this page. It is a pre-existing robustness
   gap that the allowlist makes more visible.

   The fix has one subtlety worth writing down before someone starts: the scrub must be
   **scoped to the cage-builders**. The workload *needs* the view's `LD_LIBRARY_PATH` to run
   the software the uenv exists for, so the shape is save → exec `bwrap` with `LD_*` cleared →
   `--setenv` the saved values back inside the cage. A blanket scrub breaks every uenv job.

**The correction worth keeping (2026-08-14):** this was written up as "the allowlist cannot ship
until the guard stops using `PATH`", and that was wrong — Christoph caught it by asking the
obvious question, *the job can only choose uenvs the operator supplied, so what is the escape?*
There isn't one. The lesson is about how the mistake was made: an attack was described against
a design (agent names an image) that the design already forbids, and the conclusion outlived the
premise. **Check that the threat still applies to the thing being built, not to the thing it
replaced.**

## Credentials the agent uses but never holds

**The problem husk has today.** Any credential a job needs must be readable by the job. husk
masks credential *files* by name, which protects the ones nobody asked for, and does nothing
for the one the work actually requires — a git token, an API key. Once the network opens, a
token the agent can read is a token the agent can send. `AV8`, one layer up.

**What Anthropic do, and why husk should not simply copy it.** Their proxy holds credentials
and injects them per-domain (`sandbox-config.ts`, defaulting to `network.allowedDomains`), so
the agent never sees the secret. It is the right idea — and for HTTPS it **requires terminating
TLS**, because you cannot add a header to an encrypted stream. That drags in a MITM CA in the
sandbox trust store, a proxy that reads every byte in plaintext, and the multi-consumer
hostname problem that produced their `#470`. husk is CONNECT-only precisely to avoid that
class, and `srt-watch.md` records the evidence that the choice was right. Copying the feature
would spend exactly the surface we just observed them paying for.

**Two husk-shaped answers instead, in increasing cost.**

### 1. Scoped, short-lived credentials from the broker

A `git-credential-husk` helper inside the cage that asks the **out-of-cage broker** over the
existing spool — the `sbatch` stub's shape, one protocol over. The broker decides scope and
returns a narrowly-scoped, short-lived token (a GitHub App installation token for one org, an
hour's validity).

Honest about what it does *not* do: the token reaches the cage, so the agent can read it. What
changes is the **blast radius** — the secret is no longer a long-lived operator credential but
one that expires and can only touch what the operator scoped it to. That is the answer to *"all
of GitHub or none"* which the network layer structurally cannot give: **scope the credential,
not the route.** Cheap, and it composes with the allowlist rather than replacing it.

### 2. A git broker

Mediate `git` the way `sbatch` is mediated: the operation runs **outside** the cage, so the
credential never enters it at all, and the org restriction becomes a property of the trusted
side rather than a pattern match on bytes. Strictly better and considerably more work — git has
many verbs, and the surface is the same construct-and-re-emit problem the sbatch registry
solved.

**The criterion for choosing.** Option 1 bounds a leak; option 2 prevents one. Take 2 only when
a credential exists that a one-hour scoped token cannot make safe — otherwise 1 buys most of
the value for a fraction of the work, and it is the same trusted-broker machinery husk already
runs.

**The through-line, which is why this is not a feature request but the same axiom again:** the
credential question is an *authorization* question, and husk's answer everywhere else is to
move the decision outside the cage. Path-filtering `github.com/MeteoSwiss/*` fails because it
tries to answer an authorization question at the network layer, where the information does not
exist — the path is inside TLS, and git over SSH has no path at all.

## The config file needs a longer discussion — Christoph, 2026-08-18

`~/.husk/config.json` was added in a day to solve one problem (install-time is the wrong
lifetime for an account list) and has since grown a per-system dimension, a schema version and
three allowlists. That is the point at which a config format stops being an implementation
detail. **Open before it grows further:**

- **Is one file the right shape at all?** It currently mixes *policy* (which accounts may be
  billed) with what will become *site facts* (which partitions exist). The ROADMAP's
  `SiteProfile` / `AgentProfile` split says those are different rates of change, and the config
  file is quietly becoming a fourth thing beside them.
- **What else moves in?** The env allowlist, the network allowlist and the credential list are
  all operator policy living in three other places today (`HUSK_SUBMIT_ENV_ALLOW`, the vendor's
  `settings.json`, `credentials.files`). Every one of them is a candidate, and every move is a
  `P8` pairing to maintain.
- **The three legacy paths should go.** Flags, `~/.local/lib/husk/slurm-*` plus the env vars
  the launcher exports from them, and the config file. The precedence is coherent and
  documented, but it is three lists where there should be one — deliberate removal after every
  install has a config file, and the kind of cleanup that quietly never happens unless written
  down.
- **Per-system selection needs a second instance before it generalises.** Today it is
  hostname-keyed with no merge, which is right for twins sharing a home. A site with three
  systems and mostly-shared policy would want inheritance, and inheritance is exactly where
  config systems go wrong — so wait for the second instance rather than designing for it.


## Smaller items

- **The check should stop flagging its own operator.** `between-runs-check.sh` watches `$HOME`,
  and the findings directory has to live there (it is the only place a reviewer cannot read), so
  every artifact copy reads as drift. Same for a root-owned site indexer that touches `$HOME` on a fixed cadence.
  Both belong in the known-churn set. **Oracle change — after the round**, never mid-instrument:
  A5 and A1 must be judged by the same check.
- **Egress `socat` survives an abnormal session exit.** Three orphans found on one login node,
  6–10 days old, `PPID 1`, sockets alive with zero peers; a fourth on another node. A session
  that dies hard leaves its relay behind and nothing reaps it — the same resource-lifecycle
  shape husk already fixed for spools on the abnormal-exit path, one process over (`B1`).

- **The tool gate — a `PreToolUse` hook, AFTER v0.5.** Deferred deliberately 2026-08-13: it is
  new machinery on the exact surface the pen test is aimed at, and the deny list already covers
  every tool we know of. Its unique value is the one thing `permissions.deny` structurally
  cannot do — **refuse a tool that does not exist yet**, which is the `P5` hole that opens on
  every `/compact` (see `constraints.md` C0.1).

  What is already settled, so it does not need re-deriving:
  - **A hook works and survives re-entry.** Measured: `PreToolUse` with `matcher: "*"` and
    exit 2 blocks the call, the reason reaches the agent in husk's words, and it holds across
    `--continue` where `--tools` does not.
  - **It fails OPEN.** A missing or broken hook script lets the call through — only the
    advisory permission layer remains. So it complements `permissions.deny` (which removes the
    tool and cannot fail that way) rather than replacing it. Script goes in
    `~/.local/lib/husk/`, already `denyWrite` and inside the masked home.
  - **It must parse JSON properly, and a shell version must not ship.** The hook's stdin
    carries `cwd` *before* `tool_name`, a directory name may contain a quote, and the agent
    can create directories: `mkdir '"tool_name":"Bash"'` and `cd` into it makes a naive
    first-match parse read `Bash` for **every** tool. The default-deny gate becomes
    allow-everything, silently, from inside the cage. Two parsers, one input, the cheap one
    wrong — F13/F14 in a new costume.
  - **Cost, measured on the laptop:** shell hook 1.55 ms/call, python 17.1 ms, versus 5.69 ms
    for the `bwrap` spawn every Bash call already pays. So the right shape is a subcommand of
    the binary husk already installs (`--tool-gate`), which buys a real `serde_json` parse for
    roughly the cost of a bare fork. **Re-measure on Lustre before committing.**


- **`sbatch --wait`, by polling in the STUB — low priority.** `--wait` is `Class::Rejected`
  today (`sbatch.rs`) because it blocks until the job completes, and the broker is
  single-threaded: one `--wait` wedges it for the job's whole runtime, `scancel` included, so
  the agent can no longer stop the job that did it. The refusal names the flag and gives the
  substitute, which is why this is low priority — the workaround is already in the agent's
  hands.

  **"Make the broker multi-threaded" was considered and REJECTED (2026-08-29), twice over.**
  It does not fix the DoS: a `--wait` holds its worker for hours, so N of them exhaust any
  bounded pool and the broker is wedged again — the limit moves, it does not go away. Fixing
  it properly means the wait occupies no worker at all (an event loop with registered
  waiters), which is a redesign, not a flag. And concurrency costs the property the
  containment rests on: single-threaded, one request at a time, is *why* every check in the
  broker is still true when it acts on it. Go concurrent and each one becomes a TOCTOU
  question — this project's dominant bug class, with a mild instance already recorded
  (`BROKER.md`, the queue-wait window). One flag is not worth trading a design that is hard
  to get wrong for one that is hard to get right.

  **The wait belongs on the caged side, where husk already puts it.** `step.rs` (and
  `srun-stub.test.sh`): *"The stub has exactly one wait, and it is unbounded — correctly,
  because a step legitimately runs for hours and killing a simulation on a wall clock would
  be worse than waiting."* The stub blocks; the broker answers and returns. So this is an existing
  pattern applied, not a new one invented — and the implementation is exactly what the
  refusal message already tells the caller to do by hand:

  1. submit through the broker as today — job id back immediately, broker untouched;
  2. poll `sacct -j <id> -o State,ExitCode` over the **existing** Tier-1 query path
     (`lib.rs` already brokers `squeue`/`sacct`/`sstat`);
  3. exit with the job's exit code.

  **The srun precedent transfers only halfway, and the difference decides the design.**
  That unbounded wait lives in the COMPUTE cage, in a job body, with no harness above it.
  `sbatch --wait` would wait in the LOGIN cage, inside the agent's own Bash tool call —
  which is bounded (`HUSK_SLURM_TIMEOUT` defaults to 120 s in the stub; the tool itself caps
  at 600 s). An unbounded wait there is killed at ≤10 min, leaving a running job and a
  truncated shell: the same broken control-flow contract the rejection exists to prevent,
  only later. So the stub's wait must be explicitly bounded and, on hitting the bound, print
  the job id with the poll command and exit NON-ZERO. That still satisfies the contract that
  matters — `&& collect_results` must never run against a job that has not finished — while
  being honest that husk waited as long as it could rather than pretending the job ended.

  Things to get right beyond that. Map every non-`COMPLETED` terminal state (`CANCELLED`,
  `TIMEOUT`, `NODE_FAIL`, `OUT_OF_MEMORY`) to a non-zero exit, as real sbatch does — that
  step is the whole point, because `sbatch --wait && collect_results` is the idiom and only
  the exit code makes the `&&` mean anything. **`PREEMPTED`/`REQUEUED` is neither terminal
  nor a failure, and under husk it is the NORMAL case** — husk forces the preemptible
  partition, and `lib.rs` already records that a requeued job re-running its script is
  routine here. A poll that scores it either way is wrong; it has to keep waiting. Likewise
  `sacct` depends on slurmdbd and lags submission, so "no row yet" is not a terminal state.
  Back the poll off (~2s to ~30s) so several waiting shells cannot congest a serialized
  broker; unlike a blocking wait this degrades instead of wedging. And honour the lesson
  `step.rs` paid for: one wait must not answer two questions at once (*has it started* vs
  *has it finished*) — that conflation is what made the srun stub hang.

- **Detonate a real `sbatch` inside a compute job — the missing enforcement test.**
  Surfaced by review 2026-08-29: there is **no executable test anywhere in this repo** — Rust,
  shell or Python — that a real `sbatch`/`srun` reached by ABSOLUTE PATH inside a cage
  actually fails. The candidates all test something adjacent. `containment cred.munge`
  (`selftest.sh`) asserts the munge directory is empty and counts tmpfs mounts, and never
  invokes a SLURM binary; `net.scheduler` tests that the *proxy* returns 403; `steps.allowlist`
  (`srun-probe.sh`) asserts husk's own *message* and its `else` branch treats "failed, but not
  via husk" as a FAILURE — so it detects an unbound stub, it does not assert that the real
  srun is contained. The rest are string assertions on generated args.

  What makes this cheap to close: the harness already knows how to drive real SLURM. There
  ARE executable tests that invoke a real `sbatch` — `selftest.sh` `probe.submit` asserts
  "real sbatch accepted", and `directive-parity-probe.sh` does the same — deliberately
  OUTSIDE the cage with `HUSK_SLURM_SPOOL` unset, asserting the converse. Only the negative
  arm is missing, not the machinery.

  This matters more than it looks, because the compute cage measurably contains a **real,
  configured** `sbatch`/`salloc`/`squeue`/`scancel`/`scontrol` (`findings_round2/N4.md`, job
  5169678 — only `srun` is stubbed there, and `SLURM_CONF` is forwarded on purpose). The
  claim that MUNGE-mask-plus-no-route contains it is asserted in prose in five places
  (`THREAT-MODEL.md`, `doc/threat-model.md`, `profile.rs`, `netallow.rs`, `srun-stub.py`) and
  probed once, partially: N4 measured `scontrol ping` failing at `getaddrinfo` from a compute
  cage and explicitly did NOT detonate `sbatch child.sh` from inside a job.

  That is `P3`/`P7` in its usual costume — **a mask being APPLIED is not evidence that
  submission is REFUSED**. It belongs in the escape battery, where the trusted layer runs it,
  not the caged agent. On the login side the same wall rests on the vendor's per-command
  `apply-seccomp` AF_UNIX block, which is fail-open telemetry; on the compute side AF_UNIX is
  deliberately UN-blocked (CUDA treats the refusal as fatal), so the mount mask carries that
  wall **alone and singly-sourced** — which is the argument for testing it rather than
  citing it.

- **`which()` returns the FIRST match, and husk masks only that one** (`P15`).
  `husk-slurm-wrapper.rs` picks one `sbatch` to shadow in the login cage, and the guard's
  `command -v srun` picks one target to bind the compute stub over. A site with two `sbatch`
  on `PATH` gets one shadowed and one real, and no test covers the two-on-PATH case. Not
  agent-reachable — the human's `PATH` decides it before the agent exists — which is why this
  is backlog and not a finding, but it is exactly the "the name resolved, and you assumed it
  was the only one" shape `P15` names.

- **Per-site network policy should be durable, like partitions are.** `sandbox.network`
  lives inside the `sandbox` block, which the installer owns and rewrites on every install,
  so an operator's `allowedDomains` or a deliberate `strictAllowlist` removal is replaced on
  reinstall. `~/.husk/config.json` — where partitions and accounts live — survives by design.
  Two policies, two durabilities, and nothing says which is which. Observed 2026-08-30 on
  Santis: a loosening made for an agent's work was restored to the shipped default, and it
  took eliminating two hypotheses to notice. **Not a defect** — the installer cats the whole
  settings file and asks for confirmation, `sandbox` is husk's block by design, and uninstall
  restores the pre-install values; a hand edit to a managed key is understood to be
  temporary. Since 2026-08-31 the install also names each managed sub-key it replaces. The
  open question is whether a site wants a durable allowlist, which means moving network
  policy to the operator-owned file.

- **Validate the configured partitions at startup** (`sinfo`/`scontrol`) and fail fast with an
  actionable message. This is also the open instance of `P7` behind H11: nothing verifies that
  a partition is actually preemptible, and nothing fails loudly if it is not.
- **Report carve-outs that silently did not apply.** Floor-overlapping ones are already
  reported; a symlinked component (F20) and a non-existent path are both dropped in silence.
  Same teaching-message machinery, three sentences.
- ~~Allow a LIST of partitions~~ **DONE** — shipped; `HUSK_SLURM_PARTITION` takes a list.

---

## Open questions

- **Sub-home carve-outs — NOT DECIDED, needs separate reasoning.** Whether an operator may
  expose a path *below* another user's home (operational data) while the floor keeps home
  roots hidden. It is a real workflow with no workaround today, and it is a genuine policy
  change rather than a bug fix, so it gets its own discussion before any code.
- `salloc`: block permanently, or revisit? (`srun`/`salloc` from the login node stays low
  priority.)
- Network scope: SNI/host allowlist vs full TLS-MITM.
- Recursive lifecycle robustness (`PDEATHSIG` chains across nested pairs).
- Whether the cage holder should clear `PR_SET_DUMPABLE` — measured on 6.8 a non-dumpable
  holder is still joinable, so the reasoning and the measurement disagree; the flag stays set
  because the failure mode is fail-closed on the MPI path. Revisit only with a measurement on
  the target kernel.
