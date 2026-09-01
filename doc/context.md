# Context

**Beside the stack, not in it.** L1 → L4 descend in *abstraction*
([`PRINCIPLES.md`](PRINCIPLES.md) → [`threat-model.md`](threat-model.md) →
[`constraints.md`](constraints.md) → the internal finding record and the git log).
This file descends in *time*: where the work stands, what is undecided, what is still
owed.

**The test for what belongs here: if a line would still be true next release, it is in
the wrong file.** Repository layout lives in the tree and the README; configuration
lives in the settings files; rationale lives in L1 and L3; the model lives in L2.

**As of 2026-09-02 · branch `main` · v0.5 released.**

---

## Status

| | |
|---|---|
| **Feature work** | complete (2026-08-01) |
| **Security review** | complete — 2 passes, 9 briefs, 102 candidates, 84 distinct findings |
| **Review verdict** | *do not release as-is* — 3 CRITICAL (one defect), plus a host-code-execution chain executed against shipped defaults |
| **Fix phase** | above-LOW fixes committed and unit-tested, each with a test verified to fail against the unfixed code |
| **Hardware re-run** | **both green at `ef85aa5`** — Balfrin 91/0/0, Santis 92/0/1 |
| **LOW tail** | untouched — `review-v0.5/LOW-BACKLOG.md` |
| **Agent memory** | **still broken — measured 2026-08-11.** `allowWrite: ~/.claude/projects` emits its `rw` bind and the HARNESS re-binds the same path read-only on top of it. Not husk's deny. Cluster path differs (`denyRead` tmpfs + restore) and is unmeasured |
| **Known blocker, not husk's** | a `git merge` that rewrites `.gitmodules` fails PARTWAY THROUGH and cannot be aborted cleanly — the file is in Claude Code's own `DANGEROUS_FILES`, bind-mounted read-only, **no knob and not escapable by nesting** (measured 2026-08-13). Run such merges outside the sandbox; report drafted in `doc/upstream/` |
| **Known flake** | `steps.egress` — the rank relay is backgrounded with no readiness check and its stderr goes to `/dev/null`, so "not bound yet" and "died on exec" are indistinguishable. Failed once on Santis 2026-08-11, passed on re-run, no code on that path changed. **Re-run before treating it as a finding** |
| **Tool allowlist** | **widened 2026-08-10** to `Bash,Skill,Agent,Task*` on measurement, not argument — subagents inherit `--tools`, `ToolSearch` cannot escape it. Full per-tool disposition: [`agent-profile-claude-code.md §7`](agent-profile-claude-code.md). `Workflow` is still out, so **ultracode does not run under husk** |
| **Pen-test re-run** | A5 and A1 ran (the two highest-value briefs). A5-F1 (env asymmetry, LOW) fixed. A1 re-found the `--output` family: **F2 (content into a protected path — the real CRITICAL) SEALED; F1 (leaf TOCTOU) content-blocked by the run-time guard AND name-checked, with a bounded EMPTY-FILE residual accepted for v0.6**; leaked step spool reaped. The earlier "A1 closed, fd grep empty" claim was wrong twice over and is retracted — see below |
| **A1 status, correctly** | the CONTENT half holds, verified by job-5138292's log (fd1 was the real file, guard refused). The residual is empty-file creation at an agent-writable path (slurmd opens pre-guard); LOW, closes for free at v0.6 (ROADMAP Track B, output ownership). NOT "closed", NOT "critical open" |
| **Unreviewed by the pen test** | the code THIS round added — the config file (A11), uenv resolver (A10), account resolver (N9), widened tool allowlist — did not run. Shipping v0.5 accepts that as a residual |
| **Release-candidate build** | `v0.4-302-g359e8ba` deployed and green on BOTH clusters: Balfrin 91/0/2 (2 env skips, node busy), Santis 92/0/1. F2 hardware-confirmed on Santis: `-o .claude/hooks/x.sh` refused at submit naming the protected path; `-o out.log` and `-o logs/x.out` still submit (no over-block) |
| **FULL pen-test round IN PROGRESS** | decided 2026-08-20: run every remaining brief, **batch findings, do not stop on a finding**, then ONE fix pass → redeploy → selftest → release. Running on **Balfrin**. Done: R1/A5, R2/A1, N5/A3 (findings in `findings_round2/A3.md`, **not yet triaged**). Next: A11 → A10 → N9 → R3 → R4 → N1–N4, N6–N8. Tier-3 one-command probes (A7, A9) any time |
| **OPEN at compaction** | `~/.claude/settings.json` hash drifted during the N5 cycle — **under investigation, not yet explained**. Innocent candidates: `install-husk.sh` rewriting its 3 managed keys after the baseline, or `/model` persisting a preference (written HOST-side, so it bypasses the cage by design). A finding only if `sandbox.enabled`/`denyRead`/`permissions.deny`/`~/.husk` denyWrite changed, or the mtime lands inside the reviewer window with no install and no `/model` |
| **Blocking release** | finish the round, triage all findings, one fix pass, redeploy, selftest |

The review's one-sentence verdict is worth keeping visible because it is the shape
of every review so far, v0.4 included:

> husk's kernel-enforced boundary is sound; v0.5 was held only by how the guard was
> delivered and by default-allow seams in policy, parsing, config, and lifecycle.

The breaks are never in the kernel-enforced core. They are in policy, parsing,
guard delivery, config handling, and lifecycle. **"Secure the interface, not your
model of it"** is still the through-line.

---

## What v0.5 buys

Worth stating plainly, because it is a lot: an agent on a CSCS system, externally
confined, that can run its own single-node multi-GPU jobs. ICON runs to completion
on Balfrin — one node, 4 MPI ranks, GPU, brokered throughout, with Cross Memory
Attach enabled and no `MPICH_SMP_SINGLE_COPY_MODE=NONE`, so nobody pays an
intra-node message tax. A production KENDA assimilation experiment ran green end to
end — the first real production workload through husk.

That is a daily-work tool, not a demo.

---

## Where the design attention is

**1. The AV2 mask is a denylist, and denylists are bug lists.**
The auto-exec mask enumerates what husk knows about. The v0.5 review demonstrated
the git version end to end: a planted `core.hooksPath` survived the job, `git init`
preserved it, and the next `git commit` executed the payload as the user, outside
the cage, at a time husk has no say over.

The by-construction version — *the job may write outputs but may not create or
modify dot-entries at the root of a writable directory* — is not expressible in
bwrap, which masks paths rather than classes of future creation. It would mean
staging job output and filtering on the way out: real work, and a change to how
husk feels to use. **If the mask list keeps growing, that is the honest direction.**

**2. H11 — preemption must be loudly distinguishable from completion.**
The forced preemptible partition is what makes the resource envelope structural,
and it is also the one place husk *introduces* a failure mode. With
`lrestart = .FALSE.` an interrupted ICON run resembles a finished one to anything
reading its output directory, and an agent may report that the science ran. For a
weather service that is worse than an escape. **Open; not built.** Needs to show up
in the job's output *and* the husk job log.

**3. Diagnostic attribution as a security property.**
Measured, not theorised: 22 `Read-only file system` lines across a 390-line log,
none naming husk. Confinement worked and failed closed; the cost was entirely
diagnostic, and for an LLM an unattributed error invites confident wrong
remediation. The banner and `HUSK_WRITABLE` are the answer; the standard to match
is the partition guard, which the same agent complied with in one step with no
investigation.

**4. Login/compute cage parity.**
The compute cage is roughly 40% of the vendored login model, and the two have
drifted in both directions — the review found `.Rprofile` and `.hg/hgrc` masked on
compute but not on login. Parity is a ROADMAP 6a deliverable, but the *divergences
should be enumerated now*, while the vendored runtime is still there to diff
against. Afterwards that is archaeology; today it turns 6a from "reimplement a
sandbox" into "close a known list".

---

## Open decisions

| decision | state | what would settle it |
|---|---|---|
| **Partition: one forced value or an operator allow-set** | leaning allow-set | Santis legitimately wants `debug` for short tests and `shared` for longer runs. Natural shape: the option-registry pattern applied to a value rather than a flag. Keeps "operator decides, agent cannot escape". |
| **`salloc`** | blocked / deferred | interactive allocation is the highest complexity and lowest value for an agent. Revisit only on a concrete need. |
| **Holder `PR_SET_DUMPABLE`** | off, deliberately | measured on 6.8: a non-dumpable holder is still joinable via `bwrap --userns`. Left off because the gain is a third layer on a process that is already unreadable and holds nothing, while the risk is kernel-dependent — Balfrin runs 5.14, and if joining broke there every step dies. **Three docs still call this a "cheap win"; they are wrong.** Measure on target before trading. |
| **Network scope** | SNI/host allowlist today | full TLS-MITM only if content filtering is actually needed. It also buys credential injection (6b), which is the stronger argument for it. |
| **apinfo read-only shim** | accepted as residual | reviewer judgement. The fix is known — bind a husk-owned copy over the path, the same mediated-stand-in move as the broker itself — but it can only be done per-rank after the step exists, putting a race into the path MPI bootstrap depends on. **If a reviewer judges the exposure to justify that, say so and it gets built.** |
| **Managed settings for cage integrity** | needs CSCS admin | `"sandbox":{"enabled":true}` in `/etc/claude-code/managed-settings.json` cannot be overridden by any user-writable file — closing the override vector structurally rather than by enumerating files to deny. Pair with an admin-side SLURM layer. The `settings.local.json` deny is the user-side stopgap. |
| **Two-tier seccomp (KILL vs ERRNO for unclear syscalls)** | deferred | needs empirical profiling and a management call on the productivity/security trade. |
| **Baseline env allowlist** | not started | would close residual AV7. Forced `--export=ALL` is required for the uenv view, so the fix is on the value side, not the flag side. |

---

## Hardware residual list

Facts only Balfrin/Santis can settle. Each shard supplied exact commands; these are
consolidated from `review-v0.5/SYNTHESIS.md`.

1. **Does SLURM signal the whole step container or only the batch script?** Payload
   that traps `SIGTERM`, `scancel`, compare the `husk: step spool removed` timestamp
   to the cancel. *Settles the severity of the lifecycle findings.*
2. **Does the site honour `#SBATCH hetjob`?** If yes, the ungated-directive finding
   is CRITICAL rather than HIGH — a second component asked for 512 nodes × 24 h.
3. **`munge -n` inside a rank vs inside the job cage** — is the MUNGE socket
   reachable from a rank? *Load-bearing the day `--unshare-net` relaxes.*
4. **`cat /proc/sys/kernel/pid_max; ulimit -u`** — can the zombie leak exhaust
   node-global pids for other users?
5. **apinfo bind writability (host DAC) from a rank.**
6. **Non-dumpable holder behaviour on the 5.14 Cray kernel** — before anyone acts on
   the "cheap win."
7. **Is the hard-coded preemptibility claim actually false on Balfrin?**
8. **`scontrol show config | grep -i job_container`** — does `job_container/tmpfs`
   clean `/dev/shm` regardless? If so, that is an unstated dependency.
9. **`ss -ltnp | grep claude` during a first-party login** — settles the login-side
   loopback-listener question for 6a.

---

## Known gaps and dispositions

Gaps that are *architectural* rather than bugs. Bug-shaped items live in the review
directory.

**husk does not yet meet three clauses of its own interface spec**, and that is deliberate
rather than discovered — see [`sandbox-interface.md` §8.1](sandbox-interface.md), which is
the authoritative list. In short: the login side wraps each *command* rather than the
harness (§2.1, the reason a tool allowlist exists at all); there is no integration profile
artifact (§5); and policy is still expressed in the vendor's configuration shape with no
adapter layer (§6). The first and third close with ROADMAP 6a. They are written as
requirements in the spec on purpose — a clause softened to match today's implementation
stops being a contract — and each row is deleted when closed, never reworded.

**Unmappable ACL groups — a permanent cost of the axiom, not a backlog item.**
An unprivileged user namespace can map exactly **one** gid. Every other group on a file's ACL
is therefore unmapped, the kernel renders it as `(gid_t)-1`, and any operation that COPIES an
ACL fails with `EINVAL` — `shutil.copystat`, `copytree`, `setfacl`, and so `spack install`.
The KENDA session paid two from-scratch builds for it, because the symptom surfaces seven
steps later as ICON failing at runtime with a missing GRIB variable.

**No husk version fixes this, including 6a.** Owning the login cage changes whose namespace it
is, not what a namespace may do. `newgidmap`/`subgid` would need site cooperation *and* still
would not help — it grants unused ids to map, not permission to map a foreign real gid, and the
ACL usually names a group the user is not in. Dropping the user namespace means dropping the
cage; a privileged helper means dropping "no root". Each escape costs the property that let
husk be installed at CSCS without asking anyone.

So the disposition is: **husk detects and explains, and the real fix is upstream.** The wrapper
checks the project dir's ACL at session start and prints the chain before any of it happens.
Beyond that, `shutil._copyxattr` tolerating `ENOTSUP`/`EACCES`/`ENODATA` but not `EINVAL` looks
like a CPython bug — a best-effort metadata copy should not abort a file copy because an ACL
cannot be represented — and fixing it there would silently repair every tool in the chain.

**H4 — data destruction in the writable set.** No in-cage defence, by design: the
project directory *is* the agent's working surface. Disposition is operational —
see the table at the end of `constraints.md`. No sandbox-layer fix exists without
giving up the working surface.

**H3 magnitude.** husk bounds neither node-hours against the account nor queue
pressure. Deliberate: partition, QOS and account limits are the operator's
instruments, and forcing a single partition is what makes them apply. Whether they
*should* be bounded further is a question for the site.

**Lustre stalls in large trees.** Availability, not security. Cause is understood —
an in-process deny-set walk in the vendored runtime, whose result is then
bind-mounted over Lustre. Not configurable (`mandatoryDenySearchDepth` is not
honoured by the shipped binary). The 6a fix is a design constraint, not tuning:
**express policy as mounts, not as a scanned deny-set.** The compute cage already
is.

**AF_UNIX on compute.** Open by necessity — socat relay and CUDA both need it. So
the login-side `apply-seccomp` guarantee does not extend to compute, and cross-uid
protection there rests on directory ownership and mode rather than on the filter.

---

## Doc map

| level | question | file |
|---|---|---|
| **L1** | What would still be true in another language, for another scheduler? | `PRINCIPLES.md` |
| **L2** | Who is the adversary, what can they reach, what do we lose? | `threat-model.md` |
| **L3** | What control exists, where is it enforced, how much weight does it carry? | `constraints.md` |
| **L4** | What actually happened? | `review-v0.5/`, the git log |
| — | Where does the work stand? What is undecided? | this file |
| — | How does the compute side work? | `slurm-broker/` |
| — | What is the contract with the wrapped agent? | `sandbox-interface.md` |
| — | What is planned? | `ROADMAP.md` |

**The stack is a loop, not a hierarchy.** L4 is where L1's entry bar is satisfied, and
`PRINCIPLES.md`'s "Not yet earned" section is the pipeline from L4 back to L1. A reader
who sees only the descending arrow will read L1 as the authority and L4 as an
appendix, which is backwards: L1 has authority *because* L4 paid for it.

**Two follow-ups this restructure implies, not yet done:**

1. `slurm-broker/THREAT-MODEL.md` currently holds both the *model* and the *design
   principles*. The principles that generalise — construct-and-re-emit, reason about
   the sink, capture values not references, the unit of confinement — are
   project-wide and belong at the top level. What is left is compute mechanism, and
   would be better named `slurm-broker/DESIGN.md`.
2. `sandbox-interface.md` still describes a v0.2/v0.3 contract and cites the old
   H-IDs. It needs to describe what husk actually offers now — a session-level
   external wrap, a brokered scheduler surface, and an egress proxy — and to say
   which properties an agent must satisfy to be wrapped. That is also the acceptance
   criterion for ROADMAP 6b, so it is worth doing before, not after.

## v0.5 fix round DONE (Phase 1) — 2026-08-23

All barrage + synergizer findings triaged and fixed or documented. HEAD after the round; 274 lib
+ 19 + 10 tests green, clippy clean, nothing deployed yet (RC unchanged from the review).

**Sealed (test-first, each verified failing against the unfixed code):** A4-S1 CRITICAL
(52a4e4a, step-broker create_new+O_NOFOLLOW), N6-F1 HIGH (9cfc58d, wrapper pre-seeds login
masks + .Renviron swept), N1 (18ccb42, hard-link leaf nlink>1), A3 (af5880b, quote-aware
heredoc that resets), N3 (db4d4a7, boundary before glue-split), N8+N9/R1 (c3040b2, banner
lists both bind forms + directives glue-split like CLI), body-reaper (7c9b2b7).

**Documented residuals (doc/review-v0.5/FIX-ROUND.md), considered-and-not-coded with reason:**
N2 (LD_LIBRARY_PATH strip is correct security; safe fix = v0.6 inner-script injection after the
fd-close), A10 (uenv binding is an operational invariant, guard runs from inside the image so no
runtime check possible), A4-L1/N7 (credential globs are a bwrap/vendor limitation on Linux;
home-masking is the control), A4-S2 (spool remove_dir is deliberate), N9 R3/R4/R5 message nits.

**The synergizer's Chain 1** (A4-S1 write + auto-exec target = operator RCE) is severed by the
A4-S1 seal AND the N6-F1 seal AND the N1 seal — three independent members of the chain now
closed. Phase 4 must RE-RUN the synergizer against the fixes to confirm the chain is dead, not
just each part patched.

**Next: Path A Phase 2 — login-cage egress.** Decisive test not yet run (plain claude vs
husk-claude :3128). If husk's mount-namespace unshare is orphaning srt's relay -> a husk fix;
if srt just doesn't start on CSCS -> deeper. See srt-watch.md.

## Backlog (2026-08-23) — husk must verify the EFFECTIVE sandbox config, not just its own file

Christoph found (and it is now doc/upstream/claude-code-sandbox-toggle-drops-strict-settings.md)
that `/sandbox off` then `/sandbox on` leaves a minimal `sandbox` block in
`.claude/settings.local.json` that REPLACES (not deep-merges) the strict block in
`~/.claude/settings.json`, silently dropping husk's network allowlist and denyWrite while the UI
says "sandbox on". This is an upstream bug, but it is a husk FOOTGUN: husk's whole boundary lives
in the global settings, and a local override disables it with no warning.

**Hardening for husk (wrapper, fail-closed):** before launch, husk-slurm-wrapper should check that
no more-specific settings scope weakens the strict sandbox — if a local `sandbox` block lacks
`network.allowedDomains` / `filesystem.denyWrite` while the global one has them, REFUSE to launch
and name the offending file. Same SandboxReady-witness discipline, extended from "my stub is
bound" to "the boundary I configured is actually in effect". Relatedly: husk already denyWrites
`.claude/settings.local.json` against the AGENT, but a USER (or /sandbox) writes it out of band, so
the deny is not enough — the wrapper must VERIFY, not just deny.

## 2026-08-23 (late) — egress allowlist CRITICAL: FIXED AND OBSERVED

The 403 we never saw all week. After `488e988` (strictAllowlist: true) was reinstalled into the
live `~/.claude/settings.json`, a session showed: `github -> curl (56) 403 from proxy after
CONNECT` (BLOCKED), `opendatadocs.meteoswiss.ch -> 200` (allowed). husk's egress allowlist
ENFORCES for the first time, confirmed by observation.

Key facts learned:
- The permissiveness all week was PURELY the missing `strictAllowlist` flag. Not `/sandbox`, not
  `--resume`, not sandbox rebuild -- all red herrings (three wrong predictions). Christoph's
  single hypothesis (allow/deny/ASK permission model + auto-mode auto-approves the ASK) was the
  complete answer.
- The proxy consults `config.network.strictAllowlist` LIVE per-CONNECT. The reinstall's config
  change took effect in a RESUMED session with the SAME netns (4026533797, no rebuild). So the
  netns/resume angle was never relevant to the allowlist.
- Deployment path validated: reinstall -> flag in live config -> running session honors it ->
  github blocked.
- CSCS relay bug is now cleanly an AVAILABILITY problem, separable from confinement: the allowlist
  works when the relay is up. Once Anthropic fixes the CSCS relay, husk-with-this-fix confines.

This is the most important fix of the review. Egress confinement (AV7/AV8) was non-functional for
the life of the network feature and is now real + observed.

## 2026-08-24/25 — the networking+credential debugging session (SURVIVAL RECORD)

### THE ABSTRACT LESSON (if one sentence survives, this is it)
**A boundary is what it DOES, not what you configured it to do. When husk does not own the
enforcer, the config is only a REQUEST; the boundary is the observed EFFECT — so you test the
boundary that exists, never trust the one you asked for.** Every surprise this week came from
inferring the boundary from the config/mechanism instead of observing the effect against the live
system. Corollaries proven the hard way: a config-shape test is a false friend for enforcement
(it proves husk asked, not that the harness obeyed); `test -r` is a false friend for masking
(`access()` passes on `/dev/null` — verify by an ACTUAL READ). This generalises the older
"secure the interface not your MODEL of it" and "the mount table is the oracle."

### The seven findings (each cost real time, each was config not code)
1. **Egress allowlist was a PROMPT HINT, not enforcement.** `allowedDomains` alone -> unlisted
   hosts fall to the ask-callback, which AUTO-APPROVES in auto-mode. So egress was OPEN on every
   environment where the relay runs. Fix: `network.strictAllowlist: true`. FIXED + OBSERVED
   (github 403, opendatadocs 200). The barrage could never find this (reviewers can't see config).
2. **CSCS relay blackout = husk's own `denyRead: /users` starved the srt relay.** The relay is a
   claude child that reads its runtime from `~/.local/share/claude`; masking the home ($HOME under
   /users on CSCS) hid it -> relay never binds :3128 -> total egress blackout. NOT Anthropic-only
   (I wrongly "exonerated" husk first). Fix: `allowRead: ["./", "~/.local"]`.
3. **OAuth token leak (CRITICAL).** The runtime binds `~/.claude` back RO over the home mask so the
   agent has its config -> `.credentials.json` + `history.jsonl` + session-env + shell-snapshots
   readable in EVERY login-cage session, incl. every pen-test reviewer. COMPUTE cage is safe (husk's
   bwrap full-tmpfs's the home). Fix: `denyRead` the sensitive CHILDREN of ~/.claude.
4. **denyRead precedence (confirmed in linux-sandbox-utils.ts:869/1510):** a FILE deny -> /dev/null
   (works); a top-level `denyRead ~/.claude` -> IGNORED (the runtime's bind wins on mount ordering);
   a SUBDIR/CHILD deny -> tmpfs (works). So we mask children, never the parent. `allowRead` a
   subpath -> --ro-bind back over the tmpfs (clean; siblings stay masked).
5. **`test -r` is a false friend** for a /dev/null-masked file. Verify masking by `ls` (shows
   `crw-rw-rw- 1,3`) or a real read that fails — never access().
6. **Live config APPLIES masks live but does NOT cleanly REMOVE mounts** — removal tests are
   contaminated by stale mounts; use a FRESH session for any "did the mount disappear?" test.
7. **Testing split:** unit tests (this repo) verify husk's REQUEST (config shape, drift). Only a
   LIVE-CAGE integration test verifies the harness's ENFORCEMENT. The latter is the one that
   matters and can only run inside a real session against the real (not vendored) harness.

### 2026-08-27 — the W round, its fixes, and what v0.5 actually is

**Three caged whitebox reviewers (W1/W2/W3), each WITH the source.** 16 findings. The black-box
barrage had found ZERO of the three config CRITICALs; this round found the class they belong to.

**The triage rule that changed the answer.** Christoph: *"This is a feature… This is only an
exploit if the AGENT itself can do this."* W2 says it in its own §5 — *"The caged agent cannot
loosen its own boundary through any settings layer."* Applying that dropped 2 CRITICALs to
residuals. **Ask reachability FIRST**; husk contains the AGENT, and a hostile repo or a careless
flag is a different adversary.

**Fixed (each: fix + test pinned at the bug's level + exploit + why the fix defeats it, and an
adversarial subagent review before commit — Christoph's standing instruction, and it caught a
real defect in four of five):**
- `.Renviron` masked on the COMPUTE cage; `.Rprofile`'s mask was defeatable without it
- mount-point RECLAIM in the guard: husk removes only what husk created (proved with real bwrap)
- `precreate_login_masks` DELETED — measured on Balfrin: 3 files created, 0 binds, all writable.
  It fabricated an `.hg/` repo root in every project while protecting nothing
- `SettingsIntact` now checks the git-root layer, and FOLLOWS a worktree's `.git` file — a
  reviewer demonstrated a live bypass with strace after the first fix
- `~/.claude/daemon` masked (`control.key` was readable in-cage)
- husk-verify: auto-exec exposure as a WARN, second attempt after the first was reverted

**What v0.5's login side IS, stated plainly:** sound against the agent for confidentiality
(token masked, home masked, egress strict — measured both arches), porous against the
REPOSITORY, and open on one integrity case — the agent can plant `.Rprofile` in its workdir and
it runs as the operator. Residuals R1–R5 in `review-v0.5/W-KNOWN-ISSUES.md`. **6a is the fix for
R1/R2/R5**, and it is now argued by measurement rather than asserted.

**P15 added** — a control names a target; check the name resolves to the object you meant.
Three instances in one day: denyWrite→$HOME, precreate→a bind that never existed,
SettingsIntact→cwd not the git root. Plus the corollary: an assertion that iterates the list it
checks cannot see that list shrink, and a test that stubs its oracle measures your model.

**NEXT:** cluster round on both arches (rebuild → install → selftest → husk-verify; WARN lines
are expected now, decision B3) → then the DOCUMENTATION restructure (a CLAUDE.md hub; an outside
agent found the repo hard to navigate, and the four-level rate-of-change split plus
"rationale lives in one place" must survive it) → then the big code review, ~22.5k lines of code
across 70 files, split by boundary rather than run as one pass.

**Not done:** W2-4's argv witness (`--setting-sources` can still delete husk's settings layer —
operator-reachable, not agent-reachable). The W1-1/W2-8 root cause is unfixable before 6a.

### Release state (v0.5)
- **DONE + committed:** strictAllowlist (488e988), ~/.claude child-masks + ~/.local carveout +
  projects read-only/allowWrite:[] (27682e7, e1066de), all Phase-1 code fixes.
- **DONE:** `slurm-broker/husk-verify.sh` (built 2026-08-25) — STANDALONE, runs INSIDE a live
  session, asserts by OBSERVED EFFECT (never test -r / never the config): cage present (else
  INCONCLUSIVE, exit 2, no false BREACH); token+history+sessions -> /dev/null proven by inode
  (`stat %F|%t|%T` == `character special file|1|3`, bytes never read); home mask by actual reads
  of sensitive dotfiles; projects readable+non-empty; settings.json refuses a zero-byte
  open-for-append (non-destructive real write test, not test -w). Egress: proxy CONNECT-403
  (curl exit 56) = BLOCKED, proxy unreachable (exit 7/28) = relay DOWN. Relay-down on the
  allowlisted host = HARD FAIL whenever an allowlist exists (`--no-egress` relaxes it). Exit
  0/1/2 = SECURE/BREACH/INCONCLUSIVE. Verified locally: syntax ok, fails safe (exit 2) off-cluster,
  the /dev/null discriminator + non-destructive append probe both correct. NEEDS a live-cage run
  on both clusters (see hand-over below).
- **RUN IT VIA BANG-MODE `!` — MEASURED 2026-08-25:** bang-mode `!cmd` at the Claude Code REPL
  is CAGED (runs in the same bwrap as the agent's Bash tool). Proof: `!touch ~/.husk/bla.json`
  -> `Read-only file system` (EROFS = a bwrap `--ro-bind` on a denyWrite path; a host write
  would give EACCES or succeed), and a Bash-tool probe showed a FRESH userns (`4026535681` vs
  host `4026531837`) + the srt proxy injected on `localhost:3128`. Bang-mode is undocumented
  as to sandboxing (guide agent confirmed the docs are silent), so this was tested not inferred.
  CONSEQUENCE: the operator runs `!~/husk/slurm-broker/husk-verify.sh` and reads the VERDICT
  straight from the transcript — the AGENT CANNOT FAKE IT, and this is NOT an escape (the agent
  can't emit bang-mode; only the human at the REPL can). So the planned "wrapper runs husk-verify
  pre-handoff" integration is DROPPED for v0.5 — bang-mode already IS the trusted-operator path
  into the cage. (Belt-and-suspenders network confirmation in bang-mode still optional.)
- **DONE (carve-out residual handled):** the `~/.local` audit ran clean on BOTH clusters (only
  the claude install + uv's Python tree; no credential pockets present). The carve-out is an
  ACCEPTED v0.5 residual: XDG co-mingles creds with code so no clean dir rule splits it, and a
  survey pinned the leaky set to exactly THREE stores under ~/.local/share (uv `credentials/`,
  libsecret `keyrings/`, `python_keyring/` file fallback) — everything else lives in ~/.config /
  ~/.cache / a dotfolder and is masked. Handled in three layers: strict egress (preventive
  backstop — a read secret can't leave), the husk-verify carve-out scan (detective: 3 known
  stores by name + a content-signature sweep, WARN not BREACH), and v0.6a's constructed home
  (the real fix — build the home like the compute cage, never bind the pockets). Full writeup +
  the credential-location table: `doc/review-v0.5/local-carveout-residual.md`.
- **PHASE 6 GREEN ON BOTH ARCHES (2026-08-25, live login cage, run via bang-mode `!`):**
  Balfrin ln002 + Santis ln002 both `VERDICT: SECURE`. Token `/dev/null`, ~/.claude children
  masked, home mask holds, projects readable, BOTH settings.json refuse open-for-append,
  egress strict (meteoswiss reachable / github refused), and the new `~/.local` carve-out
  scan PASSes on both (no credential store, no plaintext signature). Santis lists 7 mask
  lines to Balfrin's 8 only because `~/.claude/tasks` is absent there (absent paths are
  skipped — not a coverage gap). The `<sandbox_violations>` stderr block is self-inflicted
  by the deliberate github probe. Selftest was already 93/0/0 (Balfrin) and 92/0/1 (Santis).
- **SELFTEST GREEN ON THE NEW WRAPPER (2026-08-25 ~12:15Z):** Balfrin ln003 93/0/0, Santis
  ln002 92/0/1 (benign single-partition SKIP), both re-run AFTER the SettingsIntact witness
  + single-Rust-startup change — the 29 containment arms were undisturbed by it. The
  preflight then fired for real when Christoph launched husk in his usual testing folder
  (a /sandbox toggle had left a sandbox block there): the control works in production, and
  his feedback was that the refusal was TOO VERBOSE — cut 20 lines -> 12, pinned by a test.
- **REMAINING:** audit ~/.local/{share,state} on Balfrin AND Santis (no stray secrets); confirm
  session/transcript survives allowWrite:[]; version bump 0.4.0->0.5.0; rebuild broker per-arch;
  install-husk; selftest + husk-verify on both clusters; release (Christoph tags/pushes).
- **Upstream reports filed:** srt relay dies under home denyRead; /sandbox off->on downgrades a
  strict sandbox; ask-default egress. **Ask Anthropic to move the token OUT of ~/.claude.**
- **v0.6a is the clean fix:** husk owns the login cage -> `--tmpfs ~/.claude` + minimal bind-back,
  like the compute cage already does; then enforcement is husk's and directly testable.

### Method note
Human-in-the-loop was decisive: Christoph reasoned BACKWARD from behaviour (auto-mode not asking ->
allowlist is a permission prompt) while I reasoned FORWARD from broken docs and mispredicted 3x.
The external, independent check catching the confined reasoner's blind spot IS the husk thesis.
