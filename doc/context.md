# Context

**Beside the stack, not in it.** L1 → L4 descend in *abstraction*
([`PRINCIPLES.md`](PRINCIPLES.md) → [`threat-model.md`](threat-model.md) →
[`constraints.md`](constraints.md) → [`review-v0.5/`](review-v0.5/) and the git log).
This file descends in *time*: where the work stands, what is undecided, what is still
owed.

**The test for what belongs here: if a line would still be true next release, it is in
the wrong file.** Repository layout lives in the tree and the README; configuration
lives in the settings files; rationale lives in L1 and L3; the model lives in L2.

**As of 2026-08-05 · branch `experimental` · v0.5 unreleased.**

---

## Status

| | |
|---|---|
| **Feature work** | complete (2026-08-01) |
| **Security review** | complete — 2 passes, 9 briefs, 102 candidates, 84 distinct findings |
| **Review verdict** | *do not release as-is* — 3 CRITICAL (one defect), plus a host-code-execution chain executed against shipped defaults |
| **Fix phase** | above-LOW fixes committed and unit-tested, each with a test verified to fail against the unfixed code |
| **Hardware re-run** | Balfrin round 1 green; Santis round 1 in progress |
| **LOW tail** | untouched — `review-v0.5/LOW-BACKLOG.md` |
| **Blocking release** | hardware confirmation, then re-review of the two fixes that touch the enforcement path |

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
