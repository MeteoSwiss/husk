# Principles

**Level 1 of four.** These are the things that would still be true if husk were rewritten in
another language, for another scheduler, on another cluster. Everything below this file is an
instance: the harm catalog in [threat-model.md](threat-model.md), the control-to-harm mapping in
[constraints.md](constraints.md), and the finding-by-finding record in [review-v0.5/](review-v0.5/)
and the git log.

**The bar for entry.** A principle belongs here only if we can name **the concrete failure that
taught it** *and* **a second, different failure it later caught or would have prevented**. One
incident is an anecdote; the second is what shows the lesson generalises. Candidates with only one
instance are listed at the end, unpromoted. This bar exists because a "lessons learned" document
with no bar becomes a list of platitudes nobody reads, and the whole value here is that every line
was paid for.

**The stack is a loop, and this file is the downstream end of it.** L1 does not have authority
because it sits on top; it has authority *because L4 paid for it*. Every principle here is a debt
recorded by findings, bringups and incidents below it, and "Not yet earned" is the pipeline
running the other way — candidates waiting for a second instance to arrive from L4. A reader who
sees only the descending arrow will read L1 as the source and L4 as an appendix, which is exactly
backwards.

**How to use it.** When a finding or fix instantiates one of these, cite it (`P3`) in the commit
message or the finding. When something here is contradicted by evidence, change it — a principle
that survives by not being tested is worth nothing.

---

# Where the boundary goes

## P1 — Confinement granularity follows the workload's communication structure, not the process tree

Draw the boundary around the set of processes that must talk to each other, and confine that set
as a unit. Inside the boundary, sharing is not a weakness; it is the reason the boundary is where
it is.

**Why it isn't obvious.** The instinct is that tighter is safer: cage each process as narrowly as
possible, and a cage per rank must beat a cage per job. That instinct produces a sandbox that is
both weaker and useless — useless because it breaks the workload, weaker because you will then be
pressured to punch holes in it until it leaks.

**Taught by** four MPI ranks on one node. Given a private user namespace each, Cray MPICH's
intra-node transfers died with `EPERM` — sibling user namespaces cannot `ptrace_may_access` each
other, so `process_vm_readv` between ranks is refused by the kernel no matter what the seccomp
filter says. The fix was to draw the boundary around all four: one shared user namespace, owned by
a holder process that outlives every rank.

**Caught again** in the shape of the whole compute-side threat model. Once the unit is *the job on
a node*, the questions become answerable: mount and network namespaces stay per-rank (identical
copies, costing nothing), only the user namespace is shared, and "can a rank reach the
step-broker?" is a question about the boundary rather than about a process. `cma.peers` (ranks can
read each other — MPI works) and `cma.outside` (the step-broker is not visible at all) are the
same design decision observed from two sides.

**Shape of the fix:** identify the communication set first, then confine it, then verify both
directions — that the set can do what it must, and that nothing crosses out of it.

## P2 — The confined side supplies neither its own boundary nor its own record

Two claims, one root. A value that *defines* a boundary must come from a source the confined party
cannot write. A record of what the confined party *did* must live where it cannot reach.

**Why it isn't obvious.** The boundary value is usually sitting right there, correct-looking, in
the request. Using it feels like reading configuration, not like taking the adversary's word for
the shape of its own cage.

**Taught by** F17: the compute cage's writable root came from `req.cwd`, which the agent writes.
Launch husk from a home directory and every brokered job got that home bound writable — through
the `--tmpfs /users` floor that exists to hide it.

**Caught again**, repeatedly, once we knew to look. The egress proxy resolved its allowlist from
`$PWD` — the job's `--chdir`, which the agent picks — so the confined side chose which policy file
confined it. `--output` was confined *relative to* an agent-chosen `--chdir`. And on the record
side: the broker log lived in the spool, which must be agent-writable for the stub to reach it, so
the audited party could rewrite its own audit trail.

**The record half generalises further:** the observer must sit outside the boundary it measures.
A caged reviewer that escapes stealthily reports "all clean" — which is why, in the pen test, the
reviewer never decides whether the cage held; a check running outside every cage does. Same reason
the job guard writes its refusals to husk's log under `$HOME` rather than to the job's stdout:
stdout is the thing under suspicion.

---

# What a check is worth

## P3 — Validation is not enforcement. If you cannot close the gap, stop relying on the check

A check whose subject can change between the check and the use is a comment, not a control. When
the gap cannot be closed, either move the question to the moment of use, or remove the damage the
race can do — and say plainly which of the two you did.

**Why it isn't obvious.** The check is not wrong. It is correct at the instant it runs, it passes
review, and it passes its test. The defect lives entirely in the gap, which is invisible in the
code and often invisible in the test harness too.

**Taught by A1.** husk validated `--output` at submission; slurmd opens it when the job starts.
The job sits PENDING for hours in a directory the agent can write the whole time. `rm log.out &&
ln -s ~/.bashrc log.out` during the wait, and a validated path becomes an arbitrary write as the
user, outside the cage.

**Caught again — one week later, by me, while fixing A1's neighbour.** The cage-build fix stat'd
`<project>/.claude/settings.json` on the login node and emitted a hard bind for it. But `sbatch`
runs inside a login-cage Bash command, and the vendor runtime protects a non-existent deny path by
binding `/dev/null` over it — which makes bwrap create an empty file **on the host**, in the
project directory, for exactly as long as that command runs. husk stat'd the file during the one
moment it existed; bwrap looked for it on a compute node minutes later, and the cage died. Every
ICON job failed. The check spanned two machines and a queue wait, and I had just finished writing
this principle down.

**Shape of the fix.** A1: ask again at a moment that cannot be raced — the job guard reads
`/proc/$$/fd/1` *after* the file is open and *before* the agent's body is a process — and force
`--open-mode=append` so the race cannot destroy what it points at. The ghost file: delete the stat
entirely and let `--ro-bind-try` put the question to bwrap, which asks at the moment of use.

## P4 — Control what executes, not a description of it

Validating a document and then handing the document to someone else to run is not containment. Two
parsers will disagree, and the difference between "what we checked" and "what runs" is the whole
attack surface. Own the bytes that execute.

**Why it isn't obvious.** It looks like the same thing. You read the script, you understand the
script, you forward the script. The gap is not in time (that is P3) but in *identity*: the artifact
you inspected is not the artifact that executes.

**Taught by** the job script body, which husk used to parse for `#SBATCH` directives and then
submit verbatim. The v0.5 review demonstrated two ways to run before the cage existed: the agent's
own shebang, and a line beginning with a character Rust's `trim_start` calls whitespace and bash
does not — `\f# ; payload` looked like a comment to husk's splitter, landed in the head, and ran.
A third, a winnable rename race on the staged file, was the same lesson from a different angle. No
amount of validating harder closes that class; the next instance is whatever the two parsers
disagree about next.

**Caught again** at the option level, which is the same shape one layer down: glued short options,
`SBATCH_*` environment channels, `#SBATCH` directives, and options that do not exist yet were each
a spelling husk's model of the parse did not share with slurmd's actual parse. And once as
foresight rather than as a bug — the shim-versus-broker decision, where a submitting shim inside
the cage is porous by construction and keeping the real binary outside is the only non-porous
option.

**A corollary worth stating, because it decides charset arguments.** Whether a value is
dangerous depends on the EMISSION FORM, not on the value. An option-shaped account name is
harmless as `--account=VALUE` — one argv element, so the leading dash is data — and dangerous
as a bare argument, which is why `rank.rs` refuses option-shaped environment NAMES: those
become arguments to bwrap. Same charset question, opposite answer. Controlling the form is
what makes the value safe, which is the argument for canonical re-emission over filtering.

**Shape of the fix:** husk submits its **own** script; the agent's body is data, run by an
interpreter husk names, at a path husk chooses, inside the cage. The bytes slurmstepd executes are
ours. Options are not forwarded but **constructed** — parsed, validated, re-emitted canonically
(see P5). That retired an entire class rather than its instances, and closed three CRITICALs at
once.

## P5 — A denylist is a bug list

"Block the dangerous ones and pass the rest" is a list of the attacks someone had thought of by the
time they wrote it. The alternative is to construct what is allowed: parse, validate, re-emit
canonically, reject everything unrecognised.

**Why it isn't obvious.** Denylists are cheap, they never break a working case, and they look
complete when you write them. Allowlists break working cases immediately and loudly, which reads as
the worse option right up until the first thing you did not enumerate.

**Taught by** the sbatch option surface. Every fix was a new spelling, and the class only closed
when husk stopped forwarding agent bytes and started constructing the invocation (P4).

**Caught again** three times over. `STRIPPED_SUBMIT_ENV` named four credentials and forwarded
everything else, so `GH_TOKEN` and a live `SSH_AUTH_SOCK` agent-forwarding socket rode into every
job. The job guard's cleanup *enumerated* the files it removed, missed
`net.sock`/`socat`/`net-proxy.log`, and every networked job leaked its spool. The auto-exec dotfile
mask is still a denylist, and is recorded as a known residual rather than pretended away.

**The honest tax.** An allowlist is wrong on every new site until it has been measured there.
Balfrin's first run dropped 82 login variables, including `$SCRATCH` and the uenv library path;
Santis then dropped Lmod's serialised module table, which Balfrin does not set. One clean cluster is
not evidence about the next — which is why the drop list is printed, in full, with the remedy in
the message.

---

# What you must not forget

## P6 — Release must be structural, not remembered

Every acquired resource needs an owner and a release **on every path**, including the paths nobody
drew: the error unwind, the panic, the signal, the early return. Prefer the layer that can enforce
this for you. Where no such layer exists, enumerate the exit paths explicitly and test them,
because you will otherwise miss one.

**Why it isn't obvious.** The normal path is the one you write, run, and test. Leaks live on the
paths that only occur when something else has already gone wrong — which is precisely when you are
least able to observe them.

**Taught by** the cage holder, which outlived its parent on **every job**. The holder is init in a
PID namespace, and such a process ignores every signal it has not installed a handler for — the
same protection that stops a rank killing the holder from inside. That rule applies to ancestor
namespaces too, with only `SIGKILL` and `SIGSTOP` excepted, so `PR_SET_PDEATHSIG(SIGTERM)` was
*silently discarded* and the parent's death did nothing. Measured 2026-08-02: both the clean and
the SIGKILL path leaked while the disposition was SIGTERM. The release was written; the kernel
declined to deliver it.

**Caught again, and note where.** Every leak this project found was either in the shell layer or in
Rust code where someone wrote a *statement* instead of a `Drop`. The netproxy's tunnel counter
decremented as the thread's last line, which a panic never reaches and nothing ever resets — 64
panics and the job's egress is refused for the rest of its life, with a message about load.
`--once` claimed a spool and returned past the teardown. The job guard leaked its spool on the
abnormal exit path, and leaked a socat placeholder that could not be unlinked because it was still
a mountpoint: `EBUSY`, hidden under `2>/dev/null`.

**The language asymmetry is the practical core of this.** Starting the broker is a chain of
acquisitions — claim the spool, resolve the policy, open the session log, spawn the proxy, bind the
socket — and any link can fail. In Rust that chain is nearly free: tie each resource to a value, put
the release in `Drop`, and it runs on every path including unwinding. `BrokerHandle` kills the child
broker if startup fails after the spawn; `TunnelSlot` returns its slot however the thread ends. The
same chain in bash needs a `trap` per exit path and careful ordering, and in C a goto-cleanup
ladder — both correct only for as long as someone keeps them correct. This is not an argument for
Rust; it is an argument for putting the resource in the layer that can enforce its release, and for
treating shell-managed resources as a place where the exit paths must be listed and tested by hand.

**The acquisition-side twin:** make the unverified state unrepresentable. The wrapper's
`SandboxReady` is a witness type that can only be minted by a verified bind, so "we checked" is
carried by the type rather than by a boolean somebody has to remember to test.

## P7 — A control that can fail silently has already failed

If a control can decline to apply and tell no one, then in production you cannot distinguish
"protected" from "unprotected" — so you must assume unprotected. Every path where a control does
not apply needs a branch that says so, to someone who can act.

**Why it isn't obvious.** Failing open *quietly* is the most comfortable behaviour to write: the
job runs, nobody is blocked, no one files a bug. The absence of a complaint reads as evidence that
the control worked, when it is equally consistent with the control never having run.

**Taught by** the network allowlist. A parse error was swallowed into a boolean, so a malformed
entry meant the job simply had no egress — and *nothing said so*: not the agent, which saw a
network that did not work; not the operator; not the log. The fix is not merely to fail closed but
to fail closed **loudly**, which is why a bad allowlist now warns at startup, and again in the job.

**Caught again** three times. A malformed settings file resolved to the default policy — a stray
comma silently removed every `denyRead` and every credential mask, turning a syntax error into a
disclosure. The job guard's cleanup failed under `2>/dev/null` and leaked a spool per job with no
message anywhere; the directory mtime was the only evidence the code had ever run. And the holder's
`PDEATHSIG` above (P6) is this principle too: the kernel discarded the signal and reported nothing.

**Still open, and the reason H11 exists:** husk forces a preemptible partition, and nothing verifies
that the configured partition actually *is* preemptible. If it is not, the resource guarantee is
void and no one finds out.

**Distinct from P11** by audience, and from P3 by mechanism. P11 is about a refusal that reached the
confined party wearing the wrong name. This is about a control that did not apply and told
*nobody*. The fix shapes differ accordingly: P11's is a better message, this one's is a required
branch.

## P8 — Two lists of the same thing will drift, so make one assert the other

When the same fact must appear in two places — two languages, two files, two layers — do not
maintain both. Write a test that derives one from the other, and let the test be the single source
of truth.

**Taught by** the policy inputs: the broker reads its configuration from files that the shipped
`denyWrite` is supposed to make unwritable. The same list, written twice, in Rust and in JSON, with
nothing connecting them.

**Caught again** by A4-F3, in its most instructive form. The compute cage masked `.Rprofile` and
`.hg/hgrc`; the login cage did not. A login-session agent could plant either, and it would fire the
next time a **human** ran `R` or `hg` in that directory. What made it hard to see is that the
compute cage's masking *hid* the gap — brokered jobs looked protected, so the surface looked
covered. The fix was not "add two entries"; it was a constant asserted in both directions against
the shipped config.

**And once more, structurally, by this file.** Rationale that lived in both a code comment and
a principle here is two copies of one argument, which is the same failure at documentation
scale. Controls now cite (`P5`) instead of restating; `constraints.md` lost about a third of
its length to the same move.

---

# What your tests are actually telling you

## P9 — A passing test can be a false friend

A test one layer above the defect proves the layer, not the defect. After writing a test, remove
the fix and watch it fail; if it still passes, it is testing something else.

**Taught by** the confinement test that asserted symlinks are resolved and traversal rejected — and
passed for the entire life of A1. It exercised the whole-path case. The code split the path and
appended the leaf as text, so the one component the attacker controlled was the one component
nothing resolved. Green suite, arbitrary-write escape open.

**Caught again** by the masking tests, every one of which used a path that did not exist — so all
took the same branch and none ever met the shape that killed three of four concurrent jobs. And by
my own fix for the cage-killer: a test asserting "an absent deny is skipped" passed while the
cluster kept dying, because the test built its arguments in a directory nobody else was touching
(P10).

**Shape of the fix:** test at the level the defect lives, and make *removing the fix* the acceptance
criterion for the test.

## P10 — Know what your harness cannot see; a green suite is necessary, not sufficient

For every test harness, write down what it substitutes — because the substitution *is* the blind
spot, and it is invisible from inside the suite.

**Taught by** the guard tests, which replace `seccomp-wrapper` with a stub that drops its arguments
and execs. Nothing off-cluster runs bwrap, so a bwrap argument list that cannot possibly work looks
perfect. A malformed bind killed three real jobs while the suite was green.

**Caught again**, worse, immediately afterwards: the selftest never calls the broker *from inside a
husk session*, so no login cage is running, no ghost mount points appear in the project directory,
and the entire TOCTOU class of P3 is unobservable. **91 PASS / 0 FAIL on two clusters said nothing
about a bug that broke every single ICON job.** The real-workload run is the verdict; the suite is a
regression net.

---

# What you say when you refuse

## P11 — An unattributed denial invites confident wrong remediation

Say who refused, why, what the consequence is, and what would work instead. Keep the message
identical on retry, so it reads as standing policy rather than as weather.

**Why it isn't obvious.** A refusal feels complete when the dangerous thing did not happen. But the
party receiving it will now act on its own theory of the cause, and a confident wrong theory costs
more than the refusal saved — an agent that believes SLURM is down will retry, reconfigure, and
route around a control that was working exactly as intended.

**Taught by** husk refusals that wore SLURM's name, so the agent "fixed" the wrong layer.

**Caught again** by bwrap killing a cage with a message that never mentions husk — three ICON jobs,
and it took a human reading the job log to connect them to a sandbox at all. And by the broker's own
build identity: a session keeps the broker it started with, so a reinstall does not touch a running
session, and the log printed only the crate version, which does not move between builds. There was
no way to tell a stale broker from a current one from its own output.

**The tension, recorded honestly.** A7-1 showed the opposite failure: husk's confinement refusal
quoted the resolved host path, which made it an existence oracle for paths the cage exists to
hide — `~/.ssh` present, `~/.gnupg` absent, one probe each. Both constraints are real. The
resolution is to **split the audience**: the confined party gets the teaching, the operator gets the
detail, on a channel the confined party cannot read.

## P12 — Documentation drifts toward the intent, and always over-claims

A description of a control decays into a description of what the control was *meant* to do.
The drift is directional: docs are written at the moment of maximum confidence — just after
the thing was built or fixed — and the code moves on without them. So when auditing, read
every claim as something to falsify, and start with the ones that promise the most.

**Why it isn't obvious.** A stale doc is usually imagined as *out of date* — describing a
feature that no longer exists, which is harmless because it fails loudly on first contact. The
dangerous form is subtler: the doc describes the intent accurately, the code implements a
subset, and both look right in isolation. It reads as a specification and functions as a wish.

**Taught by** the sink matrix, which said `--output` values were "canonicalised, symlinks
resolved". That was true of the intent and false of the implementation — the leaf was never
resolved, because it may carry `%j` and cannot be canonicalised. **That gap was A1**, and a
reviewer reading the matrix would have concluded the surface was covered.

**Caught again** three times in one sweep, all in the same direction. `cage.rs` asserted that
a non-dumpable holder's namespace "no rank can open", contradicting a 6.8 measurement recorded
elsewhere in our own tree. `settings.rs` said twice that ranks cannot join a shared PID
namespace, while `rank.rs` passes `--pidns` and two hardware arms confirm it. The submission
env was documented as "stripped" when it was merely dominated. Not one of the four erred
toward caution.

**Corollary — a finding list is a document too.** The backlog entry for the `PR_SET_DUMPABLE`
drift said three docs called it a "cheap win"; that phrase was already gone, and what had
survived was the *opposite* overstatement, sitting in the code. Working from a stale list
without re-deriving costs effort and can miss the live defect entirely. The same applies to
review output that was produced from documentation rather than from source: it inherits every
overstatement the docs had, which is why an outside review's mechanism claims are checked
against the suite before they are believed.

---

# Not yet earned

Candidates with one instance. Recorded so the bar stays visible, and so they can be promoted when a
second arrives.

- **The confiner must be external, independent, and require no cooperation from the confined.**
  *This is not where its authority comes from.* It is asserted as a design premise in
  [threat-model.md §1](threat-model.md), and it decided husk's architecture before there was any
  evidence to decide it with — it is why husk wraps any agent rather than trusting a runtime's own
  sandbox. It appears here because no incident has yet tested it, which is a fact about our
  evidence and not about its standing. Promote it if one ever does.
- **The resource envelope is the threat model.** For a compute agent, what it can *consume* may
  matter more than what it can read. Currently expressed as forced partition, preemptibility and
  wall limits, and not yet tested by an incident. Note that P7 already holds one leg of it: nothing
  verifies the partition is preemptible.
- **Teaching errors are a security control.** Stronger than P11: the claim that a well-explained
  refusal actively *reduces* attack surface by removing the incentive to probe. Plausible, so far
  unmeasured.
- **Prefer the mount table to the deny set.** What is not mounted cannot be reached, which is a
  stronger statement than what is denied. One instance — the `--tmpfs` floor.
