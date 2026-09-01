# Principles

**Level 1 of four.** These are the things that would still be true if husk were rewritten in
another language, for another scheduler, on another cluster. Everything below this file is an
instance: the harm catalog in [threat-model.md](threat-model.md), the control-to-harm mapping in
[constraints.md](constraints.md), and the finding-by-finding record in review-v0.5/
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

**This example was false for months, which is why it is still the example.** Rust's encapsulation
unit is the MODULE, not the type. `SandboxReady` and `SettingsIntact` were field-less unit structs
declared beside their only consumer, so the bare name was a value expression anywhere in that file:
`SandboxReady::establish(stub, sbatch).unwrap_or(SandboxReady)` compiled with no new warnings, left
every test green, and launched the agent with the bind failed. The type carried nothing; this
paragraph did — a `P12` over-claim in the file that warns about `P12`.

**Three attempts to state a general property here were wrong, so this paragraph now states a
specific fact.** The wrapper's witnesses are unforgeable because FOUR things are simultaneously
true of them: each has exactly one field; that field is private; they are declared in `mod
witness`; and that module exposes nothing but two exact `establish` signatures and holds no trait
`impl` at all. Under those four conditions the only way for code outside the module to obtain one
is to call an `establish` and have it return `Ok`. Every one of the four is load-bearing, and every
one has been measured false in this very file at some point: the module was missing, so the bare
name was a value expression (`B5-1`); a `#[derive(Default)]` made `.unwrap_or_default()` mint from
a *failed* establish (`RC-5`); a `pub(crate) fn establish_not_applicable` was admitted by an audit
that matched a prefix (`RC2-4`); and three lines of `impl From<()> for SandboxReady` inside the
module made `().into()` compile with 33/33 green (`RC2-4`).

**Why not a rule.** "A witness is unforgeable exactly when the compiler admits no expression
outside its module that yields the type" is *sufficient and not necessary*, and it is false of
husk's own code: `SandboxReady::establish(stub, sbatch)?` in `run()` is an expression outside `mod
witness` that yields the type, and so is `w.clone()` after a derive. Neither makes anything
forgeable. The repair before that one stated the recipe as the rule and was wrong in both
directions. A criterion that calls the working example forgeable is not a criterion, and the third
rewrite of one sentence is the signal to stop writing sentences and start listing conditions.

**What the test can carry, and what it cannot.** `the_witnesses_stay_unforgeable_and_so_does_the_next_one`
enumerates the module's own `pub(crate) struct` declarations — the module, deliberately, and not the
`use witness::{…}` line, because a witness reached by full path or by a second `use` line is not on
that line and went green — and compiles four forgeries against each name: the bare constructor,
`.unwrap_or_default()`, a struct literal, and `().into()`. It also refuses trait impls inside the
module and admits only the two exact `establish` signatures. **So a fourth witness is covered by
being DECLARED, whichever way it is then imported.** What no tool can cover is the body: an
`establish` that returns `Ok` without checking anything is indistinguishable from one that checks.
That half is review, and saying so is cheaper than a naming rule that implies otherwise.

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


**Instance, 2026-08-19 (a verdict from ABSENCE):** an empty `grep` for the guard's
`not regular files on this node` message was read as "the guard enforces, A1 closed" — twice,
and wrong both times. The absent line meant only "the fail-open branch did not fire", which is
neither enforcement nor its opposite. The positive evidence — job-5138292's log showing the
guard refuse on the real descriptor — is what settled it. *A security verdict drawn from a
missing log line is a control that failed silently reported as a control that held.*
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

## P13 — The sandbox is the only layer the agent can see, so it is blamed for everything it does not explain

Announce what husk **changed**, not only what it refused. A modification the confined party
cannot observe becomes a theory about husk, and the theory is usually wrong.

**Why it isn't obvious.** `P11` covers refusals, and a refusal at least tells you something
happened. This is the quieter half: husk drops an option, masks a file, forces a value — the work
proceeds, differently, and nothing marks the difference. The agent then reasons from the only
layer it can name.

**Said best by the party it costs.** From a caged agent's own friction log, after husk silently
discarded its `#SBATCH` resource directives and it concluded "husk grants 2 CPUs per job":

> *"That was right about the symptom and wrong to name husk as the cause without evidence — but
> the reason I reached for husk is that it was the one layer I could see, and I had no way to
> tell whether my request had been modified."*

That is the asymmetry stated exactly. Every other layer — SLURM, the filesystem, the module
system — is either invisible or trusted. husk is visible and new, so it is the available
explanation for anything surprising, whether or not it is the cause. **Being the visible layer is
a duty to narrate, not just a duty to refuse.**

**Taught by** `#SBATCH` resource directives that were validated and then dropped: the job ran with
SLURM's defaults, `SLURM_NTASKS` came back empty, and nothing anywhere said husk had changed the
request. One hour, and a confident wrong conclusion about husk's design.

**Caught again** by the credential auto-scan masking `var3d.env`, a module-load script named by
DACE's own build instructions. Two layers agreed it was a secret; neither said so, and `source`
reported a bare `Permission denied`. Three failed 128-rank jobs. And a third time the same week,
when a broker that had exited left every call to time out at 120s with a message that named no
cause — the reason sat in a log the cage hides from the agent by design.

**The remedy is the banner, and it is already proven.** The same log records what worked:
*"The compute-cage banner listing the writable set. That one prevented several wrong turns."*
So the banner is husk's attribution channel, and everything husk silently changed belongs in
it — the masked files, the allocation the job actually holds, the options husk forced. It costs
a few lines at job start and converts an hour of inference into a glance.

**The tension with `P11`'s A7-1 resolution.** Splitting the audience — teaching to the confined
party, detail to the operator — is right for *refusals*, where the detail can be an existence
oracle. It is wrong for *modifications*: what husk changed about the agent's own request is not
a host fact, and withholding it is what caused all three incidents above.

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

## P14 — A config file outlives the software that reads it, so absence must be the safe answer

An operator's config file is written once and read by every version that follows. It is normal,
not exceptional, for a file to predate the field being looked up — so **what husk does when a
field is absent is a policy decision made years in advance, by someone who cannot see the
field.**

Three rules follow, and they are cheap only if adopted before the second version ships.

**Absent means the restrictive reading.** A new knob missing from an old file must never mean
"allow everything". husk's sets already work this way: no `uenvs` entry means the job may not
choose an image, not that it may choose any. The failure this avoids is silent and arrives at
upgrade time, when nobody is looking at the config.

**Never repurpose a name.** A field whose meaning changes gets a new name, and the old name is
refused with a message saying what to write instead. Nothing else can catch a same-name
semantic change — not a schema version, not a validator — because every mechanical check passes.

**Refuse what you cannot understand; never migrate silently.** husk has no merge algorithm and
must not grow one: that is the road to `.pacnew`, `.rpmnew`, and a decade of distribution
upgrade folklore. A file from a newer version is refused by name (`version`), and a file with
an unknown key is refused rather than partially applied — *a key husk does not recognise might
be a restriction*, and applying the rest of the file would enforce a policy the operator never
wrote.

**Instances.** `~/.husk/config.json`'s absent-means-unconfigured semantics, and the `version`
field accepted in v0.5 purely so a later version can be refused with a sentence instead of a
serde error. Also the reason `deny_unknown_fields` is on: it makes `"partition"` for
`"partitions"` a refusal rather than an empty policy.

**Corollary — a shared `$HOME` makes "the config file" ambiguous.** Balfrin and Tasna are twins
sharing a home, so husk selects `config.<system>.json` before `config.json` and **does not
merge them**. Merge rules are where config systems go wrong; which file is in effect should be
answerable with `ls`, and husk says which one it read at startup for the same reason the build
stamp is in the banner.

## P15 — A control names a target; check the name resolves to the object you meant

Three controls in one day were correct, enforced, and aimed at the wrong object.

`sandbox.filesystem.denyWrite: [".Rprofile"]` is a real deny that the runtime really applies
— to `$HOME/.Rprofile`, because a relative path resolves against the **declaring source's**
base directory and husk declares in `~/.claude/settings.json`. The project's `.Rprofile`, the
one the agent can write and the operator's `R` will source, was never named.

`precreate_login_masks` created that file so the bind would have a source, on the premise
that "an absent path cannot be bound". Measured on Balfrin in a directory that started
empty: three files created, **zero** binds in `/proc/self/mountinfo`, all three writable. It
supported a mechanism that was not there, and paid for it by fabricating an `.hg/` directory
— a Mercurial repository root — in every project husk was launched in.

`SettingsIntact` refused a launch when a settings layer overrode husk's sandbox block, and
checked the cwd. The runtime anchors `localSettings` on the canonical **git root**, so
launching one directory down loaded a file the control never looked at. It refused the exact
file at one path and started happily on it at another.

**None of these is a bug in the control.** Each does what it says. The failure is upstream:
nobody checked that the target it names is the object in the threat model. That question is
cheap to ask and cheap to answer — `grep /proc/self/mountinfo` settles the first two in a
second — and expensive to skip, because the artifact *looks* correct in review and in the
config, and a shape test on it passes.

The tell is that the evidence is always about the CONTROL and never about the OBJECT: "the
entry is in the list", "the file is created", "the check runs". Ask instead what the object
looks like with the control in force. If you cannot say how you would see the difference,
the control is unverified however carefully it is written.

**Corollary, from the same day (see also `P9`).** An assertion that iterates the list it is
checking cannot notice that list shrinking: moving an entry OUT removed the assertion
covering it, and the suite stayed green with the hole reopened. Anchor an assertion on the
CONTRACT — the thing that must remain true — not on the mechanism under test. And a test
that stubs its oracle measures your model of the world: switching one such stub to real
`bwrap` immediately showed mount points arriving at mode 0444, which the stub had hidden and
which made a passing assertion pass for the wrong reason.

## P16

**The failure mode of a fail-closed control is a denial of service aimed at the operator.**

Closing a hole by refusing is right. But the refusal lands on whoever is *using* husk, not on
whoever is attacking it — so every fail-closed change must answer a second question, and it is
not the one its author is thinking about:

> **What does this newly refuse, and who can trigger that?** The agent, the operator, the site's
> environment, or a nested/concurrent husk.

**Entry evidence — five instances in the round of 2026-08-31/09-01, none noticed by its author,
every one caught by an adversarial reviewer.** A `BrokerReady` fix let `pid=1` in an
agent-writable file turn a 0.007 s launch into a permanent refusal — and its own comment scored
the primitive safe because "every wrong guess is a refusal rather than a launch", when the
refusal *was* the payload; that commit was reverted. A `%A`/`%a` fix extended a symlink check to
husk's own default output, refusing **every** submission after one `ln -s`. The cage-floor fix,
done the obvious way, still killed every job off-CSCS. A reviewer's own recommended repair would
have refused every tarball install under a git-managed home. And four pre-existing guessed
ceilings were measured refusing real work: `--cpu-bind` at 8 masks, `--dependency` at 16 jobs,
`--array` at 22 indices, `--exclude` at 26 nodes.

**A limit a real job hits is a defect, not a virtue.** State the number a real submission
produces against any bound you add.

Two corollaries, both earned the same day. **Decide the question by measurement, not argument** —
the MUNGE-mask fix was settled by a live probe showing the ordinary configuration takes the
accepting path, not by reasoning about how nodes are usually built. And **where the two
directions genuinely differ, do not force symmetry**: husk's two mask enforcers are deliberately
divergent, with the guard *announcing* the divergence at job start, because making them agree
would have meant refusing.

Cited by: `FIX-C`/`FIX-C2` (the reverted attempt and its replacement), `FIX-A2`, `FIX-M`,
`FIX-JK2`, `FIX-B3`, `FIX-L`.

## P17

**A value that means "a check passed" must not be constructible where the check is not.**

Not "wrap secrets" — husk has few secrets. The rule is about *evidence*: whenever one part of
the system tells another that something was verified, ask who else can say the same thing. If
the answer is "anybody", the type or the file is a naming convention and not a control.

**The rule is not Rust-specific.** Rust gives the most elegant form, but husk has already
learned it twice at two different layers, and the second one has no types in it at all.

| layer | the evidence | who else could produce it | the fix |
|---|---|---|---|
| Rust | `SandboxReady`, a field-less unit struct beside its consumer | any line in that 1,373-line file — `.unwrap_or(SandboxReady)` | a **private field** in a module its consumers are outside of |
| POSIX | `<spool>/owner` existing | the confined agent, who must be able to write that directory — by `touch`, by `mkdir`, by symlink | a **readiness byte on an inherited fd** the agent never holds |

Both are the same sentence. In a language with encapsulation the answer is a private field
behind a module boundary; where there is no type system the answer is to choose a **channel the
other side cannot write** — a descriptor created before the untrusted process exists, not a path
in a directory it owns. The general shape is: *make the unverified state unrepresentable, and if
you cannot, make the forged state unproducible by anyone but the verifier.*

**Why a type and not a review rule.** The dangerous edit does not look careless. It looks
defensive:

```rust
let ready = SandboxReady::establish(stub, sbatch).unwrap_or(SandboxReady);
```

That reads as *"do not let a setup failure crash the launch"*, and it silently removes every
submission-surface control while the session still reports itself as brokered. A review rule
catches that only if the reviewer knows the rule and is looking. A private field catches it
always, including in the fourth witness nobody has written yet.

**Entry evidence.** `B5-1` (the Rust half, `10f87d8`), `B5-2`/`RC-4`/`RC2-1` (the POSIX half —
three attempts, because the first two argued about *dispositions of a file the agent owns*
instead of changing the channel; `36a308f`), and the contrast that proved it: `netallow::Entry`,
1,200 lines from the forgeable witnesses in the same crate, refuses the identical forgery at
compile time with `E0451`.

**Corollary — hand-construction in tests is where this rots first.** A test that builds the
value directly skips the constructor *and* every check inside it. Measured: the false friend in
`the_floor_is_the_home_the_site_has_and_not_the_string_users` hand-builds an `FsPolicy`, so
`drop_unmountable_hides` never runs on it — which is why it stayed green under the mutation that
restored `M-1`'s bug. Give tests a constructor whose **name says the validation was skipped**;
do not give them a struct literal.

