# Compute-job threat model — husk SLURM broker

## Base cage
When the broker submits a job, the injected re-exec guard re-sandboxes it on the
compute node (`seccomp-wrapper bwrap …`):
- `--ro-bind / /` — whole filesystem read-only
- `--tmpfs /users` — **all** homes hidden (own + others': `~/.ssh`, `~/.aws`, `~/.claude/settings.json`)
- `--bind <project dir>` + `allowWrite` roots — the only writable areas. The project dir
  is where **husk was launched**, captured by the broker before the agent ran — NOT the
  directory the agent happened to be in when it ran `sbatch`. `req.cwd` is agent-supplied,
  so deriving the write boundary from it would let the confined side choose its own
  confinement (see "announce the boundary" below).
- **Reads outside the cage are broadly unrestricted** (`--ro-bind / /`), deliberately:
  shared input data and the software stack live outside any project directory.
  Confidentiality rests on the `/users` mask, the credential denies and env masking, not on
  read scoping. **"Unrestricted" is not literally true and the job banner used to say it
  was** — there are three deliberate gaps, and each FAILS IN A DIFFERENT SHAPE, which is
  what made the false claim expensive: a masked home or `denyRead` path is an EMPTY
  DIRECTORY, a credential file reads empty or `EACCES` depending on how it was bound, and a
  path under a hidden home is `ENOENT`. An agent promised unrestricted reads diagnoses all
  three as "the file is not there" and goes looking elsewhere. The banner now names the
  gaps and the shape of each.
- `--ro-bind <allowRead carve-outs>` — specific re-exposed reads
- credential file denies, env masking, symlink guard (features below)
- `--dev-bind-try /dev/nvidia*` — GPUs
- `--unshare-net` — no network by default; with an allowlist configured, **one hole**: a
  unix socket to husk's egress proxy, which runs outside the cage (see below)

## Design principle (confine, do not merely forbid)

Some options cannot simply be forced to a constant without breaking the workflows husk
exists to serve. `--output`/`--error`/`--chdir` are the case in point: HPC run scripts
find their files by name, and ICON writes `#SBATCH --output=<case>/run/LOG.<exp>.%j.o`.
Forcing `slurm-%j.out` is not a cosmetic annoyance to such a workflow, it breaks it.

The resolution is not "force" versus "allow" but **construct from a confined value**:
husk reads the request, validates and canonicalises it, checks it against a boundary the
job could already reach, and emits its own option. The agent influences the value; it
never contributes bytes to slurmd's parser.

Two things make it safe, and both are load-bearing:

1. **The boundary is one the job already has.** These paths are confined to the working
   directory subtree, which is bound writable into the cage. Nothing new is granted — only
   a choice of *where within* the existing blast radius. If the confinement were to some
   other boundary, this argument would not hold.
2. **Nothing is validated that someone else will re-expand.** SLURM expands `%j`, `%x`
   and friends *after* husk has checked the string, so an allowed specifier whose value
   the agent controls is a parser differential of the F13/F14 kind — `<workdir>/%x` with
   a job name of `..` resolves above the workdir. So `%` is refused in directory
   components (husk cannot resolve what it cannot expand) and the specifier set is an
   allowlist with `%x` excluded.

Why it matters that the sink is slurmd: it writes these files **as the user and outside
the cage**. An unconfined output path is therefore an uncaged arbitrary-write primitive —
job stdout into `~/.bashrc` or a `.git/hooks/` file is AV2 with the cage bypassed
entirely. The confinement, not the cage, is what stops that.

An out-of-subtree request is **rejected with a teaching message**, not silently replaced.
A job whose logs went somewhere other than where it asked is the failure mode that wastes
an afternoon.

**Native `sbatch` is the reference.** Where husk behaves differently without a security
argument, husk is wrong. The old forced `--chdir` was such a divergence — nobody chose it,
it was just what "force the option to a constant" produced, and it silently ignored the
`#SBATCH --chdir` that plain `sbatch` honours. Verified 2026-07-31: submitting ICON
uncaged resolves every path correctly *because* `--chdir` is obeyed. A divergence with no
threat behind it is a bug, exactly as an undeclared cage-profile divergence is.

**When a constant becomes configurable, audit every place that assumed it.** Making
`--chdir` settable turned two strings that had always been identical — the job's `$PWD`
and the broker's validated `req.cwd` — into two different things, and the guard was
passing `$PWD` to the step-broker. The rank cage's writable region silently narrowed to
whatever subdirectory the job started in, and the symptom was a Fortran I/O error deep
inside ICON's initialisation with nothing pointing at husk. Same family as *capture
values, don't trust references*: the reference was fine until the thing it referred to
could move.

## Design principle (announce the boundary)

A cage whose denials are indistinguishable from filesystem or quota errors sends agents
down expensive wrong paths. Worse for an LLM specifically: an unattributed error does not
merely slow it down, it invites *confident wrong remediation* — rewriting a runscript that
was never broken, or blaming Lustre.

Measured, 2026-07-31, from a caged agent running a production KENDA experiment: the job
died with 22 `Read-only file system` lines across a 390-line log, **none** of which
mentioned husk. Seventeen were `rm:` chatter from an `rm`-then-`ln` idiom and read as
ignorable; the fatal one was 120 lines later and named the *victim* path, not the cause.
Confinement had worked and failed closed — the gap was purely diagnostic.

So: **the cage states its own boundary inside the job**, as a banner listing every writable
path and as `HUSK_WRITABLE` in the environment. A list, not a root — `allowWrite` adds
paths beyond the project dir, and announcing one root would be a new way to mislead.

Two things this deliberately does NOT do, both rejected on principle rather than cost:

* **No `LD_PRELOAD` to attribute `EROFS`.** It fails for static binaries and under MPI
  launchers, and it means injecting code into the cage to improve an error message.
* **No preflight scan of the script for write targets.** That is securing our *model* of
  shell rather than shell itself — the F13/F14 shape, where a false negative reads as
  approval. Making the boundary predictable removes the need.

The partition guard is the standard to match: it names the constraint, names the fix, and
fires at submit time before compute is burned. The same agent complied with it in one step,
with no investigation.

## Design principle (the unit of confinement) — one cage per job-on-a-node

**The security border is the job on a node, not the process.** All ranks of one MPI
job are a **single trust domain**: same uid, same allocation, same files, same data,
launched from the same script. There is no boundary between rank 0 and rank 3 to
defend — the boundary that exists is *job ↔ host*.

So the job gets **one shared user namespace**, created once per job and used by every
task of every step. A cage per *task* does not add a boundary; it makes **N redundant
copies of the same one**, and the copies are not free — they actively cost containment
and function:

| symptom | root cause |
|---|---|
| Cray MPICH dies `process_vm_readv: EPERM` | each task's bwrap makes its own **user namespace**; siblings cannot `ptrace_may_access` each other |
| `--unshare-pid` unusable **for a rank** | it would put each rank in its own PID namespace and break rank-to-rank CMA — a rank JOINS the job namespace with `--pidns` instead (see below) |
| per-job binds (`/dev/shm`, step spool) repeated per task | they were never per-task to begin with |

Only the **user** namespace turned out to be load-bearing among those copies. Mount and
network namespaces stay per task: they cost nothing, and sharing the network namespace is
not even available — `bwrap` builds its sandbox through an intermediate user namespace and
switches to a second one, so the netns it creates is owned by a namespace no rank can
join. The price is one network *relay* per rank when the network opens; the filtering
proxy, which is the part that matters, stays one per node behind a bind-mounted unix
socket.

### The PID namespace: the job cage has one, a rank cannot

Every process on a compute node runs as the **same uid**, so without a PID namespace a
caged job can see, signal and `process_vm_readv` every other process husk owns on that
node — including the un-caged step-broker and egress proxy, which deliberately hold what
the cage removes (MUNGE, the daemon route, the one route out). Those are defended by
clearing `PR_SET_DUMPABLE`, which is a *credentials* check the kernel performs. A PID
namespace is stronger and structural: the job cannot **name** them, so there is nothing
left to check. With `--proc /proc` the job's process table shows only its own tree
(measured: 5 entries against 429).

**Both cages have one, by different means, and the difference is the same finding as the
user namespace one layer down.**

The **job** cage gets `--unshare-pid` — it holds no ranks, so a private namespace costs it
nothing, and MPI started directly from the batch script stays inside that one namespace and
keeps CMA.

A **rank** must never get `--unshare-pid`: that would put every rank in its own namespace,
unable to name its peers, which is exactly how sibling *user* namespaces broke Cray MPICH's
Cross Memory Attach and killed ICON. Instead a rank **joins** the job's namespace, the same
way it joins the shared user namespace and named by the same holder pid:

```
bwrap --userns 9 --pidns 8 …      # 9 = /proc/<holder>/ns/user, 8 = /proc/<holder>/ns/pid
```

The holder creates the PID namespace *after* the user namespace — a kernel rule, not taste:
`CLONE_NEWPID` needs `CAP_SYS_ADMIN`, which an unprivileged process only has inside a user
namespace it owns. `unshare(CLONE_NEWPID)` does not move the caller, only its children, so
the holder forks; that child is PID 1, keeps the namespace alive (a PID namespace dies with
its PID 1, taking everything in it), and reaps orphans. It inherited the user namespace, so
one pid names both namespaces.

Measured end to end against the real holder: two ranks come up as **pid 2 and pid 3**, each
can see the other, and an un-caged process outside is neither in their `/proc` nor
signalable (`kill` → `No such process`). Isolation and working MPI at the same time.

One process is deliberately visible inside a rank's namespace: PID 1, the holder's
namespace-keeper.

**It is not the step-broker**, and the distinction matters because the process name invites
exactly that misreading: PID 1 is `husk-slurm-broker --hold-cage`, the same binary in its
holder mode, so `comm` reads `husk-slurm-brok`. The holder runs *outside* any cage and owns
a deliberately **bare** user namespace — no mounts, no network, no MUNGE, no daemon route,
no memory worth reading. It exists only to keep the namespace alive.

The trusted step-broker, which does hold MUNGE and the route to slurmctld, is in neither
namespace: a rank cannot see it, signal it, or read it (`cma.outside`).

**A rank cannot kill it either.** Measured 2026-08-02: `kill -9 1` from inside the
namespace is silently discarded — a PID namespace's init ignores every signal it has
not installed a handler for, and that protection holds even against `SIGKILL` from a
namespace member. An earlier version of this document said a rank could signal PID 1
and take its own job's ranks down with it; that was wrong, and wrong in husk's favour.
The `kill -0` probe it rested on tests *permission*, not *delivery*.

(The same rule is why husk tears the holder down with `SIGKILL` rather than `SIGTERM`:
from an ancestor namespace those two are the only signals a handler-less init cannot
ignore. A `SIGTERM` — including one delivered by `PDEATHSIG` — is discarded, which
left the holder outliving its parent on every job until it was measured.)

*(Earlier note, corrected: `--pidns` was thought unusable because bwrap answered `Can't send
pid: Invalid argument`. That was a holder with no uid map — the overflow-uid case. With the
identity-mapped holder husk actually creates, `--userns` and `--pidns` together work.)*

Measured, 2026-07-31: two sibling bwrap cages cannot CMA-read each other (`EPERM`)
**even with Yama neutralised**; two cages sharing one identity-mapped user namespace
can. The user namespace was the deciding gate all along — it is a fifth member of the
`ptrace_may_access` set alongside credentials, Yama, the dumpable flag and PID
visibility, and we had not written it down.

Two consequences to hold to:

1. **Joining must be fail-closed.** With a cage per task, failing to build it means the
   task does not run. When a task *joins* something instead, a bug could let it run
   **outside** — silently. Two guards, because this is the one genuinely new risk the
   design introduces: the task refuses to start if the holder's namespace is unreadable,
   and `bwrap --userns` exits rather than inventing a namespace of its own. Both are
   tests, not comments.
   Measured 2026-07-31 (laptop, Yama neutralised, against a control that succeeds
   rank-to-rank): a rank cannot `process_vm_readv` **anything outside the shared user
   namespace** — not the holder, not an uncaged process, not even a fully dumpable one.
   So the broker now has *two* independent protections rather than one: the namespace
   boundary and `PR_SET_DUMPABLE`. Keep both; neither should be load-bearing alone. It
   also means the holder is protected without needing the dumpable flag. It *could* use
   it — measured on kernel 6.8, a non-dumpable holder is still openable and joinable with
   `bwrap --userns`, correcting an earlier claim here that it could not — but it is left
   off deliberately: the gain is a third layer on a process that is already unreadable and
   holds nothing, while the risk is kernel-dependent (Balfrin runs 5.14; if joining broke
   there, every step would die). Measure on the target before making that trade.
   Belongs in `selftest.sh` as a hardware-verified arm rather than an inference.

   **Scope of the CMA concession, stated exactly.** A rank can read the memory of the
   other ranks of ITS OWN job, and nothing else: not the broker, not an uncaged process,
   not another job's ranks (they have their own holder, so they are siblings — the very
   configuration that returns `EPERM`). The login cage is untouched, since the exemption
   is `--profile=single-node` only and smoke test 8 pins that it cannot leak into
   `--profile=login`.

2. **Sharing is scoped to the job, and is exactly one namespace.** Only the **user**
   namespace is shared, because it is the only one that cost a capability; mount and
   network namespaces stay per task. Ranks can therefore CMA each other, which is within
   the trust domain defined above. Neither the broker nor any other job is inside it —
   the broker stays outside and is non-dumpable regardless, which is half the reason the
   CMA read concession is acceptable.

Generalises beyond MPI: the question to ask of any new cage is *what is the trust
domain here*, and to put exactly one wall around it.

## Design principle (the network hole)

Egress is off by default and, when configured, is **one hole of a shape husk chooses**:

```
rank/job cage (--unshare-net: no route at all)
  socat TCP-LISTEN:3128 ──► /tmp/husk-<uid>-<jobid>/net.sock ──► husk proxy ──► the internet
        (dumb relay)          (a FILE, not a route; ro-bind)      (outside the cage)
```

The socket crosses the network namespace because it is a **filesystem** object, not a
route — the same reasoning that makes the `/run/munge` mount mask load-bearing rather than
a syscall filter.

It lives in a short, node-local, owner-only directory rather than in the step spool,
for two reasons. A unix address must fit in `sun_path` (108 bytes, kernel-fixed), and
the spool path spent enough of that budget that a slightly deeper project would have
lost its network with no explanation. And the spool is inside the workdir, which the
cage binds **writable** — so the job could delete or replace its own socket. The
directory is bound in read-only, which stops that; `connect(2)` still works through a
read-only bind (measured on 6.8; confirmed on Balfrin's 5.14.21 by `net.live`, which
fetches through exactly this socket). `/tmp` is world-writable and job ids are public,
so husk creates the directory rather than accepting one, and the proxy re-checks owner
and mode before binding: a directory it cannot own means no egress.

Three properties are asserted rather than assumed, by `selftest.sh`:

1. **The hole is the only hole.** A direct connection from inside the cage must still
   fail. If it ever succeeds, the allowlist is decoration.
2. **An unlisted host is refused with a 403**, not a timeout — a refusal that looks like a
   network fault costs somebody an afternoon.
3. **SLURM daemon ports are refused**, including under `*`. AV8 as a test rather than a
   paragraph.

The policy is enforced **outside** the cage, in the broker's trust domain, and read from
files the agent cannot write. The relay inside the cage carries no policy at all: one
proxy per node, one relay per rank, and what must never be duplicated is the decision.

What this does NOT give: control over *what* a job says, only *where* it may say it.
husk tunnels bytes after authorising the destination and never inspects them. Content
control needs TLS termination — ROADMAP 6b, where it also buys credential injection so an
agent can use an API key it never sees.

## Design principle (the cage)
Layers must be **independent**. `--unshare-net` *will* be relaxed (allowlisted
socat at best, open internet at worst), so the **filesystem cage must protect
confidentiality on its own, assuming exfiltration is possible.** No secret's
safety may depend on "there's no network."

## Design principle (the gate) — deny by construction on the submission surface
The cage principle above protects a job *once it runs*. This one governs *what the
broker agrees to submit*. It exists because every critical we found (F13, F14, F24,
F26, F27) was the **same bug wearing different clothes: the broker secured its
*model* of sbatch, not sbatch.** The exploit always lived in the delta between the
argument grammar the broker parses and the one slurmd actually obeys.

Two consequences make that delta exploitable, and both are the rule to design against:

1. **Never forward adversary bytes into a second parser.** The broker forwards agent
   argv (minus a strip list) and the script body straight to slurmd, so slurmd
   re-parses adversary-influenced input. Two parsers that can disagree = a
   parser-differential hole (LangSec). Safety requires the broker to reduce every
   input to a **canonical form it fully controls** before slurmd sees it — one
   channel, one parser.
2. **A denylist is a bug list.** "Strip the dangerous options, pass the rest" is
   default-*allow*; each finding was an entry we hadn't added. The submission surface
   must be **default-deny** like the cage is: the broker *constructs* the invocation,
   forces everything security-relevant, parses the few benign resource options into
   typed values and **re-emits them canonically**, and **rejects anything it doesn't
   recognise.** Then glued shorts, `--wrap`, unknown flags, and next year's new sbatch
   option fail closed *by construction* — there is no delta left to attack.

**Reason about the SINK, not the source.** Don't enumerate input *fields*; enumerate
the security-relevant **decisions slurmd makes** (it runs as you, with MUNGE + net),
and for each list **every channel** that can influence it. That grid is *closeable*;
"list of dangerous options" is open-ended. Every unproven cell is a candidate bug —
F24 = (code-runs × body/env), F27 = (code-runs × `--wrap`), F13 = (output-path ×
glued spelling) were all *visible holes* in it:

| slurmd decision | channels that can set it | broker control today | must dominate → |
|---|---|---|---|
| **what code runs** (→ whether it's caged) | script file · `--wrap` · stdin · **the script's own first line** | snapshot all three into `body`; husk submits **its own wrapper on stdin** and runs the agent's body as DATA inside the cage. `--wrap` stripped (F27) | the bytes slurmd executes are husk's, entirely — the agent authors none of them, and there is no staged path to substitute |
| **stdout/stderr path** | `-o/-e` (4 spellings) · `#SBATCH` · `SBATCH_OUTPUT/ERROR` | husk always EMITS `--output/--error` on the CLI, which outranks both `#SBATCH` and the env (CLI > env > directive) — the env is **dominated, not stripped**; glued shorts split first (F13). The *value* may come from the request but is confined to the job's writable set: the parent is canonicalised on disk, and the LEAF is `lstat`ed separately because it may carry `%j` and cannot be canonicalised — **that omission was A1**, an arbitrary write as the user outside the cage. `%` specifiers allowlisted, `%x` excluded | confinement at submit time is necessary and **not sufficient** (P3): slurmd opens the path when the job starts, so `--open-mode=append` denies the race anything to destroy and the job guard refuses to run a body whose fd 1/2 resolve outside the writable set |
| **working dir** | `-D/--chdir` · `#SBATCH` · `SBATCH_CHDIR` · `req.cwd` | emit `--chdir`; confine `req.cwd` (reject `/`, floors, traversal) (F15/F19); a requested `--chdir` must resolve inside the `req.cwd` subtree | emitted + confined; `cwd` treated as adversarial, not metadata. The writable bind is still `req.cwd`, so `--chdir` changes where the job STARTS, never what is writable |
| **partition/account/qos/reservation** | `-p` (4 spellings) · `#SBATCH` · `SBATCH_PARTITION` | require+force a partition from the operator's allowed SET; glued split (F14); force `--account`; **`--qos` and `--reservation` REJECTED** on CLI and in the body | forced value wins; mismatch rejected. The set makes the guarantee the WEAKEST member's, so an operator adding a partition widens the envelope — see below |
| **uenv/repo mount** (root, via slurmstepd) | `--uenv/--view/--repo` · `#SBATCH` · `SBATCH_UENV*` | strip CLI; **reject** body/env selection that differs from session or names `--repo` (F26) | reject dominates (never rewrite the body) |
| **inherited env** | `--export` · `#SBATCH` · `SBATCH_EXPORT` | force `--export=ALL` on CLI in both branches (F24) | forced value wins; residual = env-secret masking (AV7) |
| **node/resources** | `--nodes/--time/--mem/--gpus` … | parse → validate (per-option grammar) → re-emit canonically; reject unknown/invalid (`interpret_cli`) | allowlist by construction — **shape only, not magnitude**: see "The resource envelope" below |
| **identity** | — (runs as you; MUNGE) | not settable via submission | n/a |

Two verbs the matrix did not cover, added after the v0.5 review found both:

| verb | decision | channels | control |
|---|---|---|---|
| **`scancel`** | which jobs die | the argument list | **provenance, not permission** — only ids this broker submitted (`Broker.submitted`); any `-` prefixed argument refused; ids matched against a grammar; all-or-nothing so ownership cannot be probed. See "The second mutating verb" above. |
| **read-only queries** | what husk reads OUT of the cluster, as you, outside the cage | the whole argv | per-verb option allowlist (`policy::query_spec`), values charset-checked with **no slash**, re-emitted as canonical `--long=value`. "Read-only" is a property of what a command does to the SCHEDULER; `sacct --completion --file=X` reads X, and `--batch-script` prints any job's stored script. Forwarding the agent's argv made husk a read oracle. |

### The second mutating verb: `scancel`, gated on provenance

Everything above governs *creating* work. `scancel` is the only other mutating verb husk
brokers, and it needs its own answer, because the harm is not confidentiality — it is
**destroying work that is already running**. On a shared cluster that is the resource
envelope again, pointed backwards: cancelling a colleague's 24-hour production run is worse
than most reads an escaped agent could manage. And SLURM will not stop it, because the agent's
jobs and the user's production jobs run under **the same uid** — the scheduler sees one
person, correctly.

So the gate cannot be permission (SLURM already grants it); it has to be **provenance**. The
broker remembers the job ids *it* submitted this session and refuses every id that is not in
that set — `Broker.submitted`, checked in `spool.rs::cancel`. Array tasks and steps
(`4991406_3`, `4991406.0`) are mapped back to their base id first, so an agent cannot launder
an id by decorating it.

Three properties are worth naming, because each is the same discipline as the submission
surface:
- **Default-deny on the option surface, not a selector denylist.** Any argument starting with
  `-` is refused outright. `-u`, `--me`, `--state=PENDING` are named in the *message* for
  teaching, but the code never enumerates them — a future `--filter` fails closed too.
- **Grammar, not sanitising.** An id must match `<digits>[_<digits>|.<digits>]`, ≤20 digits,
  before it becomes an argument to the real `scancel`. Same rule as everywhere: this string
  crosses into another program's parser.
- **All-or-nothing.** If any id in a multi-id request is unowned, the *whole* request is
  refused and nothing is cancelled — no partial effect, so the agent cannot discover ownership
  by watching which of a batch died.

**Residual, accepted:** the agent can still cancel jobs it submitted itself. That is the
point — it is the same authority it already had by not submitting them. The refusal message
lists this session's job ids, which discloses nothing: `squeue` shows them to this uid anyway.

### The resource envelope, and why the partition carries it

On a shared cluster the realistic harm from a misbehaving agent is not reading
`/etc/shadow` — it is burning node-hours, storming the scheduler, or delaying someone's
production run. That is a different axis from containment, and husk answers it in one
line rather than with parameter caps.

**The forced partition is the control.** Every brokered job is required to request, and is
forced onto, one of the partitions in `HUSK_SLURM_PARTITION` (recorded at install). That
setting is a **list**, not a single name — one partition is not enough on a real cluster
(Balfrin needs a GPU one and a post-processing one) — and the envelope is therefore only as
strong as the **weakest member of the list**. Nothing in husk checks the weakest member, or
any member. Choose
a **preemptible** one and the property is structural: a job on a preemptible partition is
interrupted by any job on any other partition, so an agent's work **cannot block the
machine** no matter how much of it there is. No cap, no accounting logic, no per-option
magnitude checks — the scheduler enforces it, continuously, for free. That is why the
resource validators in `sbatch::REGISTRY` deliberately check **shape, not magnitude**
(charset + length; `v_array` accepts `1-100000`), and why that is a defensible position
rather than an oversight: magnitude is bounded by the site's own QOS and by preemption,
both of which exist whether husk does or not.

Two things follow, and both matter:

1. **The guarantee is a property of the CONFIGURED partitions, not of husk.** If any
   partition in the list is not actually preemptible, this control silently is not there
   for jobs that request it. Confirm per site and **per member** — `scontrol show partition
   <name>` and the QOS's preempt settings. Nothing in husk checks it, and **nothing fails
   loudly if it is untrue**, which makes it an open instance of *a control that can fail
   silently has already failed* (`P7`) and the reason H11 is in the harm catalog. An
   install-time or startup-time check is the natural home; see `context.md`.

   **Choosing it is a supervision-mode decision, and operators should make it
   deliberately:**

   | you are… | choose | because |
   |---|---|---|
   | watching the agent, iterating, want a job to start *now* | a short/interactive partition | turnaround beats the guarantee; a human in the loop is the control |
   | letting an agent run for hours or weeks unattended | a **preemptible** partition | nobody is watching, so the machine must be the one that cannot be blocked |

   **The default is the safe one.** `DEFAULT_PARTITION` is `preemptible` — so an install
   that configures nothing lands on the guarantee, and weakening it takes a deliberate
   act: `install-husk.sh --slurm-partition <name>`. That is the right way round for a
   knob whose wrong setting is silent, and it is why this is a default rather than a
   required argument. A site running something else has made a choice, not drifted.
2. **Preemption is then a correctness risk, not just an annoyance.** A preempted run
   leaves partial output. With `lrestart = .FALSE.` an ICON run that was interrupted
   looks, to anything reading its output directory, much like one that finished — and an
   agent may report that the science ran. For a weather service that is a worse failure
   than an escape. Preemption must therefore be made **loudly distinguishable from
   completion** in the job's output and in the husk job log. *(Open; not yet built.)*

What husk does **not** bound: node-hours consumed against the account, and queue
pressure. Whether it should is a question for the site rather than for this document —
partition, QOS and account limits are the operator's instruments, and husk forcing a
single partition is what makes them apply.

Every row is now closed **by construction**: the broker builds the invocation from an
allowlist (`sbatch::REGISTRY`) — Forced options forced, benign resource options parsed
→ validated → re-emitted canonically, everything unrecognised rejected
(`interpret_cli`); dangerous/unknown `#SBATCH` directives and `#BB`/`#DW` lines
detect-and-rejected (`body_reject_reason`). The broker no longer forwards adversary
bytes into slurmd's parser, so the F13/F14/F24/F26/F27 class is closed at the structure,
not instance by instance.

**The rules, compressed** (each generalises the findings in parens):
1. *A denylist is a bug list* — default-deny the submission surface; construct + re-emit + reject-unknown. (F13/14/24/26/27)
2. *Never forward adversary bytes into a second parser* — canonicalise before slurmd. (F13/14/24/26)
3. *Every field is an adversarial choice, including descriptive-looking ones* (`cwd`, `id`). (F1/F15/F17/F19)
4. *Capture values, not references* — a name/path the agent can still change is unvalidated. (F20; the inline body-snapshot done right)
5. *Enforce invariants, not mechanisms*, as close to slurmd as you can reach (job/task prolog or SPANK is the privileged ideal; the re-exec guard is the unprivileged approximation). (F27)
6. *Clean architecture only proves the axes you thought about* — transport-trust, memory-safety and fail-closed control-flow were all clean; the bugs lived on **input-language coverage**, an orthogonal axis. Assume the policy is incomplete over any rich interface and buy coverage adversarially (the multi-agent + docs-vs-code passes are that budget).

## Design principle (what we rely on) — the load-bearing set

A command from the agent passes several gates. Only some are ours, and only some are
**load-bearing**: husk's guarantee must hold even if every cooperative layer fails.

- **Load-bearing (kernel- or Rust-enforced, deterministic):** the bwrap **filesystem
  cage** (read-only root, hidden homes, `/dev/null` masks — policy ours, enforcement the
  runtime's), the **network** boundary (`--unshare-net` today), husk's
  **`seccomp-wrapper`** syscall deny-list, and the **broker** (allowlist + force-safe +
  re-sandbox for every job).
- **NOT load-bearing (convenience / defense-in-depth):** the agent runtime's permission
  rules, its static command analyser, its intent classifier, and interactive prompts.
  These reduce noise and catch the obvious; they are advisory to us. In particular an
  **AI intent classifier can never be part of the guarantee** — intent is unbounded, and
  its verdicts are non-deterministic.

Two consequences we hold to:
1. **Never let a test (or a claim) rest on a non-load-bearing gate.** A probe blocked by
   a prompt or a classifier has proven nothing about containment — see the
   trusted-layer-driven rule in [BRINGUP.md](BRINGUP.md).
2. **Encode expectations about the runtime as TESTS, not prose.** The cooperative gates
   change with upstream releases (twice in one day, 2026-07-27). A doc describing them
   rots silently; `selftest.sh` asserting the cage's actual mount shape rots **loudly**.
   This is also why the mount table — not a write-probe — is the oracle: it is mechanism,
   not opinion, and no gate stands in front of it.

This invariant survives husk owning the whole sandbox: the walls become ours, the
cooperative gates disappear, and the sentence still reads correctly.

## husk features (defense references)
| id | feature | state |
|---|---|---|
| F1 | credential file denies (`credentials.files` → `/dev/null`) | committed |
| F2 | write model (`allowWrite`/`denyWrite`, default-deny) | committed |
| F3 | file-level read denies (`denyRead` files → `/dev/null`) | committed |
| F4 | env credential masking (`credentials.envVars` → `--unsetenv`) | committed |
| F5 | symlink-escape guard (drop symlinked carve-outs) | committed |
| **F6a** | bounded credential auto-scan (workdir-only, depth-capped) | committed |
| **F6b** | write-protection of auto-exec files (`.git/hooks`, `.git/config`, …) | committed |
| base | `/users` tmpfs, `--ro-bind / /`, `--unshare-net`, unix perms, the broker itself | — |

## Attack vectors (network assumed OPEN — worst case)
| # | vector | severity | who defends it | status |
|---|---|---|---|---|
| **AV1** | read a workdir/carve-out secret (`.env`, key, `.git-credentials`) → exfiltrate | HIGH | F1 (declared) + **F6a** (un-declared, workdir scan) + `/users` tmpfs (removes home secrets) | **covered** — patterns from Read() globs is a refinement |
| **AV2** | plant an auto-exec payload (`.git/hooks`, `.git/config`, build scripts) that fires later on login with net + your identity | HIGH | **F6b** (ro-bind auto-exec files in writable roots) + F2 (root ro; writes only in workdir/scratch) | **covered** — nested-repo `.git` is a refinement |
| **AV3** | tamper the job's own outputs/results you trust | LOW–MED (integrity) | — (user's own writable space) | **accepted / out of scope** |
| **AV4** | read another user's loose-perm `/capstor` data → exfiltrate | MED–HIGH | **unix permissions** (job runs as you; reads only what you can) + optional `denyRead` | not a cage regression (= login) |
| **AV5** | symlink from writable workdir to a hidden home | LOW | `/users` tmpfs (link → empty) + F5 | **covered** |
| **AV6** | general internet abuse — C2, download-and-run, botnet, internal scan | HIGH open / LOW allowlisted | **network policy**: `--unshare-net` plus, when configured, a host+port allowlist enforced by husk's own proxy OUTSIDE the cage — *not* an FS control | **implemented and hardware-verified** (Balfrin, 56/56): allowlisted host reachable, unlisted host and scheduler ports refused with 403, no direct route. `*` remains available for sites that choose open egress |
| **AV7** | read a secret from the **inherited env** → exfiltrate | HIGH | F4 (`--unsetenv` of declared `credentials.envVars`) + compute-cage `--unshare-net` (no exfil route today) | **partial** — the broker forces `--export=ALL` on BOTH paths (only ALL activates the uenv view), so an un-declared secret env var is residual on every submission |
| **AV8** | direct `sbatch`/`srun` from the compute node (MUNGE + net) → **bypass the broker** | HIGH | THREE independent controls now: `/run/munge` masked so a job cannot authenticate; SLURM daemon ports refused by the proxy even under `*`; and `srun` itself brokered. `--unshare-net` is no longer the only thing holding it | **covered** — was a landmine while no-net was the sole control |

## Key findings
1. **`/users` tmpfs is the network-independent backbone** — kills home secrets,
   SSH keys, and settings tampering (H7) under *any* network policy. Biggest win.
2. **Confidentiality features (F1, F4, F6a) are load-bearing once net opens** —
   this *reverses* the earlier "the scan is marginal" take, which quietly assumed
   no-net.
3. **F6 = both halves.** F6a's auto-scan is the HPC-safe replacement for
   Anthropic's `/users`-wide ripgrep (the Lustre-freeze culprit): bounded to the
   workdir, depth-capped, file-count circuit-breaker, skippable.
4. **AV8 is the sharpest landmine.** On compute, AF_UNIX is *not* blocked and
   `/run/munge` is bound; only `--unshare-net` stops SLURM RPCs. Relaxing the
   network without re-blocking compute-side submission reopens the exact broker
   bypass the project exists to prevent.
5. **Never open-internet on compute.** Go straight to allowlisted socat — demotes
   AV6 to LOW and lets you keep `slurmctld` off the list to blunt AV8.

## Residual: the auto-exec mask is a denylist, and denylists are bug lists

**AV2, deferred execution.** The job writes something into the writable project directory
that a program the *human* later runs treats as executable configuration. It fires outside
the cage, as the user, at a time husk has no say over. The v0.5 review demonstrated the git
version end to end: a planted `core.hooksPath` survived the job, `git init` preserved it, and
the next `git commit` ran the payload.

husk masks the ones it knows about. **That list can never be complete, and pretending
otherwise would be the more dangerous error.** What is covered today:

| path | why it executes | how it is handled |
|---|---|---|
| `.claude`, `.vscode`, `.idea` | agent/editor config, hooks, tasks | `--tmpfs` per writable root |
| `.git` | `core.hooksPath` in `.git/config` | masked *by shape* — see below |
| `.hg` | `[hooks]` in `.hg/hgrc`; hg trusts an hgrc owned by the running user | same shape rule; hgrc masked empty when absent |
| `.Rprofile` | R sources it from the cwd at startup unless `--vanilla`. No trust prompt. | real file read-only, empty file when absent |
| `.mcp.json` | an MCP server entry is a command the runtime runs | read-only when present, backstopped by `enableAllProjectMcpServers: false` |

**Masking by shape** means husk looks at what `.git`/`.hg` actually *is* before deciding. A
real repository gets its hooks masked and its config protected; a `.git` *file* (an ordinary
`git worktree`) gets bound read-only, because putting a tmpfs under a file made bwrap fail
and took the whole cage down; anything absent gets masked whole, because masking a path
*inside* a `.git` that was not there is what created the repository the plant needed.

**Two rules were learned the expensive way and generalise beyond git:**

1. *Protected-if-present is not protection.* `--ro-bind-try` silently skips a file that does
   not exist, so every auto-exec file that is not normally present stayed plantable. Anything
   harmless when empty is now masked with an empty file instead.
2. *Do not create the thing you are defending.* bwrap creates the mountpoints it is given, so
   a mask aimed inside a directory brings that directory into existence.

**Known-and-not-covered**, with reasons rather than silence:

- **`.gdbinit`** — modern gdb gates local auto-load behind `auto-load safe-path`, so it is
  usually inert. Not masked; revisit if a site loosens that.
- **`.envrc` (direnv)**, **`.dir-locals.el` (emacs)** — both require an explicit human
  approval step before they run. The approval is the control.
- **Anything not yet on the list.** Subversion is *not* on it, deliberately: SVN has no
  client-side hooks, so a `.svn` working copy executes nothing.
- **Nested config directories.** The mask applies at the top level of each writable root.
  `<root>/sub/.claude` is not masked, because finding it would mean walking the project tree
  — the in-process directory walk that is the documented cause of the Lustre stalls, and a
  thing this project has a standing rule against. Bounded instead by making the *readers*
  use trusted paths: the egress proxy now resolves its allowlist from the project dir rather
  than from the job's `--chdir`.

**The by-construction version of this control would be "the job may write outputs but may not
create or modify dot-entries at the root of a writable directory."** bwrap cannot express
that — it masks paths, not classes of future creation — so it would mean staging job output
and filtering on the way out. That is real work and a change to how husk feels to use, and it
is the honest direction if this list keeps growing.

**What keeps this survivable meanwhile** is that the writable root is chosen by a human who
knows what is in it. That is why husk refuses to run with a home directory as its write root
(a home is full of auto-exec files nobody enumerated) and announces the writable set on every
job. A user who points husk at a directory they do not understand has a weaker boundary than
one who does, and no mask list changes that.

## Closed by the v0.5 security review

Recorded because a residual list that never shrinks stops being read, and because two of
these were things this document previously asserted were already safe.

| was | now |
|---|---|
| The submitted script was `head + guard + tail`, so an agent shebang or a Unicode-whitespace line ran BEFORE the cage; and it was staged at an agent-writable path that could be `rename()`d between write and open (race won 33/100 at 2 ms) | husk submits **its own wrapper on stdin**; the agent's script is data, run inside the cage. Three demonstrated bypasses, one defect. |
| `is_workdir_allowed` was applied to `req.cwd` but never to the value that became the writable BIND, and the floor predicates were raw string compares (`//users/me` walked through) | the write root is checked too, and paths are normalised before any floor comparison |
| A `denyWrite` under the floor was emitted as a `--ro-bind`, which exposes its source — `denyWrite: ["/users"]` re-exposed every home | floor-filtered; `allowWrite: ["/"]` refused with a message saying what it would have cost |
| `--tmpfs <root>/.git/hooks` CREATED a `.git` that was not there, and `--ro-bind-try .git/config` then skipped the file it had just made creatable — a `core.hooksPath` plant that ran on the next `git commit` | `.git`/`.hg` masked by SHAPE; anything harmless-when-empty is masked with an empty file rather than protected-only-if-present |
| A malformed settings file resolved to an EMPTY policy, silently dropping every `denyRead` and credential mask | policy parse failures refuse to start; a bad allowlist warns loudly and runs with no egress (tighter, not weaker) |
| `[ -O "$_d" ]` followed symlinks, so a co-tenant could redirect a rank's `/dev/shm` bind into a directory of ours | symlink-safe; and the directory is now released |
| The cage outlived its guard on a group SIGTERM; the holder's orphans became node-global zombies | `--die-with-parent`; holder reaps by disposition |
| `--qos`/`--reservation` were agent-settable while this document claimed the family was forced | both rejected, on the CLI and in the body |
| Read-only verbs forwarded the agent's whole argv into another SLURM binary running outside the cage | per-verb allowlist, no slashes in values, canonical re-emission |
| `run_sbatch` had no timeout, so a hung submission wedged the single-threaded broker — including `scancel` | watchdog and process group, as its sibling already had |

## Residual / accepted risks
- **A caged job can write to its own per-step `apinfo` directory** inside `SlurmdSpoolDir`
  (`<spool>/mpi_cray_shasta/<job>.<step>`). Cray MPICH opens `apinfo` `O_RDWR` although it
  only reads it, and the cage's read-only root made that `EROFS` and broke the PMI
  bootstrap (gate C8) — so the rank cage binds that one directory read-write. The
  directory is the user's, mode 0600, and belongs to this job, so the exposure is narrow.
  **ACCEPTED for now, deliberately, and flagged to the security review** (Christoph,
  2026-07-31). The fix is known — bind a husk-owned COPY over the path, the same
  "mediated stand-in instead of the capability" move as the broker itself, applied to a
  file — but it can only be done per-rank after the step exists, so it puts a race into
  the pre-cage path that the MPI bootstrap depends on. Reviewers: if you judge the
  exposure to justify that complexity, say so and we build it. Detail in
  SRUN-MPI-DESIGN.md "TODO — read-only shim for the apinfo file".
- **AV3** — out of scope; treat agent-produced artifacts as untrusted.
- **AV4** — bounded by unix perms; not worse than login.
- **AV7 (all submissions)** — the broker forces `--export=ALL` on both the uenv and
  no-uenv paths (only `--export=ALL` activates the uenv view; a locked allowlist
  leaves it inactive), so the job inherits the login env; an un-declared secret env
  var (not in `credentials.envVars`) is residual → consider a vetted baseline env
  allowlist later.

## Next actions
- Build **F6a** (bounded auto-scan) + **F6b** (auto-exec write-protection).
- Treat **AV8 mitigation as a hard prerequisite** of the network rework (relax
  `--unshare-net` *only* together with compute-side SLURM re-blocking).
- Network target: **allowlisted socat, `slurmctld` excluded.**

## Design decisions (from the threat discussion)
- **One parameterized fs-sandbox generator.** `settings.rs` is *the* bwrap-arg
  builder, parameterized by a profile (`Login | Compute`) so that when husk goes
  standalone (diverges from Anthropic) it does NOT fork into two near-identical
  fs-sandbox codebases. Only the `Compute` profile is wired now; the `Login`
  profile is config, not a rewrite, when husk owns login.
- **Scan cadence = `ScanMode { PerConstruction, CacheOnce }`.** The scan always
  runs *at construction*; what differs is construction cadence + whether the
  result is cached. Compute rebuilds the sandbox per-JOB and **bwrap binds are
  frozen mid-job** → structurally scan-once. Login rebuilds per-COMMAND →
  `PerConstruction` effectively re-scans and catches mid-session credential drops.
- **Re-scan rule:** re-scan iff a *mutable, readable region prone to runtime
  credential-drops* is exposed. Compute: home is tmpfs'd + the only writable
  regions are the job's own + bwrap is frozen → **false → scan once**. A
  read-only home carve-out is static → scanning it once is exact (a scan-*scope*
  question, not a frequency one). Login: home exposed → true → re-scan.
- **Symlinks** (AV5): runtime symlinks the job creates are **namespace-confined**
  — they resolve inside the cage, and `/users` tmpfs neutralizes any that point
  into a home. Only a bind-**source** host symlink on a carve-out can escape, and
  **F5** handles that. bwrap need not "cut" symlinks; AV5 is fully covered.
- **Permission `Read()` globs on compute:** the settings-file denies
  (`.claude/settings.json`) are **moot** — home is tmpfs'd, the files don't exist
  in the cage. The credential `Read()` globs (`*.pem`, `.env*`, …) require a scan
  to translate globs → concrete `/dev/null` binds for *bash*; that scan is **F6a**,
  and its patterns can later be sourced from these globs.
- **F6a = one bounded workdir scan at submit** — workdir only (never `/users`-wide),
  depth- and file-count-capped (circuit-breaker), fail-safe, patterns = the
  standard secret set. **F6b** = read-only re-bind of auto-exec files
  (`<root>/.git/hooks`, `<root>/.git/config`) within writable roots.

## Open decision (deferred until husk owns login)
- Login-scanner **aggressiveness** (auto re-scan when the user opens a home-hole
  vs. cache-and-accept-the-risk) and **scan performance tuning**. Deferrable —
  once husk owns the login sandbox we can iterate + benchmark on the cluster. Does
  not block the compute side (which is scan-once by construction).
