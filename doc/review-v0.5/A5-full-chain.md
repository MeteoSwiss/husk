# A5 — the full chain: `sbatch → broker → srun → broker → ranks`

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `A-RULES-OF-ENGAGEMENT.md`

> **Refreshed 2026-08-05.** The chain still has four layers and the cross-hop question is
> unchanged, but both ends have moved again. Marked ★ below.
>
> ## ★★ Read this first: this brief has never actually run
>
> The last attempt did not produce a result. **The cage-build collision killed three of its
> four concurrent jobs in bwrap setup**, so the deep chain was *blocked*, not walked. The
> "REFUTED" verdicts recorded against hops 2–4 came from reading code on a laptop afterwards,
> not from the cluster. Treat them as untested hypotheses, not as prior results.
>
> That collision is fixed. **This is a first run, not a re-run** — and it is the only brief on
> the list of which that is true. Two consequences:
>
> - The concurrency this brief needs now works. If jobs start dying in setup again, that is
>   itself the finding — stop and report it rather than working around it.
> - Nothing here has been picked over. Where the other briefs are hunting for a fourth bug in a
>   surface that has yielded three, you are walking a chain that no reviewer has reached the
>   end of.

## The question

Each hop in the chain has been reasoned about on its own. Does anything cross **two** hops that
neither hop's local check would catch — a value that is benign to one broker and dangerous to
the next?

## Why this is on the list

The single-hop surfaces are covered by A2/A3/A4 and by the existing tests. This item exists
because the architecture is **recursive**: the login broker submits a job, the job runs a
step-broker, the step-broker launches ranks — and a recursive structure lets a value launder
its meaning between layers. F26 was a taste of it: a `#SBATCH` line benign to the submission
check became a root mount at the slurmd layer.

## What the code does today

The chain is two broker instances of the same code at different privilege positions:

1. **Login broker** (trusted, outside any cage) validates the `sbatch` request, constructs the
   guarded script, forces the security-relevant options, submits.
2. **The job** runs the guarded script inside the job cage; an in-cage `srun` **stub** forwards
   step requests to
3. **the step-broker** (trusted for the step, outside the rank cages) which validates each step
   request and launches
4. **ranks**, each building its own cage inside the shared namespaces.

The recursion is deliberate: `srun` inside an allocation needs a compute-node broker, which is
the same brick stacked. Both broker instances default-deny their own surface.

★ **What moved at each end, and why it matters to a cross-hop attack:**

- **Hop 1 → 2 changed shape.** husk no longer submits the agent's script. It submits **its own
  wrapper on stdin**, and the agent's body travels separately, as a file at
  `<write-root>/.husk-body-<req.id>.sh`, read by an interpreter husk names *inside* the cage.
  So the body is no longer a thing that passes THROUGH slurmd — it is a thing husk parses at
  hop 1 and the cage executes at hop 2. The laundering question survives but its carrier is
  different: the body is now **data at hop 1 and code at hop 2**, which is the classic shape
  for exactly this class.
- ★★ **A new hop appeared, upstream of everything this brief previously covered.** As of
  `da7a6e6` husk *interprets* the body's `#SBATCH` directives and **re-emits the resource
  family onto sbatch's own command line**, merged with the CLI options by option name. The
  brief you last read said the two had "no shared parser"; that is now false.
  
  This is the cross-hop shape you are hunting, and it is new: **a byte the agent writes into a
  data file at hop 1 becomes an argv element husk hands to slurmd — before hop 2 exists.** The
  agent's body is the least-trusted input in the system and sbatch's command line is the most
  trusted channel husk has. Everything in between is one parser and one merge rule, written
  in an afternoon. N5 owns the parser in detail; **your question is different — what does a
  laundered option do *further down the chain*, at hops 3 and 4, that hop 1 would not notice?**
- ★ **Hop 4 gained an inner shell.** B4-F8 put an `exec` hop inside each rank's cage: the rank
  script now carries a single-quoted inner script (`rank.rs:241`) that closes the namespace fds
  and `exec`s the workload. Another quoting surface on the MPI-critical path, and the path
  where literal quotes once took every job down.
- **`job_args` moved into the guard.** With no script operand there is nowhere on sbatch's
  command line for them, so they are `sh_quote`d into a `set --` line in the generated script.
  Agent bytes, quoted by husk, into a script the **uncaged** first instance of the guard
  parses. That is a hop-1 value landing in a hop-1.5 shell. (Overlaps A2; the chain question
  here is whether it survives *further* down.)
- **`req.id` is now a path component at hop 1** (the body file) and the guard deletes that path
  at hop 2. One agent-supplied string, two hops, two different operations. (Overlaps A3.)
- **Hop 3 → 4 gained a runtime-built argument.** The rank script now assembles the MUNGE mask
  on the compute node and expands it unquoted onto bwrap's command line. A value computed at
  hop 3, executed at hop 4.

## Starting points

1. **Value laundering.** Find a field the login broker passes through as data that the
   step-broker later treats as a control — or vice versa. The job script body is still the
   obvious carrier, but ★ **note what changed: the body is no longer opaque to the login
   broker's option checks.** husk now reads it, and a directive in it becomes an argv element.
   So the body is simultaneously (a) data staged to a file, (b) input to husk's option parser,
   and (c) the place step requests are generated. One artefact, three readers, three different
   notions of what it means. That is the richest laundering surface in the system.

   The specific chain worth walking: **a resource option accepted at hop 1 and re-emitted, that
   changes what hop 3 or hop 4 does.** `--ntasks`, `--gres`, `--distribution`, `--cpus-per-task`
   all shape the step layout the step-broker later launches ranks into. Hop 1 validates them as
   *charsets*, not as semantics — the grammar's stated job is to keep shell metacharacters out
   and let slurmd judge meaning. So ask what a value that is charset-legal and semantically
   hostile does three hops later.
2. **Trust position confusion.** Each broker instance is trusted *relative to what it launches*
   and untrusted relative to what launched it. Is there any code path where an instance treats
   input from the wrong direction as trusted? The environment carried down the chain is the
   place to look (ties to A2).
3. **The stub boundary.** The in-cage `srun` stub is inside the cage (untrusted); the
   step-broker is outside (trusted). Everything crossing that boundary is adversary-influenced.
   Is every field re-validated at the step-broker, or does any check rely on the stub having
   already done it?
4. **Identifiers across hops.** Job ids, step ids, spool paths derived at one layer and
   consumed at another — can one be forged or aliased so a later layer acts on the wrong
   resource? (`scancel` provenance, `Broker.submitted`, is a related check — see A6.)
5. **Failure interleaving.** If a step request fails validation, what state is left for the
   next request? A partial-failure that leaves a usable artefact is the resource-lifecycle
   class (B1) meeting the trust boundary.

## What counts as a finding

- A value that is safe at hop N and unsafe at hop N+1 because only hop N checked it.
- Any point where a trusted instance treats input from its confined side as trusted.
- A forged or aliased identifier that redirects a later hop.
- State from a rejected request that a subsequent request can use.

## What a null result looks like

A walk of the chain naming, at each boundary, what crosses it and where that value is
re-validated — with the laundering attempts and what each produced. A demonstrated "every
field is re-validated at every trust boundary it crosses" is the deliverable even if nothing
breaks.

## Out of scope for this item

- The single-hop mechanics already owned by A2 (env), A3 (body), A4 (step spool). Reference
  them; do not repeat them. This item is specifically about **cross-hop** effects.
- Multi-node. Single-node is the shipped profile; the chain is the same shape but this review
  targets what ships.

## Verdict

Execution inside; verdict from the trusted logs at each hop. Because the same binary is both
brokers, a finding here often reproduces as a unit test against the broker in the relevant
trust position — the strongest possible reproducer.
