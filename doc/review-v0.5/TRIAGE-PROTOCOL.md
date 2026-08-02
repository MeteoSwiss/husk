# Triage protocol — pass 2 of the husk v0.5 review

Pass 1 produced **candidates**. Your job is not to admire them. It is to find out which ones
survive contact with the code.

## Your stance: attempt refutation, not confirmation

For each finding, **try to make it wrong**. Look for the reason it does not hold: a guard
elsewhere in the call path, a precondition that cannot occur, a misread of the code, a test
that already covers it, a platform assumption that fails here.

This framing is deliberate. You are reading a document written to persuade, containing the
finder's own evidence and conclusions. An agent that sets out to check whether a good argument
is correct will usually decide that it is. An agent that sets out to break it will not.

**A REFUTED finding is a success, not a failure of the review.** The v0.4 review kept a
"what held up" section for exactly this reason: knowing a control is sound is worth as much as
knowing one is broken, and it is the half that never gets written down.

## What is yours to decide, and what is not

You are given the finder's reasoning because you need its **reproduction recipe** — withholding
that would only make you redo discovery and report false refutations.

But **the finder's verdict and severity are not evidence, and you must not inherit them.**
Treat every `CONFIRMED` in the source document as an unverified claim. Reach your own
conclusion about:

- **what the observation means** — the mechanism, not just the symptom;
- **how bad it is** — severity, with your own reasoning stated.

Where you agree with the finder, say *why you agree*, from your own work. Never "as the finder
notes".

## The four outcomes

Every finding gets exactly one:

- **CONFIRMED** — you reproduced it, and the mechanism is as described.
- **RECHARACTERISED** — the phenomenon is real, but the mechanism or the impact is materially
  different. **State the correct one.** This outcome exists because pass 1 already produced two
  findings of the form "true, but not for the stated reason" — and the stated reason is what a
  fix would be built on, so getting it wrong is expensive.
- **REFUTED** — it does not reproduce, or the reasoning does not hold. Say precisely why.
- **UNRESOLVED — NEEDS HARDWARE** — cannot be settled on this laptop. Say **exactly what
  would settle it**: the command, the cluster, the condition. This becomes the next Balfrin
  task list, so vagueness here has a cost.

Do not invent a fifth. If a finding is partly right, that is `RECHARACTERISED`.

## Rules

1. **Work in severity order**, hardest-hitting first. If you run long, the important half must
   already be done.
2. **Do not fix anything.** No source file may be modified. Verification only — fixes come
   later, test-first, from someone who can see all the triage results at once.
3. **Flag suspected overlaps, do not resolve them.** If a finding looks like it covers the same
   defect as another brief's territory, say so and move on. Deduplication happens after triage,
   deliberately: two agents finding one defect from different angles is *evidence*, and merging
   them early destroys that signal.
4. **Reproduce, do not re-argue.** Where a claim can be settled by running something — a signal,
   a generated mount table, a hostile value through the real binary — run it. Pass 1 set that
   standard; do not lower it.
5. **Read the errno before assigning a cause.** `SIGSYS` is husk's seccomp filter and the shell
   reports it as 128+31 = **159**. `EPERM`/`EINVAL`/`ESRCH` are the kernel. Conflating them has
   cost this project a hardware round.
6. **Beware the stale binary.** `slurm-broker/husk-slurm-broker-x86_64` is a gitignored prebuilt
   that outranks `target/release` in the selftest's search order. Build, and pass an explicit
   `--broker` path.
7. **Do not trust a test that could not fail.** Two arms in this project passed for months while
   measuring something other than what they claimed. If a test is cited as covering a finding,
   check that it *could* have failed.

## Output

Write to `doc/review-v0.5/triage/<ID>-triage.md`.

- A summary table first: finding ID, outcome, your severity, one line.
- Then one section per finding: what you did, what happened, your verdict, and your reasoning
  for severity. Include the commands you ran.
- A short note on any finding you could not get to, so the gap is visible rather than silent.
