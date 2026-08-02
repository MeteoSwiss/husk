# A8 — can a teaching message be turned into a tool?

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

## The question

Set aside whether a message reveals a *secret* (that is A7). Does the **guidance itself** make
an attacker more effective — by telling it where to aim, or by giving it a reliable probe?

## Why this is on the list

A7 asks "is this fact obtainable anyway?". Even when the answer is yes, obtainable-in-principle
and handed-over-immediately are not the same thing operationally. An agent that must probe to
find the writable roots spends attempts and leaves a trace; an agent that is *told* them starts
at the target.

The explicit instruction from the plan: **ask the reviewer to falsify "announcing costs
nothing", not to accept it.** This is the brief where the teaching-errors design is allowed to
lose.

## The distinction to hold onto

Three different things, and only the third is a finding here:

1. **Disclosure** — the message contains a fact the cage hides. → A7.
2. **Convenience** — the message saves the attacker effort it could have spent. Real, but by
   itself not decisive; the same convenience is what makes a legitimate agent comply in one
   step instead of hammering.
3. **Capability** — the message provides something the attacker could **not** have assembled
   by trying: a reliable oracle, a differential, or a stable signal that turns guesswork into
   measurement. **This is the finding.**

## Starting points

1. **The writable set as a target list.** A refusal names every writable root. Does knowing the
   full set enable an attack that enumeration would not? Consider roots the agent would not
   have guessed — a second `allowWrite` directory it never saw.
2. **Messages as a differential oracle.** Two inputs, two different messages ⇒ a one-bit
   read of trusted state. Look for pairs: exists vs refused, in-set vs out-of-set,
   parse-error vs policy-error. A *stable, cheap, distinguishable* pair is a measuring
   instrument. (This is the same shape as `F5`, the spool symlink read that was a path oracle.)
3. **Stability as a weapon.** Property 4 says messages are byte-identical on retry — that is
   what makes them read as standing policy. It also makes them a **reliable** oracle. Is there
   any case where stability turns a noisy guess into a clean signal?
4. **The consequence-bearing content.** Messages state what a rule costs — the inherited wall
   limit, the forced partition. Does any of that reveal *scheduling* structure useful for a
   resource attack rather than a filesystem one?
5. **Refusal timing.** Not content but behaviour: does a refusal come back measurably faster or
   slower depending on trusted state? A timing differential is an oracle the message text does
   not contain.

## What counts as a finding

- A message pair that constitutes a reliable oracle for state outside the cage.
- Knowledge from a message that enables an attack enumeration would not have found — with the
  attack named, not merely asserted.
- A timing or ordering differential in the refusal path.
- A case where making the message *less* informative would measurably reduce attacker
  capability **without** reducing legitimate compliance. That last clause matters: a proposal
  that blinds the honest agent too is not an improvement, and should be reported as a
  trade-off rather than a fix.

## What a null result looks like

An argued answer to "announcing costs nothing", with the attempts behind it. The expected
result is that disclosure is convenience rather than capability — and **stating that, with the
reasoning, is the deliverable**, because it is the justification for keeping teaching errors as
they are. A null result here actively defends a design decision.

## Out of scope for this item

- Whether the facts are secret (A7).
- Message wording and the six properties (B2).
- Whether teaching errors *work* — measurable, not reviewable.

## Verdict

Execution inside; verdict outside. A claimed oracle must be **demonstrated**: show the two
inputs, the two outputs, and what trusted state they distinguish. "This message tells the agent
a lot" is not a finding without the mechanism that turns it into an advantage.
