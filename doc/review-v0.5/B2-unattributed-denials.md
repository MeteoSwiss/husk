# B2 — is any denial path unattributed?

**Workstream B** (control-coverage) · **code-only, laptop** · **mechanical and complete**

## The question

Enumerate **every** refusal husk can produce, and check that each emits husk-attributable
output meeting the six properties. Which denials reach the agent without husk's name on them?

## Why this is on the list

A caged agent hit 22 `EROFS` lines. **Not one mentioned husk.** It concluded the filesystem
was broken and set about confident, wrong remediation — retrying, rewriting paths, working
around a rule it could not see. The opposite case is the partition guard: attributed, so the
agent complied in one step and stopped.

This is why teaching errors are a **security control**, not UX polish. An agent that cannot
see a rule routes around it; that is what persistence looks like without attribution.

## The six properties

1. **Actionable in one step** — names the constraint *and* the remedy.
2. **Attributed** — says *who* denies.
3. **Believable** — does not appear to contradict what the agent can observe. "Only `short` is
   permitted" while `sinfo` shows `normal` idle made an agent suspect a **spoofed message**.
4. **Stable** — byte-identical on retry, so it reads as standing policy, not transient failure.
5. **Consequence-bearing** — states what the rule *costs*, e.g. the inherited wall limit.
6. **Correctly scoped** — never claims a cause it cannot know (`SIGTERM` is preemption *or*
   wall limit *or* scancel, so the message says "ended early").

## The distinction that makes this interesting

Denials come from **two different places**, and only one can be attributed at the point of
failure:

- **husk's own refusals** — roughly 52 sites: `policy.rs` (~45), `step.rs` (5), `spool.rs` (2).
  These can and must carry husk's name.
- **The kernel's refusals** — `EROFS` from a read-only mount, `SIGSYS` from seccomp, `EPERM`
  from a namespace. **husk cannot attribute these at the point of failure**; the agent sees a
  bare errno from a syscall.

So for kernel-enforced denials the real question is different: **does husk pre-announce the
rule** so the errno is interpretable when it arrives? That is what the writable-set banner is
for. Treat "is the rule announced somewhere the agent will have seen" as the test, not "is the
error message attributed", which is impossible.

## Starting points

1. Enumerate all `Decision::Reject` / `Response::rejected` sites and score each against the six.
2. Separately enumerate the kernel-enforced denials the cage produces by design — read-only
   root, masked homes, `--unshare-net`, seccomp — and ask which are pre-announced.
3. Check property 4 (**stable**) mechanically: does any message interpolate a timestamp, a
   pid, a random id, or an ordering-dependent list? Those break byte-identity on retry.
4. Check property 6 (**correctly scoped**) for any message asserting a cause.

## What counts as a finding

- A husk refusal with no husk attribution.
- A kernel-enforced denial that no announcement anywhere prepares the agent for.
- A message that varies between two identical requests.
- A message asserting a cause husk cannot know.
- A message that names the constraint but no remedy.

## What a null result looks like

The enumeration itself, as a table: every refusal site, its six-property score, and the
exceptions with reasons. This brief is **mechanical and complete by design** — a partial
sample is not an answer. If every site passes, say so and hand over the table.

## Out of scope for this item

- Whether the messages *work* — that is measurable, not reviewable, and belongs to the
  agent-that-does-not-know-husk-exists instrument.
- Whether a message **discloses too much** — that is A7, and it pulls in the opposite
  direction. Note collisions and hand them over rather than resolving them here.
- Prose style, tone, phrasing preferences.

## Verdict

The table is the verdict. Where a message is claimed stable, generate it twice and `diff`.
