# C1 — the real remaining delta to dropping Anthropic's runtime

**Workstream C** (substitution gap analysis) · **one agent, code-only** · **the crux is
plumbing, not security**

## The question

If husk provided the login sandbox itself, what would actually be missing? Produce a
**closeable list**, not an assessment.

## Why this is on the list

Step 6 of the roadmap is dropping Anthropic's runtime, split into 6a (husk provides the login
sandbox, still Claude-only) and 6b (any agent). The strategy is incremental reimplementation
until dropping it is nearly free — so the value of this brief is turning "reimplement a
sandbox" into "close a known list".

**The timing is deliberate.** Doing this earlier would have produced an incomplete answer,
because a third of the delta *was* the network layer and ours did not exist. It exists now, so
this is the first moment the question can be answered in one pass instead of two partial ones.

## What is already known — do not re-derive

- **The old "~40% of their fs model" gap is superseded.** F1–F6b closed it.
- **Their `apply-seccomp` is not enforcement, it is telemetry.** Their own header says
  *"bwrap's mount table is the only enforcement boundary"*, and it fails open. Do not count
  it as a control husk must replicate; count it as a **feature** (visibility) husk may want.
- **The PID-namespace half of the delta closed on 2026-08-01** (`8966289`). husk's job cage
  has `--unshare-pid` and ranks join it.
- Believed remaining: **fs telemetry** (a feature) plus **login plumbing**.
- `sandbox-runtime/` in the repo root is a vendored clone; the installed runtime can also be
  inspected. It does not expire — there is no deadline pressure on this analysis.

## Starting points

1. Enumerate their runtime's components and mark each: **replicated** / **not needed**
   (telemetry, Claude-coupling) / **missing in husk**.
2. For anything marked missing, say whether it is a *boundary* or a *feature*. Only boundaries
   block 6a.
3. The three 6a deliverables are agent-neutral by design — check the delta against them:
   (i) husk's own policy source (they read `.claude/settings.json`; husk needs its own),
   (ii) credential masking, (iii) a **session-level** wrap rather than their per-Bash-command
   bwrap.
4. Their `remove-bwrap-socat` branch is a useful data point: they moved bwrap+socat into one
   static Rust binary but **kept BPF generation in C/libseccomp**. The relay placement trick —
   relay in the sandbox netns, host pid/mount namespaces — is worth copying.

## The trap to check for explicitly

The Balfrin/Santis freeze is **not** "ripgrep is slow". It is an in-process **deny-set walk
blocking on Lustre metadata**. Dropping their runtime removes it only if husk's policy layer
does not reproduce the shape.

**Rule: express policy as MOUNTS, never as a scanned deny-set.** The compute cage is already
built that way, which is why it does not freeze. Flag any proposed 6a design that reintroduces
a walk.

## What counts as a finding

- A component of their runtime that is load-bearing for a **boundary** and has no husk
  equivalent.
- Something husk currently gets from their runtime **without knowing it** — an implicit
  dependency is the highest-value finding here.
- A proposed replacement that reintroduces the deny-set walk.
- Anything in the delta that is Claude-*specific* and therefore also a 6b problem.

## What a null result looks like

The list, itemised, each entry marked boundary-or-feature and blocking-or-not. A short list is
a good outcome. "Roughly equivalent" is not an answer; the point is the enumeration.

## Out of scope for this item

- Building any of it.
- 6b (non-Claude agents) beyond noting which delta items are Claude-coupled.
- TLS termination — that is 6b, and C2 touches its sequencing.
- Judging whether their runtime is *good*. The question is only what husk would have to
  provide.

## Verdict

Source-level on both sides. Cite their file and ours for each row, so the list stays checkable
when the code moves.
