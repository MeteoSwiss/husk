# C3 — the 6a acceptance test: how Claude-coupled is husk?

**Workstream C** (substitution gap analysis) · **one agent, code-only** · **partly mechanical**

## The question

Does the string `claude` — and the assumptions behind it — appear anywhere except one row of a
three-column table?

## Why this is on the list

The design axiom says the confiner must be external to, independent of, and not reliant on the
cooperation of the confined. A consequence falls out: husk should wrap **any** agent
identically — Claude, a closed vendor CLI, a self-hosted model's harness. Generalisation is
not a feature request; it is a property of the trust model.

6a's real deliverable is therefore not "a login sandbox" but three **agent-neutral** pieces:
(i) husk's own policy source, (ii) credential masking, (iii) a session-level wrap. What is
genuinely Claude-specific should reduce to a three-column table: **binary to exec · config
directory to allow · API hosts to allowlist.**

**The acceptance test: if `claude` appears anywhere else, 6b is a rewrite rather than an
extension.** This brief measures how far from that husk is today.

## The part that is mechanical

Grep for `claude`, `anthropic`, `.claude/`, `ANTHROPIC_*`, and classify every hit:

- **Table row** — the three legitimate columns.
- **Vendor artefact** — a path husk did not choose (`.claude/settings.json` is *their*
  settings format; husk reading it is a coupling, and a known one).
- **Incidental** — comments, docs, test fixtures. Note but do not weight.
- **Real coupling** — logic that behaves differently because the agent is Claude.

## The part that is not mechanical, and matters more

A grep finds the string. It does not find **assumptions**. Ask also:

1. **Policy source.** husk reads `.claude/settings.json` today. That is a vendor format with a
   vendor schema. What is the neutral equivalent, and what breaks when the vendor changes it?
2. **Process shape.** Does anything assume the agent is a single long-lived process, or a
   Node process, or that it re-execs per command? Their runtime wraps per Bash command; husk's
   compute cage is session-level. Which shape does the login side assume?
3. **Filesystem conventions.** Does anything assume a config directory *at all*, or that it
   sits under `$HOME`?
4. **Credential names.** `ANTHROPIC_AUTH_TOKEN` is one vendor's spelling. Is masking keyed on
   specific names, or on a declared set?
5. **Behavioural coupling.** Does anything depend on how the agent *behaves* — how it invokes
   tools, how often it retries, whether it reads stderr? This is the coupling nobody greps for,
   and the cheap experiment that finds it is running husk against a **different model**
   (Claude Code speaks to any OpenAI/Anthropic-compatible endpoint, so this costs almost
   nothing).

## Starting points

The three 6a deliverables, the settings-file reader, the credential masking configuration, and
the launcher. `rank.rs`'s controlled environment set is a good example of the *neutral* shape
to compare against.

## What counts as a finding

- A `claude`/`anthropic` reference outside the three legitimate columns.
- An **assumption** that is Claude-specific without naming Claude — the highest-value finding
  here, because the acceptance test as written would miss it.
- A design decision that would have to be reversed to support a second agent.
- Coupling to agent *behaviour* rather than to agent *identity*.

## What a null result looks like

The classified hit list, plus an explicit answer to the assumption questions. A short list of
real couplings — with the vendor policy format almost certainly on it — is the expected
outcome. **The honest answer may be "husk is more Claude-coupled than the axiom implies"**;
that is useful, and it is better learned now than during 6b.

## Out of scope for this item

- Removing any coupling found.
- Whether other agents are *worth* supporting.
- IDE-embedded agents: the per-session wrap works for anything you can `exec`, and those are
  not that. It is a stated hard boundary, not a gap.

## Verdict

Mechanical for the string; argued for the assumptions. Cite a file and line per coupling so
the list can be re-run later as an actual test.
