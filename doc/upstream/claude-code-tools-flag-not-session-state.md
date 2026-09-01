# Upstream: `--tools` is invocation state, not session state — the restriction is silently lost

**Status:** drafted 2026-08-11, not yet filed.
**Where:** Claude Code CLI — `--tools`.
**Why husk cares:** `--tools` is the mechanism an external sandbox uses to keep host-side file
tools away from the agent. husk's whole reason for using it is that `Read`/`Write`/`Edit` run
*beside* the sandbox rather than inside it (see [`doc/agent-profile-claude-code.md`](../agent-profile-claude-code.md)).
If the restriction can lapse, the sandbox has a hole it cannot see.

## The report

A session started with a restricted tool set can regain the full default set — including
`Read`, `Write` and `Edit` — without the operator doing anything and without any notice.

**Observed by the operator, twice, after `/compact`** in an interactive session launched with
`--tools Bash`. After compaction the agent used file tools normally. This is the case that
matters most, because `/compact` is *in-session*: no new invocation, no chance for the operator
to re-supply the flag.

**Minimal reproduction of the same class**, measured 2026-08-11, headless:

```bash
mkdir /tmp/probe && cd /tmp/probe && echo x > README.md
claude --tools Bash -p 'Say READY.'
claude --continue -p 'Using the Write tool, create probe.txt containing X.
                      If you have no Write tool say NO-WRITE-TOOL. Do NOT use Bash.'
```

The continued session reports *"I have the Write tool and used it"*. The write is then stopped
only by the permission prompt — i.e. by the advisory layer, not by the tool restriction. With
the prompt approved, or in any configuration where writes are auto-allowed, it lands.

Whether `--continue` should re-apply a prior invocation's flags is arguable. **The `/compact`
case is not**: the restriction is lost inside a single session the operator configured once.

## Why this is a security issue rather than an ergonomics one

`--tools` is what a sandbox integration reaches for, because the file tools do not go through
whatever the sandbox wraps. In our case the wrapped surface is the Bash command (bubblewrap),
and `Read`/`Write`/`Edit` execute in the agent process on the host — no mount table applies to
them. Restricting the tool set is the documented, supported way to close that gap.

Three properties make the failure severe:

1. **Silent.** Nothing reports that the tool set changed. The operator's next signal is an
   agent doing something it should not be able to do.
2. **It widens, not narrows.** The lapse restores capability rather than removing it, so it
   cannot be caught by "the agent stopped working".
3. **The fallback is the layer being compensated for.** What actually stopped the write in our
   test was the permission prompt — precisely the advisory, human-answerable layer that the
   tool restriction exists to avoid depending on.

## What does work, and is worth documenting either way

A **bare tool name in `permissions.deny`** (settings file) is durable:

```json
{ "permissions": { "deny": ["Read", "Write", "Edit", "Glob", "Grep"] } }
```

Measured: this removes the tool from the registry rather than gating it — the call reaches no
permission prompt, and `ToolSearch` reports *"No matching deferred tools found"* — and it
**survives** the `--continue` path above, because settings are re-read per session.

That asymmetry is itself surprising and undocumented: two supported ways to restrict tools, one
durable and one not, with no indication which is which. An integrator reaching for the
command-line flag — the more discoverable of the two — gets the weaker one.

## The change

Any of these would fix the case that matters, in decreasing order of preference:

1. **Make the tool restriction session state.** Once a session is created with `--tools`, keep
   it across compaction and resumption, so it cannot be lost by an in-session operation.
2. **Warn loudly when the effective tool set widens** relative to how the session started.
3. **At minimum, document it** — that `--tools` is per-invocation, that compaction may reset
   it, and that `permissions.deny` is the durable form for security use.

## Smaller, related, same file

`--tools default` does not return the full selectable set: `Glob` and `Grep` are absent from it
but are accepted by name. Unmatched names are silently dropped (`--tools TypoBash` yields no
error and no `Write`) — that direction is fail-safe, and is only worth a line in the docs.
