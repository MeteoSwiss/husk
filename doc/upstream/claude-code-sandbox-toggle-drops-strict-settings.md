# Claude Code: `/sandbox off` then `/sandbox on` silently downgrades a strict sandbox to permissive

**Product:** Claude Code CLI (observed 2.1.x, Linux). **Security-relevant:** the network allowlist
and filesystem write-denies are silently dropped while the UI reports "sandbox on".

## Summary

A strict sandbox configured in `~/.claude/settings.json` (a `network.allowedDomains` allowlist and
a `filesystem.denyWrite` list) is silently REPLACED by a permissive one after a `/sandbox off`
followed by `/sandbox on`. The session ends up sandboxed-but-unrestricted: base cage on (cwd
writable, rest read-only), but **all outbound network allowed** and **denyWrite not enforced** —
with no indication that the strict policy is no longer in effect.

## Mechanism (two compounding flaws)

1. **`/sandbox off` writes a local override.** It creates/updates `.claude/settings.local.json`
   with `sandbox: { enabled: false, autoAllowBashIfSandboxed: true }`.
2. **`/sandbox on` flips that local block in place** to `enabled: true` instead of DELETING it. The
   local block still carries only `enabled` + `autoAllow` — no `network`, no `filesystem`.
3. **The `sandbox` object is replaced, not deep-merged.** The more-specific
   `.claude/settings.local.json` `sandbox` object overrides the `~/.claude/settings.json` one
   WHOLESALE, so the global `network.allowedDomains` and `filesystem.denyWrite` are gone — not
   merged in.

Net: a minimal local `sandbox` block (a leftover of the off→on toggle) strips every strict
restriction from the global config.

## Reproduction

1. `~/.claude/settings.json`: `sandbox.enabled: true`,
   `sandbox.network.allowedDomains: ["opendatadocs.meteoswiss.ch:443"]`,
   `sandbox.filesystem.denyWrite: [".Rprofile", …]`. No `.claude/settings.local.json` sandbox block.
2. `/sandbox off`, then `/sandbox on`.
3. In a Bash tool call:
   - `curl -sS -o /dev/null -w '%{http_code}\n' https://github.com/` → **200** (should be a 403
     from the allowlist proxy; github is not on the list).
   - `echo x > ./.Rprofile` → **succeeds** (denyWrite lists `.Rprofile`).
   - `echo x > /some/path/outside/cwd` → `Read-only file system` (base cage IS on).

Observed: `.claude/settings.local.json` `sandbox` = `{ "enabled": true, "autoAllowBashIfSandboxed":
true }`, mtime == the moment `/sandbox on` ran.

## Expected

Either: `/sandbox on` should DELETE the local override when it exists only to hold the off-state
(reverting to the global config); OR the `/sandbox` toggle should modify only the `enabled` key via
a deep-merge that preserves the global `sandbox.network` / `sandbox.filesystem`; OR the sandbox
object should deep-merge across settings scopes so a partial local block cannot strip global
restrictions. Any of these avoids the silent downgrade.

## Impact

A user who toggles the sandbox off (to run one thing) and back on reasonably believes they are
protected again. They are not: the network allowlist and write-denies are gone, silently, while
the UI says "sandbox on". For any deployment that RELIES on a strict global sandbox (e.g. an
allowlist limiting egress to specific hosts, write-denies protecting auto-exec files), a single
off→on toggle disables those protections for the rest of the session with no warning.
