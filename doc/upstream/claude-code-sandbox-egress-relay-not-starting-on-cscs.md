# Claude Code sandbox: egress proxy relay never binds inside the netns (CSCS login nodes)

**Product:** Claude Code CLI 2.1.241, Linux, CSCS supercomputer login nodes (SLES/HPE Cray,
unprivileged user namespaces). **Not husk-related** — reproduced with plain `claude`, no wrapper.

## Summary

With `sandbox.enabled: true` and `network.allowedHosts` set, **all outbound network from
sandboxed Bash fails at TCP connect to `localhost:3128`** (`curl: (7) Connection refused`). The
allowlist is never exercised. `/proc/net/tcp{,6}` inside the sandbox network namespace contain
**zero LISTEN entries** — nothing ever binds `127.0.0.1:3128`, although `HTTP_PROXY`/`HTTPS_PROXY`
injected into that namespace point there. The relay that should bind `:3128` inside the sandbox
netns and forward to the host-side proxy port does not start.

## Reproduction

1. On a CSCS login node, a project dir on Lustre, `~/.claude/settings.json` with:
   `sandbox.enabled: true`, `network.allowedHosts: ["opendatadocs.meteoswiss.ch:443"]`.
2. `claude` (plain — no wrapper). In a Bash tool call:
   ```
   curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://opendatadocs.meteoswiss.ch/
   ```
   → `curl: (7) Failed to connect to localhost port 3128: Connection refused`.

## What is and isn't working

| Component | State |
|---|---|
| Host-side proxy (`CLAUDE_CODE_HOST_HTTP_PROXY_PORT`, e.g. 41887/43453) | **listening on the host** (`ss -ltnp` shows it) |
| Unix messaging socket `/run/user/$uid/cc-socks/<pid>.sock` | **works**, visible + correctly permissioned inside the sandbox |
| Claude Code control-plane / API traffic | **works** throughout (does not traverse `:3128`) |
| TCP relay binding `127.0.0.1:3128` inside the sandbox netns | **MISSING** — never binds |
| Sandbox netns | loopback only (`lo 127.0.0.1/8`), no DNS |

So host↔sandbox plumbing over the filesystem (the unix socket) is healthy; **only the TCP relay
into the network namespace is absent.**

## Ruling out the usual causes

- **Not the allowlist.** A live proxy refusing a host returns `curl: (56) CONNECT tunnel failed,
  response 403`. Here both the allowlisted host and a blocked control fail identically at TCP
  connect, earlier in the path.
- **Not the target / DNS.** `api.anthropic.com`, `example.com`, and the allowlisted host all fail
  the same way; `--noproxy '*'` gives `curl: (6)` (no DNS in the netns) as expected.
- **Not credentials.** Per-caller proxy usernames (`srt.<base64>`) are minted and well-formed;
  they rotate per Bash call.
- **Not namespace visibility.** The failure is identical from the host shell and from inside the
  sandbox, ruling out "proxy alive but unreachable."
- **Not a wrapper.** Reproduced with plain `claude` (and independently under the husk wrapper,
  identically) — the wrapper is not involved.

## Hypothesis

The relay placement (sandbox netns, host pid/mount ns) requires entering the sandbox's network
namespace from a host-side process (setns). On CSCS login nodes — unprivileged user namespaces,
possibly restricted setns/CAP in that userns — that step appears to fail silently, so the relay
never binds while the sandbox env still advertises `:3128`.

## Impact & ask

Total egress blackout for sandboxed Bash on CSCS: the netns has loopback only and no DNS, so
there is no degraded mode, and the failure surfaces as `curl: (7) … port 3128`, which reads as
"the cluster network is down" rather than "the sandbox egress relay didn't start." Two asks:

1. **Fix / make robust the netns relay startup** on unprivileged-userns HPC login nodes (or
   surface a hard startup error when it fails, instead of advertising a proxy that isn't there).
2. **A startup health check** on the proxy port, or annotating a connect-refused on the proxy
   address with "sandbox egress proxy is not listening," would turn a silent blackout into a
   diagnosable error. (The agent cannot self-diagnose beyond enumerating `/proc/net/tcp`.)
