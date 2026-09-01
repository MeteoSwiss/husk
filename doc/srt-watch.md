# Watching Anthropic's sandbox-runtime

**Why this file.** husk will own the login-side cage at 6a, but it will not stop being worth
reading what Anthropic does: they are solving the same problems on three platforms with more
users hitting them. This is a running log of what changed upstream and what husk learned —
cumulative, so a pull does not mean re-deriving the same conclusions.

**L4 (append-only record).** One entry per pull. Keep the "what husk should check" column
honest: an entry with no action is a fine entry, and pretending otherwise makes the file noise.

**The standing caveat, established 2026-08-13 and worth re-reading every time:** *this tree is
not the running code.* A plain `config/` directory in a project root is bind-mounted read-only
in a live session — measured — and nothing in this source produces that mount. Read it for
hypotheses; settle them against `/proc/mounts`.

---

## 2026-08-13 — v0.0.71 → v0.0.73

**Nothing touched `linux-sandbox-utils.ts`.** All movement was proxy, macOS and Windows. So the
Linux mount model husk's reading is based on is stable, and the unexplained `config` mount is
still unexplained here.

| upstream change | what it is | husk |
|---|---|---|
| **`#470` proxy: route and dial the canonical host, not the client's spelling** | the filter canonicalised (trailing dot, case, `inet_aton`) but MITM routing matched the raw name, so `api.example.com.` passed the allowlist and then skipped the MITM proxy it was pinned to | **This is A9's premise, found in their production.** husk is immune structurally: one `host` variable is checked and dialled, no canonicalisation to disagree with, no second consumer. The variant — an `inet_aton` spelling of localhost dodging the SLURM-port refusal — also fails, because that check is on the PORT alone (`SCHEDULER_PORTS.contains(&port)`) |
| **`d106511` macOS: keep glob `denyRead` denied inside `allowRead` regions** | an allow carve-out re-exposing a denied path | husk's `F18` and `F22`, already fixed both instances. Same class, different platform, reached independently — good evidence the class is real rather than a quirk of our design |
| **`#461` proxy: close CONNECT clients that abandon a slow permission decision** | connection lifetime tied to a decision that may never come | `B1`'s resource-lifecycle criterion. husk has no permission prompt on this path, so the specific case does not arise; the abandon-during-dial case is bounded by `DIAL_TIMEOUT` |
| SOCKS, MITM routing, TLS termination, credential injection, parent-proxy bypass | breadth in the proxy | **The reason `#470` was possible at all: seven consumers of one hostname.** husk is CONNECT-only by design, and A9 records the choice to avoid a second HTTP parser. That judgement now has independent support |
| Windows ACL / session-store work | — | not applicable |

**Taken from this pull, as work:** their **credential injection** — the proxy holds the secret
and the agent never does — is the best idea here, and ROADMAP's *"Credentials the agent uses but
never holds"* records why husk should reach the same goal by a different route. Their mechanism
needs TLS termination, which is the surface that produced `#470`.

**Also worth knowing, because it is the question everyone asks:** their config cannot express
`github.com/MeteoSwiss/*` either. It is `domainPortPattern` — domain plus optional port — even
though the MITM path gives them `url.pathname`. They see the path and still do not write policy
about it, which is a useful data point when someone proposes that husk should.

**The transferable lesson, and it is about shape rather than code:** their bug was not a bad
check, it was *one name with several consumers*. Every husk equivalent — the sbatch registry,
the two cages, the tool lists — is the same risk, and the defence husk already uses is
construct-and-re-emit: derive one canonical value and make every consumer take it, so there is
no second spelling to disagree about.

---

## 2026-08-23 — login-cage egress proxy failed to start (srt proxy, not husk's)

**Symptom (from a caged agent on Santis, project tracer_advection_port):** every outbound
request — inside AND outside the cage — failed at TCP connect to `localhost:3128` with
`curl: (7) connection refused`. `CLAUDE_CODE_HOST_HTTP_PROXY_PORT=43453` had nothing listening
either. The harness's OWN API traffic stayed up (session lived throughout), so only the
sandbox-egress path for shell commands was dead.

**Diagnosis:** the proxy is DOWN, not misconfigured. Ruled out by the agent: not the allowlist
(a blocked host returns `(56) … 403` from a LIVE proxy; this fails earlier at connect), not the
target (`api.anthropic.com` fails identically), not credentials (per-caller `srt.<b64>` creds
well-formed — decode to a `toolu_*` id in-cage, `<session-uuid>:inner` host-side), not namespace
visibility (fails identically on both sides of the boundary).

**Whose component:** the `srt.` username + `CLAUDE_CODE_HOST_*` env prove this is Anthropic's
sandbox-runtime mux-proxy (front-end TCP port in a range, unix-socket backend — see vendored
`sandbox/mux-proxy.ts` / `listen-in-range.ts`, NOT the running code), launched by the harness
during sandbox setup. husk supplies `allowedDomains` + the bwrap/seccomp config but does not run
this proxy. So a proxy that fails to bind or crashes at startup is an srt failure husk depends on,
not a husk bug.

**Leading hypothesis:** transient port-BIND failure in the proxy's range on a busy shared login
node — the login-side analog of the compute-side "egress relay started in the background, never
waited for" flake. A fresh session usually re-attempts the bind. Confirm from the HOST with
`ss -ltnp | grep -E ':3128|:43453'`, `ps -u $USER | grep -iE 'proxy|srt|node'`, and the startup
capture `husk 2>&1 | tee $SCRATCH/husk-start.log` grepped for `EADDR|listen|bind|port|range`.

**husk actions taken:**
- SKILL §4 now distinguishes `(56) 403` (proxy up, host not allowed) from `(7) refused` (proxy
  DOWN) in a table, and tells the agent to REPORT the `(7)` case to the human and stop — not to
  read it as "the cluster/site is broken." This was the agent's own top UX suggestion.

**husk actions still open (backlog):**
- A **startup health-check on `:3128`** in husk's wrapper (which already runs before the agent,
  and already mints a `SandboxReady` witness by verified bind) — probe the egress proxy and
  refuse-with-explanation if it is not listening, turning a silent blackout into a named failure
  at launch instead of a mid-session `curl: (7)`.
- Consider surfacing the srt proxy's startup error into husk's own log/banner, since the agent
  cannot read `~/.husk/log` and a human otherwise has to go hunting for the cause.

## 2026-08-23 (cont.) — login-cage egress is OFF under husk; compute-cage egress works

**Reproduced on Balfrin**, inside the N4 reviewer's own agent cage: `curl (7)` to
`localhost:3128`, no listening TCP sockets at all in the cage, DNS blocked. The agent
correctly localized it: the in-cage relay that should listen on `:3128` and forward to the
host socat is not present, while the COMPUTE cage (brokered jobs) has working egress via
husk's own `HUSK_NET_SOCK`/`HUSK_SOCAT` + netproxy.

**Why husk cannot just "fix the proxy":** `husk-slurm-wrapper.rs` unshares only
`CLONE_NEWUSER | CLONE_NEWNS` (user + mount), never net. Login-cage networking is entirely
Anthropic's srt proxy, driven by husk's `settings.json` `allowedDomains` (correctly set).
husk's own egress machinery is compute-side only.

**Leading root-cause theory (may be husk-caused after all):** srt places its relay in the
*sandbox netns but the HOST mountns*, reaching the host socat via a unix socket at
`/tmp/claude-http-*.sock`. husk's wrapper unshares the MOUNT namespace before claude starts,
so the sandbox's mount view may not resolve that host `/tmp` socket — the host socat exists
(seen: pid 217901, `UNIX-LISTEN:/tmp/claude-http-*.sock → TCP:localhost:36443`), the in-cage
`:3128` relay half does not. Consistent-under-husk, not transient — which fits a namespace
interaction rather than a random bind failure. (Supersedes the earlier transient-bind
hypothesis for the login cage; that one may still explain the separate Santis incident.)

**Security posture:** egress-off **fails closed** — the login agent reaches nothing, so
nothing leaks. This is a USABILITY gap, not a containment hole; it does NOT weaken the threat
model and should NOT block v0.5 on security grounds.

**Decisive test (run before deciding the fix):** does a PLAIN `claude` sandbox (no husk
wrapper) get a live in-cage `:3128`? 
  - YES  -> husk's mount-namespace unshare is breaking the relay's socket path; fix = make the
           relay unix socket survive husk's mountns (bind it in, or don't unshare mount around
           the relay). Candidate v0.5.x.
  - NO   -> srt's relay genuinely does not start on CSCS login nodes; not husk's to fix.
           DOCUMENT: login agent has no direct egress; network work goes through a brokered
           job, where husk's proxy enforces the allowlist. Ship v0.5 with that note.

**v0.5 decision:** do not block. Run the decisive test; either a quick mountns fix or a
documented "network via jobs" workaround. Real long-term answer is husk owning login-cage
egress the way it already owns job egress = v0.6a scope. The compute-cage path is the
confirmed working egress today (agent offered a job that curls the allowlisted host: expect
200 vs 403).

## 2026-08-23 (decisive) — the srt relay does NOT start on CSCS; husk is EXONERATED

Ran the decisive test: `claude --resume` DIRECTLY (husk off, no wrapper, pure vendor sandbox) on
a CSCS login node. **Identical failure to husk-claude:** `/proc/net/tcp{,6}` have ZERO LISTEN
entries in the sandbox netns — nothing ever binds `127.0.0.1:3128`, while the env points Bash
there. So my mount-namespace theory is WRONG: husk's CLONE_NEWNS unshare is not the cause. This
is Anthropic's sandbox-runtime, and it breaks sandboxed-Bash egress for ANY Claude Code user on
CSCS, husk or not.

**Precise fault (from the plain-claude diagnosis):** the host side is healthy — the host proxy
listens (`:41887`/`:43453` seen host-side) and the unix messaging socket
`/run/user/27069/cc-socks/*.sock` works and is visible inside the sandbox. What is missing is the
TCP RELAY into the netns: the process that should bind `127.0.0.1:3128` inside the sandbox and
forward to the host proxy. The srt relay's placement is "sandbox netns, host pid/mount ns" (a
setns into the sandbox netns from a host process); on CSCS login nodes that step does not happen.
Likely a userns/setns restriction specific to CSCS's unprivileged-userns config, but the running
srt is not the vendored source, so the WHY is Anthropic's to pin.

**Why husk cannot lightly fix it:** the relay must live INSIDE the vendor's netns (husk does not
build it) AND reach the host. A socat husk starts in the cage cannot help — the netns is
loopback-only with no route to the host port, and the only working host channel is the control-
plane messaging socket, not egress. Nothing reachable to bridge to. A real husk fix = husk owns
the entire login-cage network (v0.6a), independent of the vendor relay.

**Decision (Path A fork), pending Christoph:**
1. REPORT TO ANTHROPIC — their bug, affects all CSCS sandbox users, clean evidence in hand; a
   vendor fix needs zero husk work.
2. Pull v0.6a login-cage ownership forward into v0.5 — robust, but weeks and re-opens the login
   cage for review.
3. Ship v0.5 now with the security fixes, login egress documented as a vendor limitation on CSCS
   (fails CLOSED = secure), compute-cage egress the working path.
RECOMMENDATION: 1 + 3 in parallel (do not hold the A4-S1 CRITICAL hostage to a vendor bug), 2 as
the long-term answer on its own schedule.

**Evidence for the Anthropic report** is assembled from the two agent diagnoses (husk-on and
husk-off, identical): zero netns LISTEN, host proxy up, messaging unix socket up, relay absent.

## 2026-08-24 — CRITICAL: the runtime binds ~/.claude ro over a home mask, exposing the OAuth token

**The most serious finding of the whole review.** When the sandbox masks the home (`denyRead`
covering `$HOME`), the runtime UNCONDITIONALLY bind-mounts the entire `~/.claude` back into the
cage READ-ONLY — so the agent has its config/skills/projects. That wholesale ro bind carries
`~/.claude/.credentials.json` (the user's Claude OAuth token) with it. **A Bash-only caged agent
can read the user's account credential.**

**Where it bites:** on CSCS, `$HOME` is `/users/<user>`, so husk's `denyRead: /users` triggers it.
The token has been readable in EVERY caged session all week, including every pen-test reviewer.
On the laptop it is normally hidden only because `$HOME=/home` and `denyRead: /users` masks
nothing — the leak is invisible there until you mask the real home.

**Proven (laptop, 2026-08-24), reliable because it is a FRESH session with a MINIMAL config:**
```
filesystem: { denyRead: ["/home/christoph"], allowRead: ["./"], denyWrite: [<project-local only>] }
```
`test -r ~/.claude/.credentials.json` -> READABLE; `test -r ~/.claude/husk-sentinel.txt` (a
decoy) -> READABLE; `grep ' /home/christoph/.claude ' /proc/self/mountinfo` ->
`/@home/.../.claude -> /home/.../.claude ro btrfs` (mount 12281). The token was tested by
existence/readability only (`test -r`, `ls`), never `cat` — its bytes never entered a log.

**It is the TWO-DOOR PROBLEM in its purest form:** husk masks the home through one door
(`denyRead`), the runtime re-opens `~/.claude` through another (its own bind), and the credential
is in the overlap. husk's config asked for none of it.

## GOTCHA 1 — hypotheses tested and REFUTED for this leak
The `~/.claude` ro bind is UNCONDITIONAL. Neither of these triggers it (each removed, token still
exposed): `allowWrite: ~/.claude/projects` (removed live), `denyWrite: ~/.claude/settings.json`
(removed live AND in a fresh minimal config). Christoph's recollection that "denyWrite of a path
CONSTRUCTS a read of it" (from building husk) is NOT the cause here — the token is exposed with
zero `~/.claude` denyWrite. KEPT AS A WATCH ITEM for other paths; not the mechanism here.

## GOTCHA 2 — live config APPLIES masks but does NOT cleanly REMOVE mounts
Adding a `denyRead` takes effect live in a running session (verified: a tmpfs mask appeared over
a newly-denied dir without a restart, mount visible immediately). But REMOVING a config entry
does NOT reliably tear down the mount it created — the runtime layers new mounts on re-apply and
leaves stale ones. So **any test of the form "I removed X, did the mount disappear?" is
unreliable and needs a FRESH session.** Additions can be tested live; removals cannot. This
contaminated several intermediate tests tonight before we caught it.

## FIX — open, next test
Can a targeted `denyRead ~/.claude/.credentials.json` mask the file ON TOP of the runtime's
wholesale ro bind? If yes, that ships (verified by `test -r`, not config shape). If no, no config
can hide the token and it is escalate-to-Anthropic + husk-owns-the-cage (v0.6a). Also an upstream
report: a sandbox that binds `~/.claude` wholesale over a home `denyRead`, exposing
`.credentials.json`, is a vendor bug for anyone whose `$HOME` holds the token.

## 2026-08-24 — mechanism confirmed in vendored source + tomorrow's TODOs
linux-sandbox-utils.ts:869 IS the behaviour we mapped: denyRead dir -> --tmpfs; allowRead subpath
-> --ro-bind back; file deny -> /dev/null. :1510 documents the file-vs-directory rule we found.
The wholesale ~/.claude ro-bind that leaks the token is NOT in the lib -- it is the harness's
(vendored != running); it wins over a top-level denyRead ~/.claude on mount ordering, so only
CHILD masks work.

OPEN for tomorrow:
1. Finalise the ~/.claude mask list. Confirmed-maskable children: .credentials.json,
   history.jsonl, stats-cache.json, sessions, session-env, shell-snapshots, paste-cache,
   file-history, .cc-writes. Christoph leans: leave projects WHOLESALE readable (memory lives
   there; accept transcript exposure). Verify each by ACTUAL READ (ls -> /dev/null, or a failing
   read) -- NOT test -r (false friend: access() passes on /dev/null). Add allowRead ~/.local.
2. Audit what allowRead ~/.local exposes on Balfrin AND Santis (feeds the relay via
   ~/.local/share/claude; exposes all of ~/.local). No secrets under ~/.local/{share,state}.
3. Real fix is v0.6a: husk owns the login cage -> --tmpfs ~/.claude + minimal bind-back.
