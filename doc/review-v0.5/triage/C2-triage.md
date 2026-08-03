# C2 — triage (pass 2): the login-side agent's own egress

**Triaged at `6c4e75f`** (pass 1 wrote against `f5fd395`; nothing in the intervening commits
touches `netproxy.rs`, `netallow.rs`, `policy.rs`'s egress block, `spool.rs`'s strip list or
`settings.rs`'s mask sets). Comparison target: vendored `sandbox-runtime/` package version
`0.0.67`. Laptop only, kernel `6.8.0-136-generic`, `bubblewrap 0.6.1`, no cluster access.
**No source file was modified.** Everything below that says "measured" was run here.

Two of this shard's headline items are **negative results** — claims that something is *not*
a problem. I gave those the most time, because a wrong "this is fine" is the error nobody
revisits. Both survived in part and neither survived intact.

## Summary

| # | Finding | Outcome | My severity | One line |
|---|---|---|---|---|
| C2-1 | Direction is settled: egress-only is sufficient | **RECHARACTERISED** | **none as a bug today; MEDIUM as a planning input** | The *model* leg really is egress-only, but two of the three "looks inbound, isn't" rows are factually wrong — IDE integration is a **loopback TCP dial, not AF_UNIX** (measured against the shipped `claude` binary), and the OAuth listener would sit **inside** the cage, not on the host. A third loopback-listener case (remote-MCP OAuth) was missed. And the IDE leg is a login requirement the egress layer **cannot express**, which the table records as "N/A". |
| C2-3 | The proxy is structured so TLS termination can be *added* | **RECHARACTERISED** | **MEDIUM (6b planning)** | The `parse → gate → dial → 200 → pump` shape does admit termination between gate and tunnel — verified against `http-proxy.ts:246-345`. "Nothing would have to be undone" is **false**: husk's deliberate `*` support plus Anthropic's `injectHosts ?? allowedDomains` default is a credential-exfiltration primitive (`credential-mask-env.ts:97-103`), and the early-200 re-order costs husk a *stated* design guarantee, not just a "clean property". Two of the three named costs are also numerically wrong. |
| C2-6 | The settings hierarchy becomes plantable on login | **CONFIRMED** | **MEDIUM–HIGH as a 6a design item; none today** | Reproduced the plant with real bwrap: with `.claude` absent, `--ro-bind-try` skips and a caged process writes `settings.local.json` onto the host. But the "shape `--ro-bind-try` fails at" is **cheap to build** — I built two working constructions in one command each. The genuinely hard half is the one the finding does not name: `~/.claude` needs *mixed* read-only/writable inside one directory, and holds `.credentials.json`. |
| C2-5 | Host granularity cannot express "one host, two principals" | **RECHARACTERISED** | **HIGH (6a/6b design)** | The observation is right and is the most important thing in the shard. The proposed remedy is wrong: credential masking bounds **disclosure**, not **use** — the sentinel lives in the sandbox env and any process there can spend it at an `injectHost` (`credential-sentinel.ts:50-62`). The discriminator husk actually has, and Anthropic's loopback design cannot have, is that its transport is a **file**. |
| C2-2 | No instantiation path for the proxy outside a SLURM job | **CONFIRMED** | **HIGH as the 6a work item; none as a bug** | Verified exhaustively: exactly two call sites of the network modules, both compute. One thing to add — `netallow`/`netproxy` are `mod` in `main.rs`, not in `lib.rs`, so they are private to the binary; "reusable verbatim" is true of the source and false of the crate. |
| C2-4 | `ANTHROPIC_BASE_URL`/`_MODEL` in no controlled set | **CONFIRMED** | **none today; MEDIUM for 6a** | Verified by exhaustive grep. Adds: a **test actively pins them as non-members** (`spool.rs:483-485`), so the 6a fix must change a test, and the docstring's justification ("useless without a token or a route") expires the moment login egress exists. Overlaps C3. |
| C2-7 | No SOCKS path: non-HTTP TCP has no route at all | **REFUTED** (headline) | **LOW** | **Measured:** husk's real proxy tunnelled an SSH protocol banner bidirectionally on port 47322. `CONNECT` *is* a generic TCP tunnel. What is missing is client plumbing (`GIT_SSH_COMMAND`), not a route — and `socat` is already bound into every cage at `/tmp/husk-socat`. |
| C2-8 | The unix-socket transport avoids Anthropic's `proxyAuthToken` bug | **CONFIRMED**, with a refinement | **informational** | Verified. Refinement: mode `0600` separates **users**, not **same-uid processes** — and same-uid processes are exactly the population that matters once the proxy holds a credential the caged side must not have. `proxyAuthToken` would not help husk either, because the caged side has to hold the token. |
| C2-9 | The in-cage relay is a position the agent occupies | **CONFIRMED** | **LOW (record for 6b)** | Precondition measured: an unprivileged process in a `--unshare-net --unshare-pid` cage binds `127.0.0.1:3128` without difficulty. |

**Net.** C2 produces **zero security bugs at HEAD** — correct, because the login cage this
brief is about does not exist yet. What it produces is a 6a/6b work list, and the two
negative results that list was going to be planned on are both weaker than written. The one
finding I would move to the top is C2-5, restated: not "the allowlist needs help from
masking", but "the login cage has two principals in one address space, and husk's
socket-is-a-file transport is the only mechanism on the table that can tell them apart."

New observations that are not in the source document are collected at the end (N1–N3); N1 in
particular may be A9's territory.

---

## C2-1 — Direction is settled: egress-only is sufficient — **RECHARACTERISED**

This is the shard's load-bearing negative result, so it got the most adversarial effort.
What I tried, in order:

### Attack 1 — is IDE integration really AF_UNIX?

The finding's row says *"Agent ↔ IDE integration | **AF_UNIX**, local | N/A — never crosses a
netns"*, cited to `seccomp_wrapper.c:51-62`. That citation is a **comment in husk's own
source** (`"the agent runtime legitimately uses unix sockets for its own IPC (MCP servers,
IDE integration)"`), not an observation of the client. Rule 7 applies: I checked whether the
comment could be wrong.

I went to the shipped binary — `~/.local/share/claude/versions/2.1.220`, a 275 MB Bun
executable — and extracted its strings:

```
strings -n 6 ~/.local/share/claude/versions/2.1.220 > cc-strings.txt
grep -o '.\{300\}\.claude","ide".\{300\}' cc-strings.txt
```

The discovery path is:

```js
function gco(){ let e=[GKr.join(fn(),"ide")]; ... }     // ~/.claude/ide
// ...
u.createConnection({host:e,port:t,timeout:r})            // TCP liveness probe
```

plus a `ws://127.0.0.1:` template string and a `CLAUDE_CODE_SSE_PORT` read
(`CLAUDE_CODE_SSE_PORT!==void 0||Z.CLAUDE_CODE_AUTO_CONNECT_IDE===!0`). So the IDE extension
is the **server**; Claude Code reads `~/.claude/ide/<port>.lock`, probes the port with a TCP
`createConnection`, and dials `ws://127.0.0.1:<port>`. It is **loopback TCP, not AF_UNIX**,
and Claude Code is the client.

Direction is therefore still *outbound* — the finding's headline survives this — but the
row's reasoning ("never crosses a netns") is wrong, and the consequence is a finding of a
category the brief explicitly lists ("a login-side requirement the compute egress layer
**cannot** express"). Measured:

```
python3 idesrv.py &                       # host loopback listener on 127.0.0.1:47311
python3 ideclient.py                      # → CONNECTED: HELLO-IDE
bwrap --dev-bind / / --unshare-net python3 ideclient.py
                                          # → FAILED: ConnectionRefusedError [Errno 111]
```

`ECONNREFUSED`, i.e. the kernel and the empty netns — not `SIGSYS`/159, so this is not the
seccomp filter (protocol rule 5). And the egress layer cannot carry it:

- the relay exports `NO_PROXY=localhost,127.0.0.1` (`policy.rs:773`), so a proxy-aware client
  would bypass the proxy for exactly this destination;
- a raw `net.createConnection` never consults a proxy env var at all;
- `ws://` through a proxy is an `Upgrade` GET, i.e. an absolute-URI request, which
  `parse_connect` refuses by construction (`netproxy.rs:93-104`);
- and expressing it in the allowlist would mean granting `127.0.0.1` on **all** ports (the
  IDE port is ephemeral), i.e. handing the cage every loopback service on the login node.

So `/ide` is broken by 6a and nothing today says so. That is not "materially new work" in the
finder's sense (no inbound listener), but it is a real 6a gap the shard reports as `N/A`.

### Attack 2 — is the OAuth callback really "outside any husk cage"?

The finding says: *"Even in the tunnelled case the listener and the browser-facing end are
both on 127.0.0.1 **of the host**, i.e. outside any husk cage — husk would only need to not
break it, not to route it."*

That is **wrong**, and it is wrong in the direction that matters. In 6a the process that
binds the callback port *is* the caged agent. An `ssh -L 54545:localhost:54545` terminates in
`sshd` in the **host** netns and then dials `127.0.0.1:54545` there; the listener is in the
cage's netns. Same measurement as Attack 1, with the roles swapped: the two loopbacks are
different loopbacks. So the tunnelled workaround does not work, and this *is* the
"listener reachable from outside the netns" case.

The finding's *conclusion* nonetheless mostly holds, for the reasons it gives (headless
paste-the-code variants exist; CSCS uses `CSCS_INFERENCE_API_KEY`). I am not refuting the
conclusion on this row — I am refuting the argument, because the argument is what a reader
would reuse.

### Attack 3 — is there a loopback listener the finding missed?

Yes. Searching the same binary for OAuth callback plumbing:

```
grep -o "Fixed loop[^\"]\{0,200\}" cc-strings.txt
→ "Fixed loopback callback port for the IdP OIDC login.
   Only needed if the IdP does not honor RFC 8252 port-any matching."
```

`callbackPort` is a field of the **MCP server** config schema (alongside
`authServerMetadataUrl`), i.e. Claude Code binds an RFC 8252 loopback redirect listener when
authenticating to an OAuth-protected **remote MCP server**. Neither of the finding's two
escape hatches covers it: `--no-browser` is about the *Claude* login, and the CSCS bearer
token is about the *model API*. Authenticating a remote MCP server from inside a 6a cage
needs a listener reachable from outside the netns.

How much this matters depends on whether 6a users are expected to use OAuth-protected remote
MCP servers. Note the shipped sample `project-config/settings.json` denies `mcp__*` outright,
which lowers it further — but that is a *sample*, not a boundary.

### Attack 4 — anything else that binds

- **stdio MCP / `claude mcp serve` / SDK stream-json** — pipes. Row is correct.
- **Local HTTP/SSE MCP server started outside the cage** — same shape as Attack 1 (host
  loopback, unreachable, `NO_PROXY` guarantees a silent bypass rather than a refusal).
- **A dev server the user wants to reach** (`npm run dev`, `python -m http.server`,
  jupyter) — genuinely inbound, genuinely severed by `--unshare-net`. Less plausible on an
  HPC login node than elsewhere, but it is the standard "run it and I'll look" workflow.
- **Local package registries, git credential helpers, language servers, debuggers** — all
  either outbound or `exec`/pipe. I found nothing here; the finding is right about them.

### Verdict and severity

**RECHARACTERISED.** The correct statement is narrower than the finding's:

> The *model-API* leg, and every package/docs leg, are outbound `CONNECT` and transfer
> verbatim. But "nothing on the login side requires a listener reachable from outside the
> netns" is not established: remote-MCP OAuth does, and so does any workflow where a human
> must reach a port the agent opened. What *is* established is that no such case is on the
> critical path for CSCS's bearer-token deployment. Separately — and this is the part the
> table hides — several legs are **host-loopback**, which a netns severs regardless of
> direction, and which the egress layer as built cannot express at any granularity an
> operator would accept.

**Severity: none as a bug today** (there is no login cage); **MEDIUM as a planning input**,
because "the socat bridge's inability to provide an inbound listener is not a gap for 6a" is
exactly the sentence a roadmap would quote, and it is too strong. The concrete 6a
consequence to write down is smaller and more certain than an inbound listener: **`/ide`,
and any host-loopback service, stop working, silently.**

---

## C2-3 — TLS termination can be *added* — **RECHARACTERISED**

### What I checked

**The splice point.** `serve_one` (`netproxy.rs:173-245`) is
`read_head → parse_connect → gate → resolve/dial → write 200 → pump`. Anthropic's
`http-proxy.ts:230-345` is the same sequence with termination between the gate
(`options.filter`, line 232) and the tunnel, and their opaque fallback (lines 296-345) is
byte-for-byte husk's behaviour. The single gate at `netproxy.rs:196` really is one call in
one place on the name the client asked for. **This half of the finding is correct and I
agree with it from my own reading.**

I then looked for things that *would* have to be undone, which is what the finding claims
there are none of.

### Undo #1 — `*` plus Anthropic's `injectHosts` default is an exfiltration primitive

`credential-mask-env.ts:97-103`:

> *"Effective injectHosts: per-entry narrows; if unset, default to every reachable host
> (network.allowedDomains). injectHosts is an optional narrowing, not a required allowlist.
> Trade-off: a masked credential with no injectHosts is injectable at every host the sandbox
> can reach."*

The finding cites this same default approvingly — *"their `injectHosts` **defaults to
`allowedDomains`** so that 'where a secret may go' derives from 'what the network allows'"*.
But husk's allowlist has something Anthropic's config does not: a deliberate, documented,
tested `*` entry (`netallow.rs:91-98`, `netallow.rs:413-442`), justified on the grounds that
"a site that has deliberately chosen open egress should be able to say so". Compose the two
and `sandbox.network.allowedDomains: ["*"]` means **inject the model credential into every
host on the internet** — i.e. the agent gets a one-request exfiltration channel for a
credential it is not supposed to have, delivered by husk.

That is a decision taken *today* that has to be revisited when injection arrives. It is not
in the ordering, but it is squarely in the brief's category "a proxy design decision that
would have to be undone to add TLS termination". The fix is one line and belongs in the
ledger now: **injection hosts must never derive from an allowlist that can contain `*`.**

### Undo #2 — the early 200 costs a *stated* guarantee, not just a clean property

The finding says the re-order means "the current clean 'dial first, then commit' property is
lost". The sharper cost is that `netproxy.rs:51-52` states a design rule:

> *"A refusal says what was refused and why, on the job's own connection: a silent drop would
> be indistinguishable from a network fault and would cost somebody an afternoon."*

After an early 200 there is no status line left to write — Anthropic just `socket.destroy()`
(`http-proxy.ts:329`). So on the terminated path, a *dial* failure becomes exactly the silent
drop that rule forbids. It is recoverable (once you terminate you own the TLS session and can
serve a real 502 with a body, which is better than today), but it is recoverable *only by
doing extra work*, and the project's own teaching-message criterion is the thing at stake.
Worth naming because this project treats teaching messages as a security control.

### The three named costs, checked

1. **"The 200 must move earlier"** — correct, `netproxy.rs:227` vs `http-proxy.ts:267-268`,
   `wrote200` at `:329`. Verified.
2. **"Anthropic's list is thirteen entries long (`sandbox-utils.ts:424-441`)"** — the array
   is at `sandbox-utils.ts:424-442` and has **eleven** entries, not thirteen
   (`awk 'NR>=423&&NR<=442' … | grep -c "^  '"` → 11). The conclusion is unaffected; I flag
   it because the number was quoted *as* the cost. And the cost is understated in kind: every
   one of those eleven is a *path to a PEM*, which does nothing for a JVM, whose trust store
   is a keystore. Java needs a `cacerts` import, not an env var.
3. **"a workspace that currently vendors seven crates"** — `slurm-broker/vendor/` holds
   **eleven** (`itoa memchr proc-macro2 quote serde serde_core serde_derive serde_json syn
   unicode-ident zmij`). `broker/Cargo.toml` does have exactly two direct dependencies and no
   `libc`, which is the load-bearing half and is correct.

### Verdict and severity

**RECHARACTERISED.** Correct version:

> The accept/gate/dial **ordering** admits TLS termination with no rewrite — confirmed
> independently. But "nothing would have to be undone" is false at the policy layer: `*`
> support becomes unsafe the moment injection hosts derive from the allowlist, and husk's
> stated refusal-must-teach guarantee is lost for post-200 failures unless termination is
> built to restore it. Three costs to add, not two; and the CA-trust-var list is eleven
> PEM-path variables that do not cover the JVM at all.

**Severity: MEDIUM, 6b planning.** No bug at HEAD. The reason it is not LOW is undo #1:
`is_open()` exists *specifically* so the broker can announce open egress, and an operator who
has chosen `*` is precisely the operator who would not notice that their key just became
world-reachable.

---

## C2-6 — the settings hierarchy becomes plantable on login — **CONFIRMED**

### Reproduction

The finding is marked `PLAUSIBLE`; it reproduces. Real bwrap, real writable project bind,
mimicking a login cage where the project directory must be writable:

```
# CASE A — .claude EXISTS, --ro-bind-try the DIRECTORY
bwrap --dev-bind / / --bind $P $P --ro-bind-try $P/.claude $P/.claude sh -c '...'
  READ ok
  WRITE-NEW refused      (Read-only file system)
  OVERWRITE refused      (Read-only file system)
  project write ok

# CASE B — .claude ABSENT (the common case)
bwrap --dev-bind / / --bind $P $P --ro-bind-try $P/.claude $P/.claude sh -c 'mkdir -p …'
  PLANTED (hole)
host side: $P/.claude/settings.local.json =
  {"sandbox":{"network":{"allowedDomains":["evil.example.com"]}}}
```

So the mechanism is exactly as described: `--ro-bind-try` skips an absent source, the caged
process creates the directory *on the real filesystem*, and the file it plants is one of the
three `SETTINGS_SOURCES` (`settings.rs:278-282`) that `Allowlist::resolve` reads
(`netallow.rs:337-346`) — additively, so it **widens**. The compute side is safe for exactly
the reason the finding gives: `--tmpfs <root>/.claude` per writable root
(`settings.rs:763-766`), which is absent-safe by construction, and the job cannot read its
own agent config at all — which on compute costs nothing and on login is not an option.

I also confirmed the pairing test cannot catch this: `settings_sources_are_all_write_denied_
by_the_shipped_config` (`settings.rs:945-981`) compares two *lists of strings* and never
touches a mount table. It could not have failed here (protocol rule 7).

### Where I disagree: the "hard shape" is not hard

The finding frames "readable, unwritable, absent-safe" as *"exactly the shape `--ro-bind-try`
fails at"*, and asks triage to establish what mount-table construction gives it. It took two
commands:

- **existing directory** → `--ro-bind $P/.claude $P/.claude` (Case A above): read works, new
  files refused, overwrite refused, rest of the project still writable. Done.
- **absent directory** → `--ro-bind <empty-host-dir> $P/.claude`: bwrap creates the
  destination and the mount is read-only, so the plant fails:

```
bwrap --dev-bind / / --bind $P $P --ro-bind $SB/empty $P/.claude sh -c '...'
  dest created by bwrap
  plant refused          (Read-only file system)
  project write ok
```

Side effect: bwrap leaves an empty `.claude/` behind on the host, which
`settings.rs:124-126` already judges harmless for the same reason ("a tmpfs leaves at most an
empty directory"). Both branches are decided **outside** the cage, from a stat the trusted
side does — which is the right side of the boundary.

So the answer to the finding's triage question is: yes, and it is a two-branch bind, not
research. That lowers this from "structural" to "design item with a known answer".

### Where the finding *understates* it: `~/.claude` is the hard one

The finding treats `~/.claude` and `<project>/.claude` as the same problem ("whether the
answer differs"). It does. `<project>/.claude` can be wholly read-only — a project's agent
config is not written during a session. `~/.claude` **cannot**: on this laptop it holds, live,

```
.credentials.json  history.jsonl  projects/  sessions/  session-env/  shell-snapshots/
todos-equivalents  file-history/  paste-cache/  telemetry/  statsig-equivalents  ide/
```

all of which Claude Code writes during a normal session, alongside `settings.json`, which is
`SETTINGS_SOURCES[0]` and must be read-only. So the login home config directory needs
**mixed** read-only and writable regions inside one directory — a shape the compute side has
never had to build, because compute tmpfs-masks the whole of `$HOME`
(`HIDDEN_FLOOR = ["/users"]`, `settings.rs:18`).

And it contains `~/.claude/.credentials.json` (mode `0600` here), the OAuth token store. That
is the *same* problem as C2-5 wearing different clothes: one directory, two principals — the
harness must read the token store, the tools must not. Today `sandbox.filesystem.denyRead:
["/users"]` in the shipped config keeps per-Bash cages out of it; under 6a husk owns that
mount table.

### Verdict and severity

**CONFIRMED**, with the mechanism refined: the hole is `<project>/.claude` (absent-safe
read-only inside a writable tree) and it is cheap to close; the *hard* half is `~/.claude`
(mixed permissions + credential store), which the finding folds into the easy one.

**Severity: none at HEAD** — there is no husk login cage, and today the file is protected
twice over, by `denyWrite` in the shipped config (enforced by the runtime's per-Bash cage)
and by `permissions.deny` on `Edit`. **MEDIUM–HIGH as a 6a design item**, and it is the right
finding to have raised: the file that becomes plantable is the one holding the boundary on
the agent's own model traffic, and the widening is *additive* and *persistent across
sessions* (the proxy resolves once at start, so a plant lands on the next session, not this
one — which makes it quieter, not safer).

Suspected overlap: B3's territory covers the same settings hierarchy from the filesystem
side. Not resolving it here.

---

## C2-5 — one host, two principals — **RECHARACTERISED**

### The observation: confirmed, and it is the best thing in the shard

`Entry::parse` refuses `://`, `/` and `@` outright (`netallow.rs:137-145`); `matches` compares
host and optional port and nothing else (`netallow.rs:190-215`). There is no way to write
"the harness may POST `/v1/messages`; `Bash` may not talk to this host at all". Confirmed by
reading, and by the parse rules being tested for it (`an_entry_is_a_host_not_a_url`,
`netallow.rs:444-453`). The finding's characterisation of *why* a model API is the worst
thing to grant — arbitrary POST body in, arbitrary content out, i.e. a bidirectional channel
rather than a fetch target — is right and worth keeping verbatim.

### The remedy: wrong, and the error matters

The finding concludes: *"credential masking is not an optional polish item for 6a — it is the
thing that makes the login allowlist honest."*

It does not make it honest. From `credential-sentinel.ts:1-9` and `:50-62`: the sandboxed
process is handed a **sentinel**, `fake_value_<uuid4>`, in its environment; the host proxy
swaps sentinel bytes for real bytes on egress to that credential's `injectHosts`. Anything
inside the sandbox that can read the env var can therefore **spend** the credential — it just
cannot **read** it. Three lines of Python from `Bash` still reaches
`https://api.anthropic.com/v1/messages` with a working key.

So masking converts *"the agent can steal the token"* into *"the agent can spend the token
without seeing it"*. That is a real and valuable reduction — it stops the key leaving the
cluster, appearing in a transcript, or being used after the session — but it does **not**
separate the harness from the tools, which is what C2-5 says is needed. Presenting it as the
answer would buy a false sense of closure on exactly the problem the finding correctly
identified.

### The remedy husk actually has

Anthropic's transport is a loopback **port**, which every process in the sandbox shares by
construction; that is why they cannot express two principals and why `proxyAuthToken` is a
per-session shared secret rather than a per-principal one. husk's transport is a **file**
(`netproxy.rs:15-18`), and file visibility is a mount-table question. So husk *can* express
two principals: bind the injecting socket into the harness's mount namespace only, and give
tool cages a second socket to a non-injecting proxy with a narrower allowlist. The
granularity already exists in the shape Anthropic ship today (a cage per Bash command) and in
husk's own rank cages (one relay per namespace, `rank.rs:183-220`).

That is a genuinely favourable structural result for husk and it belongs on the 6a/6b design
page next to the negative one.

### Verdict and severity

**RECHARACTERISED.** The observation stands; the remedy is restated as: *masking bounds
disclosure, not use; separating the two principals needs two sockets, and husk's
socket-is-a-file transport is what makes that possible.*

**Severity: HIGH as a design constraint on 6a/6b**, none as a bug. It is the highest thing in
this shard because it is the item that decides an architecture rather than a patch. The
current substitute the finding names — `Bash(curl *)` / `Bash(wget *)` denied in
`project-config/settings.json` (verified: both present, alongside `Bash(ssh *)`,
`Bash(scp *)`, `Bash(rsync *)`, `mcp__*`) — is a denylist of program names and does not
survive `python3 -c`. That part of the finding is correct.

---

## C2-2 — no instantiation path outside a SLURM job — **CONFIRMED**

### What I did

Tried to find a second instantiation path, and failed:

```
grep -n "netproxy\|netallow\|Allowlist" slurm-broker/broker/src/*.rs slurm-broker/broker/src/bin/*.rs
```

Exactly two call sites outside the modules themselves: `main.rs:303/355` (the `--net-proxy`
mode) and `policy.rs:362` (the submit-time "does this job get a proxy at all" decision). The
guard block that starts it (`policy.rs:643-786`) is shell, keyed to
`/tmp/husk-$(id -u)-${SLURM_JOB_ID:-nojob}` (`:715`), backgrounded with `$!` captured
(`:721-723`), and emitted only when `net_enabled` was decided at submit time. The wrapper
(`bin/husk-slurm-wrapper.rs`) never mentions the network modules. The login launcher is
`exec "$wrapper" --broker "$broker" -- seccomp-wrapper claude "$@"` — no bwrap, no netns, no
proxy (`install-husk.sh:419,427`), and `grep -n bwrap install-husk.sh` returns only prose and
a PATH check. That corroborates C1's conclusion that husk builds no login-node bwrap at all.

The finding's positive note about the proxy binary is also right and worth keeping:
`net_proxy_mode` takes only `--socket`/`--workdir` and **re-resolves the policy from files**
rather than trusting its command line (`main.rs:275-279, 303`), so nothing about the policy
travels on an argv a `/proc` reader could see.

### What to add

`netallow` and `netproxy` are declared `mod` in **`main.rs`** (lines 10-11), not in `lib.rs`
— `lib.rs` declares no modules at all. So they are private to the binary crate. The finding's
table says these are "Yes, verbatim" reusable; that is true of the *source text* and false of
the *crate*: a login supervisor cannot `use husk_slurm_broker::netallow` today. Small, but it
is a line item in the 6a plumbing estimate that the table hides behind "verbatim".

Incidental verification of the socket-path vetting, which the finding lists as reusable: I hit
it by accident when I first ran the proxy from the scratchpad —

```
husk-proxy: refusing to bind the egress socket: socket path is 122 bytes but a unix
socket address holds at most 107 (sun_path is fixed by the kernel): /tmp/claude-1000/…
```

That is `check_socket_path` (`lib.rs:241-277`) doing exactly what its docstring says, with an
actionable message, on a path length nobody planned for. It is topology-free and it works.

### Verdict and severity

**CONFIRMED.** **Severity: none as a bug** (it is an absence, and the thing it is absent from
does not exist yet); **HIGH as the 6a work item**, because it is the work item — a session
supervisor that mints a per-session directory, starts the proxy, waits for the bind, binds
the socket read-only into the cage, and reaps on exit. The finding's "policy is done, plumbing
is zero percent done" is a fair summary and I reached it independently.

---

## C2-4 — `ANTHROPIC_BASE_URL` / `_MODEL` in no controlled set — **CONFIRMED**

### What I did

Exhaustive grep across everything but the vendored runtime and the review docs:

```
grep -rn "ANTHROPIC_BASE_URL\|ANTHROPIC_MODEL\|ANTHROPIC_AUTH_TOKEN\|ANTHROPIC_API_KEY\|apiKeyHelper" \
  --include=*.rs --include=*.sh --include=*.json --include=*.c --include=*.md .
```

The only occurrences in husk's own code are `spool.rs:383-396` (`STRIPPED_SUBMIT_ENV`) and
its test. No `RESERVED_ENV_PREFIXES` entry covers them (`rank.rs:35-36`: `SLURM_ SBATCH_ PMI_
PMIX_ PALS_ HUSK_`), no `PROXY_ENV` entry (`rank.rs:49-52`), no
`sandbox.credentials.envVars` in the shipped `user-config/settings.json`. Confirmed.

### What to add

**There is a test pinning them as non-members.** `spool.rs:483-485`:

```rust
for k in ["ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL"] {
    assert!(!STRIPPED_SUBMIT_ENV.contains(&k), "{k} is not a credential");
}
```

This is not a gap that a fix quietly fills — the 6a fix has to *change a test that currently
asserts the opposite*. That is a useful thing to know before someone writes the fix and is
surprised. (The test is correct **for the surface it names**: on the submission surface these
are not credentials and stripping them would be noise. It becomes wrong the moment a second
surface exists, which is the finding's point.)

The docstring's justification also has an expiry date worth recording: *"a job that somehow
carried them can do nothing with them without a token or a route"* (`spool.rs:384-386`). A
brokered job now **can** have a route — that is what step 3 shipped. What still holds is the
token half (`ANTHROPIC_AUTH_TOKEN` and friends are stripped). So the argument is now
single-legged rather than double-legged, and it is the leg that the allowlist controls.

The finding's list of unlisted credential *selectors* (`ANTHROPIC_API_KEY_HELPER`,
`ANTHROPIC_PROFILE`, `ANTHROPIC_CONFIG_DIR`, `ANTHROPIC_IDENTITY_TOKEN[_FILE]`) is the right
observation — a denylist of three exact names is the pattern this project distrusts. I did not
independently verify that each of those names is honoured by the current Claude Code build;
that would need the strings dump cross-checked name by name, and it does not change the
structural point (denylist → allowlist).

### Verdict and severity

**CONFIRMED.** **Does it matter today?** No. There is no husk login cage, and on the login
node the user *is* the trust root — an `ANTHROPIC_BASE_URL` in their own shell is their own
choice, not an escape. On the submission surface the strip list is correct as written.
**Severity: none today, MEDIUM for 6a**, where it becomes an instance of "the confined side
must not supply its own boundary".

**Suspected overlap with C3** (agent neutrality) — C3's triage already discusses this exact
test and list. Flagging, not resolving.

---

## C2-7 — "no SOCKS path: non-HTTP TCP has no route at all" — **REFUTED**

### What I tried

The claim is that husk removes `git+ssh` and "any MCP server or tool speaking raw TCP" **by
construction**. I tried to send raw TCP through husk's proxy, and it went.

Built the real binary and ran the real `--net-proxy` mode against a real allowlist:

```
cargo build --offline
mkdir -m 700 /tmp/hk-tri
echo '{"sandbox":{"network":{"allowedDomains":["127.0.0.1"]}}}' > $P/.claude/settings.json
HOME=$H target/debug/husk-slurm-broker --net-proxy --socket /tmp/hk-tri/net.sock --workdir $P
  → husk-proxy: allowing 127.0.0.1
  → husk-proxy: listening on /tmp/hk-tri/net.sock
```

Upstream was a plain TCP server on **port 47322** that speaks an SSH banner, not HTTP. Client
spoke `CONNECT 127.0.0.1:47322 HTTP/1.1` over the unix socket:

```
status: HTTP/1.1 200 Connection established
upstream banner (NOT HTTP): b'SSH-2.0-OpenSSH_9.6 STANDIN\r\n'
echo back:                  b'ECHO:SSH-2.0-husk-client\r\n'
```

Bidirectional, arbitrary bytes, non-443 port, non-HTTP protocol. `CONNECT` **is** a generic
TCP tunnel. (This also confirms the finding's own sub-claim that bare-IP exact allowlist
entries parse and match.)

### What is actually missing

Not a route — **client plumbing**:

- the relay exports `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` but no `GIT_SSH_COMMAND`
  (`policy.rs:766-777`, `rank.rs:206-215`);
- `ALL_PROXY=http://127.0.0.1:3128` is an *HTTP* proxy URL, which SOCKS-expecting clients
  will not use;
- and `socat` — the exact binary Anthropic use for `ProxyCommand='socat - PROXY:localhost:%h:
  %p,proxyport=…'` (`sandbox-utils.ts:569`) — is **already bind-mounted into every husk cage**
  at `/tmp/husk-socat` (`rank.rs:152`).

So the finding's own "cheap partial answer" is not a partial answer: it is the whole answer
for git+ssh, and it is two exported variables away. What SOCKS would additionally buy is
clients that cannot be told to use a `ProxyCommand` and do not read `*_PROXY` — a much
smaller set than "non-HTTP TCP".

### Verdict and severity

**REFUTED** as stated ("non-HTTP TCP has no route at all", "removes by construction"). The
residue that survives and is worth keeping: **there is no teaching message.** A `git push`
inside a netns cage fails with a bare connection error and nothing says why — that half of the
finding is right, and it is the half this project treats as a security property.

**Severity: LOW.** No bug; a documentation and one-env-var gap. The `CONNECT`-only /
no-plain-`http://` limitation is separately real and correctly not rediscovered
(`netproxy.rs:88-104`, tests at `:303-330`).

---

## C2-8 — the unix socket avoids Anthropic's `proxyAuthToken` bug — **CONFIRMED**, with a refinement

Verified all three legs: their comment (`http-proxy.ts:145-151`, *"Without this, any host
process can dial 127.0.0.1 and reach the filter callback"*), husk's `0600` chmod immediately
after bind (`main.rs:347-353`), and the parent-directory owner/mode re-check before binding
(`lib.rs:241-277`, `md.uid() != me` and `md.mode() & 0o077 != 0`). The observed socket after a
real run: `srw------- christoph christoph … net.sock` in a `drwx------` directory. Correct.

**The refinement, and it points the opposite way from the finding's closing advice.** Mode
`0600` separates **users**. It does not separate **processes of the same user**, and on a
login node the caged agent runs as the user. So:

- today that costs nothing — the proxy holds no secret, and every same-uid process outside the
  cage already has full network anyway;
- once the proxy injects a credential the caged agent must not have, *every same-uid process
  on the login node* — cage or no cage — can open that socket and spend it. The filesystem
  boundary does not help, because the confined party is on the same side of it.

And `proxyAuthToken`'s equivalent would not fix that either: their token has to be *given to
the sandboxed process* (it is embedded in the proxy URL, `sandbox-utils.ts:445+`), so a
caged agent holds it by construction. Their token defends the loopback platforms (macOS
Seatbelt, Windows WFP) where the sandbox runs under a **different account**; on Linux they use
a unix socket exactly as husk does.

So the finding's advice — *"if a login proxy ever listens on loopback TCP, it needs
`proxyAuthToken`'s equivalent on day one"* — is right but insufficient as stated. The correct
version: **the discriminator for "who may spend an injected credential" cannot be uid or a
shared token; it has to be mount visibility** (see C2-5).

**Severity: informational.** A positive finding, correctly identified, with its limit named.

---

## C2-9 — the in-cage relay is a position the agent occupies — **CONFIRMED**

The relay text is as quoted (`policy.rs:766-777`; the rank form at `rank.rs:206-215` starts it
from `_husk_inner` and then `exec "$@"`, so it is a child of the workload's own process
group). Measured the precondition:

```
bwrap --dev-bind / / --unshare-net --unshare-pid python3 -c "…bind(('127.0.0.1',3128))…"
  → pid 2 bound 127.0.0.1:3128 as uid 1000
```

An unprivileged process in the cage's own netns binds 3128 without difficulty; the relay is in
the same pid namespace and is killable by its own parent/sibling. So the described position is
reachable.

I agree with the finding's own severity assessment and reached it the same way: today it buys
nothing (the agent already sees its own conversation, and the injected header never crosses
3128 because injection happens outside the cage). What it becomes is the ability to observe
and *alter* the harness's requests before they reach the injection point — request rewriting,
not credential capture. The `anthropic-srt-launcher` relay-placement trick (relay in the
sandbox's netns, host pid/mount namespaces) is the right structural answer if it is ever
needed.

One thing to add to the 6b note: under the two-socket design C2-5 argues for, this stops being
a curiosity. If the harness's socket is the *injecting* one, then whoever owns the harness's
relay owns the injected channel — so the relay for the injecting socket is the one that must
not be in the agent's pid namespace, and the tools' relay can stay where it is.

**Severity: LOW**, record for the 6b design. Not a bug at HEAD.

---

## New observations (not findings I was given)

**N1 — an allowlist entry with no `:port` is a generic TCP tunnel to that host.**
`Entry::parse` makes the port optional and "no suffix means any port" is tested
(`netallow.rs:382-387`); `permits` blocks only `SCHEDULER_PORTS`. Combined with the C2-7
measurement, `github.com` on the allowlist means the cage can `CONNECT github.com:22` and
tunnel SSH. That is the documented semantics — but `netproxy.rs:31-37` frames the layer as
*"`CONNECT` only, which means HTTPS works and plain `http://` does not… In practice everything
that matters is HTTPS"*, which an operator will read as "this grants HTTPS". The shipped
default correctly pins `:443`. **Suspected A9 territory (compute-side allowlist correctness);
flagging, not resolving.**

**N2 — `panic = "abort"` plus thread-per-connection.** `broker/Cargo.toml` sets
`panic = "abort"` for release; `netproxy::serve` spawns a thread per client. A panic in any
`serve_one` thread takes the whole proxy down, which on compute costs the job its network
mid-flight and on login would cost the agent its model connection. I read `parse_connect` /
`read_head` looking for a hostile-input panic and did not find one (all fallible operations use
`unwrap_or_default` / `ok_or_else` / `map_err`, and `MAX_HEAD` bounds the buffer). Recording the
coupling, not a bug.

**N3 — the socket-is-a-file transport is a capability, not just a hardening choice.** Stated in
C2-5 and C2-8 above; repeated here because it is the one place in this shard where husk's design
is *strictly better* than the comparison target rather than equivalent, and it is not written
down anywhere in the repo.

---

## Not reached

Nothing in the finding set was skipped. Two claims I could not settle from the laptop, both
inside C2-1 and neither load-bearing for the verdict:

- **Whether Claude Code's *own* login flow has a paste-the-code path that never binds a
  loopback port** (as opposed to `ant auth login --no-browser`, which is a different tool). I
  found `callbackPort`, `skipBrowserOpen` and `onAuthorizationUrl` in the shipped binary but
  did not exercise the flow. *What would settle it:* on a CSCS login node with no
  `CSCS_INFERENCE_API_KEY` set, run `claude` and `ss -ltnp | grep claude` during the login
  prompt; a listener means the loopback callback is on the critical path even for the first
  party.
- **Whether the ephemeral IDE port could ever be routed** — i.e. whether an operator would
  accept `127.0.0.1` (all ports) on the allowlist. That is a policy question, not a code one.
