# C2 — the login-side agent's own egress: findings

**Pass 1 (discovery) · code-only, laptop, no cluster · reviewed at HEAD `f5fd395`**

## Summary

The bet paid, but not evenly. **Connection direction is settled: the login agent needs
egress only** — its model traffic is an outbound HTTPS `CONNECT` to one host, which is
exactly what `netproxy.rs` already serves, and nothing in the login agent's normal
operation requires a listener reachable from outside its netns. The two *policy* files
(`netallow.rs`, `netproxy.rs`, ~930 lines) are topology-free and transfer to login
verbatim. **What does not transfer is the wiring**: every line that instantiates a proxy
lives in a shell guard that only exists inside a submitted SLURM job, and the socket's
name and lifetime are keyed to `SLURM_JOB_ID`. On the credential question the answer is
better than expected structurally and worse than expected in practice: the proxy's
accept-gate-dial ordering is compatible with inserting TLS termination — nothing would
have to be *undone* — but husk today has **no** controlled set covering
`ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_MODEL` on the login side (the
only control that exists is `STRIPPED_SUBMIT_ENV`, which is the *submission* surface and
says so in its own docstring), and the allowlist is structurally incapable of expressing
the one distinction login needs most — that the agent's model host is simultaneously its
credentialed API and a general-purpose data sink reachable from `Bash`. Two things the
compute layer cannot express at all: non-HTTP TCP (no SOCKS), and a *readable but
unwritable* `.claude` directory.

---

## THE SHAPE — the required deliverable

### Direction: **outbound only**, for every leg the login agent actually needs

| Leg | Direction | Covered by step 3? |
|---|---|---|
| Agent → model API (`api.anthropic.com` or the CSCS inference endpoint) | **out**, HTTPS `CONNECT` | **Yes**, verbatim |
| Agent → package/docs hosts (PyPI, conda, GitHub, MeteoSwiss docs) | **out**, HTTPS | **Yes**, verbatim |
| Agent → OAuth token refresh (`/v1/oauth/token` on the API host) | **out**, HTTPS | **Yes**, verbatim |
| Agent ↔ stdio MCP servers | **neither** — pipes/AF_UNIX, no netns crossing | N/A |
| Agent ↔ IDE integration | **AF_UNIX**, local; `seccomp_wrapper.c:51-62` names this as the reason `PROFILE_LOGIN` keeps AF_UNIX open | N/A — never crosses a netns |
| Agent ↔ HTTP/SSE MCP servers | **out** | Yes if HTTPS; **no** if `http://` (see C2-8) |
| `claude` / `ant auth login` browser-callback flow | **in**, loopback only | **Not needed** — see below |

**The one inbound-shaped thing is avoidable, and it is not truly inbound.** The
browser-callback OAuth flow starts a loopback listener that the user's browser hits. On a
CSCS login node that browser is on the user's laptop, so the flow is *already* impossible
without an SSH tunnel — which is why the headless variants exist (`ant auth login
--no-browser` prints the authorize URL and takes the code back on the terminal; Claude
Code has the equivalent paste-the-code path), and why the CSCS deployment uses a bearer
token (`CSCS_INFERENCE_API_KEY`) rather than OAuth at all. Even in the tunnelled case the
listener and the browser-facing end are both on 127.0.0.1 *of the host*, i.e. outside any
husk cage — husk would only need to not break it, not to route it. **Nothing on the login
side requires a listener reachable from outside the netns.** The socat bridge's inability
to provide one is not a gap for 6a.

*(The one direction question left genuinely open is 6b's self-hosted case — model served
on the H100 vcluster, harness on Balfrin — but ROADMAP.md:128 already flags exactly that,
and it is out of scope here.)*

### Hosts

One host is load-bearing (`api.anthropic.com`, or a CSCS-internal inference endpoint);
everything else is convenience. The allowlist expresses a bare host or `*.suffix` with an
optional numeric port, case-insensitively, with a strict-subdomain wildcard
(`netallow.rs:190-215`). That is sufficient for a single API endpoint and for
`*.inference.cscs.ch`. It is **not** sufficient for two things:

- **Anything below the host.** `Entry::parse` rejects `://`, `/` and `@` outright
  (`netallow.rs:137-145`), so a path can never be written. GitHub org scoping is therefore
  impossible, as the brief states — confirmed, not rediscovered.
- **A self-hosted endpoint reachable only by IP.** Bare-IP *exact* entries do parse
  (`is_ip_literal` only suppresses *wildcard* matching, `netallow.rs:204-209`), so this
  works today — worth recording because ROADMAP.md's step-3 scope note called for
  "host-or-IP + port" and the code delivers it.

### Credential handling

Today, on login: **nothing**. `husk` is `seccomp-wrapper claude` (`install-husk.sh:419`,
`:427`) — no bwrap, no netns, no proxy. Claude Code holds the token in its own
environment, dials the API directly, and `sandbox.network.allowedDomains`
(`user-config/settings.json:23`, one documentation host) governs only the per-Bash-command
cages that Anthropic's runtime creates. `seccomp_wrapper.c:56-58` states this asymmetry in
so many words: *"applied per BASH COMMAND rather than to the runtime process… the agent's
commands cannot open a unix socket, while the runtime that supervises them can."*

Once husk wraps the session, the agent and its `Bash` tool are inside **one** cage
governed by **one** allowlist, and the requirement becomes: *usable but not stealable.*
The three pieces:

1. **The token must reach the harness and not the tools.** Requires TLS termination plus
   either header injection or Anthropic's sentinel-substitution (`credential-mask-env.ts`,
   `credential-sentinel.ts` — note their mechanism is *not* header injection: the agent
   sees a fake value and the proxy swaps sentinel bytes for real ones at egress, which is
   what lets it work with an unmodified client). **Out of scope to build; the structural
   question is C2-3 and the answer is favourable.**
2. **The model host must be on the allowlist.** Unavoidable, and it is what makes C2-5 a
   real cost rather than a theoretical one.
3. **The agent must not be able to redirect its own traffic.** Not covered today — C2-4.

### What step 3 already covers, named piece by piece

| Piece | File | Reusable on login? |
|---|---|---|
| Allowlist parse/match, default-deny, scheduler-port refusal | `netallow.rs:1-287` | **Yes, verbatim** — pure function of its inputs |
| Settings-hierarchy resolution | `netallow.rs:289-348` | **Yes, verbatim** — already takes `(home, project_dir)` |
| `CONNECT` parse, the gate, resolve-and-dial, tunnel, refusal messages, DoS caps | `netproxy.rs:54-284` | **Yes, verbatim** |
| Socket-path vetting (length, owner, mode) | `lib.rs:227-275` | **Yes, verbatim** — topology-free |
| Proxy instantiation, socket naming, lifetime, bind-into-cage | `policy.rs:643-760` | **No.** Shell embedded in the job guard, keyed to `SLURM_JOB_ID` |
| Per-namespace relay + proxy env vars | `policy.rs:766-777`, `rank.rs:183-220` | Pattern reusable; both instances are job/rank-shaped |
| Credential env handling | `spool.rs:391-396` | **No.** Submission surface only, by its own admission |

Concretely: **the policy is done and the plumbing is zero percent done.** That is the
right way round, and it is what the sequencing bet was buying.

---

## Findings

### C2-1 — Direction is settled: egress-only is sufficient. **CONFIRMED**

`netproxy.rs:1-52`, `seccomp_wrapper.c:51-62`, ROADMAP.md:128.

Every leg the login agent needs is an outbound dial (table above). The two things that
*look* inbound are not: IDE integration and stdio MCP are AF_UNIX/pipes that never cross a
network namespace — and `PROFILE_LOGIN` deliberately leaves AF_UNIX open for exactly that
reason — while the OAuth browser callback is loopback-only, already impractical on a login
node, and has a supported headless variant. **No listener reachable from outside the netns
is required for 6a.** The materially-new-work branch does not trigger.

### C2-2 — There is no instantiation path for the proxy outside a SLURM job. **CONFIRMED**

`policy.rs:715-724`, `main.rs:268-357`, `policy.rs:362-367`.

`--net-proxy` is only ever spawned by the guard script that `wrap_script` injects into a
submitted job. The socket lives at
`/tmp/husk-$(id -u)-${SLURM_JOB_ID:-nojob}/net.sock` (`policy.rs:715`), the proxy is
backgrounded from the guard with `$!` captured for teardown (`policy.rs:721-723`), its
lifetime is the job's, and the decision to start one at all is taken at *submit* time
(`policy.rs:362-367`). None of that has a login analogue: there is no job id, no guard, no
`--chdir`-forced workdir, and no submit/run split. The proxy binary itself is fine
(`net_proxy_mode` takes only `--socket` and `--workdir`, and re-resolves policy from files
rather than trusting its command line, `main.rs:275-279`) — what is missing is a session
supervisor that mints a per-session directory, starts the proxy, waits for the bind,
binds the socket read-only into the cage, and reaps on exit. **This is the delta, and it
is plumbing, exactly as C1 predicted.**

### C2-3 — The proxy is structured so TLS termination can be *added*. **CONFIRMED**, with three costs named

`netproxy.rs:173-245`, `netproxy.rs:40-43`.

`serve_one` is already `read head → parse CONNECT → gate on the name → resolve/dial →
write 200 → pump`. Anthropic's terminating path is the same sequence with the termination
step spliced between the gate and the tunnel (`http-proxy.ts:254-296`), and their opaque
fallback is byte-for-byte husk's current behaviour. **The single gate at
`netproxy.rs:196` — one call, one place, on the name the client asked for — is the
decision that makes this cheap**, and the file's own docstring already anticipates it
("neither the accept loop nor the allowlist gate below changes when that arrives",
`netproxy.rs:42-43`). Nothing would have to be undone. Three things would have to be
*added*, and they are worth writing down now because two of them are not obvious:

1. **The 200 must move earlier.** husk writes `200 Connection established` *after* a
   successful upstream dial (`netproxy.rs:227`). Termination requires writing it *before*,
   so the client sends its ClientHello and the proxy can sniff it — that is precisely what
   `http-proxy.ts:267-268` does, and why it needs a `wrote200` flag to avoid emitting a
   `502` status line *into* an already-open tunnel (`http-proxy.ts:329`). This is a
   re-order plus one error-path branch, not a rewrite, but it does mean the current clean
   "dial first, then commit" property is lost on the terminated path.
2. **A CA and a trust-injection surface.** Termination needs a CA, per-host leaf minting,
   and — the part usually discovered late — a *list of per-tool trust env vars* pushed
   into the cage. Anthropic's list is thirteen entries long
   (`sandbox-utils.ts:424-441`: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
   `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`,
   `CARGO_HTTP_CAINFO`, `DENO_CERT`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`,
   `NIX_SSL_CERT_FILE`, …), each earned from a client that ignores the others. That is a
   denylist-shaped artifact of the kind this project has learned to distrust, and it is
   the real cost of termination — not the TLS.
3. **A TLS dependency where there is none.** `broker/Cargo.toml` has exactly two
   dependencies (`serde`, `serde_json`); there is no `libc` crate, let alone `rustls`.
   Termination means vendoring a TLS stack plus an X.509 minting path into a workspace
   that currently vendors seven crates. This is a decision not yet taken, not a decision
   to undo — but it is the largest single item in 6b and belongs on the ledger now.

### C2-4 — `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_MODEL` are in no controlled set on the login side. **CONFIRMED**

`spool.rs:365-396`, `spool.rs:388-390`, `rank.rs:35-52`, `install-husk.sh:419`.

The only control that exists is `STRIPPED_SUBMIT_ENV` (`spool.rs:391-396`), which removes
`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CSCS_INFERENCE_API_KEY` and
`SECCOMP_WRAPPER_DEBUG` from the environment handed to `sbatch`. Its docstring says the
quiet part out loud:

> *"This is the submission surface only. Preventing the AGENT from redirecting its own
> model traffic — `ANTHROPIC_BASE_URL` pointed at a host husk did not intend — needs husk
> to own the login environment, which is ROADMAP step 6a."* — `spool.rs:388-390`

So the gap is known and recorded; what this review adds is the shape of the fix. **Compare
with `rank.rs`, which already has the right pattern in two flavours:**

- `RESERVED_ENV_PREFIXES` (`rank.rs:35-36`) — `SLURM_`, `SBATCH_`, `PMI_`, `PMIX_`,
  `PALS_`, `HUSK_` — names that are *inputs to a parser or a control plane* and therefore
  unforwardable by the confined side.
- `PROXY_ENV` (`rank.rs:49-52`) — names that *describe a namespace* and therefore must be
  re-derived rather than inherited, with the general rule stated at `rank.rs:47-48`.

`ANTHROPIC_BASE_URL` belongs squarely in the first category: it is an input to the
harness's own destination selection, i.e. husk's control plane for the thing husk is
confining. `ANTHROPIC_MODEL` is weaker but same family. The current absence is invisible
because the login agent is not caged at all today — the moment husk sets the login
environment, an unlisted `ANTHROPIC_BASE_URL` becomes an agent-settable boundary, which is
the F17/A1 shape ("the confined side must not supply its own boundary"). **Recommended
reproducer for triage: a unit test asserting that whatever login-side env constructor 6a
introduces refuses `ANTHROPIC_BASE_URL` from agent-supplied input, paired with the
existing `model_credentials_are_stripped_from_the_submission` test (`spool.rs:469-486`) so
both surfaces are covered by one convention.**

Note also that the strip list is a **denylist of three exact names** — the pattern the
project's own meta-lesson warns about. `ANTHROPIC_API_KEY_HELPER`, `ANTHROPIC_PROFILE`
(selects a stored OAuth profile), `ANTHROPIC_CONFIG_DIR`, and the Workload-Identity
variables (`ANTHROPIC_IDENTITY_TOKEN`, `ANTHROPIC_IDENTITY_TOKEN_FILE`) are all credential
*selectors* that resolve to a token, and none is on the list. On the submission surface
that is harmless (a compute job has no route); on a login surface it would not be.

### C2-5 — The allowlist cannot express the distinction login needs most: one host, two principals. **CONFIRMED (structural)**

`netallow.rs:137-145`, `netallow.rs:190-215`, `user-config/settings.json:21-25`.

On compute, the allowlist governs one principal — the workload. On login it would govern
two that share an address space: the **harness** (which must reach the model API) and the
**tools** the harness runs (`Bash`, `curl`, sub-agents), which must not have a
credentialed general-purpose data sink. Putting the model host on the allowlist grants it
to both. And a model API is the worst possible thing to grant: it accepts arbitrary POST
bodies and returns arbitrary content, i.e. it is a bidirectional channel, not a fetch
target. The allowlist can restrict *host* and *port* and nothing finer
(`netallow.rs:137-145` refuses paths by construction), so there is no way to write "the
harness may POST /v1/messages; Bash may not talk to this host at all."

This is not an argument against the design — it is the reason Anthropic built
credential masking (`credential-mask-env.ts:97-103`) rather than relying on the allowlist,
and it is why their `injectHosts` **defaults to `allowedDomains`** so that "where a secret
may go" derives from "what the network allows" rather than being a second list. **The
finding is that host-granularity alone is insufficient on the login side, and that
therefore credential masking is not an optional polish item for 6a — it is the thing that
makes the login allowlist honest.** husk's current substitute is the permission layer
(`Bash(curl *)`, `Bash(wget *)` denied in `project-config/settings.json`), which is a
denylist of program names and does not survive the agent writing three lines of Python.

### C2-6 — On login, the settings hierarchy that carries the allowlist becomes plantable. **PLAUSIBLE**

`netallow.rs:289-303`, `settings.rs:276-282`, `settings.rs:946-981`, `settings.rs:105-136`.

Two facts that are safe on compute and interact badly on login:

- **The hierarchy is additive, and a project file can *widen* it.** `netallow.rs:296-299`
  says so explicitly: *"because the combination is additive, a PROJECT file can widen the
  allowlist and not only narrow it… egress policy travels with a copied project
  directory."*
- **What makes that safe on compute is a mount, not a permission.** `AUTO_EXEC_DIRS`
  (`settings.rs:131-136`) puts a **fresh tmpfs over the whole `.claude` directory** in
  every compute cage, precisely because `--ro-bind-try` skips absent sources and "a project
  with no `.claude/settings.local.json` — the common case — let a job simply CREATE one"
  (`settings.rs:119`). The test `auto_exec_masks_apply_to_absent_paths_too`
  (`settings.rs:1607-1619`) locks that in.

**A tmpfs mask is not available on login**, because the login agent must *read* its own
`.claude/` — that is where its settings, hooks, skills and commands live. So the login cage
needs `.claude` **readable but unwritable, including for paths that do not yet exist** —
which is exactly the shape `--ro-bind-try` fails at, and exactly the hole the compute side
had to close a different way. Today the gap is covered by Anthropic's runtime honouring
`denyWrite` (`user-config/settings.json:14-19`) and by `permissions.deny` on `Edit`; the
`settings_sources_are_all_write_denied_by_the_shipped_config` pairing test
(`settings.rs:946-981`) asserts the *config* is right but says nothing about the
*mechanism* that will enforce it once husk owns the cage.

Why this is a C2 finding and not a B3 one: the file that becomes plantable is the one that
holds `sandbox.network.allowedDomains`, i.e. **the boundary on the login agent's own model
traffic**. An agent that can create `<project>/.claude/settings.local.json` widens its own
egress. Triage should establish what mount-table construction gives "readable, unwritable,
absent-safe" for a directory (a read-only bind of the *parent* plus a writable overlay
elsewhere? an explicit `--ro-bind` with a pre-created mountpoint?) — and whether the
answer differs for `~/.claude` and `<project>/.claude`.

### C2-7 — No SOCKS path: non-HTTP TCP has no route at all. **CONFIRMED**

`netproxy.rs:88-104`, `sandbox-runtime/src/sandbox/socks-proxy.ts`, README.md:130 of the
vendored runtime.

husk tunnels `CONNECT` and nothing else. Anthropic ship **two** proxies — HTTP for
CONNECT/absolute-URI and **SOCKS5 for "other TCP traffic"** — and route both through the
bind-mounted unix sockets. husk has one. On compute that is the right call (a batch job
wants HTTPS). On login it removes, by construction:

- `git+ssh` (`git@github.com:…`) — the default clone/push transport for most developers.
  Anthropic route this by pointing `GIT_SSH_COMMAND` at `socat - PROXY:` through their
  CONNECT proxy (`http-proxy.ts:260-266`), which husk could copy without SOCKS — worth
  noting as the cheap partial answer.
- any MCP server or tool speaking raw TCP.

This is one of the brief's named finding categories — "a login-side requirement the
compute egress layer **cannot** express" — and the honest answer is that it is a real gap
whose cost depends entirely on whether 6a's users are expected to use git over SSH. It
should be a stated limitation with a teaching message, not a silent failure; today a
`git push` inside a netns-caged login session would fail with a bare connection error and
nothing would say why.

*(The `CONNECT`-only / no-plain-`http://` limitation is separately confirmed at
`netproxy.rs:88-104` and its tests at `:304-318`, as the brief instructed — not
rediscovered. Note it is mitigated for local MCP by `NO_PROXY=localhost,127.0.0.1`,
`policy.rs:773`.)*

### C2-8 — husk's unix-socket transport already avoids the bug Anthropic had to fix; a TCP-loopback login proxy would reintroduce it. **CONFIRMED**

`http-proxy.ts:145-151`, `main.rs:340-353`, `lib.rs:227-275`.

Their `proxyAuthToken` exists because *"without this, any host process can dial 127.0.0.1
and reach the filter callback"* (`http-proxy.ts:148-150`) — a per-session bearer token
bolted onto a TCP listener to recover the confinement a shared loopback address gives
away. husk does not have that problem: the proxy listens on a **unix socket**, chmod
`0600` (`main.rs:349-353`), in a directory whose ownership and mode are re-verified before
binding (`lib.rs:245-275`), and reachability is a filesystem question rather than a
network one. **This is a mistake husk gets to not repeat — provided the login-side
instantiation (C2-2) keeps the unix socket.** The pressure to use TCP loopback on login is
real (it is what Anthropic do on macOS and Windows, per their README:126-128, because
Seatbelt and WFP have no unix-socket equivalent), so record the constraint now: *if a
login proxy ever listens on loopback TCP, it needs `proxyAuthToken`'s equivalent on day
one.*

### C2-9 — With header injection, the in-cage relay becomes a position the agent occupies. **PLAUSIBLE, low severity, recorded for the 6b design**

`policy.rs:766-777`, `rank.rs:206-215`.

The relay is `socat TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:$sock`,
started *inside* the cage as a background child of the workload's own shell. On compute
that is fine: the cage runs one workload, and killing your own relay only costs you your
network. On login the caged process is an agent that can spawn arbitrary children — so it
can kill the relay and bind its own listener on `127.0.0.1:3128`, becoming a
man-in-the-middle on **its own harness's** requests.

Today that buys nothing (the agent already sees its own conversation). It becomes
interesting only once the proxy injects a credential the agent is not supposed to have:
the injected header never crosses 3128 (injection happens outside the cage, at the proxy),
so the credential still cannot be captured — **but the agent gains the ability to observe
and alter the harness's requests before they reach the injection point**, which is a
position no threat model has yet been written against. Worth one sentence in the 6b design
rather than a fix now. The clean structural answer, if it is ever needed, is the
relay-placement trick already noted in the `anthropic-srt-launcher` reference: put the
relay in the sandbox's *netns* but the *host's* pid and mount namespaces, so the caged
process cannot signal it.

---

## What a null result would have looked like, and why this isn't one

The brief asked for the shape and warned that "it should mostly work" is not an answer.
The shape is above. The one-line version: **direction is a non-issue, policy transfers
verbatim, instantiation is 100% missing and is the real 6a work item, TLS termination can
be added without undoing anything, and the two things step 3 genuinely cannot express are
non-HTTP TCP and a readable-but-unwritable config directory.**
