# C2 — the login-side agent's own egress, once husk owns the sandbox

**Workstream C** (substitution gap analysis) · **one agent, code-only** · **pin the shape
early**

## The question

If husk provides the login sandbox, the agent's own traffic to its model API becomes husk's
problem. What shape does that take, and does the egress layer built for compute already cover
it?

## Why this is on the list

Today Anthropic's runtime handles the login agent's network. Remove it and husk owns that
route. This is the item most likely to be discovered late and to be **structural** rather than
incremental, which is why it is asked now rather than during 6a.

The sequencing decision already made: network-on-compute (roadmap step 3) came **first**
precisely because the proxy + allowlist layer built there is the same layer login needs. That
was a bet. This brief checks whether the bet paid.

## What the egress layer looks like today

The cage keeps `--unshare-net` and gains **one hole**: a unix socket, relayed by socat on
loopback:3128 inside the cage to a proxy running outside it. A unix socket crosses a netns
because it is a **file**. Policy lives in `netallow.rs`, the proxy in `netproxy.rs`, wiring in
`policy.rs`. Off unless `sandbox.network.allowedDomains` is set.

**Known limitation, by design: CONNECT only.** `https://` works, plain `http://` does not — a
proxied `http://` request is an absolute-URI GET, and serving it needs a second HTTP parser,
which is the F13/F14 shape. Everything that matters is HTTPS.

## The distinction that decides the difficulty

**Connection direction.** Our model is **egress-only**:

- Agent dials the model API → reuses step 3 directly.
- Anything dialling **inward** to a caged agent → needs a listener reachable from outside the
  netns, which the socat bridge does **not** provide. That is materially new work.

Establish which of these the login agent actually needs. This is the single most valuable
output of this brief.

## The credential tension

`ANTHROPIC_AUTH_TOKEN` / `CSCS_INFERENCE_API_KEY` are bearer tokens buying paid inference.
husk masks credentials today via `credentials.envVars` → `--unsetenv`, but a login agent
**needs to authenticate**. So the requirement is head-on: *usable but not stealable*.

The known-good answer, which Anthropic already built: **husk holds the key and injects the
`Authorization` header at the proxy**, so the caged agent never sees it. Their design couples
it properly — `injectHosts` defaults to `allowedDomains`, so "where a secret may go" derives
from "what the network allows".

**Consequence for sequencing: header injection requires TLS termination**, which is the
expensive piece and belongs to 6b. So the question for *this* review is narrower: **is the
v0.5 proxy structured so termination can be added rather than retrofitted?**

Related and cheap to check: `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN` and
`ANTHROPIC_MODEL` are **security-relevant environment variables** — an agent that can set them
redirects its own model traffic. They belong in a controlled set, like `SLURM_*` and `HUSK_*`
in `rank.rs`.

## Starting points

1. Which hosts does a login agent actually need? Compare with what an allowlist can express —
   note that **GitHub org scoping is impossible** with a host allowlist: same hosts serve every
   org, the org is in the path, and inside TLS we do not terminate. `github.com` means all of it.
2. Does anything need to dial *in*?
3. Is the proxy's structure compatible with later TLS termination, or would it need rewriting?
4. Are the model-selection env vars controlled, or agent-settable?

## What counts as a finding

- A login-side requirement the compute egress layer **cannot** express.
- Anything requiring inbound connections.
- A proxy design decision that would have to be undone to add TLS termination.
- A credential that must be present in the agent's environment with no path to injection.

## What a null result looks like

A statement of the login egress shape: hosts, direction, credential handling, and which of
those step 3 already covers. "It should mostly work" is not an answer — name the pieces.

## Out of scope for this item

- Implementing TLS termination or header injection.
- Non-Claude agents (6b), except where a decision here would foreclose them.
- The compute-side allowlist's correctness — that is A9.

## Verdict

Source-level, plus their `http-proxy.ts` / `tls-terminate-proxy.ts` for allowlist semantics,
so we do not repeat a mistake they already fixed.
