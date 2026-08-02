# A9 — the network allowlist: what is authorised vs what is dialled

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `review-v0.5-questions.md`

## The question

The proxy authorises a **name** and then makes a **connection**. Can those two come apart — so
that what is checked is not what is reached?

## Why this is on the list

This is the newest boundary in the system and the only deliberate hole in the cage. It is also
the classic location for a parser differential: allowlists are string matching, connections are
addresses, and the gap between them is where `F13`/`F14`-shaped bugs live. `netallow.rs`'s own
comments flag one such trap already — reading a trailing `:...` as a port would make
`evil.com:...` parse as host `evil.com` with a nonsense port.

## What the code does today

The cage keeps `--unshare-net` and gains one hole: a unix socket, relayed by socat on
loopback:3128 inside the cage to a proxy **outside** it. A unix socket crosses a netns because
it is a file.

Two design decisions do most of the work, and both should be attacked rather than assumed:

1. **One gate, one place, on the name the client asked for.** `parse_connect` extracts
   host:port from the CONNECT line; the allowlist is consulted once, on that name.
2. **The trusted process resolves and dials.** `to_socket_addrs` then `connect_timeout` happen
   in the proxy — **the job never supplies an address**, so it cannot authorise a name and
   connect to something else.

Also current: `*` is accepted as an explicit "everything" entry while `*.com` is refused
(vagueness is what is refused, not breadth); SLURM daemon ports are refused **even under `*`**;
and it is **CONNECT-only**, so `https://` works and plain `http://` does not — serving an
absolute-URI GET would need a second HTTP parser, which is the shape we are avoiding.

## Starting points

1. **The CONNECT line parser.** Trailing dot (`example.com.`), IDN/punycode, uppercase, a
   userinfo `@`, IPv6 literals in brackets, a port with leading zeros, `host:443:443`, absurd
   lengths, embedded whitespace or `\r`. Does husk's reading match what the dial does?
2. **Wildcard semantics.** Does `*.example.com` match `example.com` itself? `a.b.example.com`?
   `evil-example.com`? `example.com.evil.net`? Prefix/suffix confusion is the classic bug.
3. **Name vs address.** The gate is on the name — so confirm there is genuinely **no** path
   where a client-supplied address reaches the dial. If a name resolves to multiple addresses,
   which is used, and can that be influenced?
4. **DNS.** Resolution happens once, in the trusted process, after authorisation. Confirm there
   is no second resolution anywhere (that would reopen rebinding). Can the agent influence
   resolution at all — `/etc/hosts`, `resolv.conf`, `HOSTALIASES`, `LD_PRELOAD` on the *proxy*
   (ties to A2)?
5. **Scheduler ports** — refused even under `*`. Try to reach one anyway: by name rather than
   number, via a redirect, via an alternate port that reaches the same daemon (AV8).
6. **The relay itself.** socat is bound into the cage. Can a rank point it somewhere else, or
   start its own relay to a different unix socket? Can it reach the proxy's socket directly and
   speak something other than CONNECT?
7. **Known-and-accepted, do not report as new:** `github.com` means *all* of GitHub — org
   scoping is impossible with a host allowlist because the org is in the path and we do not
   terminate TLS. Confirm, do not rediscover.

## What counts as a finding

- Any connection to a host the allowlist does not authorise.
- A divergence between the name checked and the endpoint reached.
- A wildcard match wider than intended.
- Reaching a SLURM daemon port by any spelling.
- A second, unauthorised route out of the netns (not through the proxy at all).
- An `http://`-style request being served rather than refused.

## What a null result looks like

The parser table — inputs tried, what the gate saw, what the dial did — plus an explicit
statement that name-authorised equals address-dialled on every path found. This is the boundary
most likely to need a wide, mechanical enumeration; breadth beats depth here.

## Out of scope for this item

- TLS termination and header injection (6b, not built).
- Allowlist *policy* — whether the operator picked good domains.
- The step spool as a mechanism (A4); here only the socket's use as a route.

## Verdict

Execution inside; verdict from the **proxy's own log** and from the far end. A caged agent
reporting "I reached X" is a hypothesis — the proxy's record of what it authorised and what it
dialled is the evidence, and the two must agree.
