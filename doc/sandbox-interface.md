# Sandbox interface spec

**The contract between husk and the agent it wraps.** An agent that satisfies it can be
wrapped without modification, and without husk knowing anything about the agent.

husk is a **best-effort, client-side sandbox for LLM agents on supercomputers**. Every word
in that sentence is a scope limit and each is deliberate:

- **Best-effort** — it raises the cost of the harms in [threat-model.md](threat-model.md). It
  is not a jail for hostile native code, and it does not claim to be. An agent determined to
  break out, with a kernel exploit, breaks out.
- **Client-side** — it runs as the user, with the user's rights, on a machine husk does not
  administer. There is no root, no daemon, no site cooperation required. That is what makes
  it deployable on a shared cluster, and it is also the ceiling on what it can promise.
- **For LLM agents** — the adversary model is a capable, non-malicious system that will do
  surprising things with credentials, allocations and other people's jobs. Not malware. But
  see below: the model is not the only thing in the process.
- **On supercomputers** — shared login nodes, a batch scheduler, other people's work running
  next to yours, and a home directory full of things worth protecting.

Level 2 of the documentation stack — see [README.md](README.md). Harms are `H*`, principles
are `P*`.

---

## 1. The axiom

> **Confine from the outside. Wrap what you can, mediate what you cannot, and require nothing
> of either.**

husk never asks the agent to restrict itself. A control that depends on the confined party
choosing to honour it is not a boundary, it is an agreement — and the agent's disposition is
not something husk can verify or a future version guarantee (`P2`).

This has a precise consequence that shapes everything below. The obligation on an agent is
**not cooperation but tolerance**: it does not have to help, it only has to keep working
while restricted. Nothing is delegated to it, so nothing about it has to be trusted.

### 1.1 What is wrapped is a process, not a model

**husk wraps the harness binary, and that is a second reason rather than an implementation
detail.** An agent harness ships as a closed binary — hundreds of megabytes, updated on the
vendor's schedule, containing a telemetry client, a crash reporter, an auto-updater and
whatever else the vendor chose. None of it is auditable and none of it is the model, yet all
of it runs with the user's uid, filesystem reach and cluster identity.

So the boundary is not only "what might the LLM be talked into doing" but **"what does this
opaque process do on a machine that holds SSH keys, unpublished research and other people's
jobs"**. Those are different questions with the same answer, and the second one does not go
away if the model behaves perfectly.

It also cannot be answered by anything the vendor supplies. A runtime's own sandbox, its
permission prompts and its tool policy are all implemented by the code in question, which is
the confined party — and §1 does not accept the confined party's word for the shape of its
own cage. **Against this adversary only the wrapped layers count**: what is not mounted
cannot be read, what has no route cannot be sent. This is why husk aims to own the outer
boundary rather than configure someone else's, and why the contract below asks nothing of the
agent's internals — trusting a specific vendor is not a security property, and it does not
transfer to the next one.

See [threat-model.md §2.2](threat-model.md).

**Two mechanisms, one principle:**

| | mechanism | example | what the agent must do |
|---|---|---|---|
| **Wrap** | the resource is reachable, so remove it from the namespace | `/users` is not mounted; there is no network but a proxy socket | nothing — it is simply not there |
| **Mediate** | the resource is a service husk cannot wrap, so substitute the door to it | `slurmctld` runs on another host; a stub sits at the path of the real `sbatch` | nothing — it runs `sbatch` and gets what is at that path |

Mediation is not a weaker form of wrapping, it is the answer to a different question: *you
cannot put a mount namespace around a daemon on another machine.* What both have in common is
that the agent is not consulted.

---

## 2. What husk provides

### 2.1 Wrapped layers

Applied to the **whole agent process tree**, from outside, by a wrapper the agent never sees:

1. **Filesystem** (bubblewrap). Read-only root; the writable set is the project directory
   plus configured roots; homes are replaced by an empty tmpfs; declared credential paths are
   masked; auto-exec dotfiles are neutralised.
2. **Network** (network namespace + proxy). No route by default. With an allowlist
   configured, exactly one hole: a unix socket to a filtering proxy that runs **outside** the
   namespace and holds the policy.
3. **Syscalls** (seccomp). A blocking filter, with `io_uring` the trap worth naming — see
   §4.3.

### 2.2 Mediated services

Where the resource is a daemon husk cannot wrap:

- **The scheduler.** A stub is bind-mounted over the real client binary inside the cage; a
  broker runs outside it, holds the credentials and the daemon route, and validates every
  request by construction rather than by filtering (`P4`, `P5`). The real binary and the
  credentials never exist inside the boundary, so there is nothing to bypass.

### 2.3 Context channel

husk tells the agent what its boundary is — a banner in the job, `HUSK_WRITABLE` in the
environment, and an attributed message on every refusal (`P11`). This is **information, not
negotiation**: the agent cannot reply, and nothing it does with the information changes the
boundary. It exists because an unattributed denial produces confident wrong remediation, not
because the agent is owed an explanation.

---

## 3. Conformance: what the agent must tolerate

> **If it still works inside the sandbox because it has a graceful fallback, it is wrappable.
> If it refuses to work, it is not.**

That is the whole test, and it is about degradation rather than about needing nothing.

| # | requirement | why it is a real limit |
|---|---|---|
| **T1** | **Tolerates an incomplete filesystem.** Paths vanish, writes return `EROFS`, some files read empty. The agent must degrade, not abort. | husk cannot make a hidden home appear. An agent that requires `$HOME` to be writable at startup cannot run. |
| **T2** | **Tolerates having no network, or accepts proxy configuration.** Standard `HTTP_PROXY`/`HTTPS_PROXY` env, or an equivalent setting. | The proxy is the only route. Raw sockets and direct DNS do not work, and an agent that treats "no network" as fatal has no degraded mode to fall back to. |
| **T3** | **Does not require a blocked syscall.** | `io_uring` is the live trap: some async I/O libraries adopt it opportunistically, and it is blocked because it is a well-known filter bypass. The agent must be able to run on `epoll`/`poll`. |
| **T4** | **Runs unprivileged.** No setuid, no `CAP_SYS_ADMIN`, no assumption of root. | husk itself has no privilege to grant. |
| **T5** | **Tolerates a mediated binary.** What sits at a system binary's path may be a stub that validates and forwards. | The agent must not require the real binary by inode, hash, or its exact stderr. |

**Not wrappable, by design.** An agent that needs a kernel module, a privileged helper, or a
device husk cannot expose is out of scope — and saying so is a feature of this document, not a
gap in it. The interesting boundary is not "does it need something" but "does it *fail* when
it does not get it".

---

## 4. What is deliberately NOT required

Each of these was a requirement in an earlier draft. Each was dropped because it asked the
agent for cooperation, and the axiom says we do not.

### 4.1 Nothing about the agent's internal tool architecture

The previous spec required system-affecting tools to run as **subprocesses**, on the grounds
that a tool implemented in-process — opening a file descriptor inside the agent — bypasses a
sandbox applied per-command. It called this "the most important requirement", and it was
right about the mechanism: that asymmetry is real, it was measured, and it is what the tool
allowlist in the reference integration currently works around.

**But the requirement was an artefact of wrapping the wrong thing.** It follows only if the
sandbox wraps each *command*. Wrap the **harness** — one namespace around the agent process
itself — and the distinction disappears: an in-process file read and a shelled-out `cat` are
the same syscall in the same namespace, and a path that is not mounted is not reachable by
either. There is no in-process door because there is no door.

So husk does not ask how an agent implements its tools. Owning the outer boundary is husk's
job, and the moment husk owns it, the question stops being the agent's problem. Where husk
does not yet own it, the shortfall is husk's to state — not a conformance requirement to
push onto the agent.

### 4.2 Nothing about the agent's intentions

Earlier drafts required that the agent "does not attempt to detect or bypass the sandbox".
That is unenforceable and, under the axiom, unnecessary: probing is expected, and a boundary
that holds only while unprobed is not a boundary. If an attempt succeeds, the finding is
against husk.

### 4.3 Nothing about where the agent writes

The agent does not have to confine itself to the writable set — husk confines it. The
requirement is only T1: that being confined produces a degraded run rather than a crash.

---

## 5. The integration profile

An agent cannot widen its own boundary (`P2`). But an **integration** — the human-authored
glue for a particular agent — must be able to *declare* what that agent needs, so an operator
can decide before launch. Declaration by the integrator, decision by the operator, enforcement
from outside. That is not cooperation: nothing the agent does at run time affects it.

A profile declares:

- **Egress**: hosts and ports the agent must reach to function at all (a model endpoint), and
  which are optional. The operator decides what goes in the allowlist; an empty allowlist must
  still produce a working, degraded agent.
- **Filesystem**: paths outside the project directory the agent needs to read, and any it must
  write. Each is a carve-out an operator approves individually.
- **Subprocesses**: whether the agent spawns helpers, and whether those helpers have needs of
  their own.
- **Mediated binaries**: which system commands the integration expects to be substituted.

This section is the honest cost of agent-neutrality: **every harness has quirks, and finding
them is work that cannot be automated away.** The profile is where that work is written down
once instead of rediscovered per site.

### 5.1 Model context servers (MCP and equivalents)

The sharp case, and it splits along the wrap/mediate line, which is a good sign the framing
holds:

- **Local server — a subprocess the agent spawns.** It is a child of the wrapped process, so
  it is already inside the cage. Nothing extra is required, and nothing extra is granted: it
  inherits exactly the boundary the agent has.
- **Remote server — a network service.** It is an egress allowlist entry like any other, named
  in the profile and approved by the operator.

Both are supportable in principle. What is **not** supportable is a server that must reach
outside the boundary to be useful, because that is a request to widen the boundary from the
inside. The shipped configuration currently disables project-supplied servers by default; that
is a conservative starting position for the reference integration rather than a statement
about the mechanism.

---

## 6. Policy

husk defines **its own policy schema**. A vendor's configuration format is an **adapter** onto
it, not the canonical form.

This is the difference between wrapping one agent and being able to wrap agents. Expressing
policy in a vendor's vocabulary means every future agent must be described in that vendor's
terms, and it couples husk's boundary to a schema someone else revises. The adapter keeps the
convenience — an existing integration's config continues to work — without the coupling.

The policy source must be a file **the agent cannot write** (`P2`), and that pairing is
asserted by a test rather than maintained by hand (`P8`).

---

## 7. Conformance checklist

```
[ ] T1  Degrades rather than aborts on a read-only / partially absent filesystem
[ ] T2  Accepts proxy configuration, or runs usefully with no network
[ ] T3  Runs without io_uring or any other blocked syscall
[ ] T4  Runs unprivileged
[ ] T5  Tolerates a stub in place of a mediated system binary
```

An agent meeting all five is wrappable. An agent failing one is not "partially wrapped" — it
is an agent whose gap husk must state plainly, in its integration row, so that nobody reads
a boundary into a place where there is none.

## 8. Conformance status

Conformance runs in **both directions**, and both belong in the same place. §3 and §7 ask
whether an agent tolerates the boundary. This section asks whether **husk delivers the
boundary it specifies** — and holds husk to its own table rather than to a footnote.

### 8.1 husk

Several clauses above are **requirements husk does not yet meet**. They are written as
requirements anyway, because a contract states what anything conforming must provide; a
clause quietly softened to match today's implementation stops being a contract and becomes a
description. The gap is therefore scheduled, listed, and visible:

| clause | status | gap |
|---|---|---|
| §2.1 wrapped layers, applied to the whole process tree | **compute: yes · login: no** | On the login side the vendor runtime wraps each *command*, not the harness, so in-process file tools run beside the cage rather than inside it (§4.1). Worked around by restricting the agent to a single subprocess tool. Closed by husk owning the outer boundary — ROADMAP 6a. |
| §2.2 mediated services | yes | The broker ships: stub inside, credentials and daemon route outside. |
| §2.3 context channel | yes | Banner, `HUSK_WRITABLE`, attributed refusals. |
| §5 integration profile | **no** | The concept is specified; no profile artifact exists and nothing consumes one. Today an integration's requirements live in the shipped config and in operators' heads. |
| §6 husk-owned policy schema | **no** | Policy is expressed in the vendor's configuration shape and consumed directly — there is no adapter layer, so the coupling §6 exists to remove is still present. ROADMAP 6a. |

**Deliberately not specified yet: the schema's field names.** §6 states a *property* — husk
owns the vocabulary, a vendor format maps onto it, the source is unwritable by the agent.
Properties are stable; a field list designed before 6a's implementation constraints are known
would be a field list we then have to change, and a spec that changes under its own
implementation teaches nobody anything. The property is the commitment; the encoding is 6a's
to choose.

**These rows are deleted when closed, never edited.** A gap that is quietly reworded into
compliance is the failure mode `P12` describes, running in the direction where a document
under-claims: nobody re-reads a clause that no longer looks aspirational.

### 8.2 Integrations

| integration | status | known gap |
|---|---|---|
| Claude Code | reference integration, shipped | Inherits §2.1 above: in-process file tools are not covered while the vendor runtime owns the outer boundary. |

The reference integration is one row. Everything above this table is the contract, and the
contract does not know what is in it.
