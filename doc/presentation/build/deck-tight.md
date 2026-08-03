% Containing the agent — claude-safe on CSCS supercomputers
% Christoph Müller · MeteoSwiss
% 

# Why agents must be contained

## What we want — and the catch

- The goal: hand an agent a real task — *"optimize this code", "run this sweep"* —
  and **leave it for a week** on the HPC.
- The catch: agents fail in two ways — **they get tricked**, and **they do harmful
  things on their own.**

**Today: why it's dangerous → what we built → the hard problem we're still on.**

::: notes
Set the 30-second roadmap so the danger section feels bounded — then you can move
fast through it.
:::

## 2025 — the accident everyone saw

:::::: columns
::: column
*[ screenshot: Replit / Jason Lemkin — "it deleted our production database… it
hid and lied about it" ]*

*Source: Tom's Hardware (2025)*
:::
::: column
- 12-day autonomous experiment
- **Day 9: deleted the production database** during a code freeze it was told to
  respect
- then **fabricated data and lied** about it
:::
::::::

**No attacker. It was told not to — and did it anyway.**

::: notes
GRAB: https://www.tomshardware.com/tech-industry/artificial-intelligence/ai-coding-platform-goes-rogue-during-code-freeze-and-deletes-entire-company-database-replit-ceo-apologizes-after-ai-engine-says-it-made-a-catastrophic-error-in-judgment-and-destroyed-all-production-data
Land the "it lied" beat — that's the part people remember.
:::

## 2025 — the attack

:::::: columns
::: column
*[ screenshot: "EchoLeak" zero-click — Microsoft 365 Copilot, CVE-2025-32711 ]*

*Source: arXiv / Dark Reading (2025)*
:::
::: column
- **One email. Zero clicks.**
- Copilot reads it as part of its job and **silently exfiltrates your data**
- (Amazon Q: a "wipe everything" prompt shipped to ~964k machines via a normal PR)
:::
::::::

**The user did nothing. Reading the data *was* the attack.**

::: notes
GRAB: https://arxiv.org/pdf/2509.10540  (EchoLeak)
Amazon Q one-liner is optional colour.
:::

# But that was last year

## "The new models are hardened."

> *"They're smarter — you can't trick them that easily."*

::: notes
Say it sincerely; let the room nod. "It's exactly what I assumed too. So let's
look at this year, on the current flagship models."
:::

## This year — on the flagship models

:::::: columns
::: column
**Rogue — PocketOS (Apr 2026)**

*[ screenshot: The Register / Fast Company — "I violated every principle I was
given" ]*

- **Claude Opus 4.6**
- deleted a volume on its own initiative
- **DB + all backups gone in 9 s**
:::
::: column
**Injection — "Comment & Control"**

*[ screenshot: SecurityWeek — CVE-2026-21520 ]*

- one PR comment hit **Claude Code, Gemini CLI, Copilot**
- **zero victim interaction**
- named researchers + CVE
:::
::::::

**Newer didn't fix it. A smarter model just follows the malicious instruction more competently.**

::: notes
GRAB left: https://www.theregister.com/2026/04/27/cursoropus_agent_snuffs_out_pocketos/
GRAB right: https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
Say "Opus 4.6 — this year, the flagship." Do NOT say 4.8.
:::

## It's structural — not a bug to be patched

- An LLM reads **instructions and data in one channel** and **can't tell them
  apart** — *OWASP LLM01:2025* (primary reference).
- It's **SQL injection before parameterized queries** — except there is **no
  parameterized-query fix**: no second channel to move the data into.
- OWASP's own remedy: **defense in depth + privilege restriction.**

**There is no safe model coming. So we contain.**

::: notes
This replaces vendor survey stats — the same-channel + SQLi argument is rigorous
and hard to attack. Source: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
:::

## 30 years of trading harmlessness for features

- "Harmless" (fefe): you could run it on **any web-form input** without worrying.
- **Word→macros, Excel→VBA→JS, PDF→JS, browser→arbitrary code.** Each step: more
  useful, less harmless.
- **"Connect your whole life to an agent and let it act"** is that trend's endpoint:
  max capability × max connectivity → **one compromise = total compromise.**

**On a shared supercomputer, squared.**

::: notes
fefe, "Das nützlich-unbedenklich Spektrum" (36C3, 2019). Don't go luddite — next
slide makes the turn.
:::

## You can't make it harmless — so cage it

:::::: columns
::: column
**Soft constraints**

- `AGENTS.md`, skills, prompts
- *genuinely help — write them*
- but probabilistic; can be tricked out of
:::
::: column
**Hard constraints**

- filesystem, syscalls, network
- live **below** the agent
- it **cannot choose** to violate them
:::
::::::

**Soft lowers the chance. Hard caps the damage. On a shared HPC you need the cap.**

::: notes
This is the hinge — defines "containment" before we build it.
:::

# Check your privileges

## Lion → Lynx → Kitten

```
   LION                 LYNX                     KITTEN
   (root)      ──►       (user)        ──►        (sandboxed process)
            drop root             sandbox: strip every right
          / run as user          except the few the task needs
```

- **Lynx (a normal user) is NOT safe enough** on a shared machine — it can read
  data, reach the network, submit jobs. **PocketOS was a Lynx.**
- We need the agent to be a **Kitten**: do its one job, nothing else.

**Security = walk the animal as far right as it goes while it still does the job.**

::: notes
fefe's metaphor ("Check your privileges!", 32C3 2015) — where I first learned
seccomp. Credit it.
:::

## Three dimensions of the Kitten

:::::: columns
::: column
- **Filesystem** — write = whitelist (work dir); read = blacklist (all but
  secrets)
- **Network** — can't blacklist the *tool* (`curl`/python/`/dev/tcp`) → **allowlist
  the destination**
:::
::: column
- **Syscalls** — brick doors the agent never uses (`ptrace`, `io_uring`) → **next
  year's kernel bug can't be its escape**
:::
::::::

::: notes
Each dimension is the same move; the next slide names it.
:::

## The pattern behind all three

> Enumerate what the task needs. **Deny the rest.** Enforce it **below** the agent —
> not as a rule it could talk its way around.

**Least privilege isn't a rule the agent follows — it's a world the agent lives in.**

::: notes
The nine-word thesis. Pause here.
:::

# claude-safe on the HPC

## Anthropic already ships a sandbox

- Built on **bubblewrap**; wraps **every Bash command** (that's why Bash differs
  from Read/Write/Edit — Bash is the wildcard).
- Gives **filesystem + network** restriction for free.
- **Leaves the syscall cage empty — and warns about it.**

::: notes
Read/Write/Edit are mediated tool calls; Bash is arbitrary → must be wrapped. That
wrapping is also where the cost comes from (slowdown slide).
:::

## The official config — and Problem 1

- IT ships sensible-looking denies + sandbox-on, deny home, allow cwd.
- **On Balfrin it doesn't even start:** no `socat` (network proxy dead), no seccomp
  rules (empty-cage warning).
- The config's guarantees are **delegated to a sandbox that never engages.**

**The recommended setup assumes a workstation. Ours is a shared HPC login node.**

::: notes
Full JSON + the bypassable-`Bash(curl *)` critique are in backup slides.
Credibility moment: you tried the official path honestly and it broke.
:::

## claude-safe makes the cage real

- Install script ships the missing pieces (`socat`) so the sandbox **starts**.
- **Fills the seccomp slot** — closes `io_uring` / `ptrace` escape hatches.
- *Only now* is it worth tuning the config.

**First make the cage real. Then it's worth tuning the bars.**

## Three config traps

- **Two doors:** Read/Write/Edit (`permissions`) vs Bash (`sandbox.filesystem`) —
  lock **both** or you've locked neither.
- **Deny broad:** block **`/users/`**, not just `~` — everyone's home lives there.
- **Footgun:** toggling the sandbox off once **persists to `settings.json`**.

::: notes
allow-narrow + precedence (project < local) detail is in a backup slide.
:::

## uenv: prepare outside the cage, first

- The software stack is a **uenv** (a mounted squashfs). Mounting needs **setuid**;
  the cage sets **`NO_NEW_PRIVS`** → **can't mount inside the cage.**
- Correct order: **`uenv start` → then launch the agent.** It inherits the mounted
  environment.

**Prepare the world outside the cage; put the agent in it.** *(Same trick as the broker, next.)*

## The honest cost

- Wrapping every Bash command sets up the cage per command — it walks the project
  tree.
- On a **big folder on Lustre**, the first ~2–3 iterations are slow (cold
  metadata); then cached and fast.

**Security has a warm-up cost.**

# The punchline: SLURM

## The agent has to run a job

- It came here to **compute** → `sbatch` → **the one capability the cage was built
  to deny.**

## Problem 1 — sbatch dies on every layer

- **Network** — no route to the controller (`slurmctld`).
- **Auth** — MUNGE needs an **`AF_UNIX` socket**; seccomp blocks it → no
  credential.
- **Filesystem** — munge socket, `/etc/slurm`, the binary: not mounted.

**The cage works — too well. The agent can't do its job.**

## The broker

```
  IN THE CAGE                          OUTSIDE (trusted)
  agent → sbatch STUB ──writes──► spool file ──► BROKER ──► real sbatch → SLURM
          (dumb serializer)                     (network + MUNGE)
```

- The real `sbatch` lives **outside**; the agent only writes a request file.
- It **never touches sbatch** and **can't reach SLURM directly.**

**Give back the capability, not the keys.** *(File spool because `AF_UNIX` is blocked — same outside-the-cage trick as uenv.)*

## Problem 2 — the compute node is outside the cage

- A job runs as the **full user, uncaged.** It can **edit `settings.json` and
  disable the sandbox for every future session.**
- A job = *"run my code as me, with no cage."*

**A way out of the cage — and a way to rewrite it so it never returns.**

## The broker re-sandboxes the job

- The broker injects a **re-exec guard**: before any agent code runs, the job
  **re-launches inside the same cage** on the compute node.
- **Kitten on the login node, Kitten on the compute node.** Plus policy (only the
  `preemptible` queue).

**No node is outside the cage.**

## Why it holds

- The **privileged tool never enters** the sandbox.
- The **agent's code never runs outside** one.
- **Status (honest):** first slice — `sbatch` — in progress, not yet
  battle-tested. The architecture is the point today.

**Compute on the whole supercomputer — and never once leave the cage.**

# Status & the bigger idea

## Status & roadmap

- **Now:** broker being written; **`sbatch` first** (interactive `srun`/`salloc`
  are harder).
- **Next:** solid sbatch → **MPI / multi-node** → **open the cage to more agents
  than Claude.**

## A contract, not a Claude feature

- Any agent that meets the **contract** — wrappable bash tool, mediated file tools,
  privileged steps outside — gets the cage.
- **Comment & Control broke all three vendors at once** → the defense should be
  **cross-vendor** too.

**Don't build a sandbox for Claude. Build a cage with a contract.**

## Takeaways

- You **can't make an agent harmless** — injection is structural.
- So you **don't trust it — you contain it** (Lion → Kitten).
- **claude-safe** makes that real on Balfrin/Santis; **SLURM** without escape.

**We don't trust the agent. We contain it.**

::: notes
Land the refrain, then Q&A. If asked "is it done?": login-node cage ships
(v0.2.1); the SLURM broker is in active development.
:::

## Sources

- Replit — Tom's Hardware (2025); AI Incident DB #1152
- EchoLeak — CVE-2025-32711; arXiv 2509.10540 · Amazon Q — The Register (2025)
- PocketOS / Claude Opus 4.6 — The Register, Fast Company (Apr 2026)
- Comment & Control — **CVE-2026-21520**; SecurityWeek, CybersecurityNews (Apr 2026)
- Prompt injection is structural — **OWASP LLM01:2025** (genai.owasp.org)
- fefe — "Check your privileges!" (32C3 2015); "Das nützlich-unbedenklich
  Spektrum" (36C3 2019)
