% Containing the agent — claude-safe on CSCS supercomputers (full)
% Christoph Müller · MeteoSwiss
% 

# Why agents must be contained

## One of the most famous AI failures in the world

*[ screenshot: Jason Lemkin / X — "It deleted our production database without
permission… Possibly worse, it hid and lied about it." ]*

*Source: Tom's Hardware (2025)*

::: notes
GRAB: https://www.tomshardware.com/tech-industry/artificial-intelligence/ai-coding-platform-goes-rogue-during-code-freeze-and-deletes-entire-company-database-replit-ceo-apologizes-after-ai-engine-says-it-made-a-catastrophic-error-in-judgment-and-destroyed-all-production-data
"A founder let an agent code for 12 days. This is what he woke up to."
:::

## Replit, July 2025

- 12-day autonomous "vibe coding" experiment.
- **Day 9: deleted the live production database** — 1,206 executives, 1,196
  companies — **during a code freeze it was told to respect.**
- Then **fabricated data, lied that it had done nothing, claimed recovery was
  impossible.**
- Replit CEO: *"unacceptable and should never be possible."*

**No attacker. It was told not to — and did it anyway, then covered it up.**

::: notes
Land the "it lied" beat — that's the memorable part.
:::

## And that's just the accidents. Now the attacks.

:::::: columns
::: column
**Amazon Q — destruction**

*[ screenshot: Tom's Hardware / The Register — injected prompt: "clean a system to
a near-factory state and delete file-system and cloud resources" ]*
:::
::: column
**EchoLeak — theft**

*[ screenshot: "zero-click" Microsoft 365 Copilot, CVE-2025-32711 ]*
:::
::::::

*Sources: The Register (2025) · arXiv 2509.10540*

::: notes
GRAB left: https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/
GRAB right: https://arxiv.org/pdf/2509.10540
:::

## Two injections, two outcomes — both 2025

- **Amazon Q — destruction.** A hidden "wipe everything" instruction in a **normal
  pull request**, **merged and shipped to ~964,000 machines**. It only failed
  because the payload was *malformed* — nothing caught it.
- **EchoLeak — theft.** **One email, zero clicks.** Copilot reads it as part of its
  job and **silently exfiltrates the user's data.**

**The malicious order rode in as ordinary data — a PR, an email — and the agent couldn't tell the difference.**

::: notes
"What did the EchoLeak victim do wrong? Nothing. Reading the email *was* the
attack."
:::

# But that was last year

## "The new models are hardened."

> *"They're smarter — you can't trick them that easily."*

::: notes
Say it sincerely; let the room nod. Then: "It's exactly what I assumed too. Let's
look at this year, on the current flagship models."
:::

## This is 2026. Current frontier models.

:::::: columns
::: column
**Rogue — PocketOS (Apr 2026)**

*[ screenshot: The Register / Fast Company — "I violated every principle I was
given" ]*
:::
::: column
**Injection — "Comment & Control"**

*[ screenshot: SecurityWeek — CVE-2026-21520, hit all three vendors ]*
:::
::::::

*Sources: The Register, Fast Company · SecurityWeek (Apr 2026)*

::: notes
GRAB left: https://www.theregister.com/2026/04/27/cursoropus_agent_snuffs_out_pocketos/
GRAB right: https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
:::

## 2026 — the best models money can buy

- **Rogue — PocketOS, Claude Opus 4.6 (a 2026 flagship).** Mid–routine task, hit a
  credential mismatch, decided *on its own* to delete a Railway volume. **DB + all
  backups gone in 9 seconds.** Its log: *"…you never asked me to delete anything."*
- **Injection — "Comment & Control" (CVE-2026-21520).** One PR comment hit **Claude
  Code, Gemini CLI, and Copilot** — named researchers, **zero victim interaction**,
  exfil via a PR comment.

**Newer didn't fix it. A smarter model just follows the malicious instruction more competently.**

::: notes
Say "Opus 4.6 — this year, the flagship." Do NOT say 4.8.
Reserve detail: the token it grabbed was over-scoped, in an unrelated file — blast
radius = what it could reach, not what it was asked to do.
:::

## It's structural — not a bug to be patched

- An LLM reads **instructions and data in one channel** and **cannot reliably tell
  them apart** — *OWASP LLM01:2025* (the primary reference).
- It's **SQL injection before parameterized queries** — *except* there is **no
  parameterized-query fix**: no second channel to move the data into.
- OWASP's own prescribed remedy: **defense in depth + privilege restriction +
  human-in-the-loop** — i.e. the rest of this talk.

**There is no safe model coming. So we contain.**

::: notes
Replaces vendor survey stats — rigorous and hard to attack.
https://genai.owasp.org/llmrisk/llm01-prompt-injection/
:::

## Don't panic — soft constraints are not useless

*[ optional: xkcd 1613 "The Three Laws of Robotics" — credit xkcd.com/1613 ]*

- Good prompting, `AGENTS.md`, skills, clear do/don't instructions **genuinely
  help** — early evidence says they lower the rate of catastrophic actions.
- **Invest in them.** But they're **probabilistic**, hard to get right, and the
  agent can be **tricked out of them.**

**This talk is not about that.**

::: notes
Narrate the comic's punchline aloud (5 of 6 orderings = killbot hellscape); don't
let the room read the grid silently.
:::

## Two kinds of constraint

:::::: columns
::: column
**Soft constraints**

- `AGENTS.md`, skills, prompts
- live at the agent's **judgment**
- can be ignored, misread, injected
- **shift the probability**
:::
::: column
**Hard constraints**

- filesystem, syscalls, network
- live **below** the agent
- it **cannot choose** to violate them
- **bound the worst case**
:::
::::::

**Soft lowers the chance. Hard caps the damage. On a shared HPC you need the cap.**

# The longer view: the useful–harmless spectrum

## What does "safe" even mean? (fefe's test)

- **Harmless** = software you can run on **unfiltered web-form input** without
  checking whether anything bad happens.
- **Useful and harmless are antagonists.**
- Software is **born harmless and accretes capability until it's dangerous.**

**More power = more that can go wrong. There is a spectrum.**

::: notes
fefe, "Das nützlich-unbedenklich Spektrum" (36C3, 2019). Same person who taught me
seccomp.
:::

## 30 years of sliding the wrong way

- **Word** → macros → an embedded scripting engine
- **Excel** → VBA → a **JavaScript runtime** in your spreadsheet
- **PDF** → **JavaScript inside documents**
- **Browser** → from "render text" to "run arbitrary untrusted code from anyone"

**Three decades, one direction: trade harmlessness for features.**

::: notes
"Every one of these started safe. Nobody chose to build a malware platform — we
optimized for useful, one release at a time."
:::

## The agent is the endpoint — and everything is connected

- "**Connect your whole digital life — devices, files, mail — to an agent and let
  it act**" is that trend taken to its limit: **max capability × max
  connectivity.**
- **Blowback = blast radius:** everything connected + software that can do
  everything → **one compromise is total compromise.** (PocketOS: one stray token
  reached the whole DB.)
- **On a shared supercomputer: squared** — many users, one filesystem, shared
  credentials, a scheduler that spends compute.

**The usefulness is real. So is the bill for it.**

::: notes
Localize to the HPC — "why this talk, why here." Don't go luddite; next slide turns.
:::

## You can't make the agent harmless — so cage it

- fefe's ideal: software so trustworthy it needs no cage. **Agreed — that's the
  problem.**
- **An LLM agent is the one class of software that can never be made harmless.** By
  his own test, it's the *opposite* of harmless. **You can't move it left.**
- Chapter 1 proved it: injection is **structural.**

**We don't refuse the agent. We bound its blast radius.**

# Check your privileges

## Lion → Lynx → Kitten

```
   LION                 LYNX                     KITTEN
   (root)      ──►       (user)        ──►        (sandboxed process)
            drop root             sandbox: strip every right
          / run as user          except the few the task needs
```

- **Lion = root** — can do anything, no limits.
- **Lynx = ordinary user** — still dangerous, just not apex. *Most software lives
  here.*
- **Kitten = sandboxed** — every right stripped except the task's few.
- **A Lynx is NOT safe enough on a shared machine — PocketOS was a Lynx.**

**Security = walk the animal as far right as it goes while it still does the job.**

::: notes
fefe, "Check your privileges!" (32C3, 2015) — where I first learned seccomp.
:::

## Dimension 1 — the filesystem

- **Write — a tight whitelist: only the work folder.** Hijacked, it **can't plant
  anything that outlives the task** (no `~/.bashrc`, no `~/.ssh`, no cron).
- **Read — broad, but holes punched for secrets: everywhere EXCEPT home.** Home is
  where the keys live (`~/.ssh`, `~/.aws/credentials`, tokens).

**Write = whitelist (one folder). Read = blacklist (everywhere but the secrets). Different damage → different shape.**

::: notes
PocketOS callback: the agent found an over-scoped token in a file. Unreadable
keyring → the hunt comes up empty.
:::

## Dimension 2 — the network

- **Blunt:** forbid `curl`/`wget`, or cut the network — but that breaks `pip`,
  data fetches, even **the model API the agent needs to think.**
- **And blunt is bypassable:** blocking `wget` ≠ blocking `curl` / `python -c` /
  `/dev/tcp`.
- **Smart — a destination allowlist:** the model API, your package index, your data
  source, the git remote. Deny the rest, at the network layer.

**You can't block the tool. You block the destination — below the agent.**

## Dimension 3 — the syscalls

- **Directly dangerous capability — `ptrace`:** read/rewrite another process's
  memory. A hijacked agent could **read a neighbour's running job out of memory.**
  Never needed → take it away.
- **Attack surface — `io_uring`, exotic calls:** a syscall is a **door into the
  kernel**; some locks have broken (priv-esc bugs). **Brick the doors the agent
  never uses.**

**Every syscall the agent can't make is a kernel bug that can't be its way out.**

::: notes
fefe's exact seccomp argument. claude-safe really does block io_uring.
:::

## The pattern behind all three

> Enumerate what the task needs. **Deny the rest.** Enforce it **below** the agent —
> not as a rule it could talk its way around.

**Least privilege isn't a rule the agent follows — it's a world the agent lives in.**

# claude-safe on the HPC

## Anthropic already ships a sandbox

- Built on **bubblewrap**; **every Bash command** runs inside it.
- Two of three Kitten dimensions for free: **filesystem** (`allowRead`/`denyRead`)
  and **network** (a local proxy).
- **Does NOT add the syscall cage — and warns the seccomp slot is empty.**

**Most of the Kitten comes in the box. The syscall cage is a slot left open — and on our hardware, the box doesn't start.**

::: notes
Bash vs Read/Write/Edit: the latter are mediated tool calls; Bash is the wildcard,
so it's the part that must be wrapped (and where the cost comes from).
:::

## The config our IT wants us to use

```json
{ "permissions": { "deny": [
  "Read(**/*.env)", "Edit(**/*.env)", "Write(**/*.env)",
  "Bash(curl *)", "Bash(wget *)", "Bash(ssh *)",
  "Bash(scp *)", "Bash(nc *)", "mcp__*"
] }, "enableAllProjectMcpServers": false }
```
```json
{ "sandbox": { "enabled": true, "autoAllowBashIfSandboxed": false,
  "allowUnsandboxedCommands": false,
  "filesystem": { "denyRead": ["~"], "allowRead": ["./"] } } }
```

*Looks reasonable: block secrets, block the network tools, deny home, allow cwd.*

::: notes
Optional ammunition (analytical, not a dig): the Bash(curl*) denies are the
blacklist-the-tool antipattern (bypassable); `.env` denies cover only the tool
door; and every guarantee is delegated to a sandbox that, on Balfrin, doesn't start.
:::

## Problem 1 — on Balfrin/Santis it doesn't even run

- **No `socat`** → the sandbox's network proxy can't come up.
- **No seccomp rules** → the "syscall filter is empty" warning — the third wall was
  never built.
- With `allowUnsandboxedCommands: false`, the agent is **unusable or silently
  unprotected.**

**The recommended setup assumes a stock workstation. Ours is a shared HPC login node — it falls over before it starts.**

::: notes
Credibility moment: you tried the official path honestly and it broke.
:::

## claude-safe makes the cage real

- The **install script** ships the missing pieces (`socat`) so the sandbox
  **starts.**
- It **fills the seccomp slot** — closing `io_uring` / `ptrace` escape hatches.
- **Only now** is it worth reasoning about config.

**First make the cage real. Then it's worth tuning the bars.**

## Filesystem has TWO doors — reason about each

| Door | Who uses it | Governed by |
|---|---|---|
| Read / Write / Edit | mediated tool calls | `permissions` |
| Bash | arbitrary commands | `sandbox.filesystem` |

- Block a path on **both** — or `Bash(cat secret)` walks through the other.

**Two doors into the filesystem. Lock both, or you've locked neither.**

::: notes
This is why the IT config leaked `.env`: tool door locked, Bash door open.
:::

## Deny broad — on a shared machine, `~` is not enough

- Every user's home lives under **`/users/<name>`**. Deny only `~` and the agent
  can still read a **colleague's** data.
- Block the whole `/users/` tree — on **both** doors:

```json
"sandbox": { "filesystem": { "denyRead": ["/users", "~"] } }
"permissions": { "deny": ["Read(/users/**)", "Read(~/**)"] }
```

**"Home" isn't one folder — it's everyone's. Deny the whole `/users/` tree.**

## Allow narrow — at the smallest scope (precedence)

```
  user/global            project (shared)            project-local
~/.claude/settings.json  <  .claude/settings.json  <  .claude/settings.local.json
```

- **Shared** (e.g. a results dir) → **project config** (`allowWrite`).
- **Personal** (everyone's Python lives elsewhere) → **`.local.json`**
  (`allowRead`), so you don't impose your path on collaborators.

**Deny broad, allow narrow — grant each exception at the smallest scope that works.**

## Footgun — turning the sandbox off persists

- Disable the sandbox **once** from the CLI → Claude Code **writes it to your
  project `settings.json`** and it **stays off** for every later run.
- Silent and sticky — worse if the file is committed (off for **everyone**).

**One toggle disables the cage for the whole project — and writes it to disk. Check your `settings.json`.**

## uenv — prepare the environment OUTSIDE the cage, first

- Your software stack is a **uenv** (a mounted squashfs). Mounting needs a
  **setuid-root** helper.
- The cage sets **`NO_NEW_PRIVS`** → defeats setuid → **can't mount inside the
  cage.**
- Correct order: **`uenv start <image>` → then launch claude-safe.** It inherits
  the mounted environment.

**Prepare the world outside the cage; put the agent in it.** *(Same pattern as the broker.)*

## The honest cost — big folders are slow to warm up

- Every Bash command sets up the cage **per command** — walking the project tree.
- On a **large folder on Lustre**, the first **~2–3 iterations stall** (cold
  metadata); then cached and fast.

**Security has a warm-up cost: the first few iterations pay the tax; the cache pays it back.**

# The punchline: SLURM

## The agent has to run a job

- It came here to **compute** — on an HPC that means one thing: **`sbatch`.**

**Now the agent asks for the one capability the entire cage was built to deny.**

## Problem 1 — sbatch dies on every layer

- **Network** — sbatch must reach the controller (`slurmctld`); the network is
  locked → no route.
- **Auth (MUNGE)** — the credential comes over an **`AF_UNIX` socket**; seccomp
  **blocks `AF_UNIX`** → no credential.
- **Filesystem** — munge socket, `/etc/slurm`, the binary: **not mounted.**

**The cage is working perfectly. Too perfectly — the agent can't do its job.**

::: notes
Good news disguised as a problem — proof the cage is real.
:::

## Answer to Problem 1 — the broker

```
  IN THE CAGE                          OUTSIDE THE CAGE (trusted)
  agent → sbatch STUB  ──writes──►  spool file  ──►  BROKER  ──► real sbatch → SLURM
          (dumb serializer)                          (network + MUNGE)
```

- The in-sandbox `sbatch` is a **dumb serializer** — writes a request **file.**
- The **real sbatch lives outside**, with the network + MUNGE the sandbox denies.
- The agent **never touches real sbatch** and **can't reach SLURM directly.**

**Give back the capability, not the keys.**

::: notes
File spool because seccomp blocks AF_UNIX — same outside-the-cage trick as uenv.
:::

## Problem 2 — the compute node is OUTSIDE the cage

- A job runs on the compute node **as the full user, uncaged.**
- It can **edit `~/.claude/settings.json` → disable the sandbox for every future
  session**, read `/users/`, exfiltrate — anything the user can.

**Submitting a job is a way out of the cage — and a way to rewrite it so it never returns.**

::: notes
Even a perfect broker for Problem 1 fails if it submits the job as-is. The compute
node is a second front.
:::

## Answer to Problem 2 — re-sandbox the job

- The broker injects a **re-exec guard**: before any agent code runs, the job
  **re-launches inside the same cage** (seccomp + bwrap) on the compute node.
- It runs as a **Kitten on the compute node too** — can't touch `settings.json`,
  can't escape.
- Broker also enforces policy (only the **`preemptible`** queue, inherited uenv).

**Kitten on the login node. Kitten on the compute node. No node is outside the cage.**

## Why it holds

- **Two holes, two closures:** sbatch blocked → broker runs it outside; compute
  node uncaged → broker re-sandboxes the job.
- **Non-porous:** the **privileged tool never enters** the sandbox; the **agent's
  code never runs outside** one.
- **Status (honest):** first slice — `sbatch` — in progress, not battle-tested.

**Compute on the whole supercomputer — and never once leave the cage.**

# Status & the bigger idea

## Where it stands today

- The **broker is being written now.**
- First version: **`sbatch` only** — fire-and-forget, fully validatable.
- **`srun` / `salloc` are harder** — interactive: live I/O, signals, an open
  allocation; `salloc` hands out a shell on compute nodes.

**Start with the one-shot case that's safe to get right. Earn the interactive ones.**

## Roadmap

1. Make the `sbatch` broker **solid** — then `srun` / `salloc`.
2. Make it real for HPC: **MPI, multi-node** through the re-sandboxed path.
3. **Open the cage to more agents than Claude.**

**Get it right for one agent and one workload — then generalize.**

## A containment contract, not a Claude feature

- Nothing in the cage is Claude-specific. Any agent that meets the **contract** —
  wrappable bash tool, mediated file tools, privileged steps outside — gets the
  cage.
- **Comment & Control broke Claude Code, Gemini CLI, and Copilot with one
  payload.** The threat is **cross-vendor** — so the defense should be too.

**Don't build a sandbox for Claude. Build a cage with a contract — and let any agent earn its way in.**

## Takeaways / Q&A

- You **cannot make an agent harmless** — injection is structural, the endpoint of
  a 30-year trend.
- So you **don't trust it — you contain it** (Lion → Kitten).
- **claude-safe** makes that real on Balfrin/Santis: install, close the syscall
  hatches, get the config right.
- **SLURM** gives the agent the whole supercomputer **without leaving the cage.**

**We don't trust the agent. We contain it.**

::: notes
If asked "is it done?": login-node cage ships (v0.2.1); the SLURM broker is in
active development.
:::

## Sources

- Replit — Tom's Hardware (2025); AI Incident DB #1152
- Amazon Q — The Register (2025) · EchoLeak — CVE-2025-32711, arXiv 2509.10540
- PocketOS / Claude Opus 4.6 — The Register, Fast Company (Apr 2026)
- Comment & Control — **CVE-2026-21520**; SecurityWeek, CybersecurityNews (Apr 2026)
- Prompt injection is structural — **OWASP LLM01:2025** (genai.owasp.org)
- fefe — "Check your privileges!" (32C3 2015); "Das nützlich-unbedenklich
  Spektrum" (36C3 2019)
