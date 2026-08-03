# husk v0.5 security review — synthesis

Two passes, nine briefs, 102 candidates, 84 distinct findings triaged. This document
deduplicates across shards, gives one severity-ranked list, resolves the cross-shard
contradictions, groups everything by **root cause so one fix closes several findings**, and
ends with the fix plan and the hardware residual list.

Severity here is **mine as coordinator**, reconciled across shards — not an average of the
finders' labels. Two scales are kept deliberately separate and must not be compared:
**SHIPPED** (a defect in husk as it runs today) and **6a/6b** (work the roadmap already owns).

---

## Verdict

**Do not release v0.5 as-is.** Not because the design is unsound — the enforced core held
under direct attack (see "What held") — but because there are **three confirmed, agent-
triggerable ways to run a job entirely outside the cage, and they are one defect**, plus a
persistent host-code-execution chain that was *executed* against the shipped default config.
The core is worth releasing; the delivery of the guard and the default-allow seams in
policy/parsing are not. All of it is fixable, and the fixes concentrate: **six changes close
every SHIPPED finding above LOW.**

The shape matches the v0.4 review exactly: the kernel-enforced boundary is sound; the breaks
are in policy, parsing, guard delivery, config handling, and lifecycle. "Secure the interface,
not your model of it" is still the through-line.

---

## The headline: three CRITICALs are one defect

`B5-F1` (agent-chosen shebang survives `wrap_script`), `B5-F2` (Rust `trim_start()` strips
Unicode whitespace bash keeps, so agent code lands above the guard), and `B6-F1` (the staged
guard is handed to sbatch **by path** in the agent-writable spool, and the rename race is
winnable — 33/100 at a 2 ms window, 0/50 control) are **the same defect wearing three masks**:

> **Containment is a re-exec guard injected into the agent's own script and handed to sbatch
> by path — so it is a property of a FILE that something else later opens and execs, not a
> property of the EXECUTION.**

The B5 triage tested this hypothesis directly and confirmed it. **One structural change closes
all three:** submit husk's *own* fixed wrapper as the batch entry point, and consume the
agent's body as **data** read *inside* the cage — never as the executable artifact slurmstepd
opens. The narrow per-finding fixes (validate the shebang; split on bash's blank-line rule;
hold an fd) each close one mask and leave the others open. **Fix the execution model, not the
three symptoms.**

Blast radius, confirmed for all three: the entire compute cage is gone — bwrap FS confinement,
seccomp, `--unshare-net`, the MUNGE mask, the PID namespace. The job runs as the user with
MUNGE, so it can talk to slurmctld directly and **bypass the broker entirely (reopens AV8)**.
Only the sbatch-CLI controls (forced partition, `--nodes=1`, account) survive.

---

## Master list — SHIPPED findings, severity-ranked (deduplicated)

| # | ID(s) | Sev | Root cause | One line |
|---|---|---|---|---|
| 1 | B5-F1 · B5-F2 · B6-F1 | **CRITICAL** | **A** | Three routes to an uncaged job; one defect — the guard is a property of a file, not of the execution. |
| 2 | B3-F6 | **HIGH** | D | AV2 chain *executed* on shipped defaults: a job planted `.git/config` → `git commit` ran `PWNED as christoph`. Deferred RCE (fires when the user next runs git / logs in). |
| 3 | B6-F4 | **HIGH** | C | `#SBATCH hetjob` + non-option tokens skipped un-gated; a 2nd component asked 512 nodes × 24 h on `normal`. Resource envelope *is* the threat model. Effectively CRITICAL if the site honours `hetjob` (HW). |
| 4 | B3-F1 · B3-F5 | **HIGH** | B | The cage's writable root is never validated (`is_workdir_allowed` applied to `req.cwd`, never to `root`); `//`, `..`, `/./` walk the string floor predicates → a submitted job binds `/users/me` writable. |
| 5 | B2-F1 | **HIGH** | E | A refusal tells the operator to add an entry that cannot be added; and the parse error is *swallowed at submit time* (`unwrap_or(false)`) so egress silently vanishes with no report to anyone. |
| 6 | B4-F5 | **MEDIUM→HIGH** | H | The only cross-user break: `[ -O "$_d" ]` follows symlinks, so a co-tenant's planted `/dev/shm/husk-<jobid>` symlink lands a victim dir **read-write** in every rank. Read a secret + wrote back, end to end. |
| 7 | B2-F10 | **HIGH (banner)** | — | The cage banner claims "reads are unrestricted" while masking `/users`, every `denyRead`, and credential files. Not a containment breach; a false security claim + two wrong source comments. Silence-claim mostly refuted. |
| 8 | B6-Structural · B6-F3 · B6-F5 · B6-F11 | **MEDIUM** | C | `Ignored` = "dropped from CLI", never "dominated" ⇒ every Ignored option is an ungated `#SBATCH` channel. `--mail-*` (SMTP egress), `--qos`/`--reservation` (envelope), query-verb forwards whole argv. |
| 9 | B1-F2b | **MEDIUM** | F | The caged process tree has **no owner**: on a group SIGTERM the guard cleans up and exits while the workload runs on in an orphaned bwrap. `--die-with-parent` passed nowhere. |
| 10 | B3-F3 · B3-F4 · B3-F2 | **MEDIUM** | G | Config values become mounts un-filtered: `denyWrite:["/users"]` re-exposes homes (a deny that grants); `allowWrite:["/"]` dissolves `--dev`/`--proc`/`--tmpfs` too; rank cages carry no MUNGE mask. |
| 11 | B1-F1 · B1-F5 | **MEDIUM** | F | `/dev/shm/husk-<jobid>` has no release on any path (RAM-resident leak); per-rank socat relays accumulate one-per-rank-per-step for the job's life. |
| 12 | B6-F12 | **MEDIUM** | F/avail | `run_sbatch` has no watchdog (its sibling `run_query_cmd` does) → a hung sbatch wedges the single-threaded broker forever, including scancel. `#SBATCH --wait` reaches it. |
| 13 | B2-F2·F3·F4·F5·F13·F14·F15 | **MEDIUM→LOW** | J | Teaching-message cluster: husk refusals attributed to SLURM; forced argv logged nowhere; carve-outs dropped silently; the login side has no writable-set banner at all. |
| 14 | B4-F3 · B1-F3 | **MED-LOW** | F | Non-reaping PID 1 turns orphaned rank children into node-global zombies (30→30 host-visible); a failing `ensure_holder` leaks one zombie per srun on an already-broken node. |
| 15 | B4-F4 | **MED-LOW** | F | `ensure_holder` caches the holder pid with no liveness check → a dead holder wedges every later step; pid-reuse onto another same-user holder is mechanically possible (PLAUSIBLE). |
| 16 | B3-F7 | **MEDIUM** | D/G | `.git` as a *file* (ordinary worktree) kills the cage with an unattributed bwrap error; `.git` *absent* fabricates `.git/hooks/` on the host — the enabling step of #2. |
| 17 | B4-F2 | **LOW** | — | Landmine: three docs call clearing the holder's `PR_SET_DUMPABLE` a "cheap win"; for husk's real (no-exec) holder it makes ranks fail **closed**. `cage.rs:89-97` is the correct one; the other three are wrong. |
| 18 | B1-F4 | **LOW** | F | The submitted SLURM job has no husk-side owner and the scancel-provenance record is memory-only → the containment gap reopens on every broker restart. Confirm it is a decision. |
| — | B3-F8·F9·F11, B6-F6·F7·F8·F9·F10, B1-F6·F7·F8, B4-F6·F7·F8 | **LOW / INFO** | various | Doc-vs-code drift, absent-path artefacts, unproven cells, log hygiene. Enumerated in the shard reports. |

**Refuted (do not act on):** `B4-F1` (holder protected by capabilities) — REFUTED; the holder's
protection is **structural** (its `mm` is in the initial userns because it runs in-process and
never execs), and the `main.rs` comment the finding attacked is closer to right than the
finding. `B6-F2` (job_args parsed as sbatch options) — the bytes land as the *script's* argv,
inside the already-caged body. `C2-7` headline (no non-HTTP route) — CONNECT is a generic TCP
tunnel, measured.

---

## Cross-shard resolutions

1. **`[ -O ]` on `/dev/shm`: B3 pass-1 marked it "Correct"; B4-F5 CONFIRMED it exploitable.**
   → **B4-F5 wins.** B4 demonstrated read+write through a live cage via a symlink; B3's pass-1
   note was an untested assertion. Row #6. The fix (symlink-safe ownership check, or resolve
   under the job's own private dir) lives with root cause F/H.
2. **B3-F12 ↔ B4-F6** (`settings.rs` says ranks can't join a pidns; `rank.rs` does, and works on
   bwrap 0.6.1). → **One finding**, a doc defect, LOW. Dedup to a single fix (correct the two
   `settings.rs` comments).
3. **B1-F1 ↔ B4-F5** — same two lines of `rank.rs`, different properties (B1 = lifetime of the
   `/dev/shm` dir, B4 = symlink-follow of the ownership check). → **Both real; one code site.**
   Whoever fixes root cause F must read both — the RAII fix and the symlink fix touch the same
   lines and must be written together.
4. **The proxy's allowlist workdir (B2 flag) ↔ B3-F1** — the proxy resolves policy from
   `--workdir "$PWD"` (the agent-influenced `--chdir`) while the submit path uses the trusted
   `project_dir`; `main.rs:277` claims the opposite. → Same root cause as #4 (B in the table):
   the trusted value and the agent value have diverged. Fix together.

---

## Root-cause groups → the fix that closes each

- **A — the guard is a file, not an execution.** #1 (3 CRITICAL). → **Fix 1.**
- **B — the confined side supplies its own boundary.** #4, the proxy-workdir flag. The F17/F13
  family. → **Fix 2.**
- **C — default-allow where default-deny was intended** (`Ignored`=dropped, not dominated;
  denylist-by-name). #3, #8. → **Fix 3.**
- **D — parser differential + fabricated masks.** #2, #16, and B5-F2 (also in A). → **Fix 4**
  (mask by construction), with the shebang/whitespace half folded into Fix 1.
- **E — fail-open on error.** #5, the `FsPolicy::parse` `unwrap_or_default` flag, C3-F3 (deny
  keys fail open). → **Fix 5.**
- **F/H — resource lifecycle + the one cross-user break.** #6, #9, #11, #14, #15, #18. → **Fix 6.**
- **G — config values become mounts unfiltered.** #10, part of #16. → **Fix 6** (shares the
  floor-filter machinery) or a small **Fix 7** for the rank MUNGE mask.

---

## Fix plan, ordered by leverage

**Fix 1 — make containment a property of the execution (closes #1, all three CRITICAL).**
Submit husk's own fixed wrapper as the batch script; pass the agent body as data read inside
the cage. Highest leverage in the review. Everything else is lower priority than this.

**Fix 2 — one trusted origin for every boundary value (closes #4, the proxy-workdir flag).**
Apply `is_workdir_allowed` to the value that becomes the `--bind` root, not only to `req.cwd`;
canonicalise before the floor predicates so `//`/`../`/`/./` cannot walk them; make the proxy
resolve its allowlist from the trusted `project_dir`, not `$PWD`. **Two existing tests pin the
broken behaviour** (`/users/x/proj` workdir) — they must flip, which is the sign the fix works.

**Fix 3 — default-deny the directive surface by construction (closes #3, #8).** `Ignored` must
mean *dominated* (emit the safe value on the CLI), never *dropped*. Reject non-option `#SBATCH`
tokens (kills `hetjob`). Force or reject `--mail-*`, `--qos`, `--reservation`. Give the read-only
query verb a constructed argv, not a passthrough. This is the v0.4 "construct + re-emit +
reject-unknown" discipline applied to the seams it hadn't reached.

**Fix 4 — mask by construction, not by name-list (closes #2, #16, C3-F2).** The auto-exec mask
is a 4-name denylist; make it structural (mask any `.*` config/exec dir at every depth, or bind
the workdir with the exec bits off). Stop fabricating `.git/hooks`. This is the finding that was
*executed*, so it ranks above its severity number.

**Fix 5 — fail closed on any policy/allowlist parse error (closes #5, C3-F3, the parse flag).**
Replace `unwrap_or(false)` / `unwrap_or_default()` with an attributed, fail-closed refusal. A
malformed settings block must not silently void `denyRead`/credential masks, and a bad allowlist
must refuse the job loudly, not disable egress in silence.

**Fix 6 — RAII for the cage (closes #6, #9, #11, #14, #15; confirm #18).** `--die-with-parent`
on both cages; own and release the `/dev/shm` dir; make the ownership check symlink-safe (this
is the cross-user fix too); reap or `SIG_IGN` the holder's children; liveness-check the cached
holder pid. B1-F1 and B4-F5 touch the same lines — write them together.

**Fix 7 — rank MUNGE mask (closes the rank half of #10).** Add `--tmpfs /run/munge` to the rank
argv. Small, independent, and load-bearing the day `--unshare-net` relaxes.

**Then:** the teaching-message cluster (#13, folds B2-F1's harmful-remedy into Fix 5), the
doc-defect dedup (#17, res. #2), and **the tests that could not fail** (below).

---

## Tests that could not have failed — a finding in its own right

The review found **five** cases of a test passing while unable to detect the thing it covers —
the same class as this session's `tmp.reclaimed` and `cpu.affinity`:

- `guard.preempt_cleanup` runs against a **stub cage with no bwrap**, and `timeout -s TERM`
  signals the whole group, so the payload always dies — it could never see B1-F2/F2b.
- The vendored runtime's silence integration test checks **only stdout** (B2-F10).
- B5-F5's completeness test derives names from string literals, so it **cannot see** the `.tmp`
  intermediates it is credited with covering.
- **Two tests actively pin the broken B3-F1 write-root behaviour** (`/users/x/proj` workdir).
- C2-4: a test **pins** `ANTHROPIC_BASE_URL` as a non-member of the controlled set.

**Recommendation:** every fix above lands with an arm that has a demonstrated failing state
(planted marker, sent signal, generated table), and the five above are rewritten or deleted.
This is the same discipline the containment tier already uses; it had simply not reached these.

---

## Hardware residual list (the next Balfrin/Santis run)

Each shard supplied exact commands; consolidated:

1. **B1-H1 (settles #9/#11 severity):** does SLURM signal the whole step container or only the
   batch script? Payload that traps SIGTERM, `scancel`, compare the `husk: step spool removed`
   timestamp to the scancel.
2. **B6-F4 (settles #3):** does the site honour `#SBATCH hetjob`? If yes, #3 is CRITICAL.
3. **B3-F2 (settles #10):** `munge -n` inside a rank vs inside the job cage — is the MUNGE
   socket reachable from a rank?
4. **B4-F3:** `cat /proc/sys/kernel/pid_max; ulimit -u` — can the zombie leak exhaust
   node-global pids for other users?
5. **B3-F10:** apinfo bind writability (host DAC) from a rank.
6. **B4-F2:** confirm the non-dumpable-holder behaviour on the 5.14 Cray kernel before anyone
   acts on the "cheap win."
7. **B2-F7:** is the hard-coded preemptibility claim actually false on Balfrin?
8. **B1-F1:** `scontrol show config | grep -i job_container` — does `job_container/tmpfs` clean
   `/dev/shm` regardless (and is that then an unstated dependency)?
9. **C3-F10 / C2-1:** `ss -ltnp | grep claude` during a first-party login — settles the
   login-side loopback-listener question for 6a.

---

## What held (the "refuted findings" section — evidence about the system, not waste)

- **The enforced core is sound under direct attack.** B4's central question — can a rank escape
  the shared namespace or reach past the job — was a clean null across twelve failure paths, and
  its sharpest candidate (capabilities as the holder's gate) was **refuted** by the triage pass.
- **The namespace/CMA design is correct**: ranks read peers by design, the step-broker is
  invisible to them, and the holder is structurally unreachable.
- **construct-and-re-emit works where it is applied**: no agent bytes reach slurmd through the
  *option* path (B6-F2 refuted); the guard's session-derived values are genuinely not agent-
  settable (B5 verified). The failures are all where that discipline was *not* applied — the
  script body, the `Ignored` class, the write root — which is a coverage gap, not a design flaw.
- **The C-series found zero shipped security bugs** — every "missing" piece is login-side, which
  their runtime still supplies. C2 settled connection direction as egress-only (with two
  factual corrections) and confirmed the proxy is shaped for TLS termination to be added.

The one-sentence version: **husk's kernel-enforced boundary is sound; v0.5 is held only by how
the guard is delivered and by default-allow seams in policy, parsing, config, and lifecycle —
six concentrated fixes, then re-review the two that touch the enforcement path (Fix 1, Fix 2).**
