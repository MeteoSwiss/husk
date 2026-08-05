# husk v0.5 — Workstream A triage synthesis (pass 2)

All 9 A briefs ran (assumed-breach, on Balfrin) and were triaged by 7 independent laptop agents
that verified each claim against the source (and, for two, built/ran husk: a local proxy for the
CONNECT parser, `cargo test` for the deep chain). This is the settled output. LOW/INFO tail is in
`LOW-BACKLOG.md`; the offensive-pass raw findings are in `findings/A*.md`.

## Verdicts (15 items)

| Finding | Verdict | Sev | Fix anchor / note |
|---|---|---|---|
| **A1** `--output`/`--error` leaf-symlink bypasses confinement → arbitrary write as the user outside the cage (AV2 code-exec) | **CONFIRMED** | **CRITICAL** | `settings.rs:257` `confine_output_pattern` (splits leaf, confines only parent, appends leaf literally). **The existing test `settings.rs:1191` PASSES while the bug is open — do not trust it.** |
| **A4-F3** login cage doesn't mask `.Rprofile`/`.hg/hgrc` → AV2 auto-exec as the user | **CONFIRMED** | **MED** | add `.Rprofile` to `DANGEROUS_FILES` (`sandbox-utils.ts:11`); mirror the `.git` conditional block for `.hg/hgrc` in `linuxGetMandatoryDenyPaths` (`linux-sandbox-utils.ts:302`). Ghost-path masking already exists (`sandbox-manager.ts:1748`). |
| **STRIPPED_SUBMIT_ENV** 4-name denylist + `--export=ALL` leaks broker-env secrets into slurmd job records | **CONFIRMED** | **MED** | `spool.rs:419` — build the submission env from an **allowlist**, not inherit-and-strip-four. Concrete leak: `GH_TOKEN` (a configured credential not in the four). = C3-F1, promoted. |
| **Cage-build collision** (A3/A5/A8): login-cage file-placeholders vs compute-cage dir-masks in the shared project dir → brokered-job outage | **CONFIRMED** | **MED avail** (LOW sec, fail-closed) | immediate: make `AUTO_EXEC_DIRS` masking shape-aware like `.git`/`.hg` (`settings.rs:885` vs `:901`). durable: per-job private mount (pattern at `policy.rs:1015`). **Test gap: F6b tests (`settings.rs:1948`) never test the file-placeholder shape.** Blocked A5's deep chain. |
| **O1** compute-cage AF_UNIX open + same-uid cross-session egress socket not permission-separated | **CONFIRMED** (liveness UNRESOLVED-hw) | **MED** | per-session private mount / 0700 dir (partly in place for `net.sock`: 0600 in a 0700 dir, `main.rs:348`/`lib.rs:242`). Cross-USER already closed. AF_UNIX is open on compute by necessity (socat/CUDA). |
| **A7-1** confine message = host-path existence oracle | **CONFIRMED** | LOW (MED as A1 multiplier) | **same fix as A1, co-designed** (see below). Only `--output/--error`; `--chdir` already sanitized via `confine_under_any`. |
| **A3** over-broad `#SBATCH` scan → false-rejects heredoc inner scripts | **CONFIRMED** | LOW usability | `sbatch.rs:491` — scan only the contiguous leading comment block, col-0, stop at first non-comment line. |
| **`_HUSK_`** filter gap (inert) | **CONFIRMED** | LOW landmine | `rank.rs:35` — reserve `_HUSK_`. `_HUSK_RESANDBOXED` is read only by the job-body guard (`policy.rs:1159`), not the rank path → inert today. |
| **Port-less tunnel** (A9 O2) | **CONFIRMED** | LOW-MED by-design | scheduler ports still refused (no AV8); prefer `host:port` entries; shipped default pinned to `:443`. |
| Env truncation "silent" | **RECHARACTERISED** | INFO | `rank.rs:118` warns to the trusted log; masks are structurally uncapped (separate `--unsetenv` loop). Optional: fail-closed at the bound. |
| CONNECT parser differentials | **ROBUST** (positive) | — | trailing-dot / CR / tab / `userinfo@` / `host:443:443` / ipv6-mapped-loopback / wildcard confusion all REFUSED/REJECTED. |
| A2 delta-beats-mask (credential) | **REFUTED** | — | credentials non-forwardable — deny list *is* `unset_env` (single source), test `rank.rs:433`. |
| A5 UENV lead | **REFUTED** | — | `run_sbatch_with` never merges `req.env` (`spool.rs:440`); `session.uenv` reads the broker's env. |
| A6 cross-session provenance | **REFUTED** | — | per-session in-memory `submitted` (`spool.rs:42`); one broker per session. |
| A6 leftover-cleanup gate | **REFUTED** (premise false) | — | no broker-side job cancel exists; the `husk-leftover` jobs are the selftest's own un-brokered probes (`selftest.sh:1641`). |
| A5 hops 2-4 (`job_args`, MUNGE-mask) | **REFUTED/DEFENDED** | — | **3 regression tests added** to the crate (bash+dash, 228 pass). `sh_quote` holds incl. embedded newline; MUNGE mask is a fixed root-owned constant, not job-influenceable. |

**Net: 1 CRITICAL · 4 MEDIUM · 4 LOW · parser proven robust · 6 refuted/defended.**

## The A1 + A7-1 combined fix (do this first — the CRITICAL)

They are the same function; a naive A1 fix RE-OPENS A7-1 one component deeper. Co-design:
1. Collapse `confine_under_workdir`'s two failure branches into ONE host-fact-free message — no
   `target.display()`, no errno, no absent-vs-present tell (mirror `confine_under_any`, the in-repo
   precedent). May still name the writable set + echo the agent's own input.
2. In `confine_output_pattern`, `symlink_metadata` the FULL leaf after confining the parent; if
   it's a symlink → refuse THROUGH that same message. (Because the parent is fully canonicalized,
   only the leaf was unresolved, so a leaf `lstat` closes A1 without a full-path walk.)
- Residual H1 (broker-checks / slurmd-opens-later TOCTOU) is narrowed to a race but NOT closed —
  husk can't force slurmd's `open()` to use `O_NOFOLLOW`. Document it.
- Add the failing test AT the `confine_output_pattern` level (the `settings.rs:1191` test is a
  false friend — it exercises the full-path case the split bypasses).

## Triage corrections (falsification worked both ways)

Killed over-claims: `_HUSK_RESANDBOXED` "cage-skip" (inert); A9's world-listable-0755 alarm (those
are Anthropic `srt-mux` sockets, not husk's 0600 `net.sock`); "silent" truncation (warns
trusted-side); A6 leftover-cleanup path (doesn't exist). Killed a stale doc anchor: `cancel_targets`
→ `cancel_base_id` (`policy.rs:824`).

## Cross-cluster overlaps (fix once) — detail in `LOW-BACKLOG.md`

1. Teaching messages: B2 cluster + A7-1 + A8.
2. Cage-build / dotfile masks: A3/A5/A8 collision + C3-F2 + B3-F7.
3. `STRIPPED_SUBMIT_ENV`: C3-F1 (pass 1) ⇒ the env MEDIUM — one allowlist redesign.
4. Provenance memory-only: B1-F4 ⇒ A6 triage confirmed the intended fail-safe.

## Fix-phase method (agreed — same as the B/C round that worked well)

Per finding, in this order (severity order overall: **A1+A7-1 CRITICAL → the 4 MEDIUMs → LOWs**):

1. **Fix the bug.**
2. **Add a unit test that pins it so it cannot decay again** — the failing-test sketches are in the
   agent reports; deepchain already planted 3. Test AT the level the bug lives (for A1, at
   `confine_output_pattern`, NOT the false-friend `settings.rs:1191`).
3. **Show a concrete exploit example** — the smallest walkthrough that would have worked before.
4. **Explain how the changed code prevents that exact example.**

Steps 3–4 are the format Christoph found most useful in the B/C round — keep it for every fix.

Then converge: re-mine the FIXED code until a depth pass comes back clean (two clean passes,
hypotheses closed). The accumulated escape-tests are the trusted-layer regression battery. The
cage-build immediate fix should land early so a reviewer can re-run A5's deep chain live.
