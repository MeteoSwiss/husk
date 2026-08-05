# husk v0.5 — consolidated LOW / INFO backlog (A + B + C)

Everything at LOW, INFO, or by-design across all three review clusters, in one place.

> **2026-08-05 (second pass): the EIGHT real code fixes in this list are DONE** — A3 scan,
> `_HUSK_` filter, B1-F6/F7/F8, B3-F8, B4-F7, B4-F8 (partial, see its row). Commit `79cd790`.
> What remains here is the doc/comment pass (~12 items), the three verify-first MED-LOWs, and
> the C structural set, which is v0.6 roadmap rather than a bug queue.
>
> **2026-08-05: two entries here were closed for free by the above-LOW fix round.**
> **A7-1** shipped with the A1 CRITICAL as designed (one host-fact-free refusal). **B6-F6**
> (`scancel`/queries run with the broker's env unfiltered) is closed by the submission-env
> allowlist, which was applied to everything the broker execs, not just `sbatch`. Both are
> struck through below. The rest of this list is untouched.

Above-LOW findings are tracked elsewhere: B/C's shipped fixes (`SYNTHESIS.md` priorities 1–16)
and A's CRITICAL/MEDIUM set (the triage table). This file is only the tail.

Status key: **OPEN** (needs a small fix) · **DOC** (comment/doc-vs-code drift) · **HYGIENE**
(resource-lifecycle/cleanup, no live impact) · **BY-DESIGN** (record the decision, maybe
document) · **VERIFY-SHIPPED** (MED-LOW; likely fixed in the 9 shipped fixes — confirm before
acting).

---

## A workstream (this review — from the triage pass)

| ID | Sev | One line | Fix / note |
|---|---|---|---|
| ~~A7-1~~ | ~~LOW (MED as A1 multiplier)~~ | ~~confine refusal message is a host-path existence oracle~~ | **DONE 2026-08-05 (`653bb2c`)** — shipped with the A1 fix as designed: one host-fact-free refusal, detail to broker stderr under `$HOME` |
| ~~A3 scan~~ | ~~LOW usability~~ | `#SBATCH` scan is whole-file/indented/last-wins → false-rejects heredoc-generated inner scripts | **DONE `79cd790`** — header-only scan + a note for directives husk did not read |
| ~~`_HUSK_` filter~~ | ~~LOW landmine (inert)~~ | reserved-prefix filter catches `HUSK_` but not `_HUSK_`; inert today (nothing on the rank path reads `_HUSK_RESANDBOXED`) | **DONE `79cd790`** |
| Port-less tunnel (A9 O2) | LOW-MED, by-design | a port-less allowlist entry = generic all-ports TCP tunnel to that host (scheduler ports still refused, so no AV8) | prefer `host:port` entries; shipped default already pinned to `:443`; document the semantics |
| Env truncation | INFO | `MAX_FORWARDED_ENV=512` truncates — but warns to the trusted log, and masks are structurally uncapped | optional: fail-closed at the bound instead of warn+truncate (`rank.rs:118`) |
| A8 attribution | LOW, trade-off | the `husk:`/`sbatch failed:` prefix is a non-executing gate-probe of the option registry | **not a bug** — same bit the honest agent needs; optionally trim the query-refusal enumeration to closest-match |
| A9 leading-zero port | INFO | `parse_connect` accepts `:0443` as 443 while the entry parser rejects leading-zero | benign request-vs-entry differential; one-line note |

---

## B workstream (deferred from pass 1 — `SYNTHESIS.md` priorities 17/18 + the LOW/INFO batch)

### Real, low-severity — worth a small fix
| ID | Sev | One line | Status |
|---|---|---|---|
| B4-F2 | LOW | three docs call clearing the holder's `PR_SET_DUMPABLE` a "cheap win"; for husk's no-exec holder it makes ranks fail **closed** (`cage.rs:89-97` is the one correct copy) | **DOC** landmine — correct the three wrong copies |
| ~~B1-F6~~ | ~~LOW~~ | `--once` creates and claims a spool it never removes | **DONE `79cd790`** — releases what it acquired, keeps what it borrowed |
| ~~B1-F7~~ | ~~LOW~~ | `~/.husk/log/` has no owner and no size bound | **DONE `79cd790`** — pruned at session start by age/count/bytes |
| ~~B1-F8~~ | ~~LOW (PLAUSIBLE)~~ | the netproxy's tunnel counter is not `Drop`-guarded | **DONE `79cd790`** — RAII slot, Drop-released, exact cap |
| ~~B3-F8~~ | ~~LOW~~ | relative `denyWrite` is silently dropped on compute (F22, unfixed on this one field) | **DONE `79cd790`** — now goes through `abs_for_cage` like every other field |
| ~~B6-F6~~ | ~~LOW today~~ | ~~`scancel`/read-only queries run with the broker's env unfiltered~~ | **DONE 2026-08-05 (`3354764`)** — the submission-env allowlist was applied to everything the broker execs, not just `sbatch` |
| ~~B4-F7~~ | ~~LOW (minor)~~ | the rank script's fail-closed guarantee is shell-dependent (bwrap covers it) | **DONE `79cd790`** — `|| exit 1` on both redirections |
| ~~B4-F8~~ | ~~LOW (hygiene)~~ | namespace fds leak into the workload (no impact found) | **PARTIAL `79cd790`** — closed on the egress path; the plain path keeps the leak because the no-network case must stay byte-for-byte (MPI-critical). A test asserts that state |
| C2-9 | LOW (PLAUSIBLE) | with header injection the in-cage relay becomes a position the agent occupies | **BY-DESIGN** — recorded for the 6b design |

### Doc-vs-code drift & comment defects
| ID | One line |
|---|---|
| B3-F9 | the comment claiming `--ro-bind /dev/null <absent dest>` is safe is false under a read-only root |
| B3-F11 | two unstated precedence rules in the option list |
| B4-F6 (= B3-F12) | `settings.rs` states twice that a rank cannot join a PID namespace; `rank.rs` gives it one and it works (bwrap 0.6.1). Dedup to one comment fix |
| B6-F7 | the resource-envelope guarantee is written for one partition; the code now takes a list and nothing checks the weakest member (operator-facing) |
| B6-F8 | the stdout/stderr matrix row says "env stripped"; nothing strips it (no exploit) |
| B6-F9 | `HUSK_SLURM_ACCOUNT` has no value grammar while `HUSK_SLURM_PARTITION` does |
| B6-F10 | the `SBATCH_UENV*` matrix cell is named but exercised by nothing (unproven cell → add a test) |

### Already resolved / accepted (record the decision)
| ID | One line |
|---|---|
| B1-F4 | submitted job has no husk-side owner; scancel-provenance is memory-only → reopens on broker restart. **A6 triage confirmed this is the intended fail-safe** (per-session in-memory set; a restarted broker disowns its own jobs by design). Document the decision; no code change. |

### MED-LOW — verify these shipped in the 9 fixes before acting (`SYNTHESIS.md` 13–15)
| ID | Sev | One line |
|---|---|---|
| B2 message cluster (F2·F3·F4·F5·F13·F14·F15) | MEDIUM→LOW | husk refusals attributed to SLURM; forced argv logged nowhere; carve-outs dropped silently; no login-side writable-set banner. **Overlaps A7/A8** — fold any survivors into the teaching-message work |
| B4-F3 · B1-F3 | MED-LOW | non-reaping PID 1 → node-global zombies; a failing `ensure_holder` leaks one zombie per `srun` on an already-broken node |
| B4-F4 | MED-LOW | `ensure_holder` caches the holder pid with no liveness check → a dead holder wedges every later step (pid-reuse PLAUSIBLE) |

---

## C workstream (Anthropic-substitution gap analysis)

Most C findings are **structural / 6a-6b roadmap** rather than LOW bugs — they describe how much
of husk still depends on the vendored Anthropic runtime. They are not "fix now" items; they are
the shape of the v0.6 work. Recorded here so the LOW list is complete, but tracked by the roadmap.

| ID | One line | Home |
|---|---|---|
| C1-1…9 | the login cage is 100% Anthropic's; version couplings unpinned; the AF_UNIX-block ↔ 6a tension; the ripgrep walk's small payoff | **v0.6a** |
| C2-4,5,6 | `ANTHROPIC_BASE_URL`/token in no controlled set on login; allowlist can't express one-host-two-principals; login settings become plantable | **v0.6a/6b** |
| C3-F1 | `STRIPPED_SUBMIT_ENV` four-name denylist → a second agent's token rides into every job. **NOW A CONFIRMED MEDIUM** (A5/env-triage found the concrete `GH_TOKEN` leak) — promote out of this list into the fix set |
| C3-F2 | `AUTO_EXEC_DIRS` masks one vendor's config dir by name; another agent's is unmasked. **Overlaps the A3/A5/A8 cage-build cluster** |
| C3-F3…F11 | husk has no policy source of its own; all inputs are the vendor's schema; install downloads a vendor binary onto the enforcement path | **v0.6 (wrap-any-agent)** |
| C3-F4 | login-side FS boundary is advisory for native tools — **already acted on** (`--tools Bash` ships) | done-for-now |

---

## Notable cross-cluster overlaps (fix once)

- **Teaching messages:** B2 cluster (13) + A7-1 (disclosure) + A8 (attribution). One coherent
  pass over husk's refusal text.
- **Cage-build / dotfile masks:** A3/A5/A8 cage-build collision (MED avail) + C3-F2 + B3-F7 (`.git`
  shape). All the "mask into the shared project dir" family.
- **`STRIPPED_SUBMIT_ENV`:** C3-F1 (pass 1) ⇒ now the env-triage MEDIUM with a concrete leak.
  Same root; promote to the fix set as an allowlist redesign.
- **Provenance memory-only:** B1-F4 ⇒ A6 triage confirmed it's the intended fail-safe.
