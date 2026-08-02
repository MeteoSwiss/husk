# husk v0.5 review — pass 1 (discovery) index

All 9 briefs complete. Full text: `doc/review-v0.5/findings/<ID>-findings.md`. Briefs: `doc/review-v0.5/<ID>-*.md`.

**These are CANDIDATES.** Nothing here has been triaged. A verdict of CONFIRMED means the
finder demonstrated it, not that an independent reviewer agreed.

## B1

- F1 — `/dev/shm/husk-<jobid>` has no owner and no release, not even on the clean path — CONFIRMED
- F2 — the step spool and the node-local egress directory are tier-1-only, and SIGKILL is a *guaranteed* ending for a workload that handles SIGTERM — CONFIRMED
- F3 — a failing `ensure_holder()` leaks one zombie per `srun` request — CONFIRMED
- F4 — the submitted job has no owner on husk's side, and the record that could stop it is memory-only — PLAUSIBLE
- F5 — per-rank socat relays are released at job (or step-cgroup) granularity, not with their rank — PLAUSIBLE
- F6 — `--once` creates and claims a spool it never removes — CONFIRMED
- F7 — `~/.husk/log/` has no owner and no bound — CONFIRMED by inspection
- F8 — the netproxy's tunnel counter is not guarded by `Drop` — PLAUSIBLE, low

## B2

- 1. sbatch path — login-side broker (delivered `sbatch: error: <msg>`)
- 2. sbatch path — `status:"error"` responses (same `sbatch: error:` delivery)
- 3. srun / step path — compute-node step-broker (delivered `srun: error: <msg>`)
- 4. Guard-emitted, into the job's own stderr (`policy.rs::wrap_script`)
- 5. Rank script — per-task stderr (`rank.rs::wrap_command`)
- 6. Egress proxy — into the caged client's HTTP stream (`netproxy.rs`)
- 7. Operator-facing refusals (config time, session/job log only — not agent-facing)
- 8. Kernel-enforced denials — is the rule PRE-ANNOUNCED?
- F1 — the 403 tells the agent to ask for a change that CANNOT be granted, and that breaks all egress if it is · CONFIRMED
- F2 — a `--chdir` that merely does not exist is reported as a confinement violation · CONFIRMED
- F3 — the "output directory must exist" refusal is husk's rule but is attributed to SLURM · CONFIRMED
- F4 — three refusals are byte-for-byte indistinguishable from real sbatch/srun errors · CONFIRMED
- F5 — a failure caused by husk's own forced options is reported as SLURM's · PLAUSIBLE
- F6 — the `#SBATCH <Forced>` refusal names the wrong reason for four of its nine triggers · CONFIRMED
- F7 — the partition refusal asserts a property of partitions husk cannot know · PLAUSIBLE
- F8 — a seccomp kill is translated for the job but not for a step · PLAUSIBLE
- F9 — one refusal string is unreachable · CONFIRMED
- F10 — the cage banner makes a false claim and understates its own carve-outs · CONFIRMED
- F11 — three rank refusals interpolate a pid or a job id, breaking byte-identity · CONFIRMED
- F12 — two proxy refusals are delivered as a silent connection reset · CONFIRMED
- F13 — four config-time denials emit nothing at all · CONFIRMED
- F14 — "this job has no network" is announced only when the network *feature* is configured · CONFIRMED
- F15 — the login-side cage has no writable-set announcement at all · PLAUSIBLE

## B3

- 1. The cage's writable root is never validated — launching husk from `$HOME` binds the home writable *through* the floor · **CONFIRMED**
- 2. Rank cages carry no MUNGE mask · **CONFIRMED (absence)**
- 3. `denyWrite` is not filtered against the floor, and a `denyWrite` is a *bind* — so `denyWrite: ["/users"]` re-exposes every home · **CONFIRMED**
- 4. `allowWrite: ["/"]` survives the floor filter and mounts the host root read-write · **CONFIRMED**
- 5. The floor predicates are raw string tests — `..` and `//` walk through them · **CONFIRMED**
- 6. The auto-exec mask set is not the superset it claims to be, and its two file entries are `-try` · **CONFIRMED (mount table); the AV2 chain is PLAUSIBLE**
- 7. `--tmpfs <root>/.git/hooks` kills the whole cage when `.git` is a file, and fabricates a `.git` when it is absent · **CONFIRMED**
- 8. Relative `denyWrite` is silently dropped on compute — F22, unfixed on this one field · **CONFIRMED**
- 9. The comment that says `--ro-bind /dev/null <absent dest>` is safe is false under a read-only root · **CONFIRMED**
- 10. The rank's apinfo bind is read-write for a path ranks only read · **PLAUSIBLE**
- 11. Two unstated precedence rules in the op list · **CONFIRMED (documentation gap)**
- 12. Stale prose: the file asserts ranks cannot join a PID namespace, and `rank.rs` gives them one · **CONFIRMED**

## B4

- F1 — the holder's protection rests on a property nothing states, tests or measures; the source records a different mechanism · **CONFIRMED**
- F2 — "the holder can clear `PR_SET_DUMPABLE`" is recorded in three places as a measured fact; I measure the opposite for the holder as built, and acting on it kills every step · **CONFIRMED**
- F3 — the non-reaping PID 1 turns orphaned rank children into **node-global** zombies; "harmless" does not survive contact · **CONFIRMED** (accumulation) / **PLAUSIBLE** (exhaustion)
- F4 — the holder is named by a bare pid that is cached forever and never revalidated · **PLAUSIBLE**
- F5 — the rank's `/dev/shm` ownership check follows symlinks, so the bind source can be redirected from outside the job · **CONFIRMED** (mechanism) / **PLAUSIBLE** (exploitability)
- F6 — `settings.rs` states, twice, that a rank cannot do what `rank.rs` does · **CONFIRMED** (doc defect)
- F7 — the rank script's fail-closed guarantee is shell-dependent · **CONFIRMED** (minor; bwrap covers it)
- F8 — the namespace fds leak into the workload · **CONFIRMED** (hygiene, no impact found)

## B5

- F-B5-1 — An agent-chosen shebang bypasses the re-exec guard entirely — CONFIRMED
- F-B5-2 — Head/tail split uses Rust whitespace rules, not the shell's, so lines run *above* the guard uncaged — CONFIRMED
- F-B5-4 — The cleanup/partial-output trap covers too few signals and is installed too late — CONFIRMED
- F-B5-3 — `cage_banner` un-quotes a non-constant value into a double-quoted `echo` — CONFIRMED (mechanism); trust-caveated
- F-B5-5 — Cleanup enumerates spool files but misses the `.tmp` intermediates — CONFIRMED (omission); overlaps B1

## B6

- F1 — The staged guard script is handed to `sbatch` **by path**, in a directory the agent can write. `PLAUSIBLE` (race), and the docs-vs-code contradiction is `CONFIRMED`.
- F2 — `job_args` is raw agent bytes appended to the real `sbatch` argv. `CONFIRMED` (the forwarding), `PLAUSIBLE` (that sbatch parses them as options).
- F3 — Mail is an ungated egress channel out of the cage, via `#SBATCH`. `CONFIRMED` (gate gap), `PLAUSIBLE` (impact, depends on site `MailProg`).
- F4 — `#SBATCH hetjob` is invisible to the body gate; the whole matrix is per-component and husk forces only component 0. `CONFIRMED` (parser gap), `PLAUSIBLE` (het semantics).
- F5 — `--qos` and `--reservation` are `Allowed`, but the matrix row claims the family is forced; both move the resource envelope the partition is supposed to bound. `CONFIRMED`.
- F6 — `scancel` (and every read-only query) runs with the broker's environment unfiltered; `SCANCEL_*` is an unlisted channel for the same decision. `CONFIRMED` (unlisted channel), severity LOW today.
- F7 — The resource-envelope guarantee is written for one partition and the code now takes a list; nothing checks the weakest member. `CONFIRMED` (docs-vs-code), operator-facing.
- F8 — The stdout/stderr row says "env stripped"; nothing strips it. `CONFIRMED` (docs-vs-code), no exploit.
- F9 — `HUSK_SLURM_ACCOUNT` has no value grammar, while `HUSK_SLURM_PARTITION` does. `CONFIRMED`, minor.
- F10 — The `SBATCH_UENV*` cell is named in the matrix and exercised by nothing. `CONFIRMED` (unproven cell).
- F11 — The read-only query verb has no row, and it forwards the agent's whole argv into another SLURM binary. `CONFIRMED` (unrowed + forwarded), `PLAUSIBLE` (disclosure impact).
- F12 — `#SBATCH --wait` is accepted in the body and `run_sbatch` has no timeout: a job-length broker wedge. `PLAUSIBLE`.

## C1

- 1. The login cage is 100% theirs, and nothing in husk says so — CONFIRMED
- 2. `--new-session` is a two-word boundary nobody has written down — CONFIRMED
- 3. 6a deliverable (iii) is in tension with the AF_UNIX block, not merely a plumbing swap — CONFIRMED
- 4. Two unpinned, mutually inconsistent version couplings to their runtime — CONFIRMED
- 5. The session-level wrap already exists, and its design note will become stale the day the runtime goes — CONFIRMED
- 6. Trap check: husk's own trusted layer already runs a Lustre directory walk — CONFIRMED
- 7. What the ripgrep walk actually buys is small and precisely nameable — CONFIRMED
- 8. 6a deliverable (ii) is new capability, not replication — CONFIRMED
- 9. `TMPDIR` / default write paths are a functional dependency the "naked Claude" check will hit — PLAUSIBLE

## C2

- C2-1 — Direction is settled: egress-only is sufficient. **CONFIRMED**
- C2-2 — There is no instantiation path for the proxy outside a SLURM job. **CONFIRMED**
- C2-3 — The proxy is structured so TLS termination can be *added*. **CONFIRMED**, with three costs named
- C2-4 — `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_MODEL` are in no controlled set on the login side. **CONFIRMED**
- C2-5 — The allowlist cannot express the distinction login needs most: one host, two principals. **CONFIRMED (structural)**
- C2-6 — On login, the settings hierarchy that carries the allowlist becomes plantable. **PLAUSIBLE**
- C2-7 — No SOCKS path: non-HTTP TCP has no route at all. **CONFIRMED**
- C2-8 — husk's unix-socket transport already avoids the bug Anthropic had to fix; a TCP-loopback login proxy would reintroduce it. **CONFIRMED**
- C2-9 — With header injection, the in-cage relay becomes a position the agent occupies. **PLAUSIBLE, low severity, recorded for the 6b design**

## C3

- 1. Policy source — "what is the neutral equivalent, and what breaks when the vendor changes it?"
- 2. Process shape — single long-lived process? Node? re-exec per command?
- 3. Filesystem conventions — a config directory at all, and under `$HOME`?
- 4. Credential names — keyed on specific names, or on a declared set?
- 5. Behavioural coupling — does anything depend on how the agent *behaves*?
- F1 — `STRIPPED_SUBMIT_ENV` is a four-name denylist, so a second agent's API token rides into every compute job by default — **CONFIRMED**
- F2 — `AUTO_EXEC_DIRS` masks one vendor's config directory by name; another agent's config dir is left unmasked inside the cage — **CONFIRMED**
- F3 — husk has no policy source of its own; all four policy inputs are the vendor's schema — **CONFIRMED**
- F4 — the login-side filesystem boundary is implemented by the confined party, and for native tools it is advisory — **CONFIRMED**
- F5 — husk's install pipeline downloads a vendor binary and places it on the enforcement path — **CONFIRMED**
- F6 — the identity uid-map is a design decision taken to accommodate a branch inside the vendor runtime — **CONFIRMED**
- F7 — the seccomp floor and the login profile are calibrated against one agent's syscall usage, and the failure mode is SIGKILL — **CONFIRMED** (calibration) / **PLAUSIBLE** (that a second agent trips it)
- F8 — column 1 (`binary to exec`) is hardcoded at three exec sites, not parameterised — **CONFIRMED**
- F9 — column 3 (`API hosts to allowlist`) does not exist — **CONFIRMED**
- F10 — the login-side confinement granularity is the vendor's, and husk has no proof it is not a functional dependency — **PLAUSIBLE**
- F11 — the install mechanism itself is agent-specific and is not separable from husk's install — **CONFIRMED**

