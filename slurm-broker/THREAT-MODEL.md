# Compute-job threat model — husk SLURM broker

## Base cage
When the broker submits a job, the injected re-exec guard re-sandboxes it on the
compute node (`seccomp-wrapper bwrap …`):
- `--ro-bind / /` — whole filesystem read-only
- `--tmpfs /users` — **all** homes hidden (own + others': `~/.ssh`, `~/.aws`, `~/.claude/settings.json`)
- `--bind <workdir>` + `allowWrite` roots — the only writable areas
- `--ro-bind <allowRead carve-outs>` — specific re-exposed reads
- credential file denies, env masking, symlink guard (features below)
- `--dev-bind-try /dev/nvidia*` — GPUs
- `--unshare-net` — no network **(current — treated as TEMPORARY)**

## Design principle (the cage)
Layers must be **independent**. `--unshare-net` *will* be relaxed (allowlisted
socat at best, open internet at worst), so the **filesystem cage must protect
confidentiality on its own, assuming exfiltration is possible.** No secret's
safety may depend on "there's no network."

## Design principle (the gate) — deny by construction on the submission surface
The cage principle above protects a job *once it runs*. This one governs *what the
broker agrees to submit*. It exists because every critical we found (F13, F14, F24,
F26, F27) was the **same bug wearing different clothes: the broker secured its
*model* of sbatch, not sbatch.** The exploit always lived in the delta between the
argument grammar the broker parses and the one slurmd actually obeys.

Two consequences make that delta exploitable, and both are the rule to design against:

1. **Never forward adversary bytes into a second parser.** The broker forwards agent
   argv (minus a strip list) and the script body straight to slurmd, so slurmd
   re-parses adversary-influenced input. Two parsers that can disagree = a
   parser-differential hole (LangSec). Safety requires the broker to reduce every
   input to a **canonical form it fully controls** before slurmd sees it — one
   channel, one parser.
2. **A denylist is a bug list.** "Strip the dangerous options, pass the rest" is
   default-*allow*; each finding was an entry we hadn't added. The submission surface
   must be **default-deny** like the cage is: the broker *constructs* the invocation,
   forces everything security-relevant, parses the few benign resource options into
   typed values and **re-emits them canonically**, and **rejects anything it doesn't
   recognise.** Then glued shorts, `--wrap`, unknown flags, and next year's new sbatch
   option fail closed *by construction* — there is no delta left to attack.

**Reason about the SINK, not the source.** Don't enumerate input *fields*; enumerate
the security-relevant **decisions slurmd makes** (it runs as you, with MUNGE + net),
and for each list **every channel** that can influence it. That grid is *closeable*;
"list of dangerous options" is open-ended. Every unproven cell is a candidate bug —
F24 = (code-runs × body/env), F27 = (code-runs × `--wrap`), F13 = (output-path ×
glued spelling) were all *visible holes* in it:

| slurmd decision | channels that can set it | broker control today | must dominate → |
|---|---|---|---|
| **what code runs** (→ whether it's caged) | script file · `--wrap` · stdin | snapshot all three into `body`, stage one guarded script; `--wrap` stripped so only the staged script executes (F27) | the *one* thing slurmd executes is the broker's guarded script — no submission spelling yields an unguarded job |
| **stdout/stderr path** | `-o/-e` (4 spellings) · `#SBATCH` · `SBATCH_OUTPUT/ERROR` | force `--output/--error` on CLI (outranks `#SBATCH`); glued shorts split first (F13); env stripped | forced value wins over every channel |
| **working dir** | `-D/--chdir` · `#SBATCH` · `SBATCH_CHDIR` · `req.cwd` | force `--chdir`; confine `req.cwd` (reject `/`, floors, traversal) (F15/F19) | forced + confined; `cwd` treated as adversarial, not metadata |
| **partition/account/qos** | `-p` (4 spellings) · `#SBATCH` · `SBATCH_PARTITION` | require+force exact partition; glued split (F14) | forced value wins; mismatch rejected |
| **uenv/repo mount** (root, via slurmstepd) | `--uenv/--view/--repo` · `#SBATCH` · `SBATCH_UENV*` | strip CLI; **reject** body/env selection that differs from session or names `--repo` (F26) | reject dominates (never rewrite the body) |
| **inherited env** | `--export` · `#SBATCH` · `SBATCH_EXPORT` | force `--export=ALL` on CLI in both branches (F24) | forced value wins; residual = env-secret masking (AV7) |
| **node/resources** | `--nodes/--time/--mem/--gpus` … | parse → validate (per-option grammar) → re-emit canonically; reject unknown/invalid (`interpret_cli`) | allowlist by construction |
| **identity** | — (runs as you; MUNGE) | not settable via submission | n/a |

Every row is now closed **by construction**: the broker builds the invocation from an
allowlist (`sbatch::REGISTRY`) — Forced options forced, benign resource options parsed
→ validated → re-emitted canonically, everything unrecognised rejected
(`interpret_cli`); dangerous/unknown `#SBATCH` directives and `#BB`/`#DW` lines
detect-and-rejected (`body_reject_reason`). The broker no longer forwards adversary
bytes into slurmd's parser, so the F13/F14/F24/F26/F27 class is closed at the structure,
not instance by instance.

**The rules, compressed** (each generalises the findings in parens):
1. *A denylist is a bug list* — default-deny the submission surface; construct + re-emit + reject-unknown. (F13/14/24/26/27)
2. *Never forward adversary bytes into a second parser* — canonicalise before slurmd. (F13/14/24/26)
3. *Every field is an adversarial choice, including descriptive-looking ones* (`cwd`, `id`). (F1/F15/F17/F19)
4. *Capture values, not references* — a name/path the agent can still change is unvalidated. (F20; the inline body-snapshot done right)
5. *Enforce invariants, not mechanisms*, as close to slurmd as you can reach (job/task prolog or SPANK is the privileged ideal; the re-exec guard is the unprivileged approximation). (F27)
6. *Clean architecture only proves the axes you thought about* — transport-trust, memory-safety and fail-closed control-flow were all clean; the bugs lived on **input-language coverage**, an orthogonal axis. Assume the policy is incomplete over any rich interface and buy coverage adversarially (the multi-agent + docs-vs-code passes are that budget).

## Design principle (what we rely on) — the load-bearing set

A command from the agent passes several gates. Only some are ours, and only some are
**load-bearing**: husk's guarantee must hold even if every cooperative layer fails.

- **Load-bearing (kernel- or Rust-enforced, deterministic):** the bwrap **filesystem
  cage** (read-only root, hidden homes, `/dev/null` masks — policy ours, enforcement the
  runtime's), the **network** boundary (`--unshare-net` today), husk's
  **`seccomp-wrapper`** syscall deny-list, and the **broker** (allowlist + force-safe +
  re-sandbox for every job).
- **NOT load-bearing (convenience / defense-in-depth):** the agent runtime's permission
  rules, its static command analyser, its intent classifier, and interactive prompts.
  These reduce noise and catch the obvious; they are advisory to us. In particular an
  **AI intent classifier can never be part of the guarantee** — intent is unbounded, and
  its verdicts are non-deterministic.

Two consequences we hold to:
1. **Never let a test (or a claim) rest on a non-load-bearing gate.** A probe blocked by
   a prompt or a classifier has proven nothing about containment — see the
   trusted-layer-driven rule in [BRINGUP.md](BRINGUP.md).
2. **Encode expectations about the runtime as TESTS, not prose.** The cooperative gates
   change with upstream releases (twice in one day, 2026-07-27). A doc describing them
   rots silently; `selftest.sh` asserting the cage's actual mount shape rots **loudly**.
   This is also why the mount table — not a write-probe — is the oracle: it is mechanism,
   not opinion, and no gate stands in front of it.

This invariant survives husk owning the whole sandbox: the walls become ours, the
cooperative gates disappear, and the sentence still reads correctly.

## husk features (defense references)
| id | feature | state |
|---|---|---|
| F1 | credential file denies (`credentials.files` → `/dev/null`) | committed |
| F2 | write model (`allowWrite`/`denyWrite`, default-deny) | committed |
| F3 | file-level read denies (`denyRead` files → `/dev/null`) | committed |
| F4 | env credential masking (`credentials.envVars` → `--unsetenv`) | committed |
| F5 | symlink-escape guard (drop symlinked carve-outs) | committed |
| **F6a** | bounded credential auto-scan (workdir-only, depth-capped) | committed |
| **F6b** | write-protection of auto-exec files (`.git/hooks`, `.git/config`, …) | committed |
| base | `/users` tmpfs, `--ro-bind / /`, `--unshare-net`, unix perms, the broker itself | — |

## Attack vectors (network assumed OPEN — worst case)
| # | vector | severity | who defends it | status |
|---|---|---|---|---|
| **AV1** | read a workdir/carve-out secret (`.env`, key, `.git-credentials`) → exfiltrate | HIGH | F1 (declared) + **F6a** (un-declared, workdir scan) + `/users` tmpfs (removes home secrets) | **covered** — patterns from Read() globs is a refinement |
| **AV2** | plant an auto-exec payload (`.git/hooks`, `.git/config`, build scripts) that fires later on login with net + your identity | HIGH | **F6b** (ro-bind auto-exec files in writable roots) + F2 (root ro; writes only in workdir/scratch) | **covered** — nested-repo `.git` is a refinement |
| **AV3** | tamper the job's own outputs/results you trust | LOW–MED (integrity) | — (user's own writable space) | **accepted / out of scope** |
| **AV4** | read another user's loose-perm `/capstor` data → exfiltrate | MED–HIGH | **unix permissions** (job runs as you; reads only what you can) + optional `denyRead` | not a cage regression (= login) |
| **AV5** | symlink from writable workdir to a hidden home | LOW | `/users` tmpfs (link → empty) + F5 | **covered** |
| **AV6** | general internet abuse — C2, download-and-run, botnet, internal scan | HIGH open / LOW allowlisted | **network policy** (`--unshare-net` today; allowlisted socat target) — *not* an FS control | network-layer decision |
| **AV7** | read a secret from the **inherited env** → exfiltrate | HIGH | F4 (`--unsetenv` of declared `credentials.envVars`) + compute-cage `--unshare-net` (no exfil route today) | **partial** — the broker forces `--export=ALL` on BOTH paths (only ALL activates the uenv view), so an un-declared secret env var is residual on every submission |
| **AV8** | direct `sbatch`/`srun` from the compute node (MUNGE + net) → **bypass the broker** | HIGH | `--unshare-net` today (no route to `slurmctld`); when net opens: re-block SLURM-from-compute (shadow `sbatch`/`srun`, or keep `slurmctld` off the allowlist, or block MUNGE AF_UNIX on compute) | **LANDMINE** — covered only by no-net |

## Key findings
1. **`/users` tmpfs is the network-independent backbone** — kills home secrets,
   SSH keys, and settings tampering (H7) under *any* network policy. Biggest win.
2. **Confidentiality features (F1, F4, F6a) are load-bearing once net opens** —
   this *reverses* the earlier "the scan is marginal" take, which quietly assumed
   no-net.
3. **F6 = both halves.** F6a's auto-scan is the HPC-safe replacement for
   Anthropic's `/users`-wide ripgrep (the Lustre-freeze culprit): bounded to the
   workdir, depth-capped, file-count circuit-breaker, skippable.
4. **AV8 is the sharpest landmine.** On compute, AF_UNIX is *not* blocked and
   `/run/munge` is bound; only `--unshare-net` stops SLURM RPCs. Relaxing the
   network without re-blocking compute-side submission reopens the exact broker
   bypass the project exists to prevent.
5. **Never open-internet on compute.** Go straight to allowlisted socat — demotes
   AV6 to LOW and lets you keep `slurmctld` off the list to blunt AV8.

## Residual / accepted risks
- **AV3** — out of scope; treat agent-produced artifacts as untrusted.
- **AV4** — bounded by unix perms; not worse than login.
- **AV7 (all submissions)** — the broker forces `--export=ALL` on both the uenv and
  no-uenv paths (only `--export=ALL` activates the uenv view; a locked allowlist
  leaves it inactive), so the job inherits the login env; an un-declared secret env
  var (not in `credentials.envVars`) is residual → consider a vetted baseline env
  allowlist later.

## Next actions
- Build **F6a** (bounded auto-scan) + **F6b** (auto-exec write-protection).
- Treat **AV8 mitigation as a hard prerequisite** of the network rework (relax
  `--unshare-net` *only* together with compute-side SLURM re-blocking).
- Network target: **allowlisted socat, `slurmctld` excluded.**

## Design decisions (from the threat discussion)
- **One parameterized fs-sandbox generator.** `settings.rs` is *the* bwrap-arg
  builder, parameterized by a profile (`Login | Compute`) so that when husk goes
  standalone (diverges from Anthropic) it does NOT fork into two near-identical
  fs-sandbox codebases. Only the `Compute` profile is wired now; the `Login`
  profile is config, not a rewrite, when husk owns login.
- **Scan cadence = `ScanMode { PerConstruction, CacheOnce }`.** The scan always
  runs *at construction*; what differs is construction cadence + whether the
  result is cached. Compute rebuilds the sandbox per-JOB and **bwrap binds are
  frozen mid-job** → structurally scan-once. Login rebuilds per-COMMAND →
  `PerConstruction` effectively re-scans and catches mid-session credential drops.
- **Re-scan rule:** re-scan iff a *mutable, readable region prone to runtime
  credential-drops* is exposed. Compute: home is tmpfs'd + the only writable
  regions are the job's own + bwrap is frozen → **false → scan once**. A
  read-only home carve-out is static → scanning it once is exact (a scan-*scope*
  question, not a frequency one). Login: home exposed → true → re-scan.
- **Symlinks** (AV5): runtime symlinks the job creates are **namespace-confined**
  — they resolve inside the cage, and `/users` tmpfs neutralizes any that point
  into a home. Only a bind-**source** host symlink on a carve-out can escape, and
  **F5** handles that. bwrap need not "cut" symlinks; AV5 is fully covered.
- **Permission `Read()` globs on compute:** the settings-file denies
  (`.claude/settings.json`) are **moot** — home is tmpfs'd, the files don't exist
  in the cage. The credential `Read()` globs (`*.pem`, `.env*`, …) require a scan
  to translate globs → concrete `/dev/null` binds for *bash*; that scan is **F6a**,
  and its patterns can later be sourced from these globs.
- **F6a = one bounded workdir scan at submit** — workdir only (never `/users`-wide),
  depth- and file-count-capped (circuit-breaker), fail-safe, patterns = the
  standard secret set. **F6b** = read-only re-bind of auto-exec files
  (`<root>/.git/hooks`, `<root>/.git/config`) within writable roots.

## Open decision (deferred until husk owns login)
- Login-scanner **aggressiveness** (auto re-scan when the user opens a home-hole
  vs. cache-and-accept-the-risk) and **scan performance tuning**. Deferrable —
  once husk owns the login sandbox we can iterate + benchmark on the cluster. Does
  not block the compute side (which is scan-once by construction).
