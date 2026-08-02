# B5 — guard-script generation, and whether `policy.rs` is auditable

**Pass 1 (discovery).** Verdicts are CONFIRMED (demonstrated by executing generated
output) or PLAUSIBLE (argued). All work was code-only on the laptop against a **scratch
copy** of the crate (`/tmp/.../scratchpad/work/broker`); the tree under `slurm-broker/`
was not modified. Every claim below was checked against **generated output**, either the
committed goldens or scripts I regenerated with instrumented probe tests, then executed
where execution could settle it.

## Summary

The construct-and-re-emit discipline holds for the values it covers: session-derived
`--uenv/--view/--account/--partition` never reach the guard *text* at all (they are sbatch
argv only, re-emitted from the trusted broker env / the allowlist, and I confirmed the
agent cannot set them), and the workdir, broker/stub/socat paths and bwrap args are
`sh_quote`d correctly everywhere they land in the script body. The exposure is not in
those values — it is in **two things the guard's safety silently assumes but does not
control: which interpreter runs the staged script, and that the guard is the first
executable content bash reaches.** Both assumptions are breakable by the agent-controlled
script *body*, and breaking either runs code **uncaged** on the compute node (F-B5-1,
F-B5-2, both CONFIRMED). Two further CONFIRMED findings: the cleanup/partial-output trap
covers too few signals and is installed too late (F-B5-4), and `cage_banner` deliberately
un-quotes a non-constant value into a double-quoted `echo` (F-B5-3, trust-caveated). On
auditability the verdict is split and stated in full in Deliverable 2: the **emitted**
shell (the goldens) is the right artifact and is readable; the **generator** is not
reliably auditable by reading, and the project's own bug history is the evidence — but a
typed builder would only retire the *quoting* class, and the two highest-severity findings
here are not quoting bugs.

---

## Deliverable 1 — can the emitted guard be made to do something it should not?

### Enumeration of interpolation sites, with quoting context

`wrap_script` (policy.rs:559-988) is the only generator; `cage_banner` (538-557) and the
`net_start`/`net_relay` blocks (643-786) feed into it. Every value that reaches the emitted
script text, its source, and how it is quoted:

| Value | Source | Site | Context in emitted shell | Quoting |
|---|---|---|---|---|
| `body` (whole agent script) | **agent** (snapshot) | 987 `{head}{guard}{tail}` | top-level shell, verbatim | **none, by design** — see F-B5-1/2 |
| agent shebang (body line 1) | **agent** | 583-585 | the `#!` line of the staged file | **preserved as-is** if present |
| `workdir` (= `project_dir`) | trusted (launch dir) | 827, 849, 865 | inside `'...'` (spool), inside `"..."` (echo), bare arg after `--workdir` | `sh_quote` → `'...'` ✓ |
| `workdir` | trusted | 546 via banner | **inside `"..."`** | `sh_quote(p).trim_matches('\'')` → **raw** (F-B5-3) |
| `writable[]` (proj + `allowWrite`) | trusted (settings.json) | 795 `HUSK_WRITABLE` | inside `'...'` | `sh_quote(join(":"))` ✓ |
| `writable[]` | trusted | 544-547 banner | **inside `"..."`** | **raw** (F-B5-3) |
| `bwrap` args | trusted (settings) | 894 | bare tokens on the `seccomp-wrapper` line | each `sh_quote`d → `'...'` ✓ |
| `broker_q` / `stub_q` / `socat_q` | trusted (`current_exe`) | 834/860/667/684 | bare / inside `'...'` | `sh_quote` ✓ |
| `mask_paths` | **compile-time const** | 809 `for _d in {mask_paths}` | word-split list | unquoted — safe (constant, path-safe) |
| `sec` (profile name) | compile-time | 894 `--profile={sec}` | bare token | unquoted — safe (constant) |
| `caged_socat` | compile-time const | 675, 767-768 | `={const}` and inside `"..."` | unquoted — safe (constant `/tmp/husk-socat`) |
| `SLURM_JOB_ID`, `HOME`, `PWD`, `hostname`, `id -u`, `date` | runtime, in-shell | many | expanded in-shell, `${x:-default}` guarded | shell-guarded ✓ |

The two `sh_quote`-not-used cases that are **not** compile-time constants are the banner
(F-B5-3) and the body (F-B5-1/2). Everything else that is non-constant is `sh_quote`d.

### Findings (most severe first)

---

#### F-B5-1 — An agent-chosen shebang bypasses the re-exec guard entirely — CONFIRMED

**Where:** policy.rs:583-585. `wrap_script` prepends `#!/bin/bash` **only if the body does
not already start with `#!`**; an agent shebang is kept verbatim. The guard's re-exec
(policy.rs:894, `... -- /bin/bash "$0" "$@"`) only forces bash *inside* the cage — reaching
it requires the *outer* interpreter to execute the file line-by-line.

**Scenario:** the agent submits a script whose first line is

```
#!/usr/bin/env -S bash -c "id > /tmp/pwned; echo RAN >&2"
```

`decide()` accepts it (the body-directive scan only inspects `#SBATCH` lines; there is no
shebang validation). slurmd honours the shebang on the compute node, so the kernel runs
`env -S bash -c "<payload>" <scriptpath>`: the payload executes and the file body — guard
included — is never read. The job runs **uncaged, as the user, with the login
environment** (`--export=ALL`). `_HUSK_RESANDBOXED` cannot help: it is set *by* the guard,
which never runs.

**Demonstrated:** through `decide()` end-to-end (ACCEPTED; staged first line =
`#!/usr/bin/env -S bash -c "id > /tmp/b5-e2e-shebang; ..."`) and by executing the staged
script — the marker file was written and `CAGE-ENTERED` (my bwrap stub) never printed. Any
interpreter that treats the file as data rather than executing it top-to-bottom works; a
POSIX shell that *mis-parses* it does not (see "what did NOT break it"). Overlaps A3 (body
→ slurmd) but the defeated mechanism is the guard that policy.rs generates, so it is
reported here.

---

#### F-B5-2 — Head/tail split uses Rust whitespace rules, not the shell's, so lines run *above* the guard uncaged — CONFIRMED

**Where:** policy.rs:570-582. The split that decides which lines go *before* the guard
(`head`) vs. after (`tail`) keeps a line in `head` when, after Rust `str::trim_start()`, it
`is_empty()` or `starts_with('#')`. `trim_start` strips **Unicode** whitespace — U+000B
(VT), U+000C (FF), U+00A0 (NBSP), CR — none of which bash treats as leading whitespace
before a `#` comment. So a line husk classifies as an inert leading comment is, to bash, a
**command**, and it is emitted *above* the guard where bash runs it before the re-exec.

**Scenario:** body line `\u{000C}# ; id > /tmp/pwned; echo RAN` (a form-feed, then `#`).
Rust: `trim_start()` removes the FF, sees `#...`, keeps it in `head`. Bash: the token is
`$'\f#'` (command-not-found), then `;`, then the payload runs — **before** the guard's
`if [ -z "$_HUSK_RESANDBOXED" ]` line.

**Demonstrated:** end-to-end through `decide()` (ACCEPTED) and by execution — for FF, VT,
NBSP and CR the payload printed and the marker was written *before* `CAGE-ENTERED`. Probe
offsets confirmed each marker sits at a byte offset below the guard's. Same root cause as
F-B5-1: husk's model of "inert text ahead of the guard" (Rust comment/whitespace rules)
diverges from the shell that actually runs it.

---

#### F-B5-4 — The cleanup/partial-output trap covers too few signals and is installed too late — CONFIRMED

**Where:** policy.rs:892-894. The trap catches **only** `TERM` and `INT`, and is installed
**after** the whole preamble: the up-to-5s wait for the egress socket (net-on) and the
step-broker spawn all precede it.

**(a) agent-settable signal, untrapped.** `--signal` is `Class::Allowed` (sbatch.rs:164,
validated by `v_signal`), so an agent may submit `--signal=B:USR1@<t>`, asking SLURM to
send **SIGUSR1 to the batch shell** (= the guard shell). SIGUSR1 is untrapped: the guard
dies with default disposition, so **none** of the cleanup runs (step-broker, egress proxy,
`/tmp/husk-<uid>-<jobid>`, and the workdir step spool all leak) **and the "TERMINATED
EARLY — output incomplete" warning never prints.** That warning is a stated husk control
("worse, for a weather service, than an escape"); its trigger is an agent-controlled
option.

**Demonstrated:** ran the generated guard, sent SIGUSR1 to the guard shell → exit 138, no
`TERMINATED EARLY`, `.husk-step-spool-<id>` left in the workdir. Control run with SIGTERM →
exit 0, warning printed, spool removed.

**(b) pre-trap window (even for SIGTERM).** A SIGTERM delivered before line 892 — e.g.
immediate preemption while the guard is in the `while [ ! -S "$_husk_net_sock" ]` wait —
kills the guard before the trap exists: same leak, warning suppressed.

**Demonstrated:** net-on guard, SIGTERM ~1s in (inside the socket wait) → exit 143, both
`.husk-step-spool-<id>` (workdir) and `/tmp/husk-<uid>-<id>` left behind, no `TERMINATED
EARLY`. (SIGKILL past GraceTime is uncatchable and is an accepted residual; these two are
*catchable* paths that are currently missed.)

---

#### F-B5-3 — `cage_banner` un-quotes a non-constant value into a double-quoted `echo` — CONFIRMED (mechanism); trust-caveated

**Where:** policy.rs:544-547. `settings::sh_quote(p).trim_matches('\'')` deliberately
strips the single-quotes `sh_quote` added, then drops the **raw** value into
`echo "husk:   <raw>" >&2`. A writable-set entry containing `"`, a backtick, or `$(...)`
breaks out of the double quotes.

**Scenario / demonstrated:** `allowWrite` = `/scratch/x"; touch /tmp/pwn; echo "y` emits
`echo "husk:   /scratch/x"; touch /tmp/pwn; echo "y" >&2`; executing it wrote the marker.
The backtick variant executed too.

**Caveat that fixes the severity:** the values that reach the banner are `project_dir`
(the human's launch dir) and `sandbox.filesystem.allowWrite` (settings.json, which the
denyWrite pairing keeps the agent from writing). Both are **operator/trusted, not
agent-controlled**, so this is not an agent escape *today*. It is reported because the
brief asks for values reaching the script unquoted whose source is not a compile-time
constant, and because the *adjacent* line does it correctly
(`export HUSK_WRITABLE='...'` via `sh_quote(join)`, policy.rs:793-796) — the banner is the
one place that undoes the safe quoting. Verdict CONFIRMED for the injection mechanism;
PLAUSIBLE as an exploit only if an operator's config or launch path ever carries such a
character. Low-cost fix: keep `sh_quote`'s output, or interpolate the raw path with a
literal single-quote wrapper rather than a double-quoted `echo`.

---

#### F-B5-5 — Cleanup enumerates spool files but misses the `.tmp` intermediates — CONFIRMED (omission); overlaps B1

**Where:** policy.rs:924-926 removes `req-*.json resp-*.json out-* err-*` then `rmdir`s.
But `write_atomic` (spool.rs:449) stages via `.{name}.tmp` and the stub via `{path}.tmp`
(srun-stub.py:57) — i.e. `.resp-<id>.json.tmp` and `resp-<id>.json.tmp`. Neither matches
`resp-*.json` (the `.tmp` suffix defeats the glob) nor `req-*.json`. On a step-broker/stub
crash *between* create and rename, such a file strands the spool: `rmdir` fails and the
directory is kept.

**Demonstrated:** planted `req-abc.json.tmp` + `.resp-abc.json.tmp` in the spool, ran the
guard → `rmdir` failed, guard printed `husk: kept ... it still holds: req-abc.json.tmp
.resp-abc.json.tmp`, directory survived. Not silent (it reports), so severity is low, but
it is the recurring "a cleanup that enumerates is a denylist" shape. The existing
completeness test (`every_file_the_guard_creates...`) scans `spool.join(format!("…"))`
literals in step.rs and so cannot see the `.tmp` path built by `with_file_name`. Primary
home is B1; noted here because the brief lists "does the cleanup name every resource the
script creates, on every exit path."

---

### Deliverable-1 explicit checks the brief named

- **`UENV_LABEL` / `UENV_VIEW` / `HUSK_SLURM_PARTITION` / `HUSK_SLURM_ACCOUNT` —
  can the agent set them?** No. `Session::from_env()` (session.rs:136-148) reads the
  **broker's** environment, and the broker is spawned by the wrapper *before* it execs the
  agent (husk-slurm-wrapper.rs:416 spawn, then 419-431 exec) — the agent runs as a later
  process image and cannot mutate the already-running broker's env. Agent-supplied
  `--uenv/--view`/`SBATCH_UENV*` are compared against the session and **rejected** on
  mismatch (policy.rs:170-200); `--partition` re-emits the matched allowlist entry, never
  the request's bytes (133-147). And none of these four reach the guard *text* regardless —
  they are emitted as sbatch options only.
- **A value legal as an sbatch arg vs. safe as a shell token:** the relevant sbatch args
  (`--chdir/--output/--error/--partition/--account/--uenv/--view`) go into the sbatch
  **argv** (`Vec<String>`, executed without a shell), not into the guard text, so shell
  metacharacters in them are not shell-evaluated. The one class that *is* shell context is
  covered above (workdir/writable → F-B5-3, correctly quoted everywhere except the banner).
- **Use-before-assignment / branch-scoped reads:** none found. The historical
  `_husk_broker`-before-use bug is fixed in the goldens (assigned at net-off line 36 / used
  at line 130); `_husk_log` likewise precedes its first `net_start` use. Branch-only
  variables (`_husk_net_pid`, `_husk_net_dir`, `_husk_socat`, `_husk_step_pid`) are all
  read through `${x:-}` defaults. `bash -n` passes on every generated variant.

---

## Deliverable 2 — auditability verdict

**Verdict: the EMITTED shell (the goldens) is auditable and is the correct artifact to
review. The GENERATOR — the `format!` string in `wrap_script` — is NOT reliably auditable
by reading, and the project's own bug history is the proof. A typed shell builder would
retire the quoting/interpolation class but would not have caught the two most severe
findings in this review, which are semantic, not syntactic.**

Reasoning, with concrete cases:

1. **The generator forces a reader to track three levels of quoting at once**, and the
   emitted shell cannot be predicted from the literal without doing so:
   - Rust string-literal escaping — the guard is one `"\` -continued literal, so every
     line ends `\n\` and every inner quote is `\"` (policy.rs:800-985);
   - `format!` brace-doubling — `${{SLURM_JOB_ID:-nojob}}` is a *literal* `${...}`, while
     `{workdir_q}` is a substitution (policy.rs:827);
   - shell quoting — `sh_quote` emits `'...'`, layered under hand-written `"..."`.

   The file **documents four shipped bugs from exactly this** (the code comments at
   645-649, 779-782, 804-806, and the tests at 1784, 2209-2216): a literal `{socat_q}`
   that `format!` never expanded; the srun bind that shipped literal quote characters;
   `${{...}}` brace escaping; `_husk_broker` used before assignment. Four of seven shipped
   guard bugs being quoting/interpolation/scoping *is* the evidence that reading the
   `format!` string does not reliably reveal what it emits.

2. **Two rendering strategies coexist and the reviewer must know which is in force** to
   tell a placeholder from a literal. The outer guard and `net_start` use `format!` with
   `{}` interpolation; `net_relay` (policy.rs:766-782) is a raw string finished with
   `.replace("{caged_socat}", …)` **specifically because** brace-doubling every `${...}`
   in that block was judged too error-prone (its own comment, 779-781). So `{caged_socat}`
   is a placeholder in one block and would be a literal in the other.

3. **The two highest-severity findings are invisible in both the `format!` string and the
   emitted shell.** F-B5-1 and F-B5-2 are not about any byte of the guard — they are about
   how the interpreter and the shell parse content emitted *elsewhere* (the untouched body,
   the shebang) *relative to* the guard. You cannot read the guard, or its golden, and see
   them; you have to reason about the head/tail split and the shebang. The goldens pin the
   guard's bytes precisely and say nothing about the body concatenated around it.

4. **Where husk can execute the emitted script, it does, and that half is well covered.**
   The goldens plus `HUSK_UPDATE_GOLDEN`, `bash -n` on both variants, the run-against-stub
   quoting/placement/ordering tests, and the "read the diff" discipline materially close
   the value-injection gap. The emitted artifact is readable *and* exercised. This is why
   the verdict is split rather than negative: **read the goldens, not the `format!`
   string.**

**Bearing on the deferred typed builder.** The evidence supports it for the quoting class
specifically — a builder that owns quoting by construction eliminates F-B5-3 and the whole
`{socat_q}`/literal-quote/brace-doubling family, and makes a rewrite checkable against the
existing goldens ("prove the bytes are identical"). But it is **not sufficient alone**: a
typed builder still emits the agent shebang (F-B5-1), still splits head/tail by whatever
rule it is given (F-B5-2), and still traps the signals it is told to (F-B5-4). Those need
*semantic* fixes — validate/normalise the shebang, split on the shell's whitespace rule (or
force the guard to run before any body line by construction), and broaden the trap /
install it first — independent of how the string is built. So: adopt the builder to retire
the quoting class and make rewrites verifiable, but do not treat it as the answer to this
review's serious findings.

---

## What I tried that did NOT break it

- **Hostile workdir (`project_dir`) values** — `$(id)`, `"; touch …`, backticks, single
  quote, embedded newline: all `sh_quote`d correctly at every guard site (spool assignment,
  `--workdir` arg, start-of-job echo). `bash -n` passes; no injection. (The banner is the
  sole exception — F-B5-3 — and `project_dir` flows through it too, same trust caveat.)
- **`HUSK_WRITABLE` export** — single-quoted via `sh_quote(join(":"))`; a `'` in a path is
  correctly escaped `'\''`. Safe.
- **`{socat_q}` / `{broker_q}` / `{stub_q}` / `{caged_socat}` / `{mask_paths}` / `{sec}`** —
  no placeholder leaked into either golden; the double-`format!` and brace-escaping hazards
  the comments warn about are absent from the emitted output. Confirmed against generated
  bytes, not the literal.
- **bwrap argument quoting** — ran the guard against a stub echoing `"$@"`; no argument
  carried a literal `'`. The pre-quoted-string-expanded-unquoted bug is not present.
- **Session `--uenv/--view/--account/--partition`** — do not reach the guard text; agent
  cannot set the broker-side source; agent-supplied copies are rejected or re-emitted from
  the allowlist. Verified in code and by the existing decide() tests.
- **`#!/bin/sh` (dash) and `#!/usr/bin/env python3` shebangs** — NOT a bypass: dash
  aborts at the guard's `_husk_extra=()` array with a *syntax error* before anything runs,
  and python raises SyntaxError on the shell text. A mis-parsing interpreter fails the
  whole job **fail-safe** (the agent body never runs either); only an interpreter that
  *ignores* the file (F-B5-1) is an escape. Confirmed by execution.
- **Here-document swallowing the guard** — a head line `\u{000C}#<<HUSKGUARD` with a
  matching terminator in the tail: the guard text does land inside a heredoc and does not
  execute, but this is strictly weaker than F-B5-2 (it relies on the same whitespace
  differential to place the opener above the guard) and reduces to "body runs uncaged,"
  already covered. Noted, not scored separately.
- The full broker test suite (192 tests) passes on the untouched scratch copy, so the
  findings above are gaps in what is asserted, not regressions against it.
