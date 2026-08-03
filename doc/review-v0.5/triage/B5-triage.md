# B5 triage — guard-script generation (pass 2)

**Stance: refutation.** Every `CONFIRMED`/`PLAUSIBLE` in `findings/B5-findings.md` was
treated as an unverified claim and attacked. Code-only, this laptop, no cluster. The broker
was built from source — `cargo build --release` in `slurm-broker/broker` — and the explicit
binary `slurm-broker/broker/target/release/husk-slurm-broker` was driven; the gitignored
`slurm-broker/husk-slurm-broker-x86_64` prebuilt was **not** used. Nothing under
`broker/src` was modified. Findings were reproduced **independently**: I wrote my own
end-to-end harness (`scratchpad/b5/`) that injects a `req-<id>.json` into a spool exactly as
`sbatch-stub.py` does, runs the real broker `--once` so the real `decide()` +
`wrap_script()` + `write_atomic()` stage the script, and a fake `sbatch` that **models
slurmstepd faithfully** — it reads the staged file by path, refuses a non-`#!` first line
(as real sbatch does), copies the bytes to `slurm_script`, `chmod 0700`, and `execve`s it so
the kernel's `binfmt_script` honours the shebang. A stub `seccomp-wrapper` prints
`CAGE-ENTERED` and runs what follows `--`, so "did the cage entrypoint ever run" is directly
observable.

## Summary

| ID | Outcome | My severity | One line |
|----|---------|-------------|----------|
| **F-B5-1** | **CONFIRMED** | **CRITICAL** | An agent-chosen shebang is preserved verbatim (`policy.rs:583-585`); `#!/usr/bin/env -S bash -c "<payload>"` makes the kernel run the payload and never read the guarded body — job runs uncaged. Reproduced end-to-end: `decide()` ACCEPTS, `CAGE-ENTERED` count 0, marker written. One residual is coreutils `env -S` on the target node (hardware). |
| **F-B5-2** | **CONFIRMED** | **CRITICAL** | Head/tail split uses Rust `trim_start()` (strips FF/VT/NBSP/CR) but bash does not, so `\f# ; <payload>` is emitted **above** the guard and bash runs it before the re-exec. Reproduced for all four chars: payload printed before `CAGE-ENTERED`, marker written. **Fully laptop-confirmable, needs no hardware.** |
| **F-B5-4** | **CONFIRMED (a) / RECHARACTERISED (b)** | MEDIUM | (a) `--signal=B:USR1@t` is `Class::Allowed`, SIGUSR1 is untrapped → guard dies, no cleanup, no "output incomplete" warning: reproduced. (b) The "pre-trap window" is real but its blast radius is a *resource/spool leak + a suppressed warning*, not an escape; and the trap-late claim is only partly right (the costly waits are net-on only). |
| **F-B5-3** | **CONFIRMED (mechanism) / trust-caveated** | LOW | `cage_banner` (`policy.rs:544-547`) strips `sh_quote`'s quotes and drops a raw value into a double-quoted `echo` — injectable, reproduced. But both sources (`project_dir`, `allowWrite`) are operator/trusted, not agent-reachable, so not an escape today. |
| **F-B5-5** | **CONFIRMED (omission) / overlaps B1** | LOW | Cleanup globs `req-*.json resp-*.json` miss the `.{name}.tmp` / `{name}.tmp` intermediates from `write_atomic`/`srun-stub.py`, so a crash-stranded tmp keeps the spool. Reproduced; it *reports* (not silent). The cited completeness test cannot see the `.tmp` path. |

**Deliverable 2 (auditability):** I concur with a *sharpened* version of the split verdict —
read the goldens, not the `format!` string — see the final section.

**Root-cause finding (the point of this shard).** F-B5-1, F-B5-2 and the sibling-shard
**B6-F1** (TOCTOU) are **one structural defect**: husk's containment is a re-exec *injected
into the agent's own script*, so it holds only if the file is (a) unchanged between
validation and execution [B6-F1], (b) executed by the intended interpreter from line 1
[F-B5-1], and (c) has no executable content before the guard [F-B5-2]. The hypothesis in my
brief **holds**: the guard is treated as a property of a *file that something later opens by
path*, not a property of the *execution*. One structural change — submit husk's **own** fixed
wrapper as the batch entrypoint and consume the agent body as **data inside the cage** —
closes all three. The narrow per-finding fixes (validate the shebang; split on the shell's
whitespace rule) close 1 and 2 but **not** B6-F1. Detail in the F-B5-1 section.

**Overlap with workstream A3 (body → slurmd) flagged, not resolved:** F-B5-1/F-B5-2 defeat
the guard that `policy.rs` generates, but the vehicle is the agent script body reaching
slurmd, which is A3's territory. Reported here because the defeated mechanism is B5's.

---

## F-B5-1 — agent-chosen shebang bypasses the re-exec guard — CONFIRMED, CRITICAL

### What I did

`wrap_script` (`policy.rs:583-585`):

```rust
if !head.starts_with("#!") {
    head = format!("#!/bin/bash\n{head}");
}
```

`head` is the body's leading comment/blank block (line 1 included). If the body's first line
is a shebang, `head` starts with `#!`, so husk does **not** prepend its own — the agent's
shebang becomes line 1 of the staged file. The guard's re-exec (`policy.rs:894`,
`seccomp-wrapper … bwrap … -- /bin/bash "$0" "$@"`) only forces bash *inside* the cage;
reaching it requires the *outer* interpreter to read the file top-to-bottom.

I searched the whole submission path for a shebang check: `decide()` (partition, uenv,
`body_reject_reason`, `interpret_cli`) has none; `body_reject_reason`
(`sbatch.rs:393-403`) inspects only `#BB`/`#DW` and `#SBATCH` directives; `sbatch-stub.py`
forwards the body verbatim; `write_atomic` just writes bytes. Nothing validates line 1.

Independent end-to-end reproduction (my harness, not the finder's snippet):

```
body line 1 = #!/usr/bin/env -S bash -c "id > .../markers/f1-pwned; echo RAN-UNCAGED >&2"
```

Result: `decide()` → `status: submitted`; staged file line 1 = the agent shebang **verbatim**;
the fake slurmd execve's it, the kernel honours the shebang, `env -S` splits and runs the
payload; `grep -c CAGE-ENTERED job.out` = **0** (the cage entrypoint never ran); the marker
`f1-pwned` was written and `RAN-UNCAGED` printed. The guarded body (`echo
this-body-never-runs`) never executed.

### Attacks I tried, and why they did not save it

- **Is there another guard on the real path?** No shebang validation anywhere in `decide()`,
  `body_reject_reason`, the stub, or the spool write. Confirmed by reading each and by the
  `status: submitted` above.
- **Does `env -S` mis-parse fail-safe?** No. `#!/usr/bin/python3` over shell text *does* fail
  safe (interpreter errors, whole job dies, body never runs) — I reproduced that too. But
  `env -S` is a *correct* interpreter selection that runs an arbitrary command string; it is
  the working vehicle, not a mis-parse.
- **Does the forced sbatch CLI still constrain it?** Partly — see blast radius. It does not
  restore the cage.

### Blast radius (precise)

The forced sbatch argv is (dry-run, verbatim):

```
sbatch --parsable --partition=normal --nodes=1 --export=ALL \
  --chdir=<projdir> --output=<projdir>/slurm-%j.out --error=<projdir>/slurm-%j.err \
  <spool>/job-<id>.sh
```

With the guard defeated, **everything the guard provides is gone**: the bwrap FS cage
(read-only root + `$HOME`/`/users` masking), the `seccomp-wrapper` syscall filter, the
`--unshare-net` network isolation, the `/run/munge` credential mask, and the job PID
namespace. The job runs **as the user, on the compute node**, with:

- full read **and write** to the user's real home and every filesystem the user can touch
  (the FS cage was the only thing confining writes; F-B5-1 removes it entirely);
- **MUNGE credentials** → it can talk to `slurmctld` directly, i.e. submit/cancel/`srun`
  **bypassing the broker altogether** — the broker's whole gate is moot from inside an
  escaped job;
- **network** (no `--unshare-net`, no egress-proxy restriction).

What *is* still enforced, because it lives on the sbatch CLI and not in the guard: the forced
**partition** (`normal`/preemptible — the resource envelope), `--nodes=1`, the forced
`--account` where configured, and `--chdir/--output/--error` confined to the workdir. Model
API keys are stripped from the submission env (`STRIPPED_SUBMIT_ENV` in `run_sbatch`), so
those specific secrets do not reach the job — but nothing else about confidentiality holds.

So: the resource-envelope controls survive; the **entire compute-side containment**
(AV1–AV8's FS/network/credential story) does not. This reopens AV8 (broker bypass) fully.
**CRITICAL.**

### Root cause shared with B6-F1 (the structural finding)

I read `triage/B6-triage.md` F1 (TOCTOU, CONFIRMED CRITICAL) and compared mechanisms:

| | how the guard is defeated |
|---|---|
| B6-F1 | file bytes are swapped by a rename race after validation, before sbatch opens the path |
| F-B5-1 | the file's own first line diverts the interpreter away from the guard bytes |
| F-B5-2 | executable bytes are placed above the guard in the same file |

All three exploit the **same** thing: containment is a re-exec **prefix injected into the
agent's script**, handed to sbatch **by path**. The guard is a property of *a file that
something else later opens/execs by path*, not a property of the *execution*. The hypothesis
in my brief holds.

**One structural change closes all three:** make the batch entrypoint husk's **own** fixed
script (husk's shebang, husk's bytes, guaranteed to run the cage first), and have that
wrapper consume the agent body as **data** *inside* the cage (e.g. bind the snapshot
read-only and `exec bash <snapshot>` after entering bwrap, or feed it on a controlled fd).
Then: the interpreter husk's script selects is husk's (F-B5-1 gone); no agent bytes precede
the guard because the body is never concatenated ahead of it (F-B5-2 gone); and a swapped
body file is read *after* the cage is up, so a won race yields a **caged** body, not an
uncaged job (B6-F1's escape neutralised).

**Is the obvious per-finding fix sufficient?** For F-B5-1 alone, forcing husk's shebang
(strip/reject an agent `#!`, always prepend `#!/bin/bash`) *does* fix F-B5-1 — but it is
immediately defeated by F-B5-2 (a command placed above the guard runs under husk's own
`#!/bin/bash`), and does nothing for B6-F1. So the shebang fix **plus** the whitespace fix
handle 1 and 2 but leave the TOCTOU open. Only the structural change closes the class. State
that plainly in the fix pass.

### Residual that genuinely needs hardware

The mechanism (SLURM `execve`s the batch script, so the shebang is honoured — which is
exactly *why* sbatch enforces a `#!` first line) is well-established and does not need a
cluster to believe. The one node-specific element is whether the target's coreutils honours
`env -S` splitting (coreutils ≥ 8.30, 2018 — near-certain on Balfrin/Santis Cray images).

**UNRESOLVED-NEEDS-HARDWARE (belt-and-suspenders only):** on a Balfrin/Santis login node,
submit through husk a job whose first line is
`#!/usr/bin/env -S bash -c 'id; hostname; cat /users/$USER/somefile > $SCRATCH/f1-marker'`
and confirm from the job output that (i) no `husk: compute cage active` banner appeared and
(ii) a file the cage would tmpfs-mask (`/users/...`) was read. A marker = confirmed
end-to-end. This only certifies `env -S`; F-B5-2 (below) needs no such step.

---

## F-B5-2 — head/tail split uses Rust whitespace, not the shell's — CONFIRMED, CRITICAL

### What I did

`wrap_script` (`policy.rs:570-585`) classifies a body line as "leading comment/blank" (→
`head`, emitted **above** the guard) when, after Rust `str::trim_start()`, it `is_empty()` or
`starts_with('#')`. `trim_start()` strips Unicode `White_Space`: U+000B (VT), U+000C (FF),
U+00A0 (NBSP), and a leading CR — none of which bash treats as a blank before `#`. So a line
husk files as an inert comment is, to bash, a **command**, emitted where bash runs it before
the re-exec.

Independent reproduction for **FF, VT, NBSP, CR**, body line `<ws># ; id > marker; echo
RAN-ABOVE-GUARD`:

```
[FF U+000C] status=submitted   job.out: RAN-ABOVE-GUARD-FF @line 3, CAGE-ENTERED @line 10
[VT U+000B] status=submitted   RAN-ABOVE-GUARD-VT @3,  CAGE-ENTERED @10
[NBSP U+00A0] status=submitted RAN-ABOVE-GUARD-NBSP @3, CAGE-ENTERED @10
[CR U+000D] status=submitted   RAN-ABOVE-GUARD-CR @3,  CAGE-ENTERED @10
```

The payload prints (and the marker is written) **before** `CAGE-ENTERED`, i.e. uncaged. I
then dumped the staged bytes to confirm placement:

```
  1: #!/bin/bash                                  <- husk-prepended (body starts with FF, not #!)
  2: <FF># ; id > /tmp/x; echo PAYLOAD            <- payload, in HEAD, ABOVE the guard
  4: if [ -z "${_HUSK_RESANDBOXED:-}" ]; then     <- guard starts here
```

To bash, line 2 is: token `$'\f#'` (command-not-found, non-fatal — no `set -e` above the
guard), then `;`, then `id > …`, then `;`, then `echo PAYLOAD`. All uncaged, all before the
guard's re-exec. (The payload then also runs a second time *inside* the cage when the guard
re-execs `"$0"` — harmless; the first, uncaged run is the escape.)

### Attacks I tried

- **Does `decide()`/`body_reject_reason` reject it?** No. `body_reject_reason` does
  `line.trim_start()` — the *same* Rust rule — so `\f#…` is not seen as `#BB`/`#DW`/`#SBATCH`
  and passes. `status: submitted` confirms.
- **Is this weaker than F-B5-1 (does it depend on `env -S`)?** No — and this is the important
  difference. F-B5-2 needs no `env -S`, no non-default interpreter: the staged line 1 is
  husk's own `#!/bin/bash`, so it is pure bash tokenisation of husk-generated bytes.
  **Fully laptop-confirmable; no hardware residual.** The only assumption is that the
  cluster's bash treats FF/VT/NBSP/CR as non-blank before `#`, which is POSIX (only space,
  tab, newline are `<blank>`), so it is certain.

### Blast radius & severity

Identical to F-B5-1 once bash runs a command above the guard: full uncaged execution as the
user before the cage exists. Same total compute-side bypass, same forced-sbatch-CLI residue.
Because it needs **no** coreutils/interpreter assumption and is confirmed here outright, I
rate it **CRITICAL**, tied with F-B5-1. Same root cause and same structural fix (above); the
narrow fix is to split head/tail on the shell's `<blank>` rule (space/tab only) **or** — far
better — stop concatenating agent bytes ahead of the guard at all.

---

## F-B5-4 — cleanup/partial-output trap covers too few signals and is installed late — CONFIRMED (a) / RECHARACTERISED (b)

### What I did

The guard installs exactly two traps (`policy.rs:892-893`, confirmed in the generated
script): `trap '_husk_signalled=SIGTERM' TERM` and `trap '_husk_signalled=SIGINT' INT`.
Nothing else is trapped. `--signal` is `Class::Allowed` (`sbatch.rs:164`, grammar `v_signal`
allows alphanumerics + `:` + `@`), so I verified the agent value survives: submitting
`--partition=normal --signal=B:USR1@60` yields `status: submitted` and the dry-run argv
re-emits `--signal=B:USR1@60` **verbatim** to the real sbatch.

**(a) agent-settable untrapped signal.** I generated the real guard and ran it, sending
signals to the guard shell:

- `kill -USR1 <guard>`: exit **138** (128+10), `TERMINATED EARLY` printed **0** times, the
  `.husk-step-spool-nojob` directory **left behind**, no cleanup lines. None of the cleanup
  ran and the completeness warning was suppressed.
- Control `kill -TERM <whole job pgroup>`: exit **143**, `TERMINATED EARLY` printed **once**,
  step spool **REMOVED**. The control works exactly as designed.

**(b) pre-trap window.** I generated a **net-on** guard (by placing a
`sandbox.network.allowedDomains` entry in the project `.claude/settings.json`, key spelled
camelCase as `netallow.rs` requires) and read the ordering: the egress-proxy spawn is at line
129, the up-to-5s socket wait `while [ ! -S "$_husk_net_sock" ] && [ "$_husk_w" -lt 50 ]` at
line 148, and the traps at lines 201-202 — i.e. the traps are installed **after** the socket
wait. I then signalled the guard shell during the preamble (confirmed `CAGE-ENTERED` had not
yet appeared): `TERMINATED EARLY` was not printed, and **both** the workdir step spool and
the `/tmp/husk-<uid>-nojob` netdir were left behind.

### Attacks / corrections to the finder's mechanism

- **Do the step-broker and egress proxy actually leak, as the finding says?** No —
  RECHARACTERISED. Both `--net-proxy` (`main.rs:283`) and the `--step-broker` path call
  `die_with_parent()` → `PR_SET_PDEATHSIG(SIGTERM)` with the guard as parent, so when the
  guard dies the kernel signals them. The guard's explicit `kill "$_husk_step_pid"` /
  `kill "$_husk_net_pid"` is the belt; pdeathsig is the suspenders (the code comments say
  exactly this). So the **processes** are reaped; what actually leaks is the two
  **directories** (the workdir `.husk-step-spool-<jobid>` and the node-local
  `/tmp/husk-<uid>-<jobid>`) and the suppressed warning.
- **Is the trap "installed too late" in general?** Only materially for **net-on** (the 5s
  socket wait). Net-off, the pre-trap preamble is short (log-dir mkdir + a backgrounded
  step-broker spawn), so the window is small though nonzero. And the deferred-trap design is
  actually *correct* for the common case — a SIGTERM arriving while the cage is the
  foreground command is deferred until the cage returns, then the handler runs — which is why
  ordinary preemption *does* get the warning (my control run proved it). The genuine gap is
  narrow: (i) a signal other than TERM/INT (agent-settable), (ii) a TERM/INT during the
  pre-trap preamble (long only when net-on).

### Verdict & severity

CONFIRMED for (a); RECHARACTERISED for (b) and for the "processes leak" claim. **This is not
a containment bypass** — the job stays fully caged either way; the seccomp/bwrap re-exec is
untouched. The impact is (1) a resource leak of two directories (one in the user's project,
one on node-local `/tmp` that accumulates on a rarely-rebooted node — the code itself flags
that as the thing node-local scratch must not do), and (2) suppression of the
"TERMINATED EARLY — output incomplete" warning, which husk's own comments call, for a weather
service, "a worse outcome than an escape". An agent can trigger (2) deliberately with
`--signal=B:USR1@t`, turning an incomplete run into one that *looks* complete with no husk
warning — an integrity-of-reporting defeat, not a confidentiality/escape one. **MEDIUM.** The
minimal fix (trap more signals; install the trap before the socket wait) helps but does not
address SIGKILL past GraceTime (uncatchable, an accepted residual). A better fix moves the
"incomplete" signalling out of the batch shell's trap entirely, so it cannot be skipped by
choosing the signal — but that is a design decision for the fix pass.

**Overlap:** `--signal` reaching sbatch verbatim is also A3/registry territory (resource
passthrough); the trap-coverage half is B5's.

---

## F-B5-3 — `cage_banner` un-quotes a non-constant value into a double-quoted echo — CONFIRMED (mechanism), LOW

### What I did

`cage_banner` (`policy.rs:544-547`) emits `echo "husk:   {}{note}" >&2` where `{}` is
`settings::sh_quote(p).trim_matches('\'')` — it calls `sh_quote` (which returns `'...'`) and
then **strips the very quotes it added**, dropping the raw value into a double-quoted string.
I set `sandbox.filesystem.allowWrite` to `/scratch/x"; touch /tmp/b5-f3-pwned; echo "y` and
generated the guard. The emitted banner line is:

```
echo "husk:   /scratch/x"; touch /tmp/b5-f3-pwned; echo "y" >&2
```

Piping that one line to bash created `/tmp/b5-f3-pwned` — the `"` closes husk's echo and the
payload runs. The **adjacent** `export HUSK_WRITABLE='…'` and the entire `bwrap` argument
line quote the *same* value correctly with `sh_quote` (single-quoted, `'\''`-escaped), so the
banner is the one site that undoes the safe quoting — exactly as the finding states.

### Attacks / why the severity is LOW

- **Is the source agent-controlled?** No. `writable` = `project_dir` (broker's
  `current_dir()`, captured pre-agent) + `fs.allow_write` (from the `.claude/settings.json`
  hierarchy, resolved once at broker startup before the agent execs, and tmpfs-masked inside
  the cage). The agent cannot set either. So this is not an escape today; it fires only if an
  operator's launch path or config ever contains `"`, a backtick, or `$(...)`.
- **Where does the banner run?** I confirmed by byte-placement that the banner sits **after**
  the guard's closing `fi` and its `exit "$_husk_rc"` (guard lines 182-183, banner 184+). On
  the first (uncaged) pass the guard re-execs and `exit`s before reaching the banner; the
  banner is reached only on the second pass, **inside** the cage. So even a triggered
  injection executes caged — a further reason the ceiling is low.

CONFIRMED mechanism, **LOW** (latent robustness/defense-in-depth, not an agent escape). Fix
is trivial and worth doing: keep `sh_quote`'s output, or interpolate the raw path inside a
literal single-quoted wrapper rather than a double-quoted echo.

---

## F-B5-5 — cleanup misses the `.tmp` intermediates — CONFIRMED (omission), LOW; overlaps B1

### What I did

Cleanup globs (`policy.rs:924-926`): `rm -f req-*.json resp-*.json` then `out-* err-*`, then
`rmdir`. The transient names actually created in the step spool are:
`.resp-<id>.json.tmp` (broker `write_atomic`, `spool.rs`, `.{name}.tmp`) and
`req-<id>.json.tmp` (srun-stub.py:57, `{path}.tmp`). Neither matches `req-*.json` /
`resp-*.json` — the trailing `.tmp` defeats `*.json` and the leading `.` defeats `req-*`.

I planted `req-abc.json.tmp` and `.resp-abc.json.tmp` in the step spool and ran the guard to
normal completion: the globbed `rm` skipped both, `rmdir` failed, the directory survived, and
the guard printed `husk: kept <spool> - it still holds: req-abc.json.tmp .resp-abc.json.tmp`.

### Could the cited completeness test catch it? (protocol rule 7)

No. `every_file_the_guard_creates_in_its_own_directories_is_cleaned_up` (`policy.rs:1705`)
derives required names from two sources only: `step.rs` `spool.join(format!("…"))` literals
(→ `resp-{id}.json`, `out-{id}`, `err-{id}` — all covered by the existing globs) and files
the **guard shell** creates. The `.tmp` transients are created inside `write_atomic` and by
the **python stub**, neither of which the test models — so the test passes and *cannot* fail
on this. Confirmed the test gap.

### Verdict & severity

CONFIRMED omission, **LOW**. The leak requires a writer (broker or stub) to die in the tiny
create-tmp→rename window, and the guard **reports** the kept directory (not silent), so the
worst case is a stranded directory in the user's project, announced. It is genuinely the
"a cleanup that enumerates is a denylist" shape and belongs primarily to **B1**; noted here
because the brief asked whether the cleanup names every resource on every exit path. (Broader
observation for B1: the step spool is bound *writable* into the cage and `HUSK_STEP_SPOOL` is
exported, so the caged job can drop *any* unmatched name there and make `rmdir` fail — the
`.tmp` case is the husk-authored instance of that general property.)

---

## Deliverable 2 — auditability

I concur with a **sharpened** version of the finder's split verdict, reached from my own
work: **read the goldens, not the `format!` string.** Two independent facts from this triage
support it:

1. **The generator forces simultaneous tracking of three quoting levels**, and I hit it
   directly: to predict the F-B5-3 banner injection I had to reason about `sh_quote` (adds
   `'...'`) → `.trim_matches('\'')` (removes them) → a hand-written `"..."` echo, layered
   under Rust `\"`-escaping and `format!` brace-doubling (`${{SLURM_JOB_ID:-nojob}}` is a
   literal, `{workdir_q}` is a substitution). And the block uses **two** rendering strategies
   — `format!` for the outer guard/`net_start`, a raw string + `.replace("{caged_socat}",…)`
   for `net_relay` — so `{caged_socat}` is a placeholder in one block and would be a literal
   in the other. You cannot read the `format!` string and know the emitted bytes; I only
   trusted my claims after regenerating and executing.

2. **The two CRITICAL findings are invisible in both the `format!` string and the goldens.**
   F-B5-1 and F-B5-2 are not about any byte of the guard — they are about how an interpreter
   parses the body/shebang concatenated *around* the guard. The goldens pin the guard's bytes
   exactly and say nothing about `{head}{guard}{tail}` assembly. A typed shell builder retires
   the F-B5-3 quoting family and makes a rewrite checkable against the goldens ("prove the
   bytes are identical"), but it would **not** have caught F-B5-1, F-B5-2, or F-B5-4 — those
   are semantic (which interpreter runs; which lines precede the guard; which signals are
   trapped), independent of how the string is built.

So: the **emitted** artifact is auditable and is well-exercised (goldens + `HUSK_UPDATE_GOLDEN`
+ `bash -n` + run-against-stub tests); the **generator** is not reliably auditable by reading,
and the project's own bug history is the proof. Adopt the typed builder to retire the quoting
class and make rewrites verifiable — but the serious findings in this shard need the
*structural* fix (below), not a builder.

---

## The structural conclusion (F-B5-1 ∧ F-B5-2 ∧ B6-F1)

All three are one defect: **husk's compute containment is a re-exec guard injected into the
agent's own script and handed to sbatch by path.** That makes the guard a property of *a file
something later opens/execs by path*, layered around agent bytes — not a property of the
*execution*. It therefore holds only if the file is unchanged after validation (B6-F1 breaks
this via a rename race), executed by the intended interpreter from line 1 (F-B5-1 breaks this
via the shebang), and free of executable content before the guard (F-B5-2 breaks this via the
whitespace differential). The hypothesis in my brief **holds**.

**One structural change closes all three:** submit husk's **own fixed wrapper** as the batch
entrypoint (husk's shebang, husk's bytes, cage-first by construction) and have that wrapper
consume the agent body as **data inside the cage** (bind the snapshot read-only, `exec bash`
it after entering bwrap, or feed it on a controlled fd). Then the interpreter is husk's
(F-B5-1 gone), no agent bytes precede the cage (F-B5-2 gone), and a body-file swap is read
*after* the cage is established, yielding a caged body rather than an uncaged job (B6-F1
neutralised). The per-finding fixes — validate/force the shebang, split on the shell's
`<blank>` rule — close F-B5-1 and F-B5-2 but leave B6-F1 open; only the structural change
retires the class. This is the single highest-leverage fix in the review and should be
decided with all three triage results in hand.

## Gaps / not reached

- The one genuinely hardware-gated item is the `env -S` splitting in F-B5-1 (coreutils
  version on Balfrin/Santis); the exact submit-through-husk command is in that section. F-B5-2
  needs no hardware. Everything else was settled on the laptop.
- Deliverable-1's "held up" checks (agent cannot set `UENV_*`/partition/account; sbatch-argv
  values never reach a shell) were spot-checked against `session.rs` (reads the broker env)
  and the forced-argv dry-run, and I concur they hold — but they are null results, not
  findings to triage, so I did not exhaustively re-derive them.
