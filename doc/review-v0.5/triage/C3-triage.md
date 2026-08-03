# C3 triage — agent neutrality (pass 2)

**Code-only, laptop, no cluster. No source file was modified.** Every claim below was
re-derived from the files; where a claim could be settled by running something, it was run
(`cargo test --offline` in `slurm-broker/broker`, `python3` against the shipped config).

## Two severity scales, deliberately kept apart

The brief for this pass insists on the distinction, and it matters more here than in any
other C-workstream file: almost everything C3 found is a **cost that lands in a future
roadmap step**, not a hole in the system as installed. Mixing the two would let a real but
purely prospective coupling borrow the urgency of a live defect.

- **SHIPPED** — a security property of husk as installed today, with Claude, on CSCS.
- **6b COST** — work that adding a second agent would require, or a control that would
  silently stop applying to it. Zero exploitability today.

## Summary

| ID | outcome | SHIPPED | 6b COST | one line |
|---|---|---|---|---|
| F1 | **CONFIRMED** | LOW–MED | MED | Every link verified, including the shipped-default claim — but the phenomenon is documented residual **AV7**, and the genuinely new part is that the control the threat model credits for AV7 is **inert in the default install**. |
| F2 | **CONFIRMED** | LOW | MED–HIGH | `AUTO_EXEC_DIRS` really is a four-name denylist applied per writable root; narrowing: `$HOME`-level dirs of *any* agent are already covered by the `/users` floor, so the exposure is project-level dirs only. |
| F4 | **CONFIRMED**, with precisions | MED | HIGH | True: on login, husk implements no filesystem boundary of its own. Precise: it *does* implement two other kernel boundaries; and "a prompt" applies to `sandbox.filesystem`, not to `permissions.deny`, which hard-blocks (in-process). Already dispositioned in husk's own docs as "structural". |
| F3 | **RECHARACTERISED** | LOW | HIGH | The fact (no husk-owned policy source) is right. The failure-direction analysis is half wrong: the **deny** keys fail OPEN, not safe. A fix built on "it fails safe, just quietly" would be built on a false premise. |
| F5 | **CONFIRMED** | LOW | MED | Vendor binary, hash-pinned, on the login enforcement path. Overlaps C1. |
| F6 | **RECHARACTERISED** | LOW | LOW–MED | The vendor-driven decision is real, but "not a test" is false — `cage.rs` isolates and tests it. The true defect is that the **login wrapper does not use the tested function**; it re-formats the map inline. |
| F7 | **RECHARACTERISED** | LOW | MED | One genuine vendor coupling (the AF_UNIX deferral), not three — `capset`/`mount`/`pivot_root` are unblocked for **husk's own** bwrap on compute too. And the kill-precedent is an unconfirmed hypothesis, not a record. |
| F8 | **CONFIRMED** | NONE | LOW | Four literal `claude` sites in the generated launcher; every layer below it is already neutral. |
| F9 | **CONFIRMED** | — | MED | Column 3 is empty: no vendor API host anywhere in shipped config; `netallow` governs compute egress only. **Overlaps C2** — flagged, not resolved. |
| F10 | **UNRESOLVED — NEEDS HARDWARE** | ? | ? | The nesting half is strongly implied by daily use; the *functional-dependency* half is genuinely open. Exact command below. |
| F11 | **CONFIRMED** | NONE | MED | `MANAGED_KEYS` + the uninstall manifest are vendor-schema-specific with no branch for a second agent. |
| — | **acceptance-test tally: partly REFUTED** | — | — | "13 couplings across 8 files" is not reproducible from the finder's own table (I count **20 R-rows across 9 files**), and "44 tracked files" matches no slice of `git ls-files` (97 / 67 / 52). The *direction* — fails, and not narrowly — holds. |
| — | **counter-list: CONFIRMED but for one clause** | — | — | `rank.rs`, both stubs and eight other broker modules have zero hits (verified). The one overstatement: the compute mount-table construction **does** emit a hardcoded vendor string. |

---

## F1 — `STRIPPED_SUBMIT_ENV` is a four-name denylist — **CONFIRMED**

### What I did

Read the four cited sites end to end and checked each link independently rather than as a
chain:

1. `slurm-broker/broker/src/spool.rs:391-396` — the constant is exactly the four names
   quoted. ✅
2. `spool.rs:398-404` — `run_sbatch` builds the `Command` and calls `cmd.env_remove(k)` for
   each; nothing else touches the child environment, so everything else in the broker's env
   is inherited. ✅
3. `--export=ALL` is forced unconditionally at `slurm-broker/broker/src/policy.rs:257`,
   on both the uenv and no-uenv branches, and outranks a body `#SBATCH --export` (F24). ✅
4. **The shipped-default claim — the one the brief asked me to try hardest to break.**
   Verified twice, structurally rather than by eye:

```
$ python3 -c "import json; c=json.load(open('user-config/settings.json')); \
print(list(c['sandbox']), 'credentials' in c['sandbox'])"
['enabled', 'autoAllowBashIfSandboxed', 'allowUnsandboxedCommands', 'filesystem', 'network'] False
```

   and a tree-wide search for any other source of a default set:
   `git ls-files | xargs grep -l credentials` — the only hits in installable config are
   `user-config/settings.json:59-64`, which are `Read()/Edit()` *file* globs in
   `permissions.deny`, not `sandbox.credentials`. `install-husk.sh` and
   `scripts/merge-claude-settings.py` never synthesise one: the merge copies
   `user_config["sandbox"]` verbatim and adds only `sandbox.seccomp.applyPath`
   (`merge-claude-settings.py:78-80`). **The finding does not collapse.** With no
   `sandbox.credentials` block, `CredentialsCfg` deserialises to its `Default`
   (`settings.rs:398-405`), `unset_env` is empty (`settings.rs:433-440`), and the
   `--unsetenv` loop at `settings.rs:806-810` emits nothing.

5. Corroborated on generated output rather than by reading: the committed golden guard
   (`tests/golden/guard-net-off.sh:95`) contains no `--unsetenv` at all, and
   `cargo test --offline golden` passes, so that fixture is what today's generator emits.

### What is wrong with the framing, and it changes the severity

**This is documented, accepted residual AV7**, in husk's own threat model, with the same
remedy already written down:

- `slurm-broker/THREAT-MODEL.md:476` — *"an un-declared secret env var is residual on every
  submission"*, status **partial**.
- `THREAT-MODEL.md:510-514` — under *Residual / accepted risks*, ending *"consider a vetted
  baseline env allowlist later"*.
- `policy.rs:255-256` says it inline, at the site: *"(AV7 caveat: env secrets NOT listed in
  credentials.envVars still reach the caged, network-off job — widen that list to mask.)"*

The finder does not mention AV7 once, which leaves the reader with a discovery where there
is a known ledger entry. Second, the **exploitability today is narrow**, for a reason the
finding's own neighbour findings establish:

- The confined agent **already holds the login environment** — the launcher is
  `exec seccomp-wrapper claude "$@"` with no scrubbing (F9's own point: husk does not own
  the login env). So forwarding `OPENAI_API_KEY` to a compute job discloses nothing *to the
  adversary* that `/proc/self/environ` did not already give it.
- The compute job is `--unshare-net` by default (`settings.rs:813`), and with egress enabled
  the allowlist is default-deny by host **and** port (`netallow.rs`, verified by
  `an_empty_allowlist_permits_nothing`). There is no general exfil route.

So the real loss is **blast radius, not disclosure**: the secret travels to slurmd's copy of
the job environment and onto a compute node, where it is visible to anything that inspects a
running job. That is precisely the argument the module comment makes for stripping
(`spool.rs:375-380`), and it is a hygiene property, not a containment one.

### The part that is genuinely new, and that I would act on

`THREAT-MODEL.md:476` credits AV7's defence as *"F4 (`--unsetenv` of declared
`credentials.envVars`)"*. **In the default install nothing is declared, so the credited
control emits zero arguments.** The threat model reads as if two mechanisms cover AV7 when
one of them is inert until an operator writes a block that no shipped file, README example
or test demonstrates. That is the finding: not "a denylist exists" but "the declared-set
half of a documented two-part control is empty out of the box, and the threat model does not
say so."

One correction to the finder's re-runnable-test note: `spool.rs:469-486` does not "assert the
opposite". It pins the four names as *required members* and pins `ANTHROPIC_BASE_URL`/
`ANTHROPIC_MODEL` as *required non-members*; it is silent on any other name, so it obstructs
nothing. A useful arm would assert a property of the **shipped config** — e.g. that
`sandbox.credentials.envVars` is non-empty, or that `FsPolicy::resolve` over the shipped file
yields a non-empty `unset_env`. No test in the tree reads the shipped config for anything
except `denyWrite` (`settings.rs:946-981`).

### Severity

**SHIPPED: LOW–MEDIUM.** Documented residual; no new disclosure to the adversary; no exfil
route by default. The residue is real (secrets reaching slurmd and the compute node) and is
worth closing, but it is hygiene.
**6b COST: MEDIUM.** A second agent's token spelling is not on the list, and nothing would
report it.

---

## F2 — `AUTO_EXEC_DIRS` masks one vendor's config directory by name — **CONFIRMED**

### What I did

- `settings.rs:131-136` — the constant is the four names quoted. ✅
- `settings.rs:748-772` — the application point. I checked the *set it iterates over*, which
  is the load-bearing half the finding asserts without showing:
  `writable_roots` = the workdir (when absolute) **plus every `allowWrite` root**
  (`settings.rs:752-760`), and for each root it pushes `--tmpfs <root>/<rel>` for all four
  names. So the mask really does apply inside every writable region, and really is keyed on
  four literals. ✅
- Generated evidence, re-verified rather than quoted: `cargo test --offline golden` passes,
  so `tests/golden/guard-net-off.sh:95` is current output. It contains
  `'--tmpfs' '/work/project/.claude' '--tmpfs' '/work/project/.git/hooks' '--tmpfs'
  '/work/project/.vscode' '--tmpfs' '/work/project/.idea'` and nothing else agent-shaped. ✅
- `AUTO_EXEC_RO_FILES = [".mcp.json"]` at `settings.rs:145`, applied at `767-772`. ✅
- The writable roots are guaranteed to be **outside** `$HOME`: `HIDDEN_FLOOR = ["/users"]`
  (`settings.rs:18`) is tmpfs'd unconditionally and `is_workdir_allowed`
  (`settings.rs:290-298`) refuses a workdir under the floor. So writes into the cage's
  writable set genuinely do persist to the real filesystem when the job ends.

### Two corrections, one narrowing and one widening

**Narrowing (reduces the finding).** A second agent's `~/.codex`, `~/.aider`, `~/.gemini`
is **not** exposed: `--tmpfs /users` hides every home directory on CSCS regardless of
config, and that floor is agent-neutral. The exposure is confined to a *project-level*
config directory inside the workdir or an `allowWrite` root. That is still a live AV2 path —
the agent's next login session runs in exactly that project directory — so the vector holds,
but the finding as written implies a wider surface than exists.

**Widening (adjacent, and not mine to resolve).** The mask is applied only at the **top
level** of each writable root. `<workdir>/subproject/.claude` is not masked, for the agent
husk actually ships with. `THREAT-MODEL.md:471` acknowledges the sibling case
(*"nested-repo `.git` is a refinement"*), so this is known, but it is a **shipped-system**
AV2 gap rather than a 6b one, and it is B-series mount-table territory. **Flagged, not
resolved** (protocol rule 3).

### On the finder's proposed test

Correct, and stronger than they claim: the *existing* AV2 arms are themselves a denylist.
`selftest.sh:1117-1118` and `1565-1574` plant `.claude/settings.local.json`,
`.claude/skills/evil.md`, `.claude/hooks/evil.sh`, `.git/hooks/post-checkout` and assert none
reached the host. Those arms *could* fail (they read the host filesystem after a real job),
so they are not vacuous — but every path in them is drawn from the same four literals the
code masks, so the test and the code share one list and one blind spot.

### Severity

**SHIPPED: LOW.** Only one agent is installable today and its directory is masked. The
nested-directory gap above is a separate, higher item that belongs to another brief.
**6b COST: MEDIUM–HIGH.** This is a *security mask* keyed on a vendor string, not a
convenience. Adding a second agent reopens AV2 for it silently, and no arm in the suite would
notice.

---

## F4 — the login-side filesystem boundary is implemented by the confined party — **CONFIRMED**, with three precisions

This is the review's most consequential architectural claim, so I tried to break it from
three directions: does husk enforce anything filesystem-shaped of its own on login; is
`constraints.txt` still current; and is "a prompt" the right word.

### 1. Does husk implement *any* login-side boundary of its own? Yes — two, and neither is filesystem.

I read the whole login path rather than trusting the summary:

- `slurm-broker/broker/src/bin/husk-slurm-wrapper.rs` — the only namespace work is
  `enter_user_mount_ns()` (292-301: `CLONE_NEWUSER|CLONE_NEWNS`, identity map) followed by
  `bind_file(stub, sbatch)` + a dev/ino read-back (`SandboxReady::establish`, 262-274) and
  the best-effort shadows at `374-386`. **There is no `--tmpfs`, no `ro-bind`, no `/users`
  mask, nothing path-shaped.** The mount namespace exists to hold the stub binds.
- `seccomp-wrapper/src/seccomp_wrapper.c` — a syscall deny-list. The only entries with a
  filesystem flavour are `open_by_handle_at`/`name_to_handle_at` and `chroot`
  (166-171), which close *escape primitives*; nothing restricts a path.

So husk's own kernel-enforced controls on the login node are (i) the seccomp floor over the
whole session and (ii) a mount namespace whose entire content is read-only stand-ins for the
SLURM binaries. **The filesystem boundary is not among them.** The finding is right, and the
qualifier it already carries ("filesystem", "on the login node") is the correct one.

### 2. Is the source still current? Yes, and the project says it more strongly elsewhere.

`doc/constraints.txt:100-108` says what the finder quotes, verbatim, including
*"These run OUTSIDE bwrap entirely and bypass its filesystem restrictions"* and *"cause
Claude Code to PROMPT the user before proceeding, but do not hard-block access"*, with the
summary table at `110-116`. Two independent corroborations in the same tree:

- `doc/threat-model.txt:51-74` splits the agent's three execution paths and states the
  native-tool path is *"subject to `permissions.deny` patterns and per-call user prompts"*,
  then at `72-74`: *"A claim like 'H2 is defended by bwrap denyRead' is true for the bash
  path; partial for the native-tool path; FALSE for the SLURM path."*
- `doc/context.txt:310-330` dispositions it: **"Disposition: structural"**, to be resolved
  when file tools become sandboxable subprocesses.

So F4 is not a discovery. It is husk's own documented, dispositioned design state, restated
in the vocabulary of the axiom. That is worth doing — the reframing is the finding's value —
but it should not be scored as an unknown.

### 3. "A prompt" is right for one of the two layers, and the distinction is load-bearing

The vendor enforces husk's login policy through **two mechanisms with different strength**,
and the finding flattens them:

| policy husk writes | who enforces | strength, native tools | strength, Bash |
|---|---|---|---|
| `sandbox.filesystem.{denyRead,allowRead,denyWrite}` | vendor runtime | **advisory — prompts** (`constraints.txt:100-108`) | kernel (bwrap; EROFS confirmed, `constraints.txt:90-96`) |
| `permissions.deny` globs | vendor runtime | **hard block, in-process** (`context.txt:315-322`, confirmed on Santis) | n/a |

The crown jewels are on the second row on purpose: `user-config/settings.json:37-40` denies
`Edit()` of the three settings files and of `~/.local/lib/husk/**`, and `41-80` denies
`Read()`/`Edit()` of the secret globs. `constraints.txt:118-125` states the reasoning —
*"the agent cannot ask the user to approve, so there is no approval prompt to
social-engineer."* So the accurate sentence is:

> For the agent's native file tools, the `sandbox.filesystem` boundary is advisory and
> defeasible by a human answering a prompt; the `permissions.deny` layer does hard-block, but
> it is an **enumerated** list enforced **inside the confined process**, so it is neither a
> kernel boundary nor a default-deny one.

Both halves are still the confined party's own code. The residual after the mitigation is:
anything under `/users` that is not matched by an enumerated glob is reachable by a native
`Read` with one human "yes". And husk's own threat model rules that control out of bounds —
`doc/threat-model.txt:48-49`: **"Inattentive: the user. Controls must not depend on careful
human review of each prompt."** That contradiction between the stated trust assumption and
the shipped mitigation is the sharpest true statement in this finding, and the finder did not
make it.

### Severity

**SHIPPED: MEDIUM.** Documented and dispositioned; partly mitigated by a deny layer that is
confirmed to hard-block; but the residual conflicts with the project's own stated
inattentive-user assumption, and the mitigation is an enumerated list — the shape this
project has repeatedly named as a bug list.
**6b COST: HIGH.** For a second agent there is no boundary to translate, only one to build.
This is 6a's entire content, and it is why the acceptance test is the wrong instrument: a
codebase with zero `claude` strings could delegate its whole boundary and still pass.

---

## F3 — husk has no policy source of its own — **RECHARACTERISED**

**The fact is confirmed.** `SETTINGS_SOURCES` (`settings.rs:278-282`), the serde structs
(`settings.rs:372-418`, `#[serde(rename_all = "camelCase")]`), `resolve()`
(`settings.rs:494-503`), `netallow.rs:289-318`. A tree-wide search for a husk-owned policy
path found only logs: `~/.husk/log` (`lib.rs:282-294`, `husk-slurm-wrapper.rs:207-224`,
`policy.rs:846-847`). There is no `husk.toml`, no `~/.husk/policy.*`, no partial step.

**The failure-direction analysis is half wrong, and that half is what a fix would be built
on.** The finder writes that renaming a `filesystem`/`credentials`/`network` key *"fails
SAFE… The compute cage gets tighter, silently."* Only the allow-side does:

| vendor renames | effect on the compute cage | direction |
|---|---|---|
| `allowRead` / `allowWrite` | carve-outs vanish; only the workdir bind and the floor remain | **tighter — safe** |
| `network.allowedDomains` | empty allowlist permits nothing (`an_empty_allowlist_permits_nothing`) | **tighter — safe** |
| `denyRead` | the `--tmpfs` hides at `settings.rs:661-697` and `739-746` vanish; the cage is `--ro-bind / /`, so everything the user can read is readable again, bounded only by `HIDDEN_FLOOR=["/users"]` and unix perms | **looser — fails OPEN** |
| `denyWrite` | the read-only re-binds at `settings.rs:725-731` vanish; paths the operator marked read-only inside a writable root become writable | **looser — fails OPEN** |
| `credentials.*` | `deny_files` `/dev/null` binds and `--unsetenv` vanish | **looser — fails OPEN** (already empty by default, see F1) |

So the correct statement is: **allow-side and network fail closed; deny-side fails open** —
silently in both directions. "Silent but safe" would justify deferring; "silent and open for
half the keys" argues for a canary now (e.g. assert that parsing the shipped config yields a
non-empty `deny_read`). Severity **SHIPPED: LOW** — the vendor schema is stable and the floor
plus `--ro-bind / /` bound the damage; **6b COST: HIGH** — this is 6a deliverable (i).

---

## F5 — vendor binary on the enforcement path — **CONFIRMED**

Verified at the exact sites: `install-husk.sh:188` (`SANDBOX_RUNTIME_VERSION="0.0.49"`), `194`
(npm URL), `205` (pinned SHA-512), `289-296` (download, `sha512sum -c` with a hard abort on
mismatch, `tar -xzOf package/vendor/seccomp/${ARCH}/apply-seccomp`, `install -m 0755` into
`$PREFIX/lib/husk/apply-seccomp`), and wiring at `install-husk.sh:505-506` →
`merge-claude-settings.py:78-80` (`sandbox.seccomp.applyPath`).
`seccomp_wrapper.c:55-61` is the deferral that makes it load-bearing on login.
Supply-chain integrity is handled (hash-pinned, fail-hard). **SHIPPED: LOW. 6b COST: MEDIUM.**
Whether `apply-seccomp` is enforcement or telemetry is **C1's question — overlap flagged, not
resolved.**

---

## F6 — the identity uid-map — **RECHARACTERISED**

The vendor-driven decision is real and documented verbatim at
`husk-slurm-wrapper.rs:277-301`. But the finding's closing claim — *"nothing records the
constraint as a constraint. It is a comment on one function, not a test"* — **does not
survive.** `slurm-broker/broker/src/cage.rs:99-108` separates `identity_map()` from the
syscall path with the stated reason *"so the one rule that must never regress is testable"*,
and `cage.rs:243-256` (`the_map_is_an_identity_map_and_never_a_root_map`) asserts
`inside == outside`, count 1, and explicitly `assert_ne!(identity_map(1000), "0 1000 1")`.

The true defect is sharper and is the project's own recurring failure mode: **the login
wrapper does not call that function.** `husk-slurm-wrapper.rs:298` writes
`format!("{uid} {uid} 1\n")` inline — the module keeps a deliberate zero-dependency audit
surface (header, 23-24) and imports only four consts from the lib. So the one tested
invariant covers the *compute* cage, while the path where the bug actually bit is a second,
untested copy. The test could not fail on a wrapper regression.

**SHIPPED: LOW** — both copies are currently correct, and a regression fails loudly
(every Bash command dies), so it is a liveness rather than a containment risk.
**6b COST: LOW–MEDIUM.**

---

## F7 — the seccomp floor is agent-calibrated — **RECHARACTERISED**

Confirmed: the header does say *"a deny-list for syscalls a Claude Code agent provably does
not need"* (`seccomp_wrapper.c:4-5`), and the action is `SCMP_ACT_KILL_PROCESS` unless
`SECCOMP_WRAPPER_DEBUG=1` (`297-299`).

Two corrections, both reducing the finding:

1. **Three accommodations, or one?** The finder lists `capset` (106-115),
   `mount`/`umount2`/`pivot_root` (153-165) and the AF_UNIX gap (52-62) as vendor
   accommodations. The first two are *widenings that husk needs for its own bwrap*: the
   compute guard runs `seccomp-wrapper --profile=single-node bwrap …`
   (`tests/golden/guard-net-off.sh:95`), where no vendor code is involved at all. They are
   bwrap accommodations, not vendor ones, and they would survive dropping the runtime
   entirely. Only the AF_UNIX deferral is genuinely vendor-shaped — and note it is a
   *non-block*, so it cannot kill anything. **A second agent cannot be killed by any of the
   three.** What could kill it is the *blocked* list (`io_uring_*`, `ptrace`,
   `perf_event_open`, `process_vm_*`, `keyctl`, `bpf`), which is generic hardening and names
   no vendor.
2. **The precedent is a hypothesis, not a record.** `resume-probe.sh:4-10` reads *"Leading
   hypothesis … prime suspect io_uring"* and the script's whole purpose is *"checks whether
   v0.4 still reproduces it and, if so, confirms the seccomp filter is the cause"*. Nothing
   in the tree records a diagnosed SIGSYS kill of the current agent. Calling it *"strong
   precedent rather than speculation"* overstates it by one full step.

What remains, and is true: the floor's *justification* is written in one agent's name, the
failure mode is an unattributed process kill, and the AF_UNIX policy on login is the
vendor's granularity rather than husk's. **SHIPPED: LOW. 6b COST: MEDIUM.**

---

## F8 — column 1 is hardcoded — **CONFIRMED**

Four literal `claude` sites in the generated launcher heredoc, not three:
`install-husk.sh:372` (preflight `command -v claude`, with messages at 373-375), `419`, `427`,
plus the post-install message at `527-533`. The counter-claim is right and is the interesting
half: `husk-slurm-wrapper.rs:86,147-151` takes the agent as `Vec<String>` after `--` and
defaults to `"husk"`; `exec_agent`/`exec_plain` (311-338) are generic; `seccomp_wrapper.c:549`
is `execvp(cmd[0], cmd)`. Everything under the launcher is already neutral.
**SHIPPED: NONE. 6b COST: LOW** — this one is a variable.

---

## F9 — column 3 does not exist — **CONFIRMED**

`user-config/settings.json:21-25` allows exactly one host
(`opendatadocs.meteoswiss.ch:443`); no vendor API host appears anywhere in shipped config.
`netallow.rs:289-318` reads `sandbox.network.allowedDomains` for **compute-job** egress, and
`spool.rs:388-390` states the login gap in the code itself. Worth adding: the same key is
also consumed by the vendor runtime for the *Bash* path on login, so the login allowlist
exists but structurally cannot cover the agent process, which is not inside bwrap.
**Overlaps C2 — flagged, not resolved.** **6b COST: MEDIUM.**

---

## F10 — nesting and the functional-dependency question — **UNRESOLVED — NEEDS HARDWARE**

Two halves, and they are not equally open.

- *Can the vendor's inner bwrap start nested inside husk's outer userns?* Strongly implied by
  daily use — the shipped launcher is `husk-slurm-wrapper … -- seccomp-wrapper claude`, and
  caged agent sessions have run on Balfrin. But **no arm asserts it**, and the probe that
  would has an explicit `INCONCLUSIVE` branch for exactly this failure
  (`verify-sbatch-inheritance.sh:105-108`).
- *Is the vendor's per-command sandbox a security layer or a functional dependency?*
  Genuinely open; `ROADMAP.md:153` records it as an open question.

**What would settle it** — Balfrin (or Santis) login node, husk installed, `claude` signed
in, **not** inside an existing husk session:

1. `bash slurm-broker/verify-sbatch-inheritance.sh` → read the verdict line. `PASS` settles
   the first half affirmatively (stub inherited **and** inner bwrap started nested);
   `INCONCLUSIVE` with a `bwrap|namespace|user namespace` match settles it negatively.
2. For the second half, run one husk session and exercise both tool paths (a `Bash` command
   and a native `Read`) with the vendor sandbox disabled — i.e. `sandbox.enabled: false` in a
   scratch `HOME` — and record whether the agent still functions. If it does, the
   per-command sandbox is a layer; if it does not, it is a dependency and 6a must replace a
   *functional* component, not only a security one.
3. While there: `bash slurm-broker/resume-probe.sh` settles F7's io_uring precedent. Read the
   exit code — **159 = 128+31 = SIGSYS = husk's filter**; any other non-zero is not.

---

## F11 — the install mechanism is agent-specific — **CONFIRMED**

`merge-claude-settings.py:23` (`MANAGED_KEYS`), `78-80`, `95-108` (wholesale overwrite of the
three keys, pre-install values recorded once into the manifest), reversed by
`install-husk.sh:103-110` against `~/.claude/settings.json` specifically. No branch, flag or
variable anywhere for a non-Claude install; `install-husk.sh:29-30` states the prerequisite.
Correctly kept separate from F4 — F4 is what enforces, this is what the installer writes.
**SHIPPED: NONE. 6b COST: MEDIUM.**

---

## The acceptance test's own arithmetic — partly REFUTED

The brief asked me to spot-check the count rather than accept it. It does not hold up:

- **"Scope = the 44 tracked husk files"** matches nothing: `git ls-files` is **97**; **67**
  excluding `doc/review-v0.5/`; **52** excluding all docs and `*.md`.
- **"9 of 44 tracked files"** — by my count **14 of 52** non-doc tracked files contain
  `claude`/`anthropic` case-insensitively (`install-husk.sh` 56 lines,
  `settings.rs` 13, `spool.rs` 10, `seccomp_wrapper.c` 9, `resume-probe.sh` 9,
  `selftest.sh` 9, `verify-sbatch-inheritance.sh` 7, `user-config/settings.json` 6,
  `merge-claude-settings.py` 3, `netallow.rs` 2, `policy.rs` 1, both golden fixtures 1 each,
  `discover-writable-spool.sh` 1) — **128 lines**, not ~100.
- **"13 shipped-code couplings across 8 files"** is not reproducible from the finder's own
  table: I count **20 rows classed `R` across 9 files** (`install-husk.sh`,
  `merge-claude-settings.py`, `user-config/settings.json`, `project-config/settings.json`,
  `settings.rs`, `netallow.rs`, `spool.rs`, `husk-slurm-wrapper.rs`, `seccomp_wrapper.c`).
  The headline **understates** its own evidence.

The numbers are wrong in the direction that does not flatter the finder, and the
classification — which is what a re-runnable test would encode — is sound. **The verdict
"husk fails the acceptance test, and not narrowly" stands; the tally should not be quoted.**

## The counter-list — CONFIRMED except one clause

Verified by grep over the whole broker source: `rank.rs`, `sbatch-stub.py`, `srun-stub.py`,
`profile.rs`, `step.rs`, `main.rs`, `session.rs`, `cage.rs`, `sbatch.rs`, `srun.rs`,
`netproxy.rs`, `protocol.rs` — **zero** `claude`/`anthropic` hits, case-insensitive. The
`rank.rs` exemplar earns the brief's praise: `RESERVED_ENV_PREFIXES` refuses by namespace,
`PROXY_ENV` by category, `is_valid_env_name` by charset.

The one overstatement, which the parent brief was right to ask about: *"The compute cage's
construction — `settings.rs:597-815`, `policy.rs`, `profile.rs` — … does not consult the
agent's identity anywhere."* `settings.rs:763` sits inside that very range and emits
`--tmpfs <root>/.claude` for every writable root; the generated mount table in
`tests/golden/guard-net-off.sh:95` carries the vendor string literally. The finding's next
sentence concedes it (*"`AUTO_EXEC_DIRS` and `SETTINGS_SOURCES` are the only vendor strings
that reach it"*), so this is an internal inconsistency rather than a false claim — but as
written the first clause would let a reader conclude the compute mount table is vendor-free,
and it is not.

## Not reached

Nothing in the findings file was skipped. The assumption analysis (sections 1–5) was checked
only where a finding rests on it; two incidental claims I verified in passing and did not
promote to findings: the `$HOME`-unset edge (`main.rs:302,423,463`, `policy.rs:363` all use
`unwrap_or_default()`, so an empty `$HOME` turns the global settings layer into a
cwd-relative read — harmless because `union()` dedups and the cwd is the broker's trusted
launch directory, not an agent-supplied path), and `settings.rs:946-981`'s early `return` on
a missing shipped config, which I confirmed does **not** make the test vacuous in this
checkout — the file resolves and the test runs (`cargo test --offline
settings_sources_are_all_write_denied` → 1 passed).
