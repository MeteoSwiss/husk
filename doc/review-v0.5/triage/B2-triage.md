# B2 — is any denial path unattributed? (triage, pass 2)

**Instrument:** code-only, this laptop. `HEAD = 6c4e75f` (no source file has changed since pass 1's
`1fe34c8`; the only commits since are review documents — `git diff --stat 1fe34c8..HEAD` touches
`doc/review-v0.5/` and nothing else).

**Binary:** rebuilt from source and invoked by absolute path throughout —
`slurm-broker/broker/target/release/husk-slurm-broker`, sha256 `3eb0eb86…`. The gitignored prebuilt
`slurm-broker/husk-slurm-broker-x86_64` is sha256 `ff686aff…` and was **never used**; the two differ,
so the stale-binary trap was live.

**Method.** Every message below was produced by running that binary, not read off the source:
45 sbatch-side requests, 20 step-side requests, a live `--net-proxy` over a real unix socket, a real
`bwrap` cage (0.6.1, kernel 6.8) for the mount-behaviour claims, and a fake `sbatch` on `PATH` for the
one path pass 1 could not reach. Harnesses in the session scratchpad: `drive.sh`, `batch.py`,
`batch2.py`, `step.py`, `f6.py`, `f12.sh`, `f13.sh`, `f5.sh`, `stability.sh`, `order.sh`.

---

## Summary

| ID | outcome | my severity | one line |
|---|---|---|---|
| **F1** | **RECHARACTERISED** | **HIGH** | The impossible remedy is real and verified; but the harm arrives by a different and worse route — the parse error is swallowed at *submit* time, so the proxy is never started and nothing is reported to anyone. |
| **F10** | **RECHARACTERISED** | **HIGH** (banner) / MEDIUM (docs) | The banner's false claim is confirmed against the mount table from the same call, with a fourth carve-out the finder missed. The *silence* claim holds for only one of three cases: masked dirs return **ENOENT** and credential files return **EACCES**, not empty reads. |
| F4 | CONFIRMED | MEDIUM | Three unattributed refusals delivered under `sbatch:/srun: error:`; not byte-identical to real SLURM text, but the stub attributes on the accepted path three lines above `die()` and not on refusals. |
| F14 | CONFIRMED | MEDIUM | Zero network announcements in the no-allowlist guard; `--unshare-net` present. |
| F13 | CONFIRMED | MEDIUM | 5 of 6 configured carve-outs silently dropped; nothing in the session log. |
| F15 | CONFIRMED | MEDIUM | `grep` finds the writable-set banner only inside a compute job; the login side has no equivalent anywhere. |
| F5 | CONFIRMED (upgraded from PLAUSIBLE) | MEDIUM | Reproduced without a cluster. Worse than stated: the forced argv is logged nowhere on the live path, so the session log the stub points at does not contain it either. |
| F2 | CONFIRMED | MEDIUM | A `--chdir` that only needs `mkdir` is reported as a confinement violation naming its own parent as writable. |
| F12 | CONFIRMED | MEDIUM-LOW | Oversize head and 15 s timeout both return 0 bytes; the trusted-side log for the timeout prints a raw `EAGAIN`, not the cap. |
| F3 | CONFIRMED | LOW-MEDIUM | husk's own rule attributed to SLURM. Plus: the message carries a 14-space run from a broken string literal (4 messages affected). |
| F7 | CONFIRMED (mechanism) | LOW-MEDIUM | The preemptibility claim is hard-coded and unconditional; whether it is false on Balfrin needs the cluster. |
| F8 | RECHARACTERISED | LOW | The asymmetry is real, but when the failing `srun` sets the job's exit status the job-level translation still fires. The gap is multi-step scripts and the step's own line. |
| F6 | RECHARACTERISED | LOW | Not "four of nine": exactly **two** options reach that message (`--wrap`, `--account`) — and for `--account` the wrong message *displaces* the good one. |
| F11 | RECHARACTERISED | INFO | Within a job — the only scope in which "retry" means anything — the holder pid and job id are constant, so the messages *are* byte-identical. Property 4 is misapplied to fatal faults. |
| F9 | CONFIRMED | INFO | Dead on both registries, verified by probe. |

**Property 4 spot-check: the finder's claim reproduces.** Two independent broker runs in two
directories: all messages and the entire generated guard diff clean. One thing their method could not
catch — see [Property 4](#property-4-i-re-ran-the-diff) below.

**Five additional observations** not in the finder's list, including one I am handing to A9/A1 and one
to B3. See [Additional](#additional-observations-found-while-verifying).

---

## F1 — the 403's remedy is refused, and complying destroys all egress · RECHARACTERISED · HIGH

I verified the chain link by link, because any broken link changes the finding. Three of four links hold
exactly as described. The fourth does not, and the truth is worse.

### Link 1 — does that message really fire for a scheduler port? YES

Real proxy, real unix socket, allowlist = `["example.com", "*.good.example.org"]`, so `example.com`
**is** on the list:

```
$ printf 'CONNECT example.com:6817 HTTP/1.1\r\nHost: h\r\n\r\n' | socat - UNIX-CONNECT:/tmp/hb2/net.sock
HTTP/1.1 403 Forbidden

husk: example.com:6817 is not on husk's network allowlist. Ask your operator to add it to
sandbox.network.allowedDomains if the work genuinely needs it.
```

Identical for 6818, 6819, 6820 and for `slurmctld.cscs.ch:6817`. The mechanism is `netallow.rs:256` —
`SCHEDULER_PORTS.contains(&port)` returns false from `permits()` *before* the entries are consulted —
and `netproxy.rs:196` has one message for every false. **P6 fails as described:** the message states a
cause husk knows is false, since the host is on the list and the port is permanently barred.

A third cause routes to the same text: a malformed request host. `CONNECT a%b.example.com:443` (rejected
by `is_valid_request_host` at `netallow.rs:253`) also produced *"a%b.example.com:443 is not on husk's
network allowlist. Ask your operator to add it…"* — advice an operator could not act on if they wanted
to, since `%` is refused by `Entry::parse` as well.

### Link 2 — does `Entry::parse` really refuse the remedy? YES

The operator complies, adding the string the 403 named:

```
allowedDomains: ["example.com", "*.good.example.org", "slurmctld.cscs.ch:6817"]

$ husk-slurm-broker --net-proxy --socket … --workdir …
husk-proxy: network allowlist entry "slurmctld.cscs.ch:6817": port 6817 is a SLURM daemon port.
A caged job that can reach the scheduler could submit work that never passes the broker (AV8),
which is the bypass husk exists to prevent. Job control goes through the broker.
EXIT=1        # no socket created
```

`Entry::parse` (`netallow.rs:155`–`158`) refuses it, `Allowlist::parse` (`:242`) returns `Err` on the
*first* bad entry, and **the two valid entries are lost with it**. The blast radius is the whole
allowlist, not the one line.

*One qualification the finder does not make.* The harm requires the operator to transcribe the
`host:port` pair. An operator who adds the bare host `slurmctld.cscs.ch` gets a policy that **compiles
fine and still refuses**, because `permits()` re-checks `SCHEDULER_PORTS` unconditionally. That path is
not destructive, but it is a second dead end from the same message: the operator does the thing they
were told and the agent's 403 does not change by one byte. Both outcomes are bad; they are bad
differently, and a fix has to cover both.

### Link 3 — does the proxy exit rather than degrade? YES — but this is not the path that matters

`main.rs:305`–`311` does exit 1, as shown above. But in the ordinary flow **that code never runs**, and
this is where the finder's mechanism is wrong.

### Link 4 — the correction: the error is swallowed at SUBMIT time, and the proxy is never started

`policy.rs:362`–`367`:

```rust
let net_enabled = crate::netallow::Allowlist::resolve(…, project_dir)
    .map(|(a, _)| !a.is_empty())
    .unwrap_or(false);          // <-- the Err, and its explanation, are discarded here
```

With `net_enabled == false`, `wrap_script` takes the `else` branch at `policy.rs:643` and
`(net_start, net_relay)` are both empty strings — **no proxy is launched at all**. So:

* `main.rs:309`'s message never appears, because that process is never started;
* the guard's own "the egress proxy did not bind … within 5s" message (`policy.rs:748`) never fires,
  because nothing was ever waited for;
* the broker's session log says nothing — `.unwrap_or(false)` has no `else` arm.

Demonstrated by generating two guards through the real broker, one with a broken allowlist and one with
**no allowlist configured at all**, and diffing:

```
$ diff <(sed 's|t-broken|ROOT|' out-broken.txt) <(sed 's|t-nonet|ROOT|' out-nonet.txt)
199c199
< broker: husk 0.4.0 session pid 9635 …
> broker: husk 0.4.0 session pid 9645 …
```

The only difference in the entire generated job script is the broker's own pid in its log header. A
broken allowlist and no allowlist are **byte-identical outcomes**. Searching the whole dry-run output
for `slurmctld|allowlist|6817|daemon port|AV8` returns nothing.

The comment sitting directly above `.unwrap_or(false)` justifies the swallow with *"the proxy reports
the error where an operator will see it"*. That is false: when the allowlist does not compile, there is
no proxy to report it. The justification is the inverse of the behaviour.

`main.rs:305` is still reachable — the submit-time resolve uses the trusted `project_dir` while the
guard passes `--workdir "$PWD"` (the forced `--chdir`), so the two can disagree — but that is the
unusual case, not the one an operator will hit.

### Verdict and severity

**RECHARACTERISED.** The finding is real and its first two bullets (P6, P1) are confirmed verbatim. The
third bullet's mechanism is materially different: the job does not lose egress because the proxy exits
with the explanation in the job log; it loses egress because the broker decided at submit time not to
have a proxy, **and the explanation exists nowhere at all**. This matters for the fix — patching
`main.rs:305` would change nothing on the path that actually bites. The fix has to be at
`policy.rs:362`, and it has to produce output.

**HIGH.** Three multipliers over an ordinary message defect: the remedy is not merely useless but
destructive; the destruction is silent on *both* sides of the boundary (agent and operator); and the
denial in question is the one guarding AV8, the bypass this project exists to prevent — so it is the
denial most likely to be argued with and least affordable to misdescribe.

**A7 collision (flagged, not resolved):** any fix that distinguishes "barred port" from "not listed"
tells the job that scheduler ports are specially treated. Hand to A7.

---

## F10 — the cage banner makes a false claim · RECHARACTERISED · HIGH (banner) / MEDIUM (the docs error)

Two halves. The first is confirmed and is larger than stated. The second is largely wrong, and being
wrong about it matters, because it is the half that makes the finding security-relevant.

### Half 1 — the banner text, against the mount table generated from the same call · CONFIRMED, +1

Driving the real broker with a policy containing `allowWrite`, `denyRead` (absolute and relative),
`allowRead` and `credentials.files`, the banner it emits is:

```
export HUSK_WRITABLE='<proj>:<scratchroot>'
husk: compute cage active - the filesystem is READ-ONLY except:
husk:   <proj>  (project dir: where husk was launched)
husk:   <scratchroot>
husk: reads are unrestricted. A write outside the list above fails
husk: with 'Read-only file system' - that is husk, not the filesystem.
```

and the `bwrap` vector in the same generated script is:

```
--tmpfs /users
--tmpfs <scratchpad>/secretdir            # denyRead
--ro-bind <scratchpad>/appsdir …          # allowRead
--bind <proj> <proj>                      # the announced writable root
--bind <scratchroot> <scratchroot>        # the announced writable root
--tmpfs <proj>/private                    # relative denyRead, INSIDE the writable root
--tmpfs <proj>/.claude
--tmpfs <proj>/.git/hooks
--tmpfs <proj>/.vscode
--tmpfs <proj>/.idea
--ro-bind-try <proj>/.mcp.json …
--ro-bind-try <proj>/.git/config …
--tmpfs <scratchroot>/.claude  … (the same five again, per writable root)
--ro-bind /dev/null <proj>/.env           # credential
--unsetenv AWS_SECRET_ACCESS_KEY
--unshare-net
```

All three of the finder's points are confirmed, and there is a **fourth**:

4. **A relative `denyRead` also lands inside the announced writable root** as
   `--tmpfs <proj>/private` (`settings.rs:739`–`745`). The finder's list has the auto-exec masks but
   not this one, and it is operator-configured rather than built in, so it is the case an operator is
   most likely to be surprised by.

### Half 2 — the silence claim · MOSTLY REFUTED

The claim is that these denials "produce **no errno at all** — an empty directory, an empty file — so
they are the one denial class an agent cannot detect by trying." I built a real `bwrap` cage with
exactly husk's mount shapes and probed it. Three different behaviours, not one:

```
=== 1. denyRead dir, tmpfs-masked ===
ls -la <cage>/secret          -> total 0, two entries, rc=0        (silent)
cat <cage>/secret/topsecret   -> "No such file or directory" rc=1  (ENOENT)

=== 2. credential file, --ro-bind /dev/null ===
cat <cage>/proj/.env          -> "Permission denied" rc=1          (EACCES)
stat <cage>/proj/.env         -> size=0 type=character special file

=== 3. tmpfs-masked dir INSIDE the announced writable root ===
ls  <cage>/proj/.claude       -> empty, rc=0                       (silent)
echo NEW > …/.claude/settings.json  -> rc=0                        (silent)
cat …/.claude/settings.json   -> "NEW"  rc=0        <-- reads back what it wrote
host afterwards               -> still "CLAUDE-SETTINGS"

=== 4. ro-bind-try file INSIDE the writable root ===
echo X > <cage>/proj/gitconfigfile -> "Read-only file system" rc=1  (EROFS)

=== controls ===
echo OK > <cage>/proj/canary  -> rc=0, persists
echo X  > /etc/husk-canary    -> "Read-only file system" rc=1
```

So:

* **Case 1 is not silent, it is *misleading*.** The directory listing is silent, but a read of a file
  inside returns `ENOENT` — "this file does not exist", which is a different lie from the one the
  finder describes, and arguably the worse one: an agent told ENOENT concludes the file was deleted or
  never written, and may go and recreate it.
* **Case 2 is not silent at all, and the code comment is wrong.** `settings.rs:788` says *"bind
  /dev/null over each so the job reads EMPTY, not the real secret"*, and `settings.rs:360` repeats it.
  The job gets **EACCES**. The mechanism is `MS_NODEV`: bwrap's `--ro-bind` sets it, and a bound
  character device on a `nodev` mount cannot be opened. Confirmed three ways —

  ```
  --ro-bind  /dev/null <path> -> stat: character special file; cat: Permission denied
  --dev-bind /dev/null <path> -> stat: character special file; cat: rc=0, empty   <- the documented behaviour
  /proc/self/mountinfo        -> …ro,nosuid,nodev,relatime … devtmpfs udev …
  ```

  Containment is unaffected — the secret is still denied. What is affected is that two source comments
  describe a behaviour the code does not produce, and a fix built on "the agent sees an empty file"
  would be built on a false premise.
* **Case 3 is exactly as described, and worse.** Not only is the write silent — the *read-back
  succeeds and returns the written bytes*. Inside the job there is no observation that distinguishes
  this from a real write. This is the one true instance of the class the finder names, and it is the
  strongest part of the finding.
* **Case 4 is confirmed:** `EROFS` inside the directory the banner names as the exception, immediately
  after the banner says a write outside the list is what fails.

**A test that could not fail.** The belief in "reads empty" is load-bearing in the vendored runtime
too, and its integration test cannot detect the difference:
`sandbox-runtime/test/sandbox/credential-deny.test.ts:479`–`486` asserts
`expect(result.stdout.trim()).toBe('')` from a `spawnSync`. `cat`'s "Permission denied" goes to
**stderr** and the exit status is never checked, so the assertion passes identically whether the file
reads empty or refuses to open. Flagged under protocol rule 7.

### Verdict and severity

**RECHARACTERISED.** The banner is false and understates its own carve-outs — confirmed, with a fourth
case added. The security-relevance argument the finder builds on top of it does not survive: only the
tmpfs-over-a-directory case is genuinely undetectable, and the two others produce errnos (one wrong,
one honest). The finding is still a real defect, but its shape is "the announcement contradicts the
mount table in four ways, one of which is undetectable" rather than "an entire denial class is silent
and the banner disclaims it".

**HIGH for the banner**, on the same reasoning the finder gives and which I agree with from my own
work: this is the single announcement written in direct response to the 22-`EROFS` field report, it is
the only pre-announcement a compute job gets, and it is generated from `writable` alone while the cage
is generated from a much longer list. One fact, two constructions — the failure mode this project has
already paid for elsewhere. **MEDIUM for the `/dev/null` documentation error**, because it is currently
correct-by-accident and the next person to touch it will reason from the comment.

**A7 collisions (flagged, not resolved):** a banner derived from the mount table would disclose the
credential mask list and the `denyRead` set. The finder's suggestion that it be a *count* rather than a
list is the right question for A7, not for me.

---

## F4 — three refusals carry no attribution and arrive wearing SLURM's name · CONFIRMED · MEDIUM

Captured from the real binary, both registries:

```
sbatch: error: option '--exclusive' does not take a value
sbatch: error: option '--time' requires a value
sbatch: error: value "$(rm -rf ~)" for '--job-name' is not allowed (must match the option's safe grammar)
srun:   error: option '--label' does not take a value
srun:   error: value "abc" for '--ntasks' is not allowed (must match the option's safe grammar)
```

`sbatch.rs:353`, `:368`, `:370`, reached from both registries as claimed. `sbatch-stub.py:35` and
`srun-stub.py:37` prefix `<tool>: error:`, so the body is the only signal and there is none.

**I tried to break it two ways and it survived both:**

* *Is `:368` even reachable?* Yes — but only when the value-taking option is the **last** token in
  `argv`, since `split_options_and_rest_in` otherwise consumes the script path as the value. Verified:
  `["--partition=short","--time"]` → `option '--time' requires a value`; `["--partition=short","--time","job.sh"]`
  → the *grammar* message instead, with `job.sh` as the offending value. Both messages exist; the
  second is the one an agent will usually see, and it is the more confusing of the two.
* *Is "byte-for-byte indistinguishable from real sbatch" true?* **No, and the finder overstates it.**
  Real getopt_long says `option '--exclusive' doesn't allow an argument` and `option '--time' requires
  an argument`; husk says "does not take a value" / "requires a value". They are not byte-identical.
  They are *stylistically* indistinguishable, which is what actually matters — the agent has no reason
  to look past the prefix — but the claim as written is wrong and a reviewer checking it against real
  SLURM output would reject the whole finding on it.

**Evidence the finder missed, which strengthens the case:** the same stub already knows how to
attribute. `sbatch-stub.py:213` writes accepted-path advice as `sbatch: husk: <note>` — three lines
above the `die()` at `:215` that writes refusals as `sbatch: error: <msg>` with no `husk:`. The
attribution mechanism exists, is in use, and is simply not applied to the refusal path.

**MEDIUM.** Not a containment gap; it is the exact "confident, wrong remediation" shape the brief
exists for, and it lands on a default-deny gate where an agent that cannot see the rule will keep
probing it. The remaining 13 unattributed bodies (rows 2, 3, 7, 8, 9, 29, 39, 48, 49, 51, 52, 54) I
confirmed individually by driving them — see the raw captures in the step-side run; `--bcast`
("the cage's filesystem policy"), `--export`, `--get-user-env`, `step.rs:240` and `step.rs:281` all
reached me with no `husk` in the body.

---

## F14 — "this job has no network" is announced only when the network is configured · CONFIRMED · MEDIUM

Generated guard with **no** `sandbox.network.allowedDomains`:

```
$ grep 'echo .*husk:' out-nonet.txt | grep -iE 'network|proxy|egress|socat|internet|offline'
  (NONE)
$ grep -c 'unshare-net' out-nonet.txt
  1
```

`--unshare-net` is on the `bwrap` line; not one `echo` mentions the network. All four "no network"
messages (`policy.rs:687`, `:749`, `:756`, `:776`) live inside the `if net_enabled` branch. Confirmed
exactly as stated.

**One correction.** The finder says "the default deployment is the one with no pre-announcement".
`user-config/settings.json` ships with `allowedDomains: ["opendatadocs.meteoswiss.ch:443"]`, so the
*shipped* default takes the announced branch. The silent case is a site that never configured egress,
or an operator who removed the demonstration entry — plus, per F1, **any site whose allowlist fails to
compile**, which is how the two findings meet.

**MEDIUM.** It is a missing pre-announcement for a kernel-enforced denial, which is precisely the
second category the brief asks about, and the remedy is one unconditional line that is the same line in
both branches.

---

## F13 — four config-time denials emit nothing at all · CONFIRMED · MEDIUM

Six carve-outs configured, one survived:

| configured | fate | said anything? |
|---|---|---|
| `allowRead: <symlinked dir>` | dropped (`settings.rs:552`) | no |
| `allowRead: /users/shared/data` | dropped (`:559`) | no |
| `allowRead: ./relative-carveout` | dropped (`:670`) | no |
| `allowRead: <real dir>` | **applied** | — |
| `allowWrite: <symlinked dir>` | dropped (`:553`) | no |
| `allowWrite: /users/me/out` | dropped (`:560`) | no |

`grep -i "drop\|skip\|symlink\|ignor\|carve"` over the full broker session log: nothing. The banner
correctly lists only the project dir — so the *job* is told the truth while the *operator* is left
believing a policy is in force that is not.

Every drop is fail-safe (they narrow, never widen), which is why this is MEDIUM and not higher. What
makes it a finding rather than a preference is the inconsistency inside one file: `settings.rs:535`
warns about a truncated credential scan under a comment that says *"Never fail silently"*, and
`netallow.rs:237` refuses to compile an allowlist rather than drop an entry *"because an allowlist that
silently drops an entry is one an operator believes is in force"*. The same file and its neighbour both
state the principle these four lines break.

**Overlap flagged:** B3 (mount table) and B5 (guard generation) both touch this. Not resolved here.

---

## F15 — the login-side cage has no writable-set announcement · CONFIRMED · MEDIUM

```
$ grep -rn "READ-ONLY except\|HUSK_WRITABLE" --include=* . | grep -v doc/review-v0.5
slurm-broker/broker/src/policy.rs:540, :794
slurm-broker/broker/tests/golden/guard-net-off.sh:185,186
slurm-broker/broker/tests/golden/guard-net-on.sh:306,307
```

Only `policy.rs::cage_banner` and its two golden files — i.e. only inside a compute job. I checked the
two places a login-side equivalent could live and neither has one:
`sandbox-runtime/src/sandbox/linux-sandbox-utils.ts` builds the same shape of cage and prints no
announcement, and `husk-slurm-wrapper.rs` emits no session banner (`grep -n echo` finds none). The
login-side seccomp kill has no translation either — the rc=159 handler lives in the generated guard,
which does not exist outside a job.

I agree with the finder's severity reasoning and reach it independently: the argument is by symmetry
rather than reproducer, but the symmetry is exact — same `FsPolicy`, same `--ro-bind / /`, same
`--tmpfs /users` — and the agent spends most of its life there.

**MEDIUM**, held down only because the login cage is partly vendored code today (ROADMAP 6a).

---

## F5 — a failure caused by husk's forced options is reported as SLURM's · CONFIRMED · MEDIUM

Pass 1 marked this PLAUSIBLE for want of a cluster. **It does not need one.** With a fake `sbatch` on
`PATH` and the broker run *without* `--dry-run`:

```
what the agent sees:
  sbatch: error: sbatch failed: sbatch: error: Batch job submission failed: Invalid account or
  account/partition combination specified
```

Note the doubled prefix — `sbatch: error: sbatch failed: sbatch: error:` — which is itself a tell that
nobody has read this message as rendered.

**Worse than the finder states.** They say the agent is given "an unexplained SLURM error about a
submission the agent cannot see, with nothing naming the forced values or pointing at the session log".
I checked whether the session log at least holds the argv, so a human could reconstruct it. It does not:

```
broker: request id=y submitted_at=t tool=sbatch script.source=file script.name=job.sh
```

The `argv:` line is printed only under `--dry-run` (`spool.rs:183`–`184`). On the live path the forced
`--partition/--account/--nodes=1/--export=ALL/--chdir/--output/--error` that caused the rejection are
recorded **nowhere** — not to the agent, not to the operator. Upgrading to CONFIRMED, MEDIUM.

---

## F2 — a `--chdir` that merely does not exist is reported as a confinement violation · CONFIRMED · MEDIUM

Reproduced (`--chdir=<proj>/nope`, where `<proj>` is the only writable root):

```
sbatch: error: --chdir: "…/proj/nope" is not inside any directory this job may write. husk confines
--chdir/--output/--error to the writable set, because SLURM writes those files as you and OUTSIDE the
sandbox. Writable here: …/proj
```

The path is inside the directory the message names. Mechanism confirmed by reading
`settings.rs:204`–`222`: `confine_under_any` binds the real error to `_` in `Some(_) =>` and discards
it. The asymmetry the finder cites is real and I reproduced both sides in the same run —
`--output=<proj>/nodir/x.out` yields *"cannot be resolved (No such file or directory (os error 2)). It
must already exist"*, because `confine_output_pattern` calls `confine_under_workdir` directly and keeps
its error. Same underlying condition, two diagnoses, one of them correct. That asymmetry is what makes
it a bug rather than a choice, and I agree.

**MEDIUM:** a message that names a *directory* as writable while refusing a path *inside* it is
self-contradictory on its face, which is the P3 failure the spoofed-message episode was about.

---

## F12 — two proxy refusals are delivered as silence · CONFIRMED · MEDIUM-LOW

Live against the real proxy:

```
=== oversize request head (>8 KiB, no blank line) ===
   received 0 bytes: b''
=== 15 s read timeout (one header, then stall) ===
   after 15.3s received 0 bytes: b''
=== control: an unlisted host ===
   HTTP/1.1 403 Forbidden … husk: bad.example.net:443 is not on husk's network allowlist…
```

Confirmed. Minor mechanism correction: I got a clean EOF (0 bytes), not the `ConnectionResetError` the
finder reports — irrelevant to the substance, since both are indistinguishable from a network fault,
which is what `netproxy.rs:52`'s own doc comment forbids.

**One thing the finder missed.** The trusted-side log is not much better for the timeout case:

```
husk-proxy: refused: request head too large                                    <- names the cap
husk-proxy: refused: reading the request: Resource temporarily unavailable (os error 11)   <- raw EAGAIN
```

`read_head` folds the `READ_TIMEOUT` expiry into the generic `Err(e) => format!("reading the request: {e}")`
arm at `netproxy.rs:131`, so the 15 s policy cap reaches the *operator* as a bare errno too. An operator
reading that line has no reason to connect it to `READ_TIMEOUT`.

**MEDIUM-LOW:** a teaching gap, not a containment one — the refusal is logged and the connection is
denied. It costs an afternoon, which is what the module's own comment says it costs.

---

## F3 — husk's rule attributed to SLURM · CONFIRMED · LOW-MEDIUM

```
sbatch: error: --output: "…/proj/nodir" cannot be resolved (No such file or directory (os error 2)).
It must already exist — SLURM does not              create output directories.
```

No "husk" anywhere; the one named party is SLURM. husk is the refuser (it canonicalises to confine),
and real `sbatch` accepts a non-existent output directory at submit time. Confirmed.

**Note the whitespace.** That run of 14 spaces is not my formatting — it is in the message. Four
messages in `settings.rs` carry it (`:228`, `:233`–`:235`, `:256`, `:261`), from Rust string literals
wrapped across lines without a `\` continuation, so the source indentation became message content.
Cosmetic, but it is direct evidence that these particular messages have never been read as rendered —
which is the same reason F5's doubled prefix survived.

**LOW-MEDIUM:** unlike F2 the remedy given is correct and one step (`mkdir`), so an agent following it
succeeds. The cost is the false model of who refuses, which persists into the next refusal.

---

## F7 — the partition refusal asserts a property husk cannot know · CONFIRMED (mechanism) · LOW-MEDIUM

`policy.rs:450`–`455`: *"These are typically preemptible/low-priority, so checkpoint your work."* is
part of a single unconditional `format!` — no branch, no dependence on the configured set. Reproduced
with `HUSK_SLURM_PARTITION=short,pp-short`; the sentence appears verbatim.

I tried to refute it two ways. Neither worked, but both narrow it:

* *Is it hedged enough to be honest?* "typically" is a real hedge, and `DEFAULT_PARTITION` is
  `preemptible` (`session.rs:15`), so for an unconfigured install the sentence is true. It becomes a
  claim about partitions husk was *told* about only when an operator overrides.
* *Does it contaminate the accepted path?* No — it lives only in `partition_refusal`. The wall-limit
  note (`time_limit_note`) is the one attached to both paths, and it is correctly suppressed when the
  allowed set has more than one member.

So the exposure is: an operator-configured set, on refusal only. That is still exactly the P3 shape
that produced the spoofed-message episode — an agent that checks `sinfo` finds husk asserting something
observably off about a partition husk itself named.

**LOW-MEDIUM.** Whether it is actually false on Balfrin is a site fact — see Needs-hardware below.

---

## F8 — a seccomp kill is translated for the job but not for a step · RECHARACTERISED · LOW

The asymmetry inside husk's code is confirmed by reading: `policy.rs:975`–`981` turns rc 159 into five
attributed lines naming `seccomp-wrapper` and giving an `strace` recipe; `step.rs:169`–`175` emits
`format!("step exited with status {code}")` with `code = 128 + signal` for a signal kill and no
translation at all.

**But the impact is materially narrower than stated, and I could not have known that without following
the exit status.** The srun stub propagates the step's code (`srun-stub.py:155`,
`sys.exit(int(resp["exit_code"]))`), and the guard's `_husk_rc=$?` captures the exit status of the
whole caged job script. So for the common case — a run script whose `srun` is what determines the job's
exit status — the job **does** get the full five-line seccomp translation, on top of the bare
`srun: error: step exited with status 159`.

The gap is real but specific: a multi-step script where a later command masks the failing step's
status, a script that does not `set -e`, or anyone reading the step's own line in the middle of a long
log. Given that ranks are where new syscalls appear, that is still worth closing — I agree with the
finder's reasoning on *why it matters*, not with the size they give it.

**RECHARACTERISED, LOW.** The exact numeral still needs hardware (below).

---

## F6 — the `#SBATCH <Forced>` refusal names the wrong reason · RECHARACTERISED · LOW

The message is confirmed:

```
sbatch: error: #SBATCH --wrap is controlled by the broker and can't be set by the job
(output/error/chdir/export are forced to safe values). Remove it.
```

**The count is wrong, and the correction changes what the fix should be.** The finder says "four of its
nine triggers". I drove all eleven `Class::Forced` options through as `#SBATCH` directives. Only **two**
reach `sbatch.rs:452`:

| `#SBATCH …` | outcome |
|---|---|
| `--output` / `--error` / `--chdir` | caught earlier as `dominated` (`sbatch.rs:429`) → their own correct confinement messages |
| `--export` / `--partition` / `--nodes` | **silently accepted and dropped** (`dominated`/`dedicated`) |
| `--uenv` / `--view` / `--repo` | caught by the uenv gate → their own correct messages |
| **`--wrap`** | → `sbatch.rs:452`, wrong reason (it is refused outright, not forced to a safe value) |
| **`--account`** | → `sbatch.rs:452`, wrong reason |

`--account` is the one that costs something. `body_reject_reason` runs at `policy.rs:207`, *before* the
account check at `:225`, so `#SBATCH --account=abc` returns the vague broker message and **never
reaches** the excellent account refusal (row 12) that explains the operator has to run
`install-husk.sh --slurm-account`. A run script with a perfectly ordinary `#SBATCH --account=` line gets
the worst message in the family instead of one of the best, and the CLI form of the same option gets
the good one.

**RECHARACTERISED, LOW** — small blast radius, but the fix is different from the one the finder implies:
it is not "widen the parenthetical to nine options", it is "two options reach here and both need their
own message, one of which already exists".

---

## F11 — three rank refusals interpolate a pid or a job id · RECHARACTERISED · INFO

The interpolation is real: `rank.rs:262`/`:268` embed `/proc/<holder_pid>/ns/{user,pid}` at generation
time, `:275` embeds `/dev/shm/husk-${SLURM_JOB_ID}` (shell-expanded at run time).

**But property 4 does not govern these, for two reasons I established rather than assumed:**

1. **Within a job — the only scope where "retry" means anything — both values are constant.** The
   holder is created once and cached (`step.rs:126`–`129`, `if let Some(h) = &self.holder { return
   Ok(h.pid) }`), and `SLURM_JOB_ID` is fixed for the allocation. An agent that re-runs `srun` after
   this failure gets a byte-identical message. The strings differ only *across jobs*, which is not a
   retry.
2. **These are not policy refusals.** Property 4 exists so a refusal reads as standing policy rather
   than transient failure ("byte-identical on retry, so it reads as standing policy"). The holder being
   gone *is* a fatal transient fault, and an agent reading it as such is reading it correctly. The
   variable part is the diagnostic — which the finder concedes.

**RECHARACTERISED, INFO.** Not a defect against the property as written. If there is anything here it
belongs to B1 (resource lifecycle), not B2.

---

## F9 — one refusal string is unreachable · CONFIRMED · INFO

`sbatch.rs:323` cannot fire from either entry point. `split_options_and_rest_in` (`:226`–`251`) breaks
at the first token that is neither an option nor a consumed value, and treats a bare `-` as a positional
(`a.starts_with('-') && a != "-"`), so `interpret_cli_in`'s `!tok.starts_with('-') || tok == "-"` branch
never sees anything. Verified by probe on **both** registries, which the finder only did for sbatch:

```
sbatch: ["--partition=short","-","job.sh"]        -> submitted
sbatch: ["--partition=short","stray","job.sh"]    -> submitted
sbatch: ["--partition=short","--","-x","job.sh"]  -> submitted
srun:   ["-","hostname"]                          -> ok
```

Dead code in a default-deny gate: worth knowing, not a hole. INFO.

---

## Property 4 — I re-ran the diff

Two independent broker runs of the same 25-case set, in two different directories, ~1 s apart:

```
### messages: diff A vs B ###           CLEAN
### generated guard scripts: A vs B ### CLEAN
### broker session log A vs B ###       differs only in: pid 17035/17040, timestamp 004553/004554Z
```

The finder's claim reproduces. The session-log header is operator-facing and should carry both.

**One thing their method could not catch.** The credential auto-scan (`settings.rs:889`,
`for entry in entries.flatten()`) emits its `/dev/null` binds in **`read_dir` order, unsorted**. Two runs
over an *unchanged* directory give the same order, so a same-directory diff cannot see it. Creating the
same ten credential files in two different orders:

```
order 1: a.pem b.pem c.pem d.key e.env f.pem g.key h.env i.pem j.key
order 2: j.key i.pem h.env g.key f.pem e.env d.key c.pem b.pem a.pem
identical? NO — the credential mask list is readdir-ordered, not sorted
```

Semantically harmless (the binds are order-independent) and it does not reach an agent-facing message.
It does mean "the entire generated guard is byte-identical" is a statement about one directory state
rather than about the generator, which matters for anyone golden-testing the guard.
**Overlap flagged: B5 (guard generation).**

---

## Additional observations found while verifying

Not in the finder's list; found while establishing the chains above.

1. **The egress proxy resolves its allowlist from an agent-influenced directory. → A9 / A1, not
   resolved here.** `main.rs:277` states the design intent: *"resolving it means the policy is read from
   files the agent cannot write."* But the guard invokes it as `--net-proxy … --workdir "$PWD"`
   (`policy.rs:723`), and `$PWD` is the forced `--chdir`, which comes from `req.cwd` or the request's
   own `--chdir` and is confined only to *the writable set* (`policy.rs:307`–`316`). The submit-time
   decision at `policy.rs:364` uses the trusted `project_dir` instead. Two different directories decide
   two halves of one policy, and the run-time half is the agent-influenced one. Whether
   `<chdir>/.claude/settings.json` is reachable to the agent before the job starts is A1/A9's question,
   not mine.

2. **One malformed sub-block silently voids an entire settings file, including its denials. → B3.**
   `FsPolicy::parse` (`settings.rs:424`) is `serde_json::from_str(json).unwrap_or_default()`. I hit this
   by accident: writing `credentials.files` as `["./.env"]` instead of `[{"path":"./.env"}]` made the
   whole `sandbox.filesystem` block — `allowWrite`, `denyRead`, `allowRead` *and* the credential list —
   vanish with no message. For `allow*` that is fail-safe. For `denyRead` and `credentials.files` it is
   **fail-open**: a typo in one sub-block leaves declared secrets unmasked, silently. This is F13's
   principle at file granularity.

3. **`#SBATCH --export=NONE` is silently overridden.** The directive is `dominated`
   (`sbatch.rs:429`), so it is dropped without a word and `--export=ALL` is emitted. Verified: status
   `submitted`, message empty, argv contains `--export=ALL`. A job author's explicit environment choice
   is reversed with no output on any channel. Small, but it is the brief's "a message that names the
   constraint but no remedy" taken to its limit — no message at all.

4. **Four `settings.rs` messages carry embedded 14-space runs** (see F3), and **`spool.rs:409`
   produces a doubled `sbatch: error: sbatch failed: sbatch: error:` prefix** (see F5). Both are
   evidence that this family of messages has not been reviewed as rendered.

5. **`check_socket_path` is stricter than documented and that is good.** Not a defect — noting it
   because it cost me a test round and it is the kind of thing worth having written down: it refuses a
   socket path whose parent is a symlink ("`/tmp/hb2` is not a directory") as well as one over 107
   bytes, and both refusals are attributed and actionable.

---

## Needs hardware

Three sub-claims cannot be settled on this laptop. None changes an outcome above; each would confirm a
number or a site fact.

1. **F7 — are `short` and `pp-short` actually preemptible on Balfrin?** The message asserts it
   unconditionally. On a Balfrin login node:
   `scontrol show partition short pp-short | grep -iE 'PartitionName|PreemptMode|MaxTime|GraceTime'`
   If `PreemptMode=OFF` for either, the message is observably false for the site husk ships to, which
   moves F7 from LOW-MEDIUM to MEDIUM.

2. **F8 — does a seccomp-killed rank really surface as `status 159`?** Inside a brokered job on
   Balfrin, with a step that makes a denied syscall (`ptrace` is on the deny-list):
   `srun --ntasks=1 -- sh -c 'strace -f true'` — or any binary calling `ptrace(2)` — and read the step
   line. Expect `srun: error: step exited with status 159`. Confirm 159 (SIGSYS = ours) and not
   `EPERM`/`EINVAL` (kernel), per protocol rule 5.

3. **F10 — does `--ro-bind /dev/null <secret>` give EACCES on the cluster kernels too?** Measured here
   on kernel 6.8 / bwrap 0.6.1; Balfrin is 5.14 Cray Shasta. `MS_NODEV` semantics are ancient and
   stable so I expect it to reproduce, but the code comment is wrong either way and it is cheap to
   settle. Inside a brokered job:
   `cat <workdir>/.env; echo "rc=$?"; stat -c '%F' <workdir>/.env`
   Expect `Permission denied`, `rc=1`, `character special file`. If it instead reads empty with rc=0,
   the comment is right on that kernel and F10's silence claim holds there.

## Not reached

Nothing in the finder's list was skipped. The eight tables were spot-checked rather than re-scored
line by line: I drove all 25 sbatch-side rows, all 20 step-side rows, all the proxy rows and the
guard-emitted rows I could reach without a cluster, and confirmed the finder's `✓`/`✗` marks on every
row I touched. Rows 31–38 (`spool.rs` internal errors) I confirmed by reading only — they are
`Response::error` sites reached through the identical channel, and F5 is the representative case I
reproduced live.
