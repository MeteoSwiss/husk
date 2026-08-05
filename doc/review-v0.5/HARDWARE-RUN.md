# husk v0.5 — hardware run plan (Balfrin / Santis)

Everything above LOW plus the eight LOW code fixes is committed and green off-cluster
(230 lib tests, clippy clean, selftest 47 PASS / 0 FAIL / 2 SKIP). **None of it is
hardware-verified.** This is the ordered list to run and what to look at.

Two goals, and they are not the same: **(A) confirm the fixes landed**, and **(B) gather the
five facts only hardware can settle**. (B) is the more valuable half — one of those facts
decides whether the CRITICAL is closed or merely narrowed.

---

## 0. Build and deploy (both clusters)

```bash
cd ~/mch/agentskills-internal
git log --oneline -12                      # expect 24a4b81 at the top
(cd slurm-broker && ./build-release.sh)    # per-arch binaries
./install-husk.sh                          # REQUIRED: merges the new sandbox denyWrite
grep -n 'Rprofile\|hg/hgrc' ~/.claude/settings.json   # must now list both
```

**The stale-binary trap:** `selftest.sh` prefers a prebuilt `husk-slurm-broker-<arch>` in
`slurm-broker/` over `target/release`. On the laptop that silently tested a July binary and
reported the A1 escape as still open. Either rebuild that prebuilt (which `build-release.sh`
does) or always pass `--broker`. Read the first four lines of selftest output — the staleness
guard warns there.

## 1. The suite

```bash
cd ~/mch/agentskills-internal/slurm-broker
./selftest.sh --full 2>&1 | tee ~/bringup-$(hostname -s)-$(date +%m%d).txt
```

Expect the previous count **plus 3 new arms**: `sbatch.output_symlink_leaf`,
`sbatch.confine_msg_opaque`, `spool.once_released`. Fail = read the arm's message; each says
what it measured.

---

## 2. (A) Confirm each fix landed

### A1 — the CRITICAL, three parts

```bash
cd $SCRATCH/claude-scratch-space && mkdir -p a1check && cd a1check
ln -sfn "$HOME/husk-A1-WITNESS.out" ./log.out
sbatch --partition=$PART -t 1 -n 1 --output="$PWD/log.out" --wrap ':'    # must be REFUSED
ls -l "$HOME/husk-A1-WITNESS.out"                                        # must NOT exist
```
Then the **run-time half**, which is the part that actually holds:
```bash
sbatch --partition=$PART -t 1 -n 1 --wrap 'echo ok'      # a normal job must still run
grep -n 'open-mode' <the forced argv in the broker log>  # expect --open-mode=append
```
✅ = refusal + no witness + normal jobs unaffected.

### A7-1 — the message is no longer an oracle
```bash
sbatch --partition=$PART --output=/users/$USER/.ssh/x.out --wrap ':'     # refused
sbatch --partition=$PART --output=/users/$USER/.gnupg/x.out --wrap ':'   # refused
```
The two refusals must be **identical apart from the path you typed** — no "resolves to", no
errno, no present-vs-absent difference. That was the leak: `.ssh` exists, `.gnupg` does not,
and husk told you which.

### A4-F3 — login cage masks the auto-exec dotfiles (needs the re-install)
Inside a husk session, in a project dir:
```bash
echo x > .Rprofile ; echo $?      # must fail
mkdir -p .hg && echo x > .hg/hgrc ; echo $?   # must fail
```

### Submission env allowlist
Watch `~/.husk/log/husk-*.log` for:
```
husk-broker: submitting a job: N login variable(s) not forwarded to SLURM: ...
```
**This is item (B2) below — do not just confirm it works, WRITE THE LIST DOWN.**

### Cage-build collision — the one that blocked A5
```bash
cd $SCRATCH/claude-scratch-space/collide
for i in 1 2 3 4; do sbatch --partition=$PART -t 1 --wrap 'sleep 5'; done
```
Previously 3 of 4 died in bwrap setup with `Can't mkdir …/.git/hooks: Not a directory`.
Expect 4/4 to run.

### O1 — egress socket directory
While a networked job runs: `ls -ld /tmp/husk-$(id -u)-*` → name must now end in a random
6-char suffix, mode 0700. `net.live` in the selftest must still pass.

### A3 — the heredoc false-reject
```bash
cat > gen.sh <<'OUTER'
#!/bin/bash
#SBATCH --partition=PART_HERE
cat > inner.sh <<'EOF'
#SBATCH --qos=elevated
#BB stage_in
EOF
echo generated
OUTER
sbatch gen.sh     # must now be ACCEPTED (it used to be refused)
```

### B1-F6 / B1-F7 / B3-F8 / B4-F7
- `--once`: covered by `spool.once_released` in the suite.
- log pruning: `ls ~/.husk/log | wc -l` before and after a few sessions; nothing under an
  hour old should ever disappear.
- relative `denyWrite`: add `"notes/secret.txt"` to the project settings, submit a job, and
  check the emitted bwrap args carry `--ro-bind <workdir>/notes/secret.txt`.
- rank script: any MPI job exercises it; the `|| exit 1` only shows up on failure.

---

## 3. (B) The five things only hardware can tell us — **the valuable half**

### B1. Does a batch script get a REGULAR FILE for stdout? ★ decides whether A1 is closed
A1's run-time guard enforces **only** when fd 1 is a regular file. If slurmstepd pipes output
instead, the guard reports and does not enforce — and A1 is then only narrowed, because the
submit-time leaf check still races the pending window.

```bash
grep -n 'not regular files on this node' ~/.husk/log/job-*.log
```
- **Nothing found** → the guard is enforcing. A1 is closed. ✅
- **Line present** → the guard is inert on this site. Tell me; the fix is to expand the
  agent-requested path in the guard and compare it directly, and it changes the design.

Belt-and-braces, from inside a job: `readlink /proc/$$/fd/1` — expect a path under the
writable set, not `pipe:[…]`.

### B2. Which env vars did the allowlist drop?
Capture the full "not forwarded" list from a **real ICON run**, not a toy job. That list is
the only evidence for whether the allowlist is too tight. Anything ICON needs goes into
`HUSK_SUBMIT_ENV_ALLOW='NAME:PREFIX*'` and then into the shipped defaults.

### B3. Does `--open-mode=append` change anything visible?
Every husk default is `%j`-unique so it should be invisible. The case to watch is a run
script with a FIXED output filename run twice — output now accumulates rather than
overwriting. Confirm no workflow depends on truncation.

### B4. Concurrency in one project dir
Beyond the 4-job check: does the shape-aware masking hold when jobs start at genuinely the
same moment? The residual is that the shape is read at SUBMIT time on the login node while
bwrap runs later on a compute node. If collisions persist, the answer is to resolve the shape
on the compute node like the credential masks already are.

### B5. Is the MPI path unchanged?
`cma.peers`, `steps.*`, and a real ICON/KENDA run. B4-F7 touched the rank script (`|| exit 1`)
and B4-F8 touched the **egress** rank path only — the plain path was deliberately left
byte-for-byte identical. If MPI regresses, those two are the first suspects.

---

## 4. If something fails

Capture the arm name, the message, and the relevant `~/.husk/log/job-*.log` — the guard now
writes its refusals there specifically so a failed job is diagnosable without the job's own
stdout, which may be the thing under suspicion.
