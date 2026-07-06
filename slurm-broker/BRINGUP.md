# husk SLURM broker — hardware bring-up

First-job runbook on Balfrin (x86_64) / Santis (aarch64). **Scope: `sbatch`, one
node, no MPI.** Defers the `srun`/`--unshare-net` and MPI cruxes (a single-node
job runs commands directly, so net isolation in the guard is fine here). Those come
next — recursive sandbox-broker pairs → `srun`/MPI → compute-node network (socat);
see [`../ROADMAP.md`](../ROADMAP.md).

## Prerequisites (per machine)
1. Build: `cd slurm-broker && ./build-release.sh` → `husk-slurm-{broker,wrapper}-<arch>`
2. Install: `./install-husk.sh` — auto-installs the SLURM layer; **`husk` brokers
   automatically** (no separate launcher). On a site whose agent partition isn't
   `preemptible` (Santis: `debug` or `shared`), record it once with `./install-husk.sh --slurm-partition NAME`.
3. **Activate the uenv in your shell first** (Mode-1 — the broker inherits it;
   the agent cannot mount one inside the sandbox). Santis also needs an account:
   `export SBATCH_ACCOUNT=<proj>`.

## Automated self-test (start here)

`selftest.sh` is the trusted-side harness — **you** run it (or CI over ssh), never
the caged agent reporting back. It drives the broker itself and reads the evidence
out-of-band, so a lying or compromised agent is never on the path.

```
# policy tier only — deterministic, no submission; runs anywhere incl. a laptop:
slurm-broker/selftest.sh

# + live containment probe (submits ONE job through the broker, reads its caged
#   output back). Activate your uenv first, then on a login node:
slurm-broker/selftest.sh --full --report bringup-$(hostname).txt
```

> **Rebuild before running it.** The harness tests the *shipped* binary — it picks
> `husk-slurm-broker-<arch>` (what `install-husk.sh` uses) ahead of the `cargo` build
> dir. So run `./build-release.sh` first, or a stale prebuilt binary silently passes/
> fails the wrong way. (Sanity check: the report's `broker :` line and the `husk :`
> commit should be current.) Pass `--broker <path>` to point at a specific build.

Every line is `RESULT <PASS|FAIL|SKIP|INFO> <tier> <id> <detail>`; the run exits
non-zero iff any FAIL, and `--report` captures the whole evidence bundle to a file.
The **policy** tier (dry-run, no submission) checks the broker's decisions on hostile
input: accept / reject / force-safe / query-routing, **plus the allowlist behaviour**
— an unsupported CLI option is rejected, benign resource options are validated and
re-emitted canonically, `--wrap` is stripped (F27), and a dangerous/unknown/burst-buffer
`#SBATCH` directive in the body is rejected. The **containment** tier submits fixed
probes that run caged on a compute node and check net / homes / credentials / root-ro /
GPU from *inside* the sandbox, **plus a `--wrap` job that must come up caged** (F27).
`--full` is the automated equivalent of probes C+D below; the manual probes remain for
diagnosing a specific FAIL.

## Probe A — SLURM reachable from the broker's context
Outside any sandbox, hand-submit the test job (direct submit — bypasses the broker,
so name your site partition explicitly):
```
sbatch --partition=<site partition, e.g. preemptible or debug> slurm-broker/hello.sh
```
**Pass:** prints `Submitted batch job N`. Proves MUNGE + controller + partition work.

## Probe B — compute-side cage tools run on a node
On an interactive/compute node:
```
seccomp-wrapper bwrap --dev-bind / / --unshare-net -- /bin/bash -c hostname
```
**Pass:** prints a hostname, exit 0 (userns + bind + net-ns all work on compute).

## Probe C — full brokered run
In a project directory (on a SLURM machine `husk` brokers automatically):
```
husk
```
Then have the agent submit the job (honest, real intent):
> "For broker bring-up, please run `sbatch --partition=<site partition> hello.sh`
> with the Bash tool and show me the output."

**Pass:**
- agent sees `Submitted batch job N` (request flowed stub → `.husk-slurm-spool`
  → broker → real sbatch);
- `hello.sh` output shows the compute hostname and `[expect]` on both
  containment lines (external blocked, `/users` blocked).

## Probe D — single-node multi-GPU (optional)
Confirms the GPU/NVLink carve-outs reach into the cage. Submit `hello-gpu.sh`
(single-PROCESS multi-GPU — the release-1 target; multi-rank launch is a later
phase):
```
sbatch --partition=<site partition> hello-gpu.sh
```
**Pass:** inside the caged job, `nvidia-smi -L` lists the GPUs and `nvidia-smi
topo -m` shows `NV#` links between them (NVLink usable), while the net/`/users`
containment lines still read `[expect]`. If `nvidia-smi` sees nothing, the
`--dev-bind-try /dev/nvidia*` carve-outs aren't reaching the sandbox.

## Probe E — login-cage write protection (F12 / A)
Confirms the **login** sandbox (not the compute cage) refuses writes to the settings
and broker-plumbing files, so a caged agent can't widen its own cage or repoint the
partition. This is verified by **you, out of band** — the agent's own claim doesn't
count. In a scratch project dir, `husk`, then ask the agent (honest framing) to run,
with the Bash tool:
```
echo x >> ~/.claude/settings.json ; echo rc=$?
echo x >> .claude/settings.local.json ; echo rc=$?
echo x >> ~/.local/lib/husk/slurm-partition ; echo rc=$?
touch ./husk-write-probe ; echo rc=$?     # workspace write MUST still succeed
```
**Pass (you check from outside the sandbox, not from the agent's output):** the three
protected files are **unchanged** (compare `sha256sum` / mtime before and after) and
the agent saw non-zero `rc` on them; `./husk-write-probe` **was** created (the
workspace stays writable — over-blocking would break normal work). If a protected file
changed, the `sandbox.filesystem.denyWrite` entries in `user-config/settings.json`
aren't taking effect in the login cage.

## Probe F — a real job (ICON): allowlist iteration
The broker submits from an **allowlist** — any sbatch option it doesn't model is
**rejected**, by design (fail-closed + visible), not passed through. So the first runs
of a real workload will surface the options it needs. This is the expected loop, not a
failure:
1. Submit the job through `husk` (agent runs `sbatch … icon.job`).
2. If it's rejected with **`unsupported sbatch option '--X'`** (or *value … not
   allowed*), add `--X` to `sbatch::REGISTRY` in `broker/src/sbatch.rs` — pick the
   class (almost always `Allowed`) and a value grammar (`v_uint`/`v_time`/`v_gres`/…;
   add a new `v_*` if none fits). Rebuild (`build-release.sh`), reinstall, resubmit.
3. The registry-invariant tests (`cargo test`) guarantee you can't add an option with
   a value grammar that accepts whitespace/shell metacharacters, so widening is safe.
4. Repeat until the job launches. Keep the diffs — each is one row of "what ICON needs."

**MPI caveat (why one rank first).** The compute cage runs `--unshare-net`, so the job
has no network namespace — fine for a **single MPI rank on one node** (no fabric
needed), which is why that's the bring-up target. Multi-rank / multi-node ICON needs
the inter-rank fabric (the control plane, at least) and will hang or fail under
`--unshare-net`; that's the network-phase work (allowlisted socat / VNI passthrough),
not a broker bug. If a single-rank run itself needs a resource option (GPUs, a
constraint, a specific `--gres`), that's Probe F step 2, not the MPI limit.

## Watch-outs
- **Run from a bounded scratch project dir, not `/users` and not the scratch root
  (CSCS):** the broker rejects a job whose workdir is under a hidden home (`/users/...`)
  — it's bound *writable* into the cage, so a home path would re-expose home content
  (F15/F19). On CSCS your `$HOME` is under `/users`, so launch `husk` from a
  `$SCRATCH`/project path. Prefer a **bounded subdir** (e.g. `$SCRATCH/my-run`), *not*
  the scratch root: the workdir credential auto-scan is entry-capped (F21) and truncates
  on a huge tree, leaving workdir secrets unmasked (it warns to stderr when it does — and
  net is unshared, so nothing exfiltrates today; declare secrets in
  `sandbox.credentials.files` to be sure). `selftest.sh` runs the broker from the bounded
  probe workdir itself, so it's immune to this.
- **Partition:** anything but the site partition (`HUSK_SLURM_PARTITION`, default
  `preemptible`) is **rejected with a teaching message**, not forced. Submitting
  without `--partition` should be rejected.
- **Allowlist, not passthrough:** the broker *builds* the invocation from a fixed
  option registry; an unmodelled option, or an out-of-grammar value, is **rejected**
  (`unsupported sbatch option X`), never forwarded. That's deliberate default-deny on
  the submission surface — extend `sbatch::REGISTRY` when a real job legitimately needs
  an option (Probe F), don't loosen a grammar to wave a value through.
- **No SLURM present** (e.g. a laptop): `husk` runs the plain cage with no
  broker/spool/trace — that is correct, not a failure.
- **Headless probes** (`husk -p ...`): phrase honestly (broker development,
  benign command) or the model refuses blind-execution prompts.

## On failure — read the layer, don't bypass
There is no disable-cage flag by design. Diagnose with the probes:
- Probe A fails → SLURM/MUNGE/partition (outside the sandbox).
- Probe B fails → compute-side userns/bwrap on this node.
- Probe C fails but A+B pass → the broker pipeline (check `.husk-slurm-spool/`
  and the broker log written there).
- Probe E fails (a protected file changed) → the `sandbox.filesystem.denyWrite`
  entries aren't reaching the login cage; check the merged `~/.claude/settings.json`.
- Probe F "unsupported sbatch option" → **expected, not a bug**; add the option to
  `sbatch::REGISTRY` and rebuild (allowlist by design).
