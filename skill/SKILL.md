---
name: husk
description: Working inside husk, the sandbox that wraps this agent on CSCS supercomputers, and submitting jobs through its SLURM broker. Use when a file read or write is refused, a network request fails, an `sbatch`/`squeue`/`srun` behaves unexpectedly, a job seems to get the wrong resources, or a command hangs or dies with no explanation — and read it BEFORE concluding that the cluster, the filesystem or a website is broken.
---

# You are running inside husk

husk is a sandbox that wraps this agent from the outside. It is not part of Claude Code and it
is not the scheduler. It restricts what you can read and write, brokers every SLURM command,
and proxies outbound network.

**Read this first, because husk is the layer you can see and the other layers are not.** When
something is refused, the temptation is to conclude the filesystem is read-only, the site is
down, or SLURM is misconfigured. Sometimes that is right. Often it is husk. An agent that
guesses here rewrites a run script that was never broken.

## The one-minute model

| | |
|---|---|
| **Filesystem** | read-only except a declared writable set; home directories are hidden |
| **SLURM** | you talk to a broker, not to `sbatch`. It constructs its own submission |
| **Network** | outbound goes through a proxy with a host allowlist, or is off entirely |
| **Jobs** | run in a second cage on the compute node, with their own writable set |

**Any line that starts with `husk:` is husk speaking.** It names the layer, the reason and
usually the remedy; it is a standing policy decision, not an outage; and it is byte-identical
if you retry. Read it rather than working around it. husk announces all of the above — **the
job banner is the single most useful thing to read**, see below.

## Errors that do NOT say `husk`

These are the ones that get misdiagnosed, because the kernel or the tool answers in its own
name. Look for your exact string here before forming a theory.

| what you saw | what it actually is |
|---|---|
| `Read-only file system` on a write | outside husk's writable set — §3 |
| a directory that reads EMPTY, or `ENOENT` under a home | husk is hiding it — §2 |
| `Permission denied` / an empty read on a `.env`, `.key` or `credentials` file | husk's credential mask — §1 |
| `curl: (56) CONNECT tunnel failed, response 403` | the host is not on the allowlist — §4 |
| the same, but `response 503` | this job's egress connection budget — §4 |
| `curl: (7) Failed to connect to … port 3128` | husk's own proxy is DOWN — §4 |
| `Device or resource busy`, `inter-device move failed` | a bind mount — §6 |
| `unable to unlink old '<file>'` during a merge/rebase | the same, and your tree is now half-updated — §6 |
| `error while loading shared libraries` inside an `srun` step | `LD_LIBRARY_PATH` is stripped per step — §4c |
| a command that dies with no output, exit 159 or `Bad system call` | husk's seccomp filter — "Things that will waste your time" |
| `Author identity unknown` from git | `.gitconfig` is masked — same section |
| `EINVAL` from `copystat` / `copytree` / `spack install` | an ACL naming a group the cage cannot map — same section |
| a job that exits 1 with an empty output file | possibly husk's run-time output guard — "If a job dies" |
| `sbatch: error: timed out after 120s waiting for the SLURM broker` | husk's broker, not SLURM — "Submitting jobs" |

## Your tool set is Bash and almost nothing else

**You have `Bash`, `Skill`, `Agent`, `AskUserQuestion` and the task-list tools. You do not
have `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` or `WebSearch`.** This is deliberate
and it is not a misconfiguration to report: those tools run in the agent process on the host,
*beside* the cage, so nothing husk mounts applies to them. Bash runs *inside* it. Routing
everything through Bash is what makes the boundary mean anything.

So use the shell for what those tools would do:

| instead of | use |
|---|---|
| `Read` | `cat`, `sed -n '10,40p'`, `head` |
| `Grep` / `Glob` | `grep -rn`, `rg`, `find` |
| `Write` / `Edit` | a heredoc (`cat > f <<'EOF'`), or `python3` for in-place edits |

This file tells you to "ask the human" in several places. `AskUserQuestion` is how, when there
is a human attending; otherwise say it plainly in your reply and stop.

**Memory is the trap, and the honest answer is that it does not work.** Your instructions tell
you to write memory files with the `Write` tool, which you do not have — and the shell route
does not save you either: `~/.claude/projects` is bound read-only by the harness itself, on top
of any carve-out, so a heredoc there fails with `Read-only file system`. Your session
*transcript* still works, because the harness writes that rather than you, which is why the two
appear to disagree. **Put durable state in a file in the project directory instead**, and say so
in your friction log rather than assuming you did it wrong.

Subagents inherit this same tool set, including ones you define yourself — so a subagent
cannot do file I/O you cannot do.

## When something is refused

### 1. Read the banner

Every brokered job prints one at the top of its output. Abridged here; the real one is longer
and is the authority:

```
husk: compute cage active - the filesystem is READ-ONLY except:
husk:   /scratch/you/project  (project dir: where husk was launched)
husk: reads are mostly unrestricted, with three deliberate gaps:  [...]
husk: masked (they read as empty or refuse - credential-named files and
husk: auto-exec files husk protects, e.g. .git/hooks):
husk:   /scratch/you/project/var3d.env
husk: this job HOLDS: nodes=1 ntasks=64 cpus-per-task=1 cpus-on-node=64
husk: this job RUNS AS: partition=normal account=csxx
husk:   uenv=/user-environment view=icon
husk: network: ...
husk: husk's own log for this job: /users/you/.husk/log/job-123456.log
```

The lines that answer the questions costing the most time:

- **`masked`** — husk hides files whose *names* look like secrets, and files it protects from
  being auto-executed. It is a heuristic and it is sometimes wrong. If a file you need is on
  that list and is not a secret, rename it (`var3d.env` → `var3d_modules.sh`) or ask your
  operator to name the real secrets in `sandbox.credentials.files`, which then become the only
  ones masked. **A masked file reads as empty or refuses — it does not say why.**
- **`this job HOLDS` / `RUNS AS`** — what SLURM actually gave you, and the partition, account
  and uenv husk resolved. husk forces `--nodes=1`, `--export=ALL`, `--open-mode=append` and the
  output paths, and resolves `--partition`, `--account` and `--uenv` against your operator's
  allowlists. Everything else is passed through, so a mismatch there is upstream of husk —
  check your `#SBATCH` lines before blaming husk.
- **`husk's own log`** — husk's side of the story, shared with the step broker and the egress
  proxy. **You cannot read it**: it is in a home directory, which the cage hides. Ask the human
  to read it. That one sentence would have saved several afternoons.

### 2. A read that returns nothing is not the same as a missing file

Three different refusals look alike from inside:

- a hidden **directory** appears *empty*, not missing
- a masked **credential** reads as empty or refuses with `EACCES`
- anything under a hidden home is `ENOENT` — including a symlink that points into one, so
  `/oprusers/...` is unreadable because it resolves under `/users`

So "the file is not there" may mean "husk is hiding it." Check the banner's list before
concluding the data was not staged.

### 3. A write that fails with `Read-only file system` is husk

Not the filesystem, not a quota. Copy what the job needs into the writable set listed in the
banner.

### 4. A network request that fails is probably the allowlist

Outbound traffic goes through husk's proxy. **husk answers a `CONNECT`, and clients throw away
a `CONNECT` response body — so the explanation husk wrote never reaches you.** What survives is
the status code, and the reason phrase, which `curl -v` shows. The codes mean completely
different things:

| curl says | what it means | what to do |
|---|---|---|
| `(56) CONNECT tunnel failed, response 403` | proxy is UP, this host is not allowlisted | ask the human to add it to `sandbox.network.allowedDomains`; or use a host already allowed |
| `(56) … response 503` | proxy is UP, the host was never consulted: this **job** is at its cap of concurrent egress connections. The cap is per job, **every rank of a step shares one proxy**, and husk never times out an idle tunnel — so a client that pools keep-alive connections accumulates them | close what you are not using; serialise the fetches. The cap is derived from the proxy's open-file limit, so the human raises it with `ulimit -n` in the shell husk is launched from — no rebuild |
| `(56) … response 400`, `408` or `431` | `400`: you asked for a plain `http://` URL — husk tunnels HTTPS only. `408`/`431`: your CONNECT **request head** took over 15 s or over 8 KiB | use `https://`. The 15 s and 8 KiB are on the request head alone — an open tunnel is never timed out and a download is never size-capped, so this is not husk killing a slow transfer |
| `(7) Failed to connect to … port 3128` (connection refused) | the egress **proxy itself is DOWN** — nothing is listening | **not the allowlist and not the site.** You cannot fix it from inside: the proxy starts outside the cage and its log is under `~/.husk/log`, hidden from you. **Report it** with the exact `curl -v` tail and stop — no host, mirror or retry will reach the network until it is restarted (usually a fresh session) |

Do not retry, do not switch mirrors, and do not report any of these as "the cluster network is
broken" or "the site is down". If the job has no network at all, the banner says so — fetch
what you need *before* submitting, into the writable set.

### 4b. A credential-named file in your WORKDIR is not reliably hidden

Home is masked (it reads empty), and that is the real protection for secrets. But a file named
like a credential (`*.pem`, `*.key`, `credentials`, `.netrc`, …) that sits in the **project /
scratch dir** is only best-effort protected on Linux: husk's globs do not bind at the mount
layer there, so a plain `cat file.pem` may be denied while `cat *` reads it. **Do not stage
secrets in the working directory** — keep them in home, which husk hides. If you find yourself
reading a credential from the workdir, that is a gap, not a licence: stop and tell the human.

### 4c. An `srun` step does not inherit `LD_LIBRARY_PATH` from the batch job

Deliberate: the rank's environment is yours to set, and `LD_LIBRARY_PATH` there could hijack the
rank launcher, so husk strips it on the step path. If a rank fails with `error while loading
shared libraries`, set the library path **inside the workload** (in the script the step runs), or
use a uenv, which carries its stack through a different variable. This is not the proxy being
down and not the cluster missing libraries.

### 5. A write into a HIDDEN directory succeeds — and then is not there

**The most expensive trap in husk, because everything says it worked.** Home directories and
`denyRead` paths are replaced by an empty in-memory filesystem. Writing into one:

```
$ echo hello > ~/test.txt ; echo rc=$?
rc=0
$ ls -l ~/test.txt ; cat ~/test.txt
-rw-r--r-- 1 you you 6 ... /users/you/test.txt      # it is there
hello                                               # and readable
```

**None of it persists.** Each Bash command gets its own private copy of that empty filesystem,
so the file is gone from the next command onwards, and it never existed for anyone outside.
The banner says a write outside the writable set fails with `Read-only file system` — that is
true of *read-only* paths, and NOT of hidden ones, which accept the write and discard it.

**So never report a write to a hidden path as done.** Verify in a *separate* command, or
better, do not write there. If a human asks you to put a file in their home directory, say that
you cannot and offer the project directory instead — an agent reporting "done" with an `ls -l`
to prove it is how this costs somebody an afternoon.

### 6. `Device or resource busy` or `inter-device move failed` means a bind mount

The cage is built out of bind mounts, and **around thirty of them land inside your project
directory** — the protected files and directories: `.claude/*`, `.mcp.json`, `.git/hooks`,
`.git/config`, `.gitmodules`, shell rc files. A mounted path is not an ordinary file. You
cannot unlink it, replace it, rename over it, or `rm -rf` a directory containing one.

The errors it produces name the kernel, never the sandbox:

| you did | you get |
|---|---|
| `rm -rf` a dir containing one | `Device or resource busy` |
| `mv` over or across one | `inter-device move failed … Read-only file system` |
| write to one | `Read-only file system` |
| git replaces one during a merge | `unable to unlink old '<file>': Device or resource busy` |

**Check before theorising.** One command tells you whether a path is mounted:

```
grep <filename> /proc/mounts          # is this specific path mounted?
grep " $PWD" /proc/mounts             # everything mounted under your project
```

**You cannot remove these from inside, and asking for them to be removed is usually not the
answer either** — some are husk's, some are Claude Code's own, and the distinction changes
nothing about what you can do. Report it.

**The part that can cost you a working tree.** Some operations fail *partway through*.
`git merge`, `rebase` and `checkout` rewrite many files and only then discover they cannot
replace `.gitmodules` — so the tree is left half-updated, and `git merge --abort` does not
restore it. **Stop there.** Do not repair the tree by hand, and do not `reset --hard` on a
guess: say exactly which operation failed and quote the error. That step needs to be run
outside the sandbox, which only the human can do.

The general rule this is an instance of: **an OS error inside husk is more often a mount than
a bug.** Reach for `/proc/mounts` before you conclude that git, the filesystem or the cluster
is broken.

## Submitting jobs

`sbatch`, `squeue`, `sacct`, `sinfo`, `sstat`, `sprio`, `sreport`, `sshare` and `scancel` are
brokered: husk validates the request and constructs its own submission. Consequences worth
knowing:

- **`sbatch --parsable` works** — use it when a script needs the job id, and it works
  written as `#SBATCH --parsable` in the script header too.
- **`sbatch --quiet` / `-Q` works** — it suppresses husk's own advisory lines on stderr. Like
  `--parsable` it is honoured by husk rather than forwarded, so the generated list below shows
  it under "ACCEPTS but does NOT APPLY"; that is where it sits in the registry, not what
  happens. (That list excepts only `--parsable` because it is generated and one edit behind —
  `C1-5`. Delete this parenthesis when the generator is fixed.)
- **An option written AFTER the script path is an argument to the SCRIPT, not to sbatch.**
  `sbatch job.sh --parsable` prints the human line, not a bare id — real sbatch reads it the
  same way, and husk says so on stderr. Put sbatch options before the script path.
- **Options husk drops are announced on stderr from EITHER channel.** `--mail-user` on the
  command line and `#SBATCH --mail-user` in the header both produce the note, and the note
  says which of the two it read.
- **`sbatch --wait` is refused.** husk cannot block until a job finishes. Poll with
  `squeue -j <id>` or `sacct -j <id> -o State`.
- **Job mail is never sent**, whatever `--mail-user` says.
- **Multi-node is refused**, with an explanation. Single-node multi-rank MPI works fully,
  including GPUs and shared memory. If the science genuinely needs multiple nodes, that is a
  conversation with the human — it is a containment decision, not a bug.
- **`#SBATCH` directives in the script body are read and honoured**, and are merged with
  command-line options the way real sbatch does (command line wins).
- **`sbatch: error: timed out after 120s waiting for the SLURM broker`** is husk's broker not
  answering, not SLURM being down — and note it wears sbatch's name. Do not resubmit blindly:
  check `squeue -u $USER` first, because a job may already be queued.

### Set variables INSIDE the job script — exporting before `sbatch` does not work

This is the one that has cost real runs, because nothing fails: the job runs and the variable
is simply not there.

- **The job's environment is the BROKER's, not yours.** husk builds the submission in a
  trusted process outside the cage and clears the environment first, so what reaches the job
  is the shell *the human launched husk from*, filtered through an allowlist. `export
  ICON_REPORT_AFFINITY=1` in your Bash command sets it in the cage, and the cage is not where
  `sbatch` really runs.
- **`--export=ALL,VAR=val` loses the `VAR=val` half.** husk forces `--export=ALL` because the
  uenv view lives in `PATH`, and it says so on stderr.
- **A few names are never forwarded at all**, including the `SLURM*` variables husk's
  compute-node guard reads to work out which file SLURM will open — `SLURM_JOB_ID`,
  `SLURM_STEP_ID`, `SLURM_ARRAY_JOB_ID`, `SLURM_ARRAY_TASK_ID`, `SLURMD_NODENAME`,
  `SLURM_NODEID`, `SLURM_LOCALID`. Only slurmd may set those for a job.

**So put the assignment in the script**, or write the values to a file the workload reads.
The same applies inside a step: if a job script sets more than 512 variables, or more than
256 KiB of them, or any single value over 64 KiB, husk carries what fits and the rest are
**not set in the ranks** — it names where it stopped, but only in its own job log, which you
cannot read.

### `--output`, `--error` and `--chdir` accept less than SLURM does

husk re-derives your output filename on the compute node, so that it can check what SLURM is
really about to open. It therefore only accepts specifiers it can expand itself:

**`%j %A %a %N %n %t %s %u`**, plus letters, digits and `._+-`, in the filename only.

Everything else is refused at submit time, in a second, with a message that names the reason
and the current set — including `%x` (the job name), `%J`, and `%%`. `%A` and `%a` are refused
unless the *same submission* carries `--array`. A `%` anywhere in `--chdir`, or in a
*directory* component of `--output`, is refused too. When in doubt use `%j`, which every job
has. Choosing from that set as you write the script costs nothing; discovering it after a
queue wait costs a round trip.

### `srun` inside a job is brokered too, with a smaller option set

It forces `--nodes`, `--chdir`, `--output`, `--error` and `--mpi`; it refuses by name anything
that runs code outside the command it wraps (`--prolog`, `--epilog`, `--task-prolog`,
`--task-epilog`, `--multi-prog`, `--bcast`), and also `--pty`, `--export` and
`--get-user-env`; and it refuses any option it does not model rather than forwarding it. The
refusal names the option. An option that is fine in an `#SBATCH` line can therefore still be
refused by the `srun` that has to run the step — set what a rank needs *inside the workload*.

**If the job output opened with `husk: NOT using … as this job's step spool`, or with
`husk: could not create …`, then `srun` is not brokered in that job at all** — the real `srun`
answers instead and fails with a scheduler-shaped error (no route, no credentials). That is
the earlier refusal arriving late, not a cluster fault. Read the top of the job output before
believing an `srun` error.

<!-- BEGIN GENERATED: husk-slurm-broker --print-option-contract -->
<!-- Regenerate with skill/build.sh — do not edit by hand. -->

### husk FORCES these — your value is discarded and husk emits its own

`--partition` / `-p`, `--output` / `-o`, `--error` / `-e`, `--chdir` / `-D`, `--open-mode`, `--export`, `--uenv`, `--view`, `--repo`, `--wrap`, `--nodes` / `-N`, `--account` / `-A`

These are the security-relevant ones. Setting them is not an error; it simply has no effect, and husk announces what it forced.

**Two of those are selections, not overrides.** `--partition` and `--account` are resolved against a set your operator configured: name one from the set and husk emits that entry; name one outside it and husk refuses and lists the set; name none and husk picks the first and says so. The bytes that reach sbatch are always husk's own copy, which is why they are listed here rather than as pass-throughs.

### husk PASSES THROUGH these, after checking the value

`--ntasks` / `-n`, `--ntasks-per-node`, `--ntasks-per-core`, `--ntasks-per-socket`, `--cpus-per-task` / `-c`, `--cpus-per-gpu`, `--hint`, `--threads-per-core`, `--sockets-per-node`, `--cores-per-socket`, `--gpu-bind`, `--mem-bind`, `--oversubscribe` / `-s`, `--time` / `-t`, `--time-min`, `--deadline`, `--begin`, `--mem`, `--mem-per-cpu`, `--mem-per-gpu`, `--gres`, `--gpus` / `-G`, `--gpus-per-node`, `--gpus-per-task`, `--gpus-per-socket`, `--constraint` / `-C`, `--nodelist` / `-w`, `--exclude` / `-x`, `--array` / `-a`, `--dependency` / `-d`, `--job-name` / `-J`, `--comment`, `--distribution` / `-m`, `--signal`, `--switches`, `--exclusive`, `--requeue`, `--no-requeue`, `--hold` / `-H`, `--overcommit` / `-O`, `--spread-job`, `--use-min-nodes`, `--contiguous`

Values are charset-checked (no whitespace, no shell metacharacters) and re-emitted canonically. If one is refused, the message names the option.

### husk ACCEPTS but does NOT APPLY these

`--parsable`, `--quiet` / `-Q`, `--verbose` / `-v`, `--mail-type`, `--mail-user`

The submission succeeds and the option is not forwarded to sbatch. husk says so on stderr — read it, because this is where a script quietly does the wrong thing. Job mail in particular is never sent, and `--mail-user` would be a way out of the cluster that husk's egress allowlist cannot see.

**Exception: `--parsable` IS honoured.** There is nothing to forward — husk builds its own sbatch invocation — but it is an output contract, so the stub prints the bare job id as you asked. `jobid=$(sbatch --parsable job.sh)` works. It appears in this list because of where it sits in the registry, not because it is ignored.

### husk REFUSES these, with a reason

- `--qos` / `-q` — husk does not let a job choose its QOS: the partition husk forces is what bounds what this job may consume, and a QOS moves those limits out from under it. Submit without --qos. If your work genuinely needs a different QOS, that is a decision for whoever configured husk, not for this job.
- `--reservation` — husk does not let a job claim a reservation: reserved nodes are set aside for particular people and particular work, and a brokered job is neither. Submit without --reservation.
- `--wait` / `-W` — husk cannot block until a job finishes: the broker answers each request and returns, so --wait would exit immediately and your script would treat a queued job as a completed one. Submit without it and poll with `squeue -j <id>` or `sacct -j <id> -o State`.

Anything not listed anywhere is refused as an unsupported option: husk submits an explicit set and rejects what it does not model, so a new option is a conversation with your operator rather than a silent pass-through.

<!-- END GENERATED -->

## Things that will waste your time if you do not know them

- **Everything is SLOWER in here, and that is husk, not the machine.** Every Bash command is
  wrapped in a fresh sandbox — a new namespace, a mount table rebuilt from the settings, and a
  seccomp filter installed before your command runs — so the per-command overhead is paid on
  every call, including trivial ones. Syscall-heavy work feels it most: large `find` or `grep`
  sweeps, builds, anything touching many small files.

  What it costs you is not the seconds, it is the WRONG DIAGNOSIS: a slow `ls` reads like a
  sick filesystem or a hung node, and hours have gone into investigating a cluster that was
  fine. If something is slower than you expect and nothing has failed, do not start diagnosing
  the site. Prefer fewer, larger commands, and say so in your friction log.

- **A command that dies with no output at all, exit 159 or `Bad system call`, hit husk's
  seccomp filter.** In a brokered job husk's guard says so and names the usual suspects. Two
  things that will not help: `strace` dies the same way, because `ptrace` is blocked too; and
  there is **no core file**, because husk sets `RLIMIT_CORE` to zero in both cages on purpose
  (a blocked syscall is a core-generating signal, and one 288-rank job left 288 cores). `ulimit
  -c unlimited` cannot undo it. Reproduce the command *outside* husk — on the login node, no
  husk — and hand over the trace.
- **`rm -rf` on a directory you have `cd`'d into can fail with `Device or resource busy`.** The
  runtime puts bind mounts in working directories. Use a fresh directory name rather than
  fighting it.
- **Background processes started with `nohup … &` are killed between tool calls.** A build
  interrupted this way can leave a zero-length object file that `make` then considers current,
  producing a link error much later. Use the harness's own background mechanism.
- **A `config/` directory in your project root is bind-mounted READ-ONLY.** Measured. It is an
  ordinary directory name — autotools projects write `config/config.h` there and `./configure`
  dies without it — and the failure arrives as `Read-only file system` or
  `mv: inter-device move failed`, naming nothing. It cost one session a whole build.
  Confirm with `grep " $PWD" /proc/mounts`. Work in a directory one level up, or have the
  human relocate the build; you cannot unmount it from inside.
- **A `git merge`/`rebase`/`checkout` that rewrites `.gitmodules` fails PARTWAY THROUGH and
  cannot be aborted cleanly** — see §6 above, and recognise it by its error alone:
  `unable to unlink old '.gitmodules': Device or resource busy`.
- **`git commit` may fail with "Author identity unknown"** — `.gitconfig` is masked. Set
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_*` in the environment.
- **A from-scratch build that dies where an incremental one worked may be the ACL problem.**
  Files here can carry a POSIX ACL naming a group the sandbox cannot map (it shows as group
  `4294967295`), so anything that copies an ACL fails with `EINVAL`: `shutil.copystat`,
  `copytree`, `setfacl`, and therefore `spack install`. husk warns at session start and cannot
  fix it — an unprivileged sandbox maps exactly one group. Copy with `cp`/`shutil.copy`
  (contents only), not `copy2`/`copystat`. Under `set -e` the symptom surfaces much later and
  looks unrelated, so check the build reached its final step.
- **`/dev/shm` is RAM.** Staging data there consumes your job's memory allocation, and SLURM
  will kill the job for exceeding it. That kill comes from SLURM, not husk, and looks like a
  node fault. Use the project directory for staging.
- **`scontrol` and `sacctmgr` are not brokered and cannot reach the controller.** You cannot
  check partition limits or QOS from inside; ask the human.

## If a job dies and nothing says why

husk's guard prints a last line on every path it controls:

```
husk: job guard finished (rc=N)
```

**If that line is missing, husk never reached the end of the job.** There are two very
different reasons, and the output file tells them apart:

**The output file has your job's output in it, then stops.** The job was killed in a way
nothing inside it could catch — the OOM killer, a cgroup limit, `scancel -9`. That is not
husk refusing you, and husk cannot report it, because the process was gone before any handler
could run. Do not read it as a transient node fault and retry: a previous session did exactly
that and burned a second 128-rank allocation. Ask for:

```
sacct -j <jobid> -o State,ExitCode,MaxRSS,ReqMem
```

`State=OUT_OF_MEMORY` with `MaxRSS` near `ReqMem` is the common one. Remember that `/dev/shm`
counts against your memory allocation.

**The output file is empty (or absent) and the job exited 1.** This can be an ordinary script
that failed on its first line — but if the script is sound, suspect husk's output guard. On the
compute node husk re-checks that the file SLURM is about to open really is the one it confined
at submit time, and refuses the whole job if it cannot show that: a directory or leaf that
became a symlink, gained a second hard link, or resolved outside the writable set after you
submitted. **The explanation goes to husk's own job log, which you cannot read.** Ask the human
for `~/.husk/log/job-<jobid>.log` and look for a `JOB REFUSED` block; it names the path and the
reason. Your body did not run and `--open-mode=append` means nothing was truncated, so
resubmitting to a clean path is safe — but find out why first, because a name that changed
under you is worth knowing about.

If the job was *trapped* instead — preemption, the wall limit, `scancel` — husk prints a
loud block saying the output is INCOMPLETE. Believe it: a model that does not checkpoint
leaves an output directory that looks like a finished run.

## What to do when you are stuck

1. **Read the banner and husk's messages.** They name the layer and usually the remedy.
2. **Say which layer you think refused you, and why.** "husk refused X because Y" is
   actionable; "the cluster seems broken" is not, and is usually wrong.
3. **Do not route around a control.** A husk refusal is standing policy and will be identical
   on retry. If the work genuinely needs what was refused, say so and let the human decide.
4. **If a command hangs with no output, say so early.** husk's failure modes are loud, so
   silence is itself information — and a hang is the one shape that has repeatedly turned out
   to be a husk bug rather than a policy.

## Before you finish a long session: offer a friction log

If husk got in your way — a refusal you had to work around, an error that cost you a wrong
diagnosis, a job that died without saying why — **tell the user at the end of the session and
offer to write it up.** Write `SANDBOX_FRICTION.md` in the project directory only if they say
yes, or if there is nobody to ask. The project directory is somebody's real checkout, and an
uninvited file in it is a cost of its own.

What makes one useful: **ordered by cost to the work**, with what you tried, what the error
actually said, and what you worked around it with. Include the things you decided were
reasonable, and say so — the distinction between "this policy cost me time and is probably
right" and "this looks like a bug" is the most useful judgement you can offer.

This is not a formality. Friction logs from real sessions have found more defects in husk than
its security reviews have, because real work goes where nobody thought to look.
