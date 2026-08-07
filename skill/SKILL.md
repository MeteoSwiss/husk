---
name: husk
description: Working inside husk, the sandbox that wraps this agent on CSCS supercomputers, and submitting jobs through its SLURM broker. Use when a file read or write is refused, a network request fails, an `sbatch`/`squeue`/`srun` behaves unexpectedly, a job seems to get the wrong resources, or a command hangs with no explanation — and read it BEFORE concluding that the cluster, the filesystem or a website is broken.
---

# You are running inside husk

husk is a sandbox that wraps this agent from the outside. It is not part of Claude Code and it
is not the scheduler. It restricts what you can read and write, brokers every SLURM command,
and proxies outbound network.

**Read this first, because husk is the layer you can see and the other layers are not.** When
something is refused, the temptation is to conclude the filesystem is read-only, the site is
down, or SLURM is misconfigured. Sometimes that is right. Often it is husk, and husk will tell
you so if you look in the right place. An agent that guesses here rewrites a run script that
was never broken.

## The one-minute model

| | |
|---|---|
| **Filesystem** | read-only except a declared writable set; home directories are hidden |
| **SLURM** | you talk to a broker, not to `sbatch`. It constructs its own submission |
| **Network** | outbound goes through a proxy with a host allowlist, or is off entirely |
| **Jobs** | run in a second cage on the compute node, with their own writable set |

husk announces all of this. **The job banner is the single most useful thing to read** — see
below.

## When something is refused

### 1. Read the banner

Every brokered job prints one at the top of its output:

```
husk: compute cage active - the filesystem is READ-ONLY except:
husk:   /scratch/you/project  (project dir: where husk was launched)
husk: a write outside the list above fails with 'Read-only file system'
husk:   - that is husk, not the filesystem.
husk: reads are mostly unrestricted, with three deliberate gaps:
husk:   home directories are hidden (they look EMPTY, not missing),
husk:   configured denyRead paths are hidden the same way, and
husk:   credential files read as empty or refuse with EACCES.
husk: masked as credentials (they read as empty or refuse):
husk:   /scratch/you/project/var3d.env
husk: this job HOLDS: nodes=1 ntasks=64 cpus-per-task=1 cpus-on-node=64
husk: network: ...
husk: husk's own log for this job: /users/you/.husk/log/job-123456.log
```

Three of those lines answer the questions that cost people the most time:

- **`masked as credentials`** — husk hides files whose *names* look like secrets. It is a
  heuristic and it is sometimes wrong. If a file you need is on that list and is not a secret,
  rename it (`var3d.env` → `var3d_modules.sh`) or ask your operator to declare the real
  secrets explicitly. **A masked file reads as empty or refuses — it does not say why.**
- **`this job HOLDS`** — what SLURM actually gave you. If it does not match what you asked
  for, compare it against your `#SBATCH` lines *before* blaming husk; husk forces only a
  short list (below) and passes the rest through.
- **`husk's own log`** — husk writes its side of the story there. **You cannot read it**: it is
  in a home directory, which the cage hides. Ask the human to read it. That one sentence would
  have saved several afternoons.

### 2. A read that returns nothing is not the same as a missing file

Three different refusals look alike from inside:

- a hidden **directory** appears *empty*, not missing
- a masked **credential** reads as empty or refuses with `EACCES`
- anything under a hidden home is `ENOENT`

So "the file is not there" may mean "husk is hiding it." Check the banner's list before
concluding the data was not staged.

### 3. A write that fails with `Read-only file system` is husk

Not the filesystem, not a quota. Copy what the job needs into the writable set listed in the
banner.

### 4. A network request that fails is probably the allowlist

Outbound traffic goes through husk's proxy. A host that is not on the operator's allowlist
fails as:

```
curl: (56) CONNECT tunnel failed, response 403
```

or a `403` from the proxy. **That is husk, not the site being down.** Do not retry, do not
switch mirrors, do not conclude the network is flaky. Ask the human to add the host to
`sandbox.network.allowedDomains`. If the job has no network at all, the banner says so — fetch
what you need *before* submitting, into the writable set.

## Submitting jobs

`sbatch`, `squeue`, `sacct`, `sinfo` and `scancel` are brokered: husk validates the request and
constructs its own submission. Consequences worth knowing:

- **Every refusal that starts with `husk:` is a policy decision, not an outage.** It will be
  identical if you retry. Retrying is never the fix; the message says what is.
- **`sbatch --parsable` works** — use it when a script needs the job id.
- **`sbatch --wait` is refused.** husk cannot block until a job finishes. Poll with
  `squeue -j <id>` or `sacct -j <id> -o State`.
- **Job mail is never sent**, whatever `--mail-user` says.
- **Multi-node is refused**, with an explanation. Single-node multi-rank MPI works fully,
  including GPUs and shared memory. If the science genuinely needs multiple nodes, that is a
  conversation with the human — it is a containment decision, not a bug.
- **`#SBATCH` directives in the script body are read and honoured**, and are merged with
  command-line options the way real sbatch does (command line wins).

<!-- BEGIN GENERATED: husk-slurm-broker --print-option-contract -->
<!-- Regenerate with slurm-broker/skill/build.sh — do not edit by hand. -->

### husk FORCES these — your value is discarded and husk emits its own

`--partition` / `-p`, `--output` / `-o`, `--error` / `-e`, `--chdir` / `-D`, `--open-mode`, `--export`, `--uenv`, `--view`, `--repo`, `--wrap`, `--nodes` / `-N`, `--account` / `-A`

These are the security-relevant ones. Setting them is not an error; it simply has no effect, and husk announces what it forced.

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

- **`rm -rf` on a directory you have `cd`'d into can fail with `Device or resource busy`.** The
  runtime puts bind mounts in working directories. Use a fresh directory name rather than
  fighting it.
- **Background processes started with `nohup … &` are killed between tool calls.** A build
  interrupted this way can leave a zero-length object file that `make` then considers current,
  producing a link error much later. Use the harness's own background mechanism.
- **`~/.claude` is not writable**, so agent memory does not persist. Put durable state in a
  file in the project directory.
- **`git commit` may fail with "Author identity unknown"** — `.gitconfig` is masked. Set
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_*` in the environment.
- **`scontrol` and `sacctmgr` cannot reach the controller.** You cannot check partition limits
  or QOS from inside; ask the human.

## What to do when you are stuck

1. **Read the banner and husk's messages.** They name the layer and usually the remedy.
2. **Say which layer you think refused you, and why.** "husk refused X because Y" is
   actionable. "The cluster seems broken" is not, and is usually wrong.
3. **Do not route around a control.** A husk refusal is standing policy; the same command will
   be refused identically. If the work genuinely needs what was refused, say so plainly and let
   the human decide.
4. **If a command hangs with no output, say so early.** husk's failure modes are usually loud,
   so silence is itself information — and a hang is the one shape that has repeatedly turned
   out to be a husk bug rather than a policy.

## Before you finish a long session: write a friction log

If you have been working for a while, write `SANDBOX_FRICTION.md` in the project directory:
everything the sandbox made harder, **ordered by cost to the work**, with what you tried, what
the error actually said, and what you worked around it with. Include the things you decided
were reasonable, and say so — the distinction between "this policy cost me time and is
probably right" and "this looks like a bug" is the most useful judgement you can offer.

This is not a formality. Friction logs from real sessions have found more defects in husk than
its security reviews have, because real work goes where nobody thought to look.
