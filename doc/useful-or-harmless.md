# Useful or harmless, pick one

*A note on deferred execution, and why sandboxing an agent on an HPC system is harder than
sandboxing one on a laptop.*

## The principle

Fefe's formulation is that a program is either **nützlich** or **unbedenklich** — useful or
harmless — and rarely both. The reason is not cynicism, it is definitional. A tool is useful
because it can *effect change*: run your build, format your paper, drive your simulation. The
capacity to effect change is the same capacity an attacker wants. Remove it and the tool stops
being worth installing.

The corollary that matters for sandboxing: **every tool worth using every day has an extension
mechanism, and every extension mechanism is an interpreter.** Nobody sets out to ship an
interpreter. They ship a config file, and then someone asks for a conditional, and then for a
variable, and then for "just run this command when X happens" — and now the config file is a
program.

And because the tool must be convenient, it reads that config **from the current working
directory**. Convenience is the attack surface.

## The shape of the exploit class

A sandbox confines a **process**. It does not confine **data that some other program will
later interpret**.

```
   inside the cage                    outside the cage, later
   ───────────────                    ───────────────────────
   job writes a config file    ─────► human runs an ordinary tool
   (allowed: it is a file           ► tool reads the config
    in a writable directory)        ► config says "run this"
                                    ► it runs, as the human, uncaged
```

Three properties make it awkward:

1. **It crosses time.** The write is innocuous when it happens. Execution is a separate event,
   possibly days later.
2. **It crosses identity.** It runs as the human, with the human's credentials, network and
   filesystem — not as the confined job.
3. **It crosses the boundary in the one direction sandboxes do not watch.** Everyone checks
   what a process can *read* and *do*. This is about what it can *leave behind*.

Nothing escaped. The cage held perfectly. The payload simply waited for someone to carry it
out by hand.

## A worked example

From the husk v0.5 security review — demonstrated, not hypothesised, against the shipped
default configuration:

```bash
# inside the cage, in a writable project directory with no repository in it
mkdir -p .payload
printf '#!/bin/sh\necho PWNED as $(whoami)\n' > .payload/post-commit
chmod +x .payload/post-commit
printf '[core]\n\thooksPath = %s/.payload\n' "$PWD" > .git/config
```

Later, on the login node, the scientist does what scientists do:

```
$ git init
$ git commit -m "results from last night"
PWNED as christoph
```

`git init` **preserves** an existing config. `core.hooksPath` redirects hooks anywhere on the
filesystem. Neither is a bug in git — both are documented, useful features that people rely
on. The sandbox did its job; git did its job; the composition is the hole.

## Why HPC is the hard case

A laptop developer runs a handful of tools. A computational scientist's daily path is
*unusually* dense with interpreters, and most of them read from the working directory:

| tool | the interpreter you forgot about |
|---|---|
| git / Mercurial | `core.hooksPath`, `[hooks]` in `.hg/hgrc` |
| R | `.Rprofile`, sourced from cwd at startup |
| Python | `sitecustomize.py`, `.pth` files, `PYTHONSTARTUP`, `setup.py` at install |
| Make / CMake | the build file *is* a program |
| LaTeX | `\write18`, shell-escape |
| Jupyter | startup scripts in the profile directory, `kernel.json` |
| vim / emacs | modelines, `.exrc`, `.dir-locals.el` |
| gdb | `.gdbinit` |
| the shell | `.bashrc`, `.profile`, `ENV`, `BASH_ENV` |
| SLURM | `--prolog`/`--epilog`, `#SBATCH` directives, job scripts |
| the linker | `LD_PRELOAD`, `LD_LIBRARY_PATH` |
| module systems | modulefiles are Tcl or Lua — a full language, by design |

Two of these deserve a note.

**Module systems are the purest case.** A modulefile is *literally a program*, in a real
language, executed to compute your environment. Nobody considers this a vulnerability; it is
the feature. Environment Modules chose Tcl because a table of key-value pairs was not useful
enough.

**Subversion is the counter-example, and it is instructive.** SVN has no client-side hooks —
hooks live server-side in the repository. So a `.svn` working copy executes nothing, and the
attack does not exist there. SVN is *less useful* than git in exactly this respect, and
therefore *more harmless*. That is the trade in one sentence, and it is why guessing "there's
probably an SVN version of this" is reasonable and, in this instance, wrong.

## Why a denylist cannot close it

The obvious defence is to mask the dangerous files. This is what husk does, and it works — for
the entries on the list.

But the list is a **denylist**, and a denylist is a bug list: it enumerates what you thought
of. Every new tool, every new version that adds a config hook, every language ecosystem
someone brings to the cluster, arrives before the list does. Two traps show up immediately,
both paid for in the husk review:

- **Protected-if-present is not protection.** Binding a config file read-only "if it exists"
  leaves every file that does not *normally* exist wide open — and those are precisely the
  ones an attacker creates.
- **Do not create the thing you are defending.** Masking a path *inside* `.git` makes the
  sandbox create `.git` itself, manufacturing the repository the attack needed.

## What actually closes it

Three honest options, in increasing order of cost:

1. **Narrow what persists.** Stage the job's output and filter on the way out, instead of
   binding a directory writable. Expressible by construction — "no dot-entries created at the
   root of a writable directory" — but it is not something mount namespaces can say, so it
   means real plumbing and a change to how the tool feels.
2. **Narrow who interprets.** Run the human's tools in a cage too. This is correct and
   recursive: now you are sandboxing git, R and make, and the same argument applies to them.
3. **Narrow the ground.** Make the writable root a directory a human deliberately chose and
   understands. This is not a technical control, and it is the one doing most of the work in
   practice. It is why husk refuses to run with a home directory as its write root — a home is
   full of auto-exec files nobody enumerated — and why it announces the writable set on every
   job.

## The point for the talk

Sandboxing an AI agent is usually presented as *containment*: keep the process in the box. On
a shared research system the interesting failure is not the process getting out. It is the
process **writing a sentence that a trusted program reads later** — and every genuinely useful
tool in the room is willing to read that sentence, because being willing is what made it
useful.

You cannot have an ecosystem of powerful, extensible, convenient tools *and* a boundary that
holds by enumeration. Pick two of useful, extensible, contained — and know which one you gave
up.
