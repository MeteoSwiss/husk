# Upstream: a gitignored nested repo gets no git protections at all; a discovered one gets half

**Status:** drafted 2026-09-01, not yet filed.
**Where:** Claude Code sandbox — `linuxGetMandatoryDenyPaths` in `linux-sandbox-utils.ts`, the
nested-repo discovery pass.
**Severity:** two independent holes, each ending in **writable `.git/config` or `.git/hooks`**,
which is arbitrary command execution (`core.sshCommand`, `core.pager`, `core.fsmonitor`,
`alias.*`; hooks execute directly). The protections are *present and working* on the paths the
scan finds — the defect is entirely in which paths it finds.

## Measured

Santis (CSCS, aarch64), 2026-09-01, inside a sandboxed session, project root
`<user>/icon-exclaim` — a workspace of three independent git repos, a layout its
`CLAUDE.md` documents as deliberate. From `grep git /proc/mounts` **inside the session**:

| path | mount |
| --- | --- |
| `<root>/.git` | **rw** |
| `<root>/.git/{config, config.lock, config.worktree, hooks}` | ro |
| `<root>/{.gitconfig, .gitmodules}` | ro |
| `icon4py/.git` | **rw** |
| `icon4py/.git/config` | ro |
| `icon4py/.git/hooks` | **absent** |
| `icon/` — anything at all | **absent** |

Both gaps confirmed by writing, not by reading the table — a shape check is not an
enforcement check:

```
$ git -C icon config --local husk.probe 1 && git -C icon config --local --unset husk.probe
                                                      # succeeded: config writable
$ touch icon4py/.git/hooks/husk-probe && rm icon4py/.git/hooks/husk-probe
                                                      # succeeded: hooks writable
```

## Gap 1 — enumeration asks git what it tracks, so anything gitignored is invisible

Nested repos are discovered with `rg --files --hidden --max-depth N --iglob '**/.git/config'`.
`rg --files` **honours ignore files**. The discriminator, measured:

```
$ git check-ignore -v icon      -> .gitignore:1:/icon/   rc=0
$ git check-ignore -v icon4py   -> (no output)           rc=1
$ cat .git/info/exclude         -> empty
```

`icon/` is gitignored, so ripgrep never lists it, so no deny path is ever constructed for it —
`config` **and** `hooks`, both writable. `icon4py/` is not ignored and was found. A tool that
*walks the tree* for `.git` directories finds both; one that asks git what it tracks finds only
the second. `icon/.git` is an ordinary directory, not a submodule pointer — there is no
`.git/modules` anywhere — so nothing exotic is required to reach this state.

**The self-reference is the serious part.** `.gitignore` is not in the protected set (`.gitconfig`
and `.gitmodules` are). So the sandboxed side can append one line to `.gitignore`, and on the
next session the named directory drops out of the scan and its `.git/config` becomes writable.
The confined party gets to author the rule that decides its own boundary. Here it happened by
accident, and because `.gitignore` is tracked and committed, **it reproduces for anyone who
clones this repository** — it is a property of the layout, not of one checkout.

## Gap 2 — a repo that *was* discovered still gets only half the protection

`icon4py/` was found. Its `config` was mounted ro. Its `hooks` was not. Enumeration does not
explain this one: the scan knew the repo existed.

The two protections travel by different routes. For the session root, hooks are added
unconditionally (`denyPaths.push(path.resolve(cwd, '.git/hooks'))`). For nested repos they are
found via the same ripgrep listing, using `--iglob '**/.git/hooks/**'` — which matches *files*
inside `hooks/`, so a hooks directory ripgrep lists nothing for yields no match and no deny
path. Whatever the precise cause on this checkout, the outcome is inverted against the threat
model: **the file that records identity is protected while the directory that executes code is
left writable, for a repo the scan can already see.**

## Reproducer

```bash
mkdir -p ws/inner && cd ws && git init -q . && git init -q inner
echo '/inner/' > .gitignore && git add .gitignore && git commit -qm x
# in a sandboxed session, from ws/:
grep git /proc/mounts                      # inner/.git/config absent
git -C inner config --local probe 1        # succeeds
```

## What integrators can and cannot do

Nothing, from outside. `allowGitConfig` only *widens* the deny — there is no setting that makes
the scan see an ignored directory, and no equivalent knob for hooks at all. Relocating the
checkout does not help; the ignore rule travels with the repository.

This matters to any integrator who relies on the mandatory deny list as a layer rather than
reimplementing it. husk does exactly that, and says so in its own source: *"Shell rc files,
`.gitconfig` and `.ripgreprc` are masked on the login side by the VENDOR's protected-file list,
so husk never needed its own copy of them."* husk's own compute-cage policy is unaffected — it
enumerates with `std::fs::read_dir` and no ignore semantics, so no ignore file can steer it —
but its **login** cage inherits both gaps whole.

## The change

In decreasing order of preference:

1. **Enumerate by walking for `.git` directories, not by asking git what it tracks.** The scan's
   subject is "repositories present on disk"; ignore files answer a different question. At
   minimum pass `--no-ignore-vcs` so a `.gitignore` cannot remove a path from a security scan.
2. **Apply one protection set per discovered repo.** `config`, `config.lock`, `config.worktree`,
   `hooks` — the root already gets all four; a nested repo should get the same set by
   construction rather than by a glob that happens to match its contents.
3. **Protect `.gitignore` / `.git/info/exclude`,** or stop letting them influence the scan. As
   long as the confined side can write the file that decides what gets scanned, the deny list
   is advisory.
4. **Report the mount decisions.** A debug line naming each path protected and each nested repo
   *skipped, with the reason*, would have made both gaps visible immediately instead of
   requiring `/proc/mounts` to be read by hand.

## A note on which code this describes

Symptoms were measured against the Claude Code shipped on Santis on 2026-09-01. This
repository's `sandbox-runtime/` checkout is pinned at `bcad388` (2026-08-18) and contains **no**
protection for `config.lock` or `config.worktree`, both of which are mounted in the measurement
above — so the running runtime is newer than the source quoted here. Line-level attributions
are from the pinned checkout and may have moved; **the measurements are from the running
system and stand on their own.**
