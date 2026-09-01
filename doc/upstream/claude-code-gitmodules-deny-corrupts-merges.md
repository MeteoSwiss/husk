# Upstream: denying writes to `.gitmodules` breaks ordinary git operations, mid-write

**Status:** drafted 2026-08-13, not yet filed.
**Where:** Claude Code sandbox — `DANGEROUS_FILES` in `sandbox-utils.ts`, applied via
`linuxGetMandatoryDenyPaths`.
**Severity:** this one does not refuse an operation, it **leaves a working tree partially
mutated** in a state `git merge --abort` cannot clean up.

## The report

`.gitmodules` is in the mandatory deny list and is bind-mounted read-only in every sandboxed
session. Unlike the other entries, **`.gitmodules` is version-controlled repository content,
not user configuration** — and git rewrites it as part of routine operations:

- `git merge` / `git rebase` where the branches differ in submodules
- `git checkout` between such branches
- `git submodule add` / `deinit`
- any upstream that restructures its submodules

When git tries to, it fails with:

```
warning: unable to rmdir 'externals/<sub>': Directory not empty
error: unable to unlink old '.gitmodules': Device or resource busy
```

**It fails partway through.** git has already begun rewriting the working tree when it hits
`EBUSY`, so the merge is neither completed nor cleanly abortable. Observed on a real ICON
merge: 1018 files touched, repository left inconsistent. The error names neither the sandbox
nor a remedy, so the natural reading is "git is broken" or "the working tree needs fixing by
hand" — and fixing 1018 files by hand is a plausible next step for someone who does not know a
bind mount is involved.

That is the difference from the rest of the list. `.bashrc`, `.zshrc`, `.profile`, `.ripgreprc`
and `.mcp.json` are configuration a repo does not normally rewrite; a denial there is a
refusal, and refusals are recoverable. `.gitmodules` is tracked content, so the denial lands in
the middle of a multi-file transaction that has no rollback.

## Reproducer

```bash
git clone <repo-with-submodules> r && cd r
# in a sandboxed session:
git merge origin/<branch-that-restructures-submodules>
# error: unable to unlink old '.gitmodules': Device or resource busy
git merge --abort           # does not restore the tree
```

Confirm the mechanism with `grep gitmodules /proc/mounts`.

## What integrators can and cannot do

Nothing. `.git/config` has an `allowGitConfig` setting; **`.gitmodules` has no equivalent
knob**, and the deny is applied unconditionally. It is also not anchored at the session root —
measured 2026-08-13, a `.gitmodules` in a nested subdirectory is bind-mounted too, so relocating
the checkout inside the project does not avoid it. The only workarounds are to run the operation
outside the sandbox entirely, which defeats the point.

## The change

In decreasing order of preference:

1. **Drop `.gitmodules` from `DANGEROUS_FILES`.** The threat it addresses — a submodule URL
   pointing somewhere hostile — is realised at `git submodule update`, i.e. at *fetch and
   checkout* time, not at write time. Writing the file is inert; acting on it is not. Blocking
   the write costs ordinary git usage and does not stop the actual dangerous step.
2. **Make it conditional**, as `.git/config` already is, so an integrator can decide.
3. **At minimum, fail before mutating.** A pre-flight check that refuses the git operation with
   an attributable message beats an `EBUSY` in the middle of a tree rewrite.

## Related, same mechanism

Several friction reports in this project trace to the same shape: a bind mount inside a working
directory turns an ordinary operation into an unattributed OS error. `rm -rf` on a directory
containing one fails with `Device or resource busy`; `mv` across one fails with
`inter-device move failed`. None of those messages names the sandbox. Whatever is decided about
`.gitmodules`, **an error that says "the sandbox mounted this path, and here is why" would
retire a whole class of misdiagnosis.**
