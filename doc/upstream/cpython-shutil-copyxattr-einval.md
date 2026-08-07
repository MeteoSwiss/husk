# Upstream: `shutil._copyxattr` should tolerate `EINVAL` on `system.posix_acl_access`

**Status:** drafted 2026-08-07, not yet filed.
**Where:** CPython — `Lib/shutil.py`, `_copyxattr`.
**Why husk cares:** this is the only path that *removes* the problem rather than explaining it.
husk cannot fix the cause (see [`context.md`](../context.md), "Unmappable ACL groups"), so the
detection it ships is a permanent mitigation unless this changes.

## The report

`shutil.copystat` (and therefore `copy2`, `copytree`) copies extended attributes via
`_copyxattr`, which tolerates a specific set of errnos and re-raises everything else:

```python
except OSError as e:
    if e.errno not in (errno.EPERM, errno.ENOTSUP, errno.ENODATA,
                       errno.EINVAL, errno.EACCES):
        raise
```

*(check the exact tuple against the target version before filing — the point stands either
way, and if `EINVAL` is already there the bug is that the version in the field predates it.)*

`EINVAL` arises for a case that is squarely "this attribute cannot be represented here":
setting `system.posix_acl_access` fails when the ACL blob names a **group id that is not
mapped in the current user namespace**. Inside an unprivileged user namespace only one gid is
mapped, so any other group entry on the source file renders as `(gid_t)-1` and the kernel
rejects the blob.

That is the same *class* of condition as `ENOTSUP` ("this filesystem has no xattrs") or
`ENODATA`. A best-effort metadata copy should not abort a file copy because an ACL is
unrepresentable in the destination's id space.

## Reproducer

On Linux, with a file whose ACL names a group you are not in:

```bash
setfacl -m g:<some-other-gid>:rx src.txt
unshare -Ur python3 -c 'import shutil; shutil.copy2("src.txt", "dst.txt")'
# OSError: [Errno 22] Invalid argument: 'dst.txt'
```

`unshare -Ur` maps one gid, which is exactly the situation inside any unprivileged sandbox
(bubblewrap, podman rootless, Flatpak, and husk).

## Why it matters beyond one project

The failure is silent and late. Observed chain (ICON/KENDA on CSCS Balfrin, 2026-08-07):

1. `spack install` copies its package repo into the install prefix with `copytree` → `EINVAL`
2. the site's `spack_install` runs under `set -e`, so it never reaches its final step
3. that final step writes the environment file the model's runscript sources
4. `ECCODES_DEFINITION_PATH` is therefore unset
5. the model fails **at runtime**, hours later, with `Variable RAD_PRECIP not found!`

Incremental builds hid it entirely, because the environment file survived from an earlier
build. Cost to diagnose: two full from-scratch builds.

Any rootless-container user copying files with `copy2`/`copytree` on a filesystem with ACLs
can hit this, which on HPC is the default state of shared project directories.

## The change

Add `errno.EINVAL` to the tolerated set in `_copyxattr` (or narrow it to
`system.posix_acl_access`, if tolerating it generally is judged too broad).

## Also worth reporting, separately

**spack** could use contents-only copies for its package repo, and **not** run its install
driver under bare `set -e` when a metadata failure can lose the final step. That is a
site/recipe fix and does not depend on CPython.
