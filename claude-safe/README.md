# claude-seccomp-wrapper

A small C wrapper that installs a seccomp deny-list for dangerous syscalls
before handing off to Claude Code (or any other process). It layers cleanly
on top of Anthropic's own sandbox without replacing it.

## Why this exists

Claude Code already uses bubblewrap + a seccomp filter for filesystem and
network isolation. That filter specifically targets Unix socket creation.
What it does **not** do is block syscalls that are categorically dangerous
for a coding agent: ptrace, process_vm_readv, kexec_load, bpf, etc.

Seccomp filters stack — the kernel applies all of them, and the most
restrictive result always wins. This wrapper installs a deny-list first;
Claude Code installs its own filter on top. Both apply simultaneously.

## Portability

The wrapper is shipped as statically-linked binaries — no libseccomp or other
runtime dependency is needed on the target machine. Requirements are:

- x86\_64 or aarch64 Linux (release tarballs ship both)
- kernel ≥ 4.14 (required for `SCMP_ACT_KILL_PROCESS`)
- bubblewrap available system-wide (provided on all CSCS supercomputers; ask
  your administrators on other HPC systems)

On x86\_64 the filter also covers the 32-bit x86 secondary ABI (`int $0x80`
syscall path) via `SCMP_ARCH_X86`. On aarch64 the filter likewise adds
`SCMP_ARCH_ARM` to cover the AArch32 compat ABI. On Santis (Neoverse V2)
AArch32 is not supported in silicon so this is belt-and-braces; on Cortex-A
series cores that do expose AArch32 it is the primary protection against the
32-bit ARM syscall bypass.

The tooling should work on any HPC system meeting these requirements. If you
need to rebuild from source — different architecture, or to pick up changes —
see [Building for development](#building-for-development).

## How it works

```
your shell
  └─ seccomp-wrapper             ← installs deny-list, then exec()s
       └─ claude                 ← Claude Code main process
            └─ bwrap             ← per-subprocess: filesystem + network namespace
                 └─ apply-seccomp  ← nested PID namespace + BPF filter
                      └─ agent subprocess (bash, python, …)
```

1. `seccomp-wrapper` calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` — a one-way
   latch that prevents `execve` from gaining privileges via setuid bits.
2. It installs the deny-list filter via `seccomp_load()`.
3. It calls `execvp(claude, ...)`. The filter survives across `exec`.
4. Claude Code starts normally. For each agent subprocess it spawns `bwrap`,
   which runs `apply-seccomp` inside the namespace.
5. `apply-seccomp` creates a nested PID namespace and applies Anthropic's
   BPF filter, then execs the subprocess. Both filters are now active.

Any blocked syscall results in `SCMP_ACT_KILL_PROCESS` — the entire process
group is killed immediately, not just the calling thread, and no error is
returned to the agent that it could potentially handle.

## Syscall classification

Classification of x86-64 Linux syscalls for use with this deny-list.

**Three categories:**
- `KEEP` — required for normal operation; blocking will break things
- `CLOSE` — no legitimate coding agent use; block unconditionally
- `CHECK` — depends on your workload; profile with `strace -f` before deciding

The `CLOSE` list is what is implemented in `src/seccomp_wrapper.c`.
The `CHECK` list needs empirical profiling — see [Empirical profiling workflow](#empirical-profiling-workflow).

### KEEP — must stay open

| syscall | notes |
|---|---|
| `read` | Core I/O — absolutely required |
| `write` | Core I/O — absolutely required |
| `openat` | Opening files — required |
| `open` | Legacy open — needed by many tools |
| `close` | Closing file descriptors |
| `fstat` | File metadata — used constantly |
| `stat` | File metadata |
| `lstat` | Symlink metadata |
| `newfstatat` | Modern stat variant used by Node.js |
| `statx` | Extended stat — used by modern glibc |
| `mmap` | Memory mapping — required by runtime |
| `mprotect` | Memory protection — needed by JIT/runtime |
| `munmap` | Freeing mapped memory |
| `madvise` | Memory hints — used by allocators |
| `brk` | Heap expansion |
| `futex` | Threading synchronisation — essential |
| `clone` | Thread/process creation — required |
| `clone3` | Modern clone — used by glibc/Node.js |
| `wait4` | Waiting for child processes |
| `waitid` | Modern wait variant |
| `exit` | Process exit |
| `exit_group` | Thread group exit — used by Node.js |
| `getpid` | Own PID — harmless, widely used |
| `getppid` | Parent PID — harmless |
| `gettid` | Thread ID — used by runtimes |
| `getuid` | Own UID — harmless |
| `geteuid` | Effective UID |
| `getgid` | Own GID |
| `getegid` | Effective GID |
| `getgroups` | Supplementary groups |
| `getresuid` | Real/effective/saved UID |
| `getresgid` | Real/effective/saved GID |
| `lseek` | File seek |
| `pread64` | Positioned read |
| `pwrite64` | Positioned write |
| `readv` | Scatter read |
| `writev` | Gather write |
| `preadv` | Positioned scatter read |
| `preadv2` | Modern variant |
| `pwritev` | Positioned gather write |
| `pwritev2` | Modern variant |
| `dup` | Duplicate file descriptor |
| `dup2` | Dup to specific fd |
| `dup3` | Dup with flags |
| `pipe` | Creating pipes for subprocess I/O |
| `pipe2` | Pipe with flags |
| `fcntl` | File descriptor control — widely needed |
| `ioctl` | Device control — subset needed (terminal, tty) |
| `poll` | I/O multiplexing |
| `ppoll` | Poll with signal mask |
| `select` | Legacy I/O multiplexing |
| `pselect6` | Modern select |
| `epoll_create` | Event polling — used by Node.js event loop |
| `epoll_create1` | Modern epoll create |
| `epoll_ctl` | Adding fds to epoll |
| `epoll_wait` | Waiting for events |
| `epoll_pwait` | Epoll with signal mask |
| `epoll_pwait2` | Modern variant |
| `eventfd` | Event notification — used by Node.js/libuv |
| `eventfd2` | Modern eventfd |
| `signalfd` | Signal file descriptors |
| `signalfd4` | With flags |
| `timerfd_create` | Timer via fd — used by Node.js |
| `timerfd_settime` | Setting timer |
| `timerfd_gettime` | Reading timer |
| `inotify_init` | Filesystem watching — used by build tools |
| `inotify_init1` | Modern inotify |
| `inotify_add_watch` | Watching a path |
| `inotify_rm_watch` | Removing a watch |
| `getdents` | Directory entries |
| `getdents64` | 64-bit directory entries |
| `getcwd` | Current working directory |
| `chdir` | Change directory — needed by shells/build tools |
| `fchdir` | Chdir via fd |
| `mkdir` | Create directory |
| `mkdirat` | Create directory at path |
| `rmdir` | Remove directory |
| `unlink` | Delete file |
| `unlinkat` | Delete file at path |
| `rename` | Rename file |
| `renameat` | Rename at path |
| `renameat2` | Rename with flags |
| `symlink` | Create symlink |
| `symlinkat` | Create symlink at path |
| `link` | Hard link |
| `linkat` | Hard link at path |
| `readlink` | Read symlink target |
| `readlinkat` | Readlink at path |
| `chmod` | Change file permissions |
| `fchmod` | Chmod via fd |
| `fchmodat` | Chmod at path |
| `chown` | Change ownership — needed by some build steps |
| `fchown` | Chown via fd |
| `lchown` | Chown symlink |
| `fchownat` | Chown at path |
| `truncate` | Truncate file |
| `ftruncate` | Truncate via fd |
| `fallocate` | Preallocate file space |
| `fsync` | Flush file to disk |
| `fdatasync` | Flush data only |
| `sync_file_range` | Partial flush |
| `utimensat` | Update timestamps |
| `clock_gettime` | Get time — used constantly |
| `clock_getres` | Clock resolution |
| `clock_nanosleep` | Sleep with clock |
| `nanosleep` | Sleep |
| `gettimeofday` | Legacy time — widely used |
| `time` | Legacy time syscall |
| `times` | Process times |
| `getitimer` | Interval timer |
| `setitimer` | Set interval timer |
| `alarm` | Signal alarm |
| `rt_sigaction` | Signal handlers — required |
| `rt_sigprocmask` | Signal mask |
| `rt_sigreturn` | Return from signal handler |
| `rt_sigpending` | Pending signals |
| `rt_sigsuspend` | Wait for signal |
| `rt_sigtimedwait` | Timed signal wait |
| `rt_sigqueueinfo` | Queue signal with info |
| `kill` | Send signal to process — needed for subprocess management |
| `tkill` | Send signal to thread |
| `tgkill` | Send signal to thread group |
| `socket` | Creating sockets — needed for proxy communication |
| `connect` | Connect socket — proxy connection |
| `bind` | Bind socket — local IPC |
| `listen` | Listen on socket |
| `accept` | Accept connection |
| `accept4` | Accept with flags |
| `sendto` | Send data |
| `recvfrom` | Receive data |
| `sendmsg` | Send message |
| `recvmsg` | Receive message |
| `sendmmsg` | Send multiple messages |
| `recvmmsg` | Receive multiple messages |
| `getsockname` | Local socket address |
| `getpeername` | Remote socket address |
| `getsockopt` | Socket options |
| `setsockopt` | Set socket options |
| `shutdown` | Shutdown connection |
| `socketpair` | Create socket pair — used by IPC |
| `execve` | Execute programs — required; restrict what can be execed via mount namespace |
| `execveat` | Execute at path — same caveat |
| `prctl` | Partially needed for PR_SET_SECCOMP and dumpable; restrict args via seccomp argument filtering |
| `arch_prctl` | CPU state — needed by glibc startup |
| `set_tid_address` | Thread bookkeeping — glibc uses this |
| `set_robust_list` | Robust futex list — glibc uses this |
| `get_robust_list` | Reading robust list |
| `sched_yield` | Yield CPU — used by runtimes |
| `sched_getparam` | Get scheduling params |
| `sched_getscheduler` | Get scheduler |
| `sched_get_priority_min` | Priority range |
| `sched_get_priority_max` | Priority range |
| `getrusage` | Resource usage — used by profiling/build tools |
| `getrlimit` | Resource limits |
| `prlimit64` | Get/set resource limits |
| `umask` | File creation mask |
| `access` | Check file accessibility |
| `faccessat` | Access at path |
| `faccessat2` | Modern variant |
| `uname` | System info — used by Node.js |
| `sysinfo` | System memory info — used by runtimes |
| `mlock` | Lock memory — may be needed by some tools |
| `munlock` | Unlock memory |
| `mremap` | Remap memory — used by allocators |
| `memfd_create` | Anonymous file — used by some runtimes and JIT |
| `copy_file_range` | Efficient file copy |
| `sendfile` | Efficient data transfer |
| `splice` | Pipe data between fds |
| `tee` | Duplicate pipe data |
| `vmsplice` | Splice memory into pipe |
| `getrandom` | Random bytes — used by crypto in Node.js |
| `mount` | Required by bwrap to bind-mount the project directory and pseudo-filesystems (tmpfs, proc) when setting up the tool sandbox. Blocked by earlier versions; removed from CLOSE after confirming that apply-seccomp does not cover it and that bwrap failing silently defeats the filesystem namespace layer entirely. Risk is bounded: inside bwrap's user namespace only bind-mounts of owned paths and pseudo-filesystems are possible — real device mounts require CAP_SYS_ADMIN outside a user namespace. |
| `umount2` | Same rationale as `mount` — bwrap tears down mounts at exit. |
| `pivot_root` | Same rationale — bwrap uses pivot_root to switch the root filesystem inside the new mount namespace. `chroot` remains blocked because bwrap does not use it. |
| `capset` | Required by bwrap to drop the capabilities it does not need while setting up its user namespace. Blocked by earlier versions — which silently killed bwrap on aarch64 (Santis, bwrap 0.11.0): every sandboxed command died with SIGSYS on `capset`. Removed from CLOSE 2026-06-03. Risk is bounded: with `NO_NEW_PRIVS` set and an unprivileged UID the permitted capability set is empty, so `capset` cannot grant a capability the process does not already hold; capabilities inside bwrap's user namespace are confined to that namespace. `build_and_test.sh` now gates on `seccomp-wrapper bwrap … true` succeeding, so a wrapper that breaks bwrap is never installed. |

### CLOSE — block unconditionally

These are implemented as `SCMP_ACT_KILL_PROCESS` in `src/seccomp_wrapper.c`.

| syscall | reason |
|---|---|
| `ptrace` | Inspect/modify another process memory — no legitimate coding agent use; classic sandbox escape vector |
| `process_vm_readv` | Read another process's memory directly — serious escape risk |
| `process_vm_writev` | Write to another process's memory — same as above |
| `setuid` | Change UID — enables privilege escalation via setuid binaries |
| `setgid` | Change GID — same |
| `setresuid` | Set real/effective/saved UID — same |
| `setresgid` | Set real/effective/saved GID — same |
| `setreuid` | Set real/effective UID — same |
| `setregid` | Set real/effective GID — same |
| `setfsuid` | Set filesystem UID — same |
| `setfsgid` | Set filesystem GID — same |
| `sched_setaffinity` | Pin process to CPU — primary use case is cache-timing side-channel attacks |
| `perf_event_open` | Performance monitoring — known side-channel attack surface |
| `kexec_load` | Load a new kernel — obviously not needed |
| `kexec_file_load` | Load kernel from fd — same |
| `init_module` | Load kernel module — not needed |
| `finit_module` | Load module from fd — same |
| `delete_module` | Unload kernel module — not needed |
| `reboot` | Reboot/halt system — not needed |
| `swapon` | Enable swap — not needed |
| `swapoff` | Disable swap — not needed |
| `adjtimex` | Adjust system clock — not needed |
| `clock_adjtime` | Adjust clock — not needed |
| `settimeofday` | Set system time — not needed |
| `acct` | Process accounting — not needed |
| `chroot` | Change root — sandbox escape risk even inside a user namespace |
| `open_by_handle_at` | Open file by NFS handle — can access files outside bind mounts; sandbox escape |
| `name_to_handle_at` | Get file handle — pairs with above |
| `fanotify_init` | Filesystem audit — could spy on file access outside sandbox |
| `fanotify_mark` | Fanotify mark — same |
| `bpf` | Install eBPF programs — could observe kernel activity or manipulate network |
| `io_uring_setup` | Creates in-kernel socket infrastructure that bypasses the `socket()` filter; extensive CVE history for sandbox escapes |
| `io_uring_enter` | io_uring operation submission — same |
| `io_uring_register` | io_uring buffer/file registration — same |
| `add_key` | Add key to kernel keyring — could persist credentials across sandbox boundary |
| `request_key` | Request keyring key — same |
| `keyctl` | Kernel keyring operations — same |
| `iopl` | I/O port privilege — dangerous, not needed |
| `ioperm` | I/O port permissions — dangerous, not needed |
| `personality` | Switch syscall ABI to 32-bit — would give a different syscall number table, bypassing the filter; the read-only query form (`0xffffffff`) is exempted via argument filtering |
| `modify_ldt` | Legacy descriptor table — not needed; used in historical exploits |
| `vm86` | Virtual 8086 mode — not needed |
| `vm86old` | Legacy — not needed |
| `lookup_dcookies` | Profiling — not needed |
| `uselib` | Obsolete library loading — not needed |
| `vhangup` | Hangup terminal — not needed |
| `nfsservctl` | NFS server control — not needed |
| `sysfs` | Deprecated — not needed |
| `vserver` | Linux-VServer — obsolete |
| `futimesat` | Deprecated — not needed |
| `_sysctl` | Obsolete sysctl — removed in kernel 5.5 |

### CHECK — verify empirically before blocking

These depend on your specific Node.js version, build tools, and workload.
Do not block these without first profiling — see [Empirical profiling workflow](#empirical-profiling-workflow).

| syscall | what to check |
|---|---|
| `io_setup` | io_uring predecessor — check if your Node.js version uses it |
| `io_destroy` | io_uring predecessor — same |
| `io_submit` | io_uring predecessor — same |
| `io_getevents` | io_uring predecessor — same |
| `io_cancel` | io_uring predecessor — same |
| `userfaultfd` | Userspace page fault handling — had sandbox escape CVEs; block unless JIT explicitly needs it |
| `flock` | File locking — needed by some package managers (npm, cargo) |
| `mlockall` | Lock all memory — less commonly needed than mlock |
| `munlockall` | Unlock all — same |
| `mincore` | Page residency — used by some allocators |
| `msync` | Sync mapped memory — verify if needed |
| `remap_file_pages` | Deprecated nonlinear mapping — likely not needed |
| `mbind` | NUMA memory policy — likely not needed unless NUMA-aware |
| `get_mempolicy` | NUMA policy — verify |
| `set_mempolicy` | NUMA policy — verify |
| `move_pages` | NUMA page migration — likely not needed |
| `migrate_pages` | NUMA migration — likely not needed |
| `process_madvise` | Advise another process's memory — probably not needed |
| `sched_setparam` | Set scheduling params — check if any runtime uses this |
| `sched_setscheduler` | Set scheduler — check if needed |
| `sched_rr_get_interval` | Round-robin interval — check if needed |
| `sched_getaffinity` | Get CPU affinity — read-only, relatively safe; verify if needed |
| `setpriority` | Process priority — check if npm/build tools use this |
| `getpriority` | Read priority — probably safe to keep |
| `ioprio_set` | I/O priority — check if needed by build tools |
| `ioprio_get` | Read I/O priority — probably safe to keep |
| `capget` | Read capabilities — harmless to keep; verify if needed |
| `seccomp` | Installing seccomp filters — children can only add *more restrictive* rules (filters stack, most-restrictive wins; a loaded filter cannot be weakened or removed), so allowing this is safe; block only if you want to prevent nested sandboxing |
| `unshare` | Required by bwrap — confirmed by strace on CSCS; do not block |
| `setns` | Join existing namespace — probably not needed; could be used to escape if a target namespace fd is accessible |
| `open_tree` | Detach mount — probably not needed |
| `move_mount` | Move mount point — probably not needed |
| `fsopen` | Open filesystem context — probably not needed |
| `fsmount` | Create mount from context — probably not needed |
| `fspick` | Pick existing mount — probably not needed |
| `mount_setattr` | Change mount attributes — probably not needed |
| `landlock_create_ruleset` | Landlock sandboxing from within — could be useful as extra layer but adds complexity |
| `landlock_add_rule` | Landlock rule — same |
| `landlock_restrict_self` | Landlock restrict — same |
| `quotactl` | Disk quota control — almost certainly not needed |
| `quotactl_fd` | Disk quota via fd — almost certainly not needed |
| `statfs` | Filesystem stats — may be needed by some tools |
| `fstatfs` | Filesystem stats via fd — same |
| `ustat` | Deprecated filesystem stats — probably not needed |
| `getxattr` | Extended attributes — may be needed by git |
| `lgetxattr` | Xattr on symlink — same |
| `fgetxattr` | Xattr via fd — same |
| `listxattr` | List xattrs — same |
| `llistxattr` | List xattrs on symlink — same |
| `flistxattr` | List xattrs via fd — same |
| `setxattr` | Set extended attribute — check if git/build tools need |
| `lsetxattr` | Set xattr on symlink — same |
| `fsetxattr` | Set xattr via fd — same |
| `removexattr` | Remove xattr — same |
| `lremovexattr` | Remove xattr on symlink — same |
| `fremovexattr` | Remove xattr via fd — same |
| `syslog` | Kernel log — probably not needed |

### Design notes

**`personality` deserves special mention:** switching to the 32-bit syscall ABI
gives a process a completely different syscall number table that the deny-list
would not cover — an easy bypass to miss. The block uses argument filtering:
`personality(0xffffffff)` (the read-only query form, used by glibc/loaders/ASAN)
is allowed through; any other argument is killed. See `src/seccomp_wrapper.c`
for the implementation.

**`io_uring`** has had a long history of CVEs enabling sandbox escapes and is
blocked unconditionally. Anthropic's `apply-seccomp` layer also blocks it. If
your Node.js version needs io_uring for performance, you can remove
`io_uring_setup/enter/register` from `BLOCKED_SYSCALLS` after profiling, but
the security tradeoff is significant.

**`prctl`** is listed as KEEP but ideally you would use seccomp argument
filtering to allow only the specific `option` values needed
(`PR_SET_SECCOMP`, `PR_SET_DUMPABLE`, `PR_SET_NAME`) and block the rest,
particularly `PR_CAP_AMBIENT` which can manipulate ambient capabilities.
In practice the risk is lower than it appears: `PR_SET_NO_NEW_PRIVS` is set
before the filter loads, which already prevents `PR_CAP_AMBIENT` from raising
capabilities above the process's permitted set.

## Empirical profiling workflow

To discover which additional syscalls Claude Code actually uses during
real workloads and decide which CHECK entries are safe to add to the deny-list:

```bash
# Profile without the wrapper — running strace inside it would observe
# only the syscalls that pass the filter, hiding everything blocked.
strace -f -e trace=all -o /tmp/claude.strace \
    claude --print "fix the bug in main.c"

# Summarise which syscalls were called and how often
awk -F'(' '{print $1}' /tmp/claude.strace | sort | uniq -c | sort -rn | head -60
```

Compare the output against the [CHECK table](#check--verify-empirically-before-blocking)
above and add anything not present to the CLOSE list in `src/seccomp_wrapper.c`.

## Debug mode

Setting `SECCOMP_WRAPPER_DEBUG=1` before launching swaps `SCMP_ACT_KILL_PROCESS`
for `SCMP_ACT_ERRNO(ENOSYS)`. Blocked syscalls return an error instead of
killing the process — the caller sees `ENOSYS` and typically crashes or logs a
message that surfaces in Claude's output, making it easy to spot which syscalls
a new workload needs without rebuilding the filter each time.

```bash
SECCOMP_WRAPPER_DEBUG=1 claude-safe
```

A warning is printed to stderr at startup so the mode is never accidentally
active. **Never use in production** — enforcement is disabled for the entire
session. This is a development tool for whoever is iterating on the deny-list,
not a feature for end users.

## Building a release binary

Release tarballs ship binaries for both architectures. Build each one natively
with `build_and_test.sh` from the `claude-safe/` directory. The script downloads
and builds gperf and libseccomp from source into a temporary `.build/` directory,
compiles `seccomp-wrapper` as a static binary, runs the smoke test, and removes
all build artifacts. It produces an arch-tagged copy (`seccomp-wrapper-x86_64`
or `seccomp-wrapper-aarch64`) alongside `seccomp-wrapper`. The binary is only
written if the smoke test passes.

```bash
# On Balfrin (x86_64):
cd claude-safe && ./build_and_test.sh   # → seccomp-wrapper-x86_64

# On Santis (aarch64):
cd claude-safe && ./build_and_test.sh   # → seccomp-wrapper-aarch64
scp claude-safe/seccomp-wrapper-aarch64 balfrin:<path-to-repo>/claude-safe/
```

Then package the release from the repo root on Balfrin:

```bash
./make-release.sh
```

## Building for development

No root access required. If `libseccomp` is not available system-wide, build
it from source into `~/.local` first:

```bash
# 1. Build libseccomp from source (skip if already available system-wide)
wget https://github.com/seccomp/libseccomp/releases/download/v2.5.5/libseccomp-2.5.5.tar.gz
tar xzf libseccomp-2.5.5.tar.gz
cd libseccomp-2.5.5
./configure --prefix="$HOME/.local" --enable-static
make -j$(nproc)
make install
cd ..

# 2. Build seccomp-wrapper (picks up ~/.local automatically)
make

# 3. Install to ~/.local/bin
make install

# 4. Test
make check
```

## Usage

```bash
# Direct
./seccomp-wrapper claude [args...]

# Via the launcher script (drop-in alias for `claude`)
./claude-safe [args...]

# Or add to your shell config
alias claude='seccomp-wrapper claude'
```

## Verifying it works

The automated test suite covers four cases. Run it with:

```bash
make check
```

This builds the test binaries and runs `test/smoke` which checks:

1. **exec passthrough** — `seccomp-wrapper echo ok` exits 0 and prints `ok`.
2. **ptrace blocked** — a minimal binary that calls `ptrace(PTRACE_TRACEME,...)` is killed by SIGSYS.
3. **personality query allowed** — `personality(0xffffffff)` (the read-only query form) exits 0 without being killed.
4. **personality ABI-switch blocked** — `personality(PER_LINUX32)` is killed by SIGSYS.

For quick manual spot-checks:

```bash
# ptrace should be killed by the kernel, not return normally
./seccomp-wrapper python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)"
```

Verify the filter is present in a running process:

```bash
# In another terminal while claude is running, find the PID then:
grep Seccomp /proc/<pid>/status
# Should show: Seccomp: 2  (meaning SECCOMP_MODE_FILTER is active)
```

## Adding more blocked syscalls

Edit the `BLOCKED_SYSCALLS` array in `src/seccomp_wrapper.c`, rebuild with `make`.

Syscall names are the standard Linux names (`man 2 syscalls`). If a name is
not recognised on the running kernel, the wrapper prints a warning and skips
it rather than failing — so it's safe to include names that may not exist on
all kernel versions.

When deciding what to add, start with the [CHECK table](#check--verify-empirically-before-blocking)
and run the profiling workflow above to confirm your workload doesn't need them.

## Notes on `NO_NEW_PRIVS`

`PR_SET_NO_NEW_PRIVS` is set before the filter is installed. This means:

- No setuid binary reachable inside the sandbox can grant elevated privileges
- All child processes inherit this — including bwrap and the agent
- It is a one-way latch — it cannot be unset by any child
- It is required for unprivileged seccomp installation (no `CAP_SYS_ADMIN`)

Anthropic's sandbox sets this too, so even without this wrapper it would
be set eventually. Setting it here first is harmless and ensures it is
active before any code runs.

## Kernel requirements

- `PR_SET_NO_NEW_PRIVS`: kernel >= 3.5
- `seccomp(SECCOMP_SET_MODE_FILTER)`: kernel >= 3.5
- `SCMP_ACT_KILL_PROCESS`: kernel >= 4.14

If you are on kernel 4.13 or older, change `SCMP_ACT_KILL_PROCESS` to
`SCMP_ACT_KILL` (kills calling thread) in `src/seccomp_wrapper.c`.
