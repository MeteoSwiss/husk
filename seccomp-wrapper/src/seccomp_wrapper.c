/*
 * seccomp_wrapper.c
 *
 * Installs a seccomp deny-list for syscalls a Claude Code agent provably
 * does not need, then execs the rest of the command line unchanged.
 *
 * Because seccomp filters STACK (most-restrictive wins), this works on top
 * of the filter Anthropic's sandbox-runtime already installs — we do not
 * need to replace or replicate their filter, just add to it.
 *
 * Build:
 *   make   (from the seccomp-wrapper/ directory)
 *
 * Usage:
 *   ./seccomp-wrapper claude [args...]
 *   ./seccomp-wrapper -- claude [args...]
 *
 * Dependencies:
 *   libseccomp-dev  (apt install libseccomp-dev)
 *
 * Requires kernel >= 3.5 for seccomp-bpf. Works without root because we
 * set PR_SET_NO_NEW_PRIVS=1 first (required for unprivileged seccomp).
 * After that call this process and all descendants cannot gain privileges,
 * which is what we want anyway.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Cage profiles — see slurm-broker/CAGE-PROFILES.md.
 *
 * The profile names the topology the wrapped process runs in, and topology is the
 * threat axis: it decides what network and credential reach the process needs.
 *
 * The base deny-list below is the FLOOR and applies to every profile. A profile may
 * add rules of its own, or declare a narrow EXEMPTION from the floor (see
 * SINGLE_NODE_EXEMPT). Exemptions are the dangerous direction, so they are kept as an
 * explicit, named table rather than a fork of the deny-list: adding a syscall to the
 * floor blocks it under every profile unless someone deliberately writes it down here
 * too, with a justification. Default-strict, opt-out-by-name.
 *
 * PROFILE_LOGIN is the default precisely because it must stay today's behaviour: the
 * husk launcher wraps the whole agent SESSION (`seccomp-wrapper claude`), and the agent
 * runtime legitimately uses unix sockets for its own IPC (MCP servers, IDE integration).
 *
 * AF_UNIX is nevertheless already blocked on the login side — by Anthropic's
 * apply-seccomp, applied per BASH COMMAND rather than to the runtime process. The
 * difference is granularity, not policy: the agent's commands cannot open a unix socket,
 * while the runtime that supervises them can. When ROADMAP step 5 drops their runtime,
 * this profile takes that block over at the same granularity. Note that it can only ever
 * apply to the AGENT's commands: a compute job cannot have it, because CUDA needs unix
 * sockets (measured — see install_filter).
 *
 * An unknown --profile is FATAL rather than a fallback to the default: a typo must not
 * silently produce a weaker cage than the caller asked for.
 */
enum wrapper_profile {
    PROFILE_LOGIN,        /* default: base deny-list only */
    PROFILE_SINGLE_NODE,  /* brokered compute job; delta = SINGLE_NODE_EXEMPT */
};

/* -------------------------------------------------------------------------
 * Syscalls to BLOCK.
 *
 * Only contains calls from the CLOSE category in README.md.
 * The CHECK category is intentionally excluded — profile your specific
 * workload with strace before adding those (see README.md).
 *
 * Each entry is a libseccomp syscall name. See `man 2 syscalls` or
 * `ausyscall --dump` for the full list on your kernel.
 * ---------------------------------------------------------------------- */
static const char *const BLOCKED_SYSCALLS[] = {
    /* --- process inspection / memory manipulation ---
     *
     * process_vm_readv is EXEMPTED under the single-node profile — Cray MPICH needs
     * Cross Memory Attach for intra-node transfers. See SINGLE_NODE_EXEMPT below for
     * the reasoning; process_vm_writev stays blocked under every profile. */
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",

    /* --- privilege escalation via UID/GID change --- */
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "setfsuid",
    "setfsgid",

    /* --- capability manipulation ---
     *
     * capset is intentionally NOT blocked. bwrap calls it while setting up its
     * user namespace (to drop the capabilities it does not need); blocking it
     * kills bwrap before it can sandbox anything — observed on Santis (aarch64,
     * bwrap 0.11.0): every sandboxed command died with SIGSYS on capset (#91).
     * On x86_64 the same block exists but Balfrin's bwrap build does not hit
     * that path, which is why it surfaced only on aarch64. Same reasoning as
     * the mount/umount2/pivot_root exclusion below.
     *
     * The security cost is ~nil here: this process runs unprivileged with
     * NO_NEW_PRIVS, so its permitted capability set is empty and capset cannot
     * grant a capability it does not already hold. Inside bwrap's user
     * namespace any capabilities are confined to that namespace and cannot
     * affect the host.
     */

    /* --- side-channel / observation ---
     *
     * perf_event_open stays blocked — it is the real side-channel/observation
     * primitive (hardware performance counters, kernel tracing).
     *
     * sched_setaffinity is intentionally NOT blocked. Every performance-oriented HPC
     * workload pins ranks/threads to cores + NUMA nodes: `numactl --cpunodebind`
     * (ICON's own launcher does exactly this), `srun --cpu-bind`, Cray MPICH rank
     * binding, OpenMP OMP_PROC_BIND — all call sched_setaffinity, and blocking it
     * KILLs the job with SIGSYS before the binary starts (observed: ICON's numactl
     * step). The security cost is ~nil for this threat model (FS confidentiality +
     * broker-escape, NOT microarchitectural side channels): SLURM's cpuset cgroup
     * already confines the job to its ALLOCATED cores, so the kernel intersects any
     * requested affinity mask with that cpuset — a job can only reshuffle within cores
     * it already owns, never onto another job's. (CLOSE -> CHECK reclassification per
     * README: profiled against the real workload.) --membind uses set_mempolicy/mbind,
     * which were never on this list. */
    "perf_event_open",

    /* --- kernel loading --- */
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",

    /* --- system control --- */
    "reboot",
    "swapon",
    "swapoff",
    "adjtimex",
    "clock_adjtime",
    "settimeofday",
    "acct",

    /* --- filesystem structure escape --- */
    /*
     * mount, umount2, pivot_root are intentionally NOT blocked here.
     * Claude Code's sandbox invokes bwrap as a child process to create a
     * filesystem namespace for each tool invocation; bwrap requires all three
     * to set up bind-mounts and pivot the root.  Blocking them kills bwrap
     * before it can sandbox anything, which is the opposite of what we want.
     *
     * The risk is bounded: inside bwrap's user namespace these syscalls are
     * restricted to bind-mounts of paths the process already owns and
     * pseudo-filesystems (tmpfs, proc).  Real device-filesystem mounts are
     * not possible without CAP_SYS_ADMIN outside a user namespace.
     */
    "chroot",   /* bwrap uses pivot_root, not chroot — safe to keep blocked */

    /* --- dangerous filesystem handles (NFS-style sandbox escape) --- */
    "open_by_handle_at",
    "name_to_handle_at",

    /* --- filesystem audit (spy on file access outside sandbox) --- */
    "fanotify_init",
    "fanotify_mark",

    /* --- eBPF (could observe kernel / manipulate network) --- */
    "bpf",

    /* --- io_uring (creates sockets in kernel context, bypasses socket() filter) --- */
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",

    /* --- kernel keyring (persist credentials across sandbox) --- */
    "add_key",
    "request_key",
    "keyctl",

    /* --- raw hardware access --- */
    "iopl",
    "ioperm",

    /* personality(2) is handled separately with argument filtering — see install_filter() */

    /* --- legacy descriptor table manipulation, used in exploits --- */
    "modify_ldt",

    /* --- virtual 8086 mode (x86 only, not needed) --- */
    "vm86",
    "vm86old",

    /* --- profiling / lookup cookies (not needed) --- */
    "lookup_dcookies",

    /* --- obsolete / removed in modern kernels --- */
    "uselib",
    "vhangup",
    "nfsservctl",
    "sysfs",
    "vserver",
    "futimesat",
    "_sysctl",

    /* sentinel — do not remove */
    NULL,
};

/* -------------------------------------------------------------------------
 * PROFILE_SINGLE_NODE — exemptions from the floor.
 *
 * Cross Memory Attach. Cray MPICH moves intra-node MPI messages by reading the peer
 * rank's address space directly instead of bouncing them through a shared-memory
 * buffer. With process_vm_readv blocked, ICON dies with SIGSYS the moment ranks
 * exchange data (Balfrin, 2026-07-31). MPICH_SMP_SINGLE_COPY_MODE=NONE avoids it, but
 * that is a diagnostic, not a fix: it taxes every intra-node message for every user.
 *
 * READ AND WRITE ARE NOT ONE CONCESSION, which is why only readv is listed:
 *   - process_vm_readv  = same-uid memory DISCLOSURE between caged ranks of one job.
 *     They already share the job's files, the allocation and the uid; a rank reading
 *     a sibling rank's memory learns nothing the cage was protecting.
 *   - process_vm_writev = writing into another process's address space. The process
 *     worth writing into is the UN-CAGED step-broker, and that is not a disclosure
 *     bug, it is arbitrary code execution outside the cage — the escape itself.
 *
 * WHAT BOUNDS THE READ. The kernel gates both calls with the ptrace-attach check:
 * credentials, Yama ptrace_scope, the target's dumpable flag, and PID visibility.
 * Balfrin has no Yama, so the load-bearing part here is the dumpable flag: the broker
 * calls prctl(PR_SET_DUMPABLE, 0) at startup and is therefore not a valid CMA target
 * whatever this filter allows. --unshare-pid cannot help — each rank gets its own
 * bwrap, so a shared PID namespace would break the very rank-to-rank CMA being
 * enabled here.
 *
 * A name listed here that is not in BLOCKED_SYSCALLS is harmless but dead; the floor
 * is the only thing an exemption can subtract from.
 * ---------------------------------------------------------------------- */
static const char *const SINGLE_NODE_EXEMPT[] = {
    "process_vm_readv",

    /* sentinel — do not remove */
    NULL,
};

static bool profile_exempts(enum wrapper_profile profile, const char *syscall_name)
{
    const char *const *exempt;

    switch (profile) {
    case PROFILE_SINGLE_NODE: exempt = SINGLE_NODE_EXEMPT; break;
    case PROFILE_LOGIN:       /* fall through — the login cage takes no exemptions */
    default:                  return false;
    }

    for (int i = 0; exempt[i] != NULL; i++) {
        if (strcmp(exempt[i], syscall_name) == 0)
            return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * install_filter()
 *
 * Builds and loads a seccomp filter that:
 *   1. Allows all syscalls by default (SCMP_ACT_ALLOW)
 *   2. Kills the entire process on any blocked syscall (SCMP_ACT_KILL_PROCESS)
 *
 * SCMP_ACT_KILL_PROCESS is used rather than SCMP_ACT_ERRNO so that a
 * blocked call terminates the whole process rather than returning an error
 * the agent could potentially recover from or work around.
 *
 * Requires kernel >= 4.14 for SCMP_ACT_KILL_PROCESS. If you need support
 * for older kernels, change to SCMP_ACT_KILL (kills only the calling thread)
 * or SCMP_ACT_ERRNO(EPERM) (returns an error).
 * ---------------------------------------------------------------------- */
static int install_filter(bool debug_mode, enum wrapper_profile profile)
{
    scmp_filter_ctx ctx;
    int rc;
    /*
     * SECCOMP_WRAPPER_DEBUG=1 swaps KILL_PROCESS for ERRNO(ENOSYS) so blocked
     * syscalls return an error instead of dying.  The process continues; the
     * caller sees ENOSYS and usually crashes or prints a message that surfaces
     * in Claude's output.  Useful for discovering which syscalls a new workload
     * needs without rebuilding the filter.  Never set in production — it
     * disables enforcement for the duration of the session.
     */
    uint32_t block_action = debug_mode
        ? SCMP_ACT_ERRNO(ENOSYS)
        : SCMP_ACT_KILL_PROCESS;

    /* default action: allow everything not explicitly blocked */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_wrapper: seccomp_init failed: %s\n", strerror(errno));
        return -1;
    }

#ifdef __x86_64__
    /*
     * Cover the 32-bit x86 secondary ABI. On x86_64, a process can issue
     * 32-bit syscalls via `int $0x80` without going through the 64-bit
     * syscall table, bypassing a filter that only covers SCMP_ARCH_X86_64.
     * Adding the secondary arch here closes that gap — libseccomp maps each
     * rule to the correct 32-bit syscall number automatically.
     */
    rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
    if (rc != 0 && rc != -EEXIST) {
        fprintf(stderr, "seccomp_wrapper: warning: could not add x86 arch"
                " to filter: %s — 32-bit syscall path uncovered\n",
                strerror(-rc));
        /* non-fatal: filter still applies to the native 64-bit ABI */
    }
#endif

#ifdef __aarch64__
    /*
     * Cover the AArch32 compat ABI. On aarch64 kernels that support it,
     * a process can switch to 32-bit ARM execution (e.g. via execve of an
     * ARM binary), bypassing a filter that only covers SCMP_ARCH_AARCH64.
     * Adding SCMP_ARCH_ARM closes that gap.
     *
     * On Santis (Neoverse V2) AArch32 is not supported in silicon, so this
     * is belt-and-braces. On other aarch64 cores (Cortex-A series) it is
     * the primary protection against the 32-bit ABI bypass.
     *
     * The personality(PER_LINUX32) block below (in install_filter) already
     * prevents ABI switches via personality(2); this is a second layer in
     * case that is bypassed.
     */
    rc = seccomp_arch_add(ctx, SCMP_ARCH_ARM);
    if (rc != 0 && rc != -EEXIST) {
        fprintf(stderr, "seccomp_wrapper: warning: could not add arm arch"
                " to filter: %s — 32-bit ARM syscall path uncovered\n",
                strerror(-rc));
        /* non-fatal: filter still applies to the native 64-bit ABI */
    }
#endif

    for (int i = 0; BLOCKED_SYSCALLS[i] != NULL; i++) {
        int nr;

        /*
         * A profile may exempt a floor entry. Silently, on purpose: the exemption
         * table is STATIC per profile, so the profile name already on the command
         * line says everything a printed line would, and this runs once per RANK —
         * a note here is N identical lines in the job's .err file for no information
         * (same reason the unresolved-syscall skip below stays quiet).
         */
        if (profile_exempts(profile, BLOCKED_SYSCALLS[i]))
            continue;

        nr = seccomp_syscall_resolve_name(BLOCKED_SYSCALLS[i]);
        if (nr == __NR_SCMP_ERROR) {
            /*
             * Syscall not known to this kernel/libseccomp version — it simply
             * doesn't exist here and therefore cannot be called. Nothing to
             * block; skip silently. This is NORMAL: one deny-list spans multiple
             * arches/kernels, so some names are always absent. A note per skip is
             * just noise — notably in SLURM job .err files.
             */
            continue;
        }

        rc = seccomp_rule_add(ctx, block_action, nr, 0);
        if (rc != 0) {
            fprintf(stderr, "seccomp_wrapper: seccomp_rule_add('%s') failed:"
                    " %s\n", BLOCKED_SYSCALLS[i], strerror(-rc));
            seccomp_release(ctx);
            return -1;
        }
    }

    /*
     * PROFILE_SINGLE_NODE adds no rules of its own; its whole delta is the
     * SINGLE_NODE_EXEMPT table applied in the loop above (CMA reads for Cray MPICH).
     *
     * It used to block socket(AF_UNIX). That is reverted: CUDA needs unix sockets, and
     * it treats the refusal as FATAL rather than falling back. Measured on Balfrin
     * 2026-07-30 with cuda-probe.sh, one variable at a time:
     *
     *     uncaged .................. cuInit OK
     *     --profile=login .......... cuInit OK
     *     --profile=single-node .... cuInit FAILED rc=304 (CUDA_ERROR_OPERATING_SYSTEM)
     *     bwrap job cage ........... cuInit OK
     *     bwrap rank cage .......... cuInit OK
     *
     * so the syscall filter was the whole cause; the mount cage is fine. ICON's ranks
     * died the same way. (`/var/run/nvidia-persistenced` is a unix socket on these
     * nodes; whatever the exact call, EPERM is not something CUDA recovers from.)
     *
     * Gate C12 had measured ZERO AF_UNIX calls in a caged 2-rank MPI run — true, but the
     * sample was a tiny MPI hello with no CUDA, a limitation recorded at the time. A real
     * GPU workload found it immediately.
     *
     * WHAT STILL PROTECTS THE THING THAT MATTERED. The point of the block was that a
     * caged job must not authenticate to slurmctld via MUNGE. That is enforced by MASKING
     * /run/munge in the cage (CREDENTIAL_SOCKET_DIRS, verified on hardware:
     * `cred.munge tmpfs_mounts=1`), which is destination-aware in a way a syscall filter
     * can never be — and AF_UNIX always had to be judged per DESTINATION, since a socket
     * to sssd is not escape surface while one to MUNGE is. The mount mask was the
     * load-bearing control; this was defence in depth, and it cost GPU support.
     *
     * The profile mechanism stays: it is where the next rule lands, the deployment check
     * depends on it, and an empty delta is honest about what today's cage does.
     */

    /*
     * personality(2) — argument-filtered rule.
     *
     * personality(0xffffffff) is a read-only query (returns the current persona
     * without changing it) used by glibc startup, ASAN, and various loaders.
     * Killing on this form would crash innocent processes at startup.
     *
     * Any other value selects a new execution domain. In particular,
     * PER_LINUX32 (0x0008) switches to the 32-bit syscall ABI, giving the
     * process a completely different syscall number table that the deny-list
     * above would not cover — a filter bypass that is easy to miss.
     *
     * Argument filtering is safe here because personality's sole argument is
     * a plain unsigned long, not a pointer, so libseccomp can compare it
     * directly inside the BPF program.
     *
     * Note: the kernel internally casts the argument to unsigned int, so
     * (long)-1 (0xffffffffffffffff on 64-bit) also triggers the query form.
     * Our filter only allows 0x00000000ffffffff, so a process passing (long)-1
     * would be killed even though the kernel treats it as a query. This is the
     * safer direction (false positive, not false negative), and in practice
     * glibc always passes (unsigned long)0xffffffff — the sign-extended form
     * does not occur with normal code.
     */
    {
        int nr = seccomp_syscall_resolve_name("personality");
        if (nr != __NR_SCMP_ERROR) {
            rc = seccomp_rule_add(ctx, block_action, nr, 1,
                                  SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)0xffffffff));
            if (rc != 0) {
                fprintf(stderr, "seccomp_wrapper: seccomp_rule_add('personality')"
                        " failed: %s\n", strerror(-rc));
                seccomp_release(ctx);
                return -1;
            }
        }
    }

    rc = seccomp_load(ctx);
    seccomp_release(ctx);

    if (rc != 0) {
        fprintf(stderr, "seccomp_wrapper: seccomp_load failed: %s\n",
                strerror(-rc));
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: seccomp-wrapper [--profile=login|single-node] [--] <command> [args...]\n");
        return 1;
    }

    char **cmd = argv + 1;

    /*
     * Optional --profile=NAME, ahead of the optional "--". Unknown names are FATAL:
     * silently falling back to the default would hand the caller a weaker cage than it
     * asked for, and the caller here is the broker's re-exec guard.
     */
    enum wrapper_profile profile = PROFILE_LOGIN;
    if (strncmp(cmd[0], "--profile=", 10) == 0) {
        const char *name = cmd[0] + 10;
        if (strcmp(name, "login") == 0) {
            profile = PROFILE_LOGIN;
        } else if (strcmp(name, "single-node") == 0) {
            profile = PROFILE_SINGLE_NODE;
        } else {
            fprintf(stderr, "seccomp-wrapper: unknown profile '%s'"
                    " (known: login, single-node)\n", name);
            return 1;
        }
        cmd++;
        if (cmd[0] == NULL) {
            fprintf(stderr, "seccomp-wrapper: no command after --profile\n");
            return 1;
        }
    }

    /* skip optional "--" separator */
    if (strcmp(cmd[0], "--") == 0) {
        cmd++;
        if (cmd[0] == NULL) {
            fprintf(stderr, "seccomp-wrapper: no command after --\n");
            return 1;
        }
    }

    /*
     * PR_SET_NO_NEW_PRIVS = 1
     *
     * Required before an unprivileged process can install a seccomp filter.
     * Inherited by all children. Prevents execve from gaining privileges
     * via setuid bits or file capabilities — which is exactly what we want
     * since the agent can call execve.
     *
     * This is a one-way latch: it cannot be unset.
     *
     * Note: `prctl` is not in BLOCKED_SYSCALLS — it is needed by apply-seccomp
     * (which installs its own filter) and by glibc/runtimes for thread setup.
     * The main residual risk is PR_CAP_AMBIENT, which can add ambient
     * capabilities. That risk is closed by this very call: with NO_NEW_PRIVS
     * set, PR_CAP_AMBIENT can only raise capabilities already in the process's
     * permitted set, which for a normal user process is empty.
     */
    const char *_dbg = getenv("SECCOMP_WRAPPER_DEBUG");
    bool debug_mode = _dbg != NULL && strcmp(_dbg, "1") == 0;
    if (debug_mode)
        fprintf(stderr, "seccomp_wrapper: DEBUG — blocked syscalls return "
                "ENOSYS instead of killing; enforcement is disabled\n");

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("seccomp_wrapper: prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }

    if (install_filter(debug_mode, profile) != 0) {
        return 1;
    }

    /*
     * Hand off to the real command. The seccomp filter is now active and
     * inherited across execve. Claude Code will install its own filter
     * on top; the kernel applies both, most-restrictive wins.
     */
    execvp(cmd[0], cmd);

    /* execvp only returns on error */
    fprintf(stderr, "seccomp_wrapper: exec '%s' failed: %s\n",
            cmd[0], strerror(errno));
    return 1;
}
