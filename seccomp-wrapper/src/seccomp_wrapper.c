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
 *   ./seccomp-wrapper --self-test          (audit the filter and exit; runs no command)
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
#include <sys/resource.h>
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

    /* --- profiling / lookup cookies (not needed) ---
     *
     * `lookup_dcookie`, singular. It read `lookup_dcookies` from the day this list was
     * written until 2026-09-01: a name libseccomp does not know, so it resolved to
     * __NR_SCMP_ERROR, the rule loop skipped it silently BY DESIGN, and the entry blocked
     * nothing through three review rounds (`B6-1`). It survived because README.md carried
     * the same misspelling — the two lists AGREED, so a reviewer cross-checking them found
     * them consistent. `P8` in its worst mode: two copies of one mistake, neither checked
     * against the only authority that matters, which is libseccomp's name table.
     *
     * `P15` is the principle it broke: a control names a target, so check the name resolves
     * to the object you meant. The one-character fix is not the interesting part —
     * audit_denylist() below is, because it is what makes the next one impossible. */
    "lookup_dcookie",

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
 * Where Yama is not enabled — as on our targets — the load-bearing part of that check is
 * the dumpable flag: the broker
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

/* -------------------------------------------------------------------------
 * GRACEFUL_ERRNO_SYSCALLS — blocked, but reported instead of fatal.
 *
 * These are still DENIED: the syscall never executes and the capability behind it is
 * refused exactly as before. Only the report changes — the caller gets ENOSYS back
 * rather than dying on SIGSYS. Nothing here subtracts from the floor; an entry moved
 * into this table is still an entry in BLOCKED_SYSCALLS.
 *
 * WHY THIS TABLE EXISTS AT ALL. KILL_PROCESS is the right default and CAGE-PROFILES.md
 * ("Failure mode: loud") gives the argument: the pmix episode, where a graceful EPERM let
 * MPI "succeed" as two independent one-rank jobs. A run that reports success and computes
 * the wrong answer is worse than a crash. That argument is sound and it still governs
 * every other name in BLOCKED_SYSCALLS.
 *
 * But it turns on a property the pmix case had and this one does not: whether the caller's
 * fallback CHANGES THE RESULT. That is the criterion for this table, and the bar for adding
 * to it —
 *
 *     Name the fallback the caller takes when this call fails, and show that it computes
 *     the same thing. If the fallback is merely slower, ENOSYS is safe. If it is
 *     semantically different — a different collective, a different rank layout, a
 *     silently reduced mode — it must keep KILL_PROCESS, because then a returned error
 *     buys exactly the pmix failure.
 *
 * MEASURED, 2026-08-29. CMake 4.4.2 died under this filter with SIGSYS and ZERO bytes of
 * output, even for `cmake --version`. CMake does not ask for io_uring: it bundles libuv,
 * and libuv >= 1.45 probes for a ring in uv_loop_init, before main() reaches any of CMake's
 * own logic. libuv handles that probe failing — it sets ringfd = -1 and falls back to its
 * threadpool, which is the ORIGINAL path and predates io_uring entirely. So the fallback is
 * the same filesystem operations at lower throughput; no result changes. Under
 * KILL_PROCESS that correct fallback is unreachable, because there is no return value to
 * inspect.
 *
 * The cost of getting this wrong is not hypothetical: two sessions and one hand-off
 * produced three different wrong root causes, because the failure carries no information.
 * Docker blocks io_uring for the same kernel-attack-surface reason and returns an errno,
 * which is why the same CMake runs there and dies here. The vendored apply-seccomp also
 * blocks io_uring with SCMP_ACT_ERRNO (constraints.md C1.2) — this makes husk's own layer
 * agree with the one stacked beside it.
 *
 * WHY ONLY io_uring_setup, AND NOT enter/register. setup is the capability PROBE and the
 * only one of the three a well-behaved caller reaches first. enter and register operate on
 * a ring fd, and no process under this filter can create one — so reaching them means
 * holding a ring that came from OUTSIDE the cage, which is anomalous by construction and
 * should be loud rather than handed a polite error.
 *
 * That is the whole claim, and it is deliberately narrower than the one first written here
 * ("we make the probe survivable without making the capability usable"). REVIEW, 2026-08-29,
 * BROKE that sentence by execution on both profiles: an uncaged parent creates a ring with
 * IORING_SETUP_SQPOLL, clears O_CLOEXEC with dup2, wakes the poll thread once, and execs
 * into the wrapper; the caged child then mmaps the rings (mmap is not blocked), writes an
 * SQE and bumps the tail, and the KERNEL's SQ poll thread executes it — with ZERO io_uring
 * syscalls, so no seccomp rule is ever consulted. Killing on `enter` is therefore not what
 * makes an externally supplied ring unusable; under SQPOLL `enter` is optional.
 *
 * Unchanged by this commit — identical before it — and it needs a cooperating UNCAGED
 * process on the node, which husk's threat model does not grant (husk wraps the session).
 * It is the same inherited-fd class apply-seccomp's own README concedes. Two things follow
 * that are worth writing down rather than re-deriving: seccomp cannot contain a resource
 * handed in by fd, only the calls that create or drive it; and io_uring fds do NOT cross
 * execve by default (measured: they are O_CLOEXEC) nor, on kernels >= 6.7, an AF_UNIX
 * socket (measured: sendmsg returns EINVAL where a plain file fd succeeds). Balfrin runs
 * 5.14.21, which PREDATES that removal, so the SCM_RIGHTS half very likely does not hold
 * there and was not testable from here.
 *
 * ENOSYS rather than EPERM: it is the canonical "this kernel does not implement this call",
 * which is the exact condition every io_uring fallback path was written and tested against.
 * EPERM invites a retry-with-more-privilege path in software that has one. It also matches
 * what SECCOMP_WRAPPER_DEBUG returns.
 *
 * But do not read that as "one errno everywhere", which an earlier draft of this comment
 * claimed. On the LOGIN side the vendored apply-seccomp filter is stacked inside this one
 * and also blocks io_uring with SCMP_ACT_ERRNO(EPERM); the kernel compares only the ACTION
 * and not its data, so the most recently installed filter's errno wins and an agent's Bash
 * command there sees EPERM. Measured, both nesting orders. Functionally irrelevant — libuv
 * branches on rc < 0 — but the claim was wrong. Compute-side, where apply-seccomp does not
 * run, the caller sees ENOSYS. Docker's default profile is likewise EPERM (its
 * defaultErrnoRet), so "Docker returns an errno" is about the ACTION CLASS, not this errno.
 * ---------------------------------------------------------------------- */
static const char *const GRACEFUL_ERRNO_SYSCALLS[] = {
    "io_uring_setup",

    /* sentinel — do not remove */
    NULL,
};

static bool blocks_with_errno(const char *syscall_name)
{
    for (int i = 0; GRACEFUL_ERRNO_SYSCALLS[i] != NULL; i++) {
        if (strcmp(GRACEFUL_ERRNO_SYSCALLS[i], syscall_name) == 0)
            return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * THE SECONDARY SYSCALL ABI.
 *
 * A 64-bit process can enter the kernel through the 32-bit syscall table — on x86_64 with
 * `int $0x80`, on aarch64 cores that implement AArch32 by executing 32-bit ARM code. The
 * seccomp arch is selected by the syscall ENTRY PATH, not by the process's persona, so this
 * is reachable with persona 0 and no personality() call at all (measured 2026-08-31). If the
 * filter only covers the native arch, every deny-list rule is absent from that table.
 *
 * Registering the secondary arch is what closes it: libseccomp translates each rule into the
 * correct 32-bit syscall number automatically (measured: `vm86` lands at 166 in the x86
 * section, `kexec_file_load` is dropped because i386 has none — 49 rules on x86_64, 48 on
 * x86). On Neoverse V2 (Santis) AArch32 is not implemented in silicon, so there this is
 * belt-and-braces; on Cortex-A class aarch64 it is the only thing covering that ABI, which is
 * why it is registered unconditionally rather than probed.
 *
 * One macro, two arches: the two #ifdef blocks this replaces were the same eight lines with
 * one token and one warning string changed, and the warning was WRONG in both copies (`P8`,
 * and `B6-2` for the wrongness — see build_filter()).
 * ---------------------------------------------------------------------- */
#if defined(__x86_64__)
#define SECONDARY_ARCH       SCMP_ARCH_X86
#define SECONDARY_ARCH_NAME  "x86"
#elif defined(__aarch64__)
#define SECONDARY_ARCH       SCMP_ARCH_ARM
#define SECONDARY_ARCH_NAME  "arm"
#else
#define SECONDARY_ARCH_NAME  "none"
#endif

/* libseccomp's own answer, not a variable we set beside the call it describes. */
static bool secondary_arch_registered(const scmp_filter_ctx ctx)
{
#ifdef SECONDARY_ARCH
    return seccomp_arch_exist(ctx, SECONDARY_ARCH) == 0;
#else
    (void)ctx;
    return false;
#endif
}

/* -------------------------------------------------------------------------
 * audit_denylist() — does every name in BLOCKED_SYSCALLS name a syscall?
 *
 * libseccomp answers THREE different things, and conflating two of them is what hid
 * `lookup_dcookies` for three review rounds:
 *
 *   nr >= 0                        the syscall exists on this arch; a rule is emitted.
 *   nr <  0, != __NR_SCMP_ERROR    a libseccomp PSEUDO-number: a real syscall this arch does
 *                                  not have (-10071 for vm86 on x86_64, -10095 for iopl on
 *                                  aarch64). The name is GOOD. seccomp_rule_add() accepts it
 *                                  and the rule appears in whichever registered arch does
 *                                  have the call. Normal, expected, one deny-list spans
 *                                  several arches.
 *   nr == __NR_SCMP_ERROR (-1)     libseccomp has never heard of this name. No rule is
 *                                  emitted anywhere, for any arch, on any kernel. There is
 *                                  no legitimate reason for an entry to be in this state.
 *
 * The old code took the second and third branches together and skipped both without a word,
 * with a correct justification for the second one. That is `P7` exactly: the control declined
 * to apply and told nobody, in a branch documented as deliberate.
 *
 * Measured 2026-09-01 with libseccomp 2.5.3 over all 49 floor names on x86_64, x86, aarch64,
 * arm and x32: exactly one name — the typo — returns __NR_SCMP_ERROR, on every arch. The ten
 * names genuinely absent from one arch (vm86, vm86old, iopl, ioperm, modify_ldt, uselib,
 * sysfs, vserver, futimesat, _sysctl) all return pseudo-numbers. So the two cases ARE
 * distinguishable by the API, and the assert below has zero false positives on both targets.
 * ---------------------------------------------------------------------- */
struct denylist_audit {
    int names;        /* entries in BLOCKED_SYSCALLS                                    */
    int resolved;     /* real syscall number on the native arch                         */
    int arch_absent;  /* known to libseccomp, absent HERE — pseudo-number, still a rule */
    int unresolved;   /* not a syscall name at all. Must be 0.                          */
};

/* `report` may be NULL. When it is not, every non-trivial name is listed, because a count
 * alone is what let a skipped entry hide behind a rule total that happened to add up. */
static void audit_denylist(struct denylist_audit *a, FILE *report)
{
    memset(a, 0, sizeof(*a));
    for (int i = 0; BLOCKED_SYSCALLS[i] != NULL; i++) {
        int nr = seccomp_syscall_resolve_name(BLOCKED_SYSCALLS[i]);
        a->names++;
        if (nr == __NR_SCMP_ERROR) {
            a->unresolved++;
            if (report)
                fprintf(report, "self-test:   UNRESOLVED %s\n", BLOCKED_SYSCALLS[i]);
        } else if (nr < 0) {
            a->arch_absent++;
            if (report)
                fprintf(report, "self-test:   arch-absent %s (libseccomp pseudo-syscall %d;"
                        " the rule still reaches any registered arch that has it)\n",
                        BLOCKED_SYSCALLS[i], nr);
        } else {
            a->resolved++;
        }
    }
}

/* -------------------------------------------------------------------------
 * assert_denylist_resolves() — fatal, at startup, before anything is built.
 *
 * WHY FATAL, and why that is not the operator-facing outage it looks like. The decision one
 * function down is the precedent: an unknown --profile aborts rather than falling back,
 * because "a typo must not silently produce a weaker cage than the caller asked for". A floor
 * entry that names nothing is the same sentence with a smaller subject.
 *
 * WHAT THIS CHECK DEPENDS ON — the part that decides whether it can brick a cluster.
 * seccomp_syscall_resolve_name() is a lookup in a table COMPILED INTO libseccomp. It does not
 * ask the kernel, and the wrapper links libseccomp statically (`-static`), so the answer is a
 * property of THIS BINARY and cannot change under it:
 *
 *   older/newer KERNEL          irrelevant — never consulted. A syscall the kernel dropped
 *                               (lookup_dcookie, gone in 6.5) still resolves; the entry
 *                               becomes a no-op the kernel enforces, which is fine.
 *   older libseccomp at BUILD   a name newer than its tables is unresolved -> this fires on
 *                               the build host, during `make check` / build_and_test.sh,
 *                               before any binary is staged. Remedy is printed: raise
 *                               LIBSECCOMP_VERSION.
 *   newer libseccomp at BUILD   strictly more names resolve. Cannot introduce a failure.
 *   a name legitimately absent  returns a PSEUDO-number, not an error (measured above), so it
 *   on some future kernel       never reaches this branch. This is the case the finding says
 *                               must not brick the wrapper, and the API distinguishes it.
 *
 * The one residual: a build that drops `-static` could load a different libseccomp.so than it
 * was built against. Then this fires at exec time — loudly, with the name — instead of
 * silently emitting no rule, which is still the better of the two.
 * ---------------------------------------------------------------------- */
static int assert_denylist_resolves(void)
{
    struct denylist_audit a;
    const struct scmp_version *v = seccomp_version();

    audit_denylist(&a, NULL);
    if (a.unresolved == 0)
        return 0;

    fprintf(stderr, "seccomp_wrapper: %d name(s) in BLOCKED_SYSCALLS are not syscall names"
            " this libseccomp knows:\n", a.unresolved);
    for (int i = 0; BLOCKED_SYSCALLS[i] != NULL; i++)
        if (seccomp_syscall_resolve_name(BLOCKED_SYSCALLS[i]) == __NR_SCMP_ERROR)
            fprintf(stderr, "seccomp_wrapper:     %s\n", BLOCKED_SYSCALLS[i]);
    fprintf(stderr,
        "seccomp_wrapper: An unresolved name emits NO RULE on ANY architecture, so the cage\n"
        "seccomp_wrapper: would be weaker than its own deny-list claims and nothing would say\n"
        "seccomp_wrapper: so. Refusing to run, for the same reason an unknown --profile is\n"
        "seccomp_wrapper: fatal rather than a fallback.\n"
        "seccomp_wrapper: This is a source or toolchain mismatch, never user input. Either the\n"
        "seccomp_wrapper: name is misspelled (a real syscall merely ABSENT on this arch gets a\n"
        "seccomp_wrapper: libseccomp pseudo-number, not this error, so it never lands here), or\n"
        "seccomp_wrapper: it is newer than the libseccomp %u.%u.%u linked into this binary — in\n"
        "seccomp_wrapper: which case raise LIBSECCOMP_VERSION in build_and_test.sh and rebuild.\n"
        "seccomp_wrapper: `seccomp-wrapper --self-test` prints the full audit.\n",
        v->major, v->minor, v->micro);
    return -1;
}

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
 * build_filter()
 *
 * CONSTRUCTS the filter and hands it back unloaded. install_filter() loads it; --self-test
 * inspects it and throws it away. Split so that the self-test audits the REAL construction
 * rather than a second copy of it — a reimplementation would be exactly the two-lists shape
 * (`P8`) this file has now been bitten by twice.
 *
 * Builds a seccomp filter that:
 *   1. Allows all syscalls by default (SCMP_ACT_ALLOW)
 *   2. Kills the entire process on any blocked syscall (SCMP_ACT_KILL_PROCESS)
 *   3. …except where the GRACEFUL-ERRNO CRITERION applies: blocked just as hard, but the
 *      caller is told rather than killed. TWO instances, and they live in different places
 *      because the criterion is a property of a RULE, not of a name:
 *        - GRACEFUL_ERRNO_SYSCALLS (name-keyed, consulted in the deny-list loop below) —
 *          io_uring_setup, ENOSYS;
 *        - the argument-filtered `personality` rule further down — EINVAL.
 *      The startup assert can only range over the first, so the second is enumerated here
 *      on purpose. A third instance is the point at which this should become one table of
 *      {name, action, arg-comparison} that the assert can check. The criterion itself is
 *      argued once, in slurm-broker/CAGE-PROFILES.md "Failure mode: loud".
 *
 * SCMP_ACT_KILL_PROCESS is used rather than SCMP_ACT_ERRNO so that a
 * blocked call terminates the whole process rather than returning an error
 * the agent could potentially recover from or work around.
 *
 * Requires kernel >= 4.14 for SCMP_ACT_KILL_PROCESS. If you need support
 * for older kernels, change to SCMP_ACT_KILL (kills only the calling thread)
 * or SCMP_ACT_ERRNO(EPERM) (returns an error).
 * ---------------------------------------------------------------------- */
static int build_filter(bool debug_mode, enum wrapper_profile profile, scmp_filter_ctx *out)
{
    scmp_filter_ctx ctx;
    int rc;

    *out = NULL;
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

    /*
     * B6-1 (review, 2026-09-01). Same shape as the D1 assert below, ONE LEVEL FURTHER OUT: that
     * one ties GRACEFUL_ERRNO_SYSCALLS to BLOCKED_SYSCALLS, this one ties BLOCKED_SYSCALLS to
     * libseccomp's name table. They are not the same KIND of check, and the difference is the
     * whole safety argument — the one below can only ever fail on a programming error in this
     * file, while this one also depends on the libseccomp the binary was linked against. That
     * dependency is why the failure modes are enumerated at the function, and why the answer
     * is "a property of this binary, fixed at link time" rather than "whatever the cluster
     * has today".
     */
    if (assert_denylist_resolves() != 0)
        return -1;

    /*
     * D1 (review, 2026-08-29): GRACEFUL_ERRNO_SYSCALLS is a SECOND list, and nothing used
     * to tie it to the first. A typo there — or a name that is blocked by some other
     * mechanism — was a silent no-op: the rule loop never sees it, the syscall keeps
     * whatever action it had, and the wrapper prints nothing. The fail-safe direction, so
     * this is availability rather than security, but invisible either way, and `personality`
     * is a live example: it gets its rule separately from this loop, so listing it here
     * would do exactly nothing. A second list that is not checked against the first is the
     * P8 shape. Checked here, at startup, and fatal — this can only fire on a programming
     * error, never on user input.
     */
    for (int i = 0; GRACEFUL_ERRNO_SYSCALLS[i] != NULL; i++) {
        bool on_floor = false;
        for (int j = 0; BLOCKED_SYSCALLS[j] != NULL; j++) {
            if (strcmp(GRACEFUL_ERRNO_SYSCALLS[i], BLOCKED_SYSCALLS[j]) == 0) {
                on_floor = true;
                break;
            }
        }
        if (!on_floor) {
            fprintf(stderr, "seccomp_wrapper: '%s' is in GRACEFUL_ERRNO_SYSCALLS but not in"
                    " BLOCKED_SYSCALLS — it would silently do nothing. Refusing to run.\n",
                    GRACEFUL_ERRNO_SYSCALLS[i]);
            return -1;
        }
    }

    /* default action: allow everything not explicitly blocked */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_wrapper: seccomp_init failed: %s\n", strerror(errno));
        return -1;
    }

#ifdef SECONDARY_ARCH
    /*
     * Register the secondary syscall ABI. The rationale is at SECONDARY_ARCH above; what
     * belongs here is the FAILURE path, and until 2026-09-01 both copies of it said the
     * opposite of what happens (`B6-2`, `P11`, `P12`).
     *
     * The old string was "32-bit syscall path uncovered". Measured: an arch that is not
     * registered is not uncovered, it is REFUSED WHOLESALE — libseccomp appends
     * "invalid architecture action / action KILL" to the program, so every syscall arriving
     * through that entry path dies with SIGSYS whether or not it is on the deny-list. A
     * scientist reading "uncovered" after a SIGSYS storm goes looking for a missing deny
     * rule; the actual state is that the whole ABI is denied. What the registration buys is
     * PRECISION, not coverage: with it, permitted 32-bit syscalls work and denied ones die.
     *
     * Still a warning rather than fatal, and now for a stated reason rather than by
     * omission: this direction fails CLOSED, so the residual risk is availability for 32-bit
     * binaries only, and refusing to start would trade that for a total outage — the failure
     * shape this review round produced three times. It is no longer only a warning, either:
     * `--self-test` reports the registration from libseccomp's own seccomp_arch_exist(), and
     * smoke test 15 asserts it, so deleting this call now turns the suite red (it did not —
     * that is the finding).
     */
    rc = seccomp_arch_add(ctx, SECONDARY_ARCH);
    if (rc != 0 && rc != -EEXIST) {
        fprintf(stderr, "seccomp_wrapper: warning: could not add the %s arch to the filter:"
                " %s\n"
                "seccomp_wrapper: the 32-bit syscall entry path is now refused WHOLESALE"
                " (unregistered arch => action KILL), so a 32-bit binary or an `int $0x80`\n"
                "seccomp_wrapper: call dies with SIGSYS even when the syscall is allowed. The"
                " native 64-bit ABI is unaffected and fully covered.\n",
                SECONDARY_ARCH_NAME, strerror(-rc));
    }
#endif

    for (int i = 0; BLOCKED_SYSCALLS[i] != NULL; i++) {
        /*
         * Resolve BEFORE the exemption check, so the audit covers the FLOOR rather than
         * whatever this profile happens to keep. Otherwise a typo in an exempted name would
         * be invisible under the profile that exempts it and fatal under the one that does
         * not — a control whose presence depends on the command line.
         */
        int nr = seccomp_syscall_resolve_name(BLOCKED_SYSCALLS[i]);

        if (nr == __NR_SCMP_ERROR) {
            /*
             * Unreachable: assert_denylist_resolves() ran before seccomp_init() and refused
             * to continue if any name was unknown. Kept as a hard failure rather than
             * deleted, because if it ever does fire the pre-pass and this loop disagree
             * about the same list, and THAT must not be the silent `continue` it used to be.
             * The old branch skipped both "unknown name" and "absent on this arch" together;
             * only the second is normal, and libseccomp distinguishes them (see
             * audit_denylist()). A pseudo-number is negative but not __NR_SCMP_ERROR, and
             * seccomp_rule_add() accepts it — that is how `vm86` gets a rule at 166 in the
             * x86 section of a filter built on x86_64.
             */
            fprintf(stderr, "seccomp_wrapper: internal error: '%s' did not resolve here but"
                    " passed the startup audit\n", BLOCKED_SYSCALLS[i]);
            seccomp_release(ctx);
            return -1;
        }

        /*
         * A profile may exempt a floor entry. Silently, on purpose: the exemption
         * table is STATIC per profile, so the profile name already on the command
         * line says everything a printed line would, and this runs once per RANK —
         * a note here is N identical lines in the job's .err file for no information.
         */
        if (profile_exempts(profile, BLOCKED_SYSCALLS[i]))
            continue;

        /*
         * Per-syscall action. debug_mode already makes everything ENOSYS, so this only
         * bites in production, and it never makes a syscall MORE permitted — both actions
         * refuse the call; they differ in what the caller is told.
         */
        uint32_t action = blocks_with_errno(BLOCKED_SYSCALLS[i])
            ? SCMP_ACT_ERRNO(ENOSYS)
            : block_action;

        rc = seccomp_rule_add(ctx, action, nr, 0);
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
     * Any other value selects a new execution domain: PER_LINUX32 (0x0008) selects the
     * 32-bit syscall ABI, ADDR_NO_RANDOMIZE (0x0040000) turns ASLR off.
     *
     * This comment used to claim PER_LINUX32 gives the process "a syscall number table the
     * deny-list would not cover — a filter bypass that is easy to miss". MEASURED FALSE,
     * 2026-08-31: the seccomp arch is chosen by the SYSCALL ENTRY PATH, not by the persona.
     * A probe issuing `int $0x80` from an ordinary 64-bit process with persona 0 and no
     * personality() call at all reaches the 32-bit table directly — and husk still kills it,
     * because seccomp_arch_add() above registers the secondary arch and every deny-list rule
     * is emitted for both (verified by exporting the filter: 49 rules on x86_64, 48 on x86,
     * the difference being kexec_file_load, which i386 lacks).
     *
     * So the arch registration is the primary and only defence against the 32-bit table, and
     * this rule never was that gate. What it does defend is the persona itself — most
     * usefully ADDR_NO_RANDOMIZE, i.e. it is an ASLR control. Keeping it is right; believing
     * it is what covers the secondary ABI is not.
     *
     * Argument filtering is safe here because personality's sole argument is
     * a plain unsigned long, not a pointer, so libseccomp can compare it
     * directly inside the BPF program.
     *
     * REPORTED, not fatal (2026-08-31), for the same reason as io_uring_setup and under
     * the same criterion in CAGE-PROFILES.md "Failure mode: loud": does the caller's
     * fallback change the RESULT, or only the speed/detail?
     *
     * Measured on Santis, outside husk: `lscpu` calls personality(PER_LINUX32) and the
     * KERNEL itself answers -1 EINVAL, because that node has no 32-bit EL0. lscpu handles
     * it, prints 64-bit only, and exits clean. Inside husk the same call took SIGSYS and
     * lscpu died before printing a byte — so husk was killing a process for asking a
     * question the hardware would have refused anyway. The fallback here is not
     * hypothetical; it is the path that node already runs.
     *
     * EINVAL rather than EPERM or ENOSYS, deliberately: EINVAL is exactly what a kernel
     * returns for a persona it cannot provide, so husk becomes indistinguishable from
     * hardware without that ABI — which is the best-tested branch in any caller. EPERM
     * invites a retry-with-privilege path in software that has one.
     *
     * The CONTROL is unchanged: the process still cannot switch ABI, which is the whole
     * point of the rule. And the rule was defence in depth to begin with — the filter
     * registers the secondary arch (SCMP_ARCH_X86 / SCMP_ARCH_ARM) above, so both syscall
     * tables are covered whatever persona is in force. What this stops is the collateral:
     * a common, harmless probe killing the process that made it.
     *
     * This rule cannot live in GRACEFUL_ERRNO_SYSCALLS: that table is keyed by NAME and
     * consulted in the deny-list loop, while personality is added here with an argument
     * comparison. Listing it there would silently do nothing — which is exactly what the
     * startup assert on that table refuses to allow.
     *
     * THE SIGN-EXTENDED QUERY (`B6-8`, decided 2026-09-01 — read this before changing the
     * comparison). The kernel declares this argument `unsigned int` and therefore truncates
     * it, so EVERY value whose low 32 bits are all ones is the same read-only query:
     * 0x00000000ffffffff and 0xffffffffffffffff are one kernel operation. The rule compares
     * the full 64-bit datum, so the second spelling is refused with EINVAL although the
     * kernel would have answered it — and `personality(-1)`, the natural C spelling, IS the
     * second one, because glibc's prototype takes an unsigned long.
     *
     * This is NOT a graceful-errno question, and reading it as one is what the criterion in
     * CAGE-PROFILES.md would mis-answer. The criterion governs a call husk INTENDS to block:
     * may it report instead of kill. Here husk intends to ALLOW the call — the query form is
     * explicitly permitted, test 3 pins it — and the rule's condition names an object
     * slightly larger than the one meant. That is `P15`, the same class as the deny-list
     * name that resolved to nothing, not a failure-mode choice.
     *
     * MEASURED, and it is the reason the rule is unchanged. libseccomp cannot express "refuse
     * unless the low 32 bits are all ones":
     *   - two conditions on one argument in one rule -> -EINVAL (rules AND within themselves
     *     but libseccomp rejects a duplicate argument index, so "!= A && != B" is out);
     *   - a second rule ORs, which only ever WIDENS the refusal;
     *   - an SCMP_ACT_ALLOW rule on an ALLOW-default filter -> -EPERM;
     *   - there is no masked NOT-EQUAL. The exact form is 32 masked rules, one per low bit —
     *     "(arg0 & (1<<i)) == 0" for each i — which is correct and expressible, and is a
     *     rebuild of a live control on both clusters, verifiable on only one of them, to fix
     *     a wrong answer to a QUERY rather than a wrong computation.
     *
     * So: kept, deliberately, as a false positive in the safe direction. The costs, stated
     * rather than assumed away: since 2026-08-31 it is also a QUIET one — the caller used to
     * die on SIGSYS and now silently misreads its own persona. A caller doing
     * `personality(0xffffffff) & ADDR_NO_RANDOMIZE` on the -1 spelling reads -1, i.e. every
     * bit set, and concludes ASLR is already off. No probe used this spelling before today.
     * It now has one, in BOTH directions: smoke test 16 fails if the sign-extended query
     * starts being allowed AND if it goes back to killing, because the one disposition in
     * this file supported by an argument rather than a measurement is the one that can drift
     * without anything noticing.
     */
    {
        int nr = seccomp_syscall_resolve_name("personality");
        if (nr != __NR_SCMP_ERROR) {
            /* debug_mode still wins: it makes everything ENOSYS for diagnosis. */
            uint32_t pers_action = debug_mode ? block_action : SCMP_ACT_ERRNO(EINVAL);
            rc = seccomp_rule_add(ctx, pers_action, nr, 1,
                                  SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)0xffffffff));
            if (rc != 0) {
                fprintf(stderr, "seccomp_wrapper: seccomp_rule_add('personality')"
                        " failed: %s\n", strerror(-rc));
                seccomp_release(ctx);
                return -1;
            }
        }
    }

    *out = ctx;
    return 0;
}

/* -------------------------------------------------------------------------
 * install_filter() — build it, load it, drop the context. The production path.
 * ---------------------------------------------------------------------- */
static int install_filter(bool debug_mode, enum wrapper_profile profile)
{
    scmp_filter_ctx ctx;
    int rc;

    if (build_filter(debug_mode, profile, &ctx) != 0)
        return -1;

    rc = seccomp_load(ctx);
    seccomp_release(ctx);

    if (rc != 0) {
        fprintf(stderr, "seccomp_wrapper: seccomp_load failed: %s\n",
                strerror(-rc));
        return -1;
    }

    return 0;
}

static const char *arch_name(uint32_t token)
{
    switch (token) {
    case SCMP_ARCH_X86_64:  return "x86_64";
    case SCMP_ARCH_X86:     return "x86";
    case SCMP_ARCH_X32:     return "x32";
    case SCMP_ARCH_AARCH64: return "aarch64";
    case SCMP_ARCH_ARM:     return "arm";
    default:                return "unknown";
    }
}

/* -------------------------------------------------------------------------
 * self_test() — `seccomp-wrapper --self-test`.
 *
 * Builds the REAL filter (same build_filter() the cage uses), reports what it contains, and
 * exits without loading it and without exec'ing anything. It exists for three jobs:
 *
 *   1. It is the oracle smoke tests 14 and 15 assert against. Both of those findings — a
 *      deny-list name that resolves to nothing, and a secondary-arch registration whose
 *      deletion left the suite 13/13 green — are properties of the filter as CONSTRUCTED, and
 *      until now nothing in the tree could see one.
 *   2. It is the cross-arch check for the claim that made the B6-1 assert safe. The
 *      zero-false-positive measurement was taken with libseccomp 2.5.3 tables on x86_64;
 *      running this on Santis with the release's 2.5.5 answers it there in one command
 *      instead of by inference.
 *   3. It gives an operator on a cluster a way to ask the SHIPPED BINARY what it blocks,
 *      rather than reading the source it was supposedly built from (`P12`: the docs drift
 *      toward the intent).
 *
 * Deliberately NOT a filter it installs: it must be safe to run from anywhere, including
 * inside a cage, and it must not be a path by which someone runs a command with the filter
 * half-applied. It takes no other arguments for exactly that reason.
 *
 * Every line is prefixed `self-test:` and the two the tests read are key=value, so a human
 * reading scrollback and a machine grepping the log see the same statement (`P8`).
 * ---------------------------------------------------------------------- */
static int self_test(void)
{
    const struct scmp_version *v = seccomp_version();
    struct denylist_audit a;
    scmp_filter_ctx ctx = NULL;
    int failures = 0;
    int pers;

    printf("self-test: seccomp-wrapper, libseccomp %u.%u.%u, native arch %s\n",
           v->major, v->minor, v->micro, arch_name(seccomp_arch_native()));

    audit_denylist(&a, stdout);
    printf("self-test: denylist names=%d resolved=%d arch-absent=%d unresolved=%d\n",
           a.names, a.resolved, a.arch_absent, a.unresolved);
    if (a.unresolved != 0) {
        printf("self-test:   an unresolved name emits no rule on any arch — it is a typo, not"
               " an absent syscall\n");
        failures++;
    }

    /* build_filter() reports on stderr; this function on stdout. Flush first, or a redirected
     * run interleaves them backwards and the fatal line appears above its own audit. */
    fflush(stdout);

    /* PROFILE_LOGIN: the floor with nothing subtracted. The audit above ranges over the whole
     * of BLOCKED_SYSCALLS regardless of profile, so nothing here is profile-dependent. */
    if (build_filter(false, PROFILE_LOGIN, &ctx) != 0) {
        printf("self-test: filter construction FAILED (see the error above)\n");
        failures++;
    } else {
        bool reg = secondary_arch_registered(ctx);
        printf("self-test: secondary-arch name=%s registered=%s\n",
               SECONDARY_ARCH_NAME, reg ? "yes" : "no");
        if (!reg) {
            printf("self-test:   without it the 32-bit syscall entry path is refused wholesale"
                   " (action KILL), not merely unfiltered\n");
            failures++;
        }
        pers = seccomp_syscall_resolve_name("personality");
        printf("self-test: personality nr=%d rule=arg-filtered\n", pers);
        if (pers == __NR_SCMP_ERROR)
            failures++;
        seccomp_release(ctx);
    }

    printf("self-test: %s\n", failures ? "FAILED" : "OK");
    return failures ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: seccomp-wrapper [--profile=login|single-node] [--] <command> [args...]\n"
                        "       seccomp-wrapper --self-test\n");
        return 1;
    }

    /*
     * --self-test audits the filter and exits. It must be the ONLY argument: `--self-test`
     * followed by a command must never be read as "audit, then run that command", because the
     * obvious mistake to make here is one that runs a command with no filter at all. Placed
     * before prctl() and setrlimit() so it changes nothing about this process either.
     */
    if (strcmp(argv[1], "--self-test") == 0) {
        if (argc != 2) {
            fprintf(stderr, "seccomp-wrapper: --self-test takes no other arguments; it audits"
                    " the filter and exits, and never runs a command\n");
            return 1;
        }
        return self_test();
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

    /*
     * No core dumps from anything this filter kills.
     *
     * SIGSYS is a core-generating signal, so every syscall this wrapper blocks writes a
     * full memory image into the cage's WRITABLE ROOT — the user's project directory, on
     * Lustre. Measured on Santis, 2026-08-29: one `lscpu` per rank in a 288-rank job left
     * 288 cores and 325 MB, and that scales linearly with rank count, so a job of ordinary
     * HPC size fills a quota with husk's own enforcement artefacts.
     *
     * It is also a resource primitive, which is the reason this is not merely tidiness: a
     * caged process that calls a blocked syscall in a loop turns each cheap call into a
     * multi-hundred-megabyte write, and the process never issues a write itself — the
     * kernel does, so anything auditing what the confined side writes sees nothing. The
     * amplification is supplied by the control.
     *
     * THE COST, stated because it is real: a genuine segfault inside the cage also stops
     * producing a core. A scientist who needs one runs the command outside husk — the same
     * answer as for strace, and for the same reason: diagnosis happens where enforcement
     * is not. Reversing this is deleting the setrlimit call.
     *
     * Both profiles. An earlier proposal was login-only, on the evidence available then
     * (the cores seen were named for a login node); the per-rank count killed that idea —
     * the compute side is where the volume actually is.
     */
    {
        struct rlimit no_core = { .rlim_cur = 0, .rlim_max = 0 };
        if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
            /* Not fatal: this is hygiene plus a resource bound, not part of the boundary.
             * A cage that refuses to start because it could not lower a limit would trade
             * a disk-space problem for an outage. Loud, so it is never a silent surprise. */
            fprintf(stderr, "seccomp_wrapper: warning: could not disable core dumps: %s"
                    " — a blocked syscall will leave a core file\n", strerror(errno));
        }
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
