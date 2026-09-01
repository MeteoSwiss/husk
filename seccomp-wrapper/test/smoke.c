/*
 * smoke.c — integration smoke tests for seccomp-wrapper
 *
 * Usage: smoke <path-to-seccomp-wrapper> <path-to-test_ptrace>
 *              <path-to-test_personality_query> <path-to-test_personality_switch>
 *              <path-to-test_af_unix> <path-to-test_cma> <path-to-test_io_uring>
 *
 * Test 1: exec passthrough               — wraps "echo ok", expects clean exit.
 * Test 2: ptrace blocked                 — wraps test_ptrace, expects SIGSYS.
 * Test 3: personality query allowed      — wraps test_personality_query, expects clean exit.
 * Test 4: personality ABI-switch blocked — the switch must not take effect (EINVAL or SIGSYS).
 * Test 5: AF_UNIX allowed under login   — the default profile must not change behaviour.
 * Test 6: AF_UNIX still ALLOWED under single-node — CUDA requires it (see below).
 * Test 7: an unknown --profile is fatal  — never a silent fallback to a weaker cage.
 * Test 8: CMA read blocked under login   — the exemption must not leak into the default.
 * Test 9: CMA read allowed under single-node — Cray MPICH needs it.
 * Test 10: CMA WRITE still blocked under single-node — read and write are not one
 *          concession; tests 9 and 10 together are the whole point of the delta.
 * Test 11: io_uring_setup reported       — wraps test_io_uring, expects ENOSYS, not death.
 * Test 12: io_uring enter AND register fatal — using a ring must stay a kill, both calls.
 * Test 13: no core dumps               — SOFT AND HARD RLIMIT_CORE are 0, after the child
 *          has tried to raise them; the soft limit alone is not a bound (B6-3).
 * Test 14: every deny-list name resolves — a name libseccomp cannot resolve emits no rule
 *          on any arch, and the loop used to skip it in silence (B6-1).
 * Test 15: the secondary syscall ABI is covered — registered, and the deny-list reaches it
 *          (B6-2). Deleting the registration used to leave this suite 13/13 green.
 * Test 16: personality's sign-extended query — pins the disposition, either way (B6-8).
 */
#include <fcntl.h>
#include <string.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/* As run(), but with the child's stderr discarded. Used for BASELINE probes, whose
 * diagnostics would otherwise print under a test heading they are not the result of —
 * "setup SUCCEEDED" beneath "test 11: io_uring_setup -> ENOSYS" reads as a failure. */
static int run_quiet(char *const argv[], int *wstatus)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp(argv[0], argv);
        _exit(127);
    }
    return waitpid(pid, wstatus, 0) < 0 ? -1 : 0;
}

/* As run(), but the child's stdout is captured. Used by the tests that read
 * `seccomp-wrapper --self-test`, whose output IS the assertion. */
static int run_capture(char *const argv[], int *wstatus, char *buf, size_t buflen)
{
    int rp[2];
    size_t got = 0;

    buf[0] = '\0';
    if (pipe(rp) != 0) { perror("pipe"); return -1; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(rp[0]); close(rp[1]); return -1; }
    if (pid == 0) {
        dup2(rp[1], STDOUT_FILENO);
        close(rp[0]); close(rp[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(rp[1]);
    for (;;) {
        char sink[512];
        /* Once the buffer is full, keep DRAINING instead of closing the pipe: a child killed
         * by SIGPIPE would arrive here as "did not run to completion", which is a different
         * finding from the one the caller is testing. */
        ssize_t n = (got < buflen - 1)
            ? read(rp[0], buf + got, buflen - 1 - got)
            : read(rp[0], sink, sizeof(sink));
        if (n <= 0) break;
        if (got < buflen - 1) got += (size_t)n;
    }
    buf[got] = '\0';
    close(rp[0]);
    return waitpid(pid, wstatus, 0) < 0 ? -1 : 0;
}

static int run(char *const argv[], int *wstatus)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }
    return waitpid(pid, wstatus, 0) < 0 ? -1 : 0;
}

int main(int argc, char *argv[])
{
    if (argc != 8) {
        fprintf(stderr, "usage: smoke <seccomp-wrapper> <test-ptrace>"
                        " <test-personality-query> <test-personality-switch>"
                        " <test-af-unix> <test-cma> <test-io-uring>\n");
        return 2;
    }
    char *wrapper          = argv[1];
    char *ptrace_bin       = argv[2];
    char *personality_qry  = argv[3];
    char *personality_sw   = argv[4];
    char *af_unix_bin      = argv[5];
    char *cma_bin          = argv[6];
    char *io_uring_bin     = argv[7];
    int failed = 0, skipped = 0, st = 0;

    /* --- test 1: normal exec passthrough --------------------------------- */
    printf("test 1: exec passthrough               ... ");
    fflush(stdout);
    char *cmd1[] = {wrapper, "echo", "ok", NULL};
    if (run(cmd1, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAIL (expected clean exit)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 2: blocked syscall kills process with SIGSYS --------------- */
    printf("test 2: ptrace blocked                 ... ");
    fflush(stdout);
    char *cmd2[] = {wrapper, ptrace_bin, NULL};
    st = 0;
    if (run(cmd2, &st) != 0) {
        printf("FAIL (could not spawn process)\n");
        failed++;
    } else if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) {
        if (WIFSIGNALED(st))
            printf("FAIL (signal %d, expected SIGSYS=%d)\n", WTERMSIG(st), SIGSYS);
        else
            printf("FAIL (exited %d, expected SIGSYS)\n", WEXITSTATUS(st));
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 3: personality query form (0xffffffff) must be allowed ----- */
    printf("test 3: personality query allowed      ... ");
    fflush(stdout);
    char *cmd3[] = {wrapper, personality_qry, NULL};
    st = 0;
    if (run(cmd3, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        if (WIFSIGNALED(st))
            printf("FAIL (signal %d, expected clean exit)\n", WTERMSIG(st));
        else
            printf("FAIL (expected clean exit)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 4: the personality ABI-switch must not TAKE EFFECT ---------
     * This asserted "killed with SIGSYS" until 2026-08-31, which was a proxy for the
     * contract rather than the contract. The rule exists so a process cannot move to the
     * 32-bit syscall table; dying for asking was a separate decision, and it is now EINVAL
     * because lscpu on aarch64 asks during normal startup and the kernel itself answers
     * EINVAL there. The probe now reads the persona, attempts the switch, and reads again,
     * so it would catch a filter that reports an error and lets the switch happen anyway —
     * which a return-value check could not. Either action is accepted here; the property
     * is what is pinned. */
    printf("test 4: personality ABI-switch blocked ... ");
    fflush(stdout);
    /* BASELINE FIRST, like tests 11 and 13. A green run here cannot by itself distinguish
     * "husk refused the persona" from "this kernel refuses it anyway" — and the second is
     * real: an aarch64 node without 32-bit EL0 returns EINVAL for PER_LINUX32 on its own.
     * That is what made the first version of this probe vacuous on the one platform it was
     * written for. So: run it UNCAGED. It must fail there, because at least one of the two
     * personas has to be accepted by a bare kernel for the caged run to prove anything. */
    char *cmd4base[] = {personality_sw, NULL};
    st = 0;
    int p4base = run_quiet(cmd4base, &st) == 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (p4base == 0) {
        printf("FAIL (this kernel refuses BOTH personas unaided, so a caged pass proves"
               " nothing — the probe needs a persona this kernel accepts)\n");
        failed++;
        goto test4_done;
    }
    if (p4base == 3 || p4base == -1) {
        printf("FAIL (baseline probe could not run: exit %d)\n", p4base);
        failed++;
        goto test4_done;
    }

    char *cmd4[] = {wrapper, personality_sw, NULL};
    st = 0;
    if (run(cmd4, &st) != 0) {
        printf("FAIL (could not spawn process)\n");
        failed++;
    } else if (WIFSIGNALED(st)) {
        /* Still valid: a KILL_PROCESS action also satisfies "the switch did not happen". */
        if (WTERMSIG(st) == SIGSYS)
            printf("PASS (killed)\n");
        else { printf("FAIL (signal %d)\n", WTERMSIG(st)); failed++; }
    } else if (WEXITSTATUS(st) != 0) {
        /* 1 = the switch was accepted, 2 = the persona moved anyway, 3 = probe broken.
         * All three mean the control is not doing its job or cannot be judged. */
        printf("FAIL (probe exit %d — the ABI switch was not refused)\n", WEXITSTATUS(st));
        failed++;
    } else {
        printf("PASS\n");
    }
test4_done:

    /* --- test 5: AF_UNIX still allowed under the default (login) profile ---
     * The husk launcher wraps the whole agent session, and the runtime uses unix
     * sockets for its own IPC — so the default must stay exactly as it was. */
    printf("test 5: AF_UNIX allowed (login)        ... ");
    fflush(stdout);
    char *cmd5[] = {wrapper, "--profile=login", af_unix_bin, NULL};
    st = 0;
    if (run(cmd5, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAIL (AF_UNIX must remain available on the login profile)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 6: AF_UNIX must remain available under single-node too ------
     * This pins a DECISION, not an accident. The single-node profile used to block
     * socket(AF_UNIX); Balfrin 2026-07-30 showed CUDA cannot survive that — cuInit
     * returns 304 under the profile and succeeds without it, with the mount cage
     * exonerated. If someone re-adds the block, this test fails and points here.
     * What kept MUNGE unreachable was never this rule: it is the /run/munge mount
     * mask, which is destination-aware in a way a syscall filter cannot be. */
    printf("test 6: AF_UNIX allowed (single-node)  ... ");
    fflush(stdout);
    char *cmd6[] = {wrapper, "--profile=single-node", af_unix_bin, NULL};
    st = 0;
    if (run(cmd6, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAIL (AF_UNIX must stay available: CUDA needs it, and blocking it broke ICON)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 7: an unknown profile is fatal, and does NOT run the command --
     * A typo must never yield a weaker cage than the caller asked for. */
    printf("test 7: unknown profile is fatal       ... ");
    fflush(stdout);
    char *cmd7[] = {wrapper, "--profile=nonesuch", "echo", "SHOULD-NOT-RUN", NULL};
    st = 0;
    if (run(cmd7, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) == 0) {
        printf("FAIL (an unknown profile must abort, not fall back)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 8: CMA read stays blocked on the default (login) profile ----
     * The exemption belongs to one profile. If it leaks into the floor, an agent
     * session gets to read other processes' memory — which is what the deny-list
     * was written for in the first place. */
    printf("test 8: CMA read blocked (login)       ... ");
    fflush(stdout);
    char *cmd8[] = {wrapper, "--profile=login", cma_bin, "read", NULL};
    st = 0;
    if (run(cmd8, &st) != 0) {
        printf("FAIL (could not spawn process)\n");
        failed++;
    } else if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) {
        printf("FAIL (the exemption must not reach the login profile)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 9: CMA read is permitted under single-node ------------------
     * Cray MPICH reads the peer rank's address space directly for intra-node
     * messages. Blocked, ICON dies with SIGSYS as soon as ranks exchange data. */
    printf("test 9: CMA read allowed (single-node) ... ");
    fflush(stdout);
    char *cmd9[] = {wrapper, "--profile=single-node", cma_bin, "read", NULL};
    st = 0;
    if (run(cmd9, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        if (WIFSIGNALED(st))
            printf("FAIL (killed by signal %d — MPI intra-node transfers need this)\n",
                   WTERMSIG(st));
        else
            printf("FAIL (exited %d, expected the read to succeed)\n", WEXITSTATUS(st));
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 10: CMA WRITE is still blocked under single-node ------------
     * This is the half of the delta that must never move. Reading a sibling rank's
     * memory discloses same-uid data inside one job; WRITING reaches into another
     * process's address space, and the process worth reaching is the un-caged
     * step-broker — that is arbitrary code execution outside the cage, i.e. the
     * escape itself. If a future MPICH release turns out to want the write side,
     * that is a decision to argue, not a test to relax. */
    printf("test 10: CMA write blocked (single-node)... ");
    fflush(stdout);
    char *cmd10[] = {wrapper, "--profile=single-node", cma_bin, "write", NULL};
    st = 0;
    if (run(cmd10, &st) != 0) {
        printf("FAIL (could not spawn process)\n");
        failed++;
    } else if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) {
        printf("FAIL (process_vm_writev must stay blocked under every profile)\n");
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 11: io_uring_setup is blocked, but REPORTED, not fatal ------
     * The only entry in GRACEFUL_ERRNO_SYSCALLS. The contract: blocked, but the caller
     * lives to take its fallback. Why that is the right call for THIS syscall and not in
     * general is argued once, in CAGE-PROFILES.md "Failure mode: loud" — not restated
     * here, because a fourth copy of the argument had already drifted from the other
     * three by the time this test was reviewed.
     *
     * Baselined against the UNWRAPPED probe on purpose. On a kernel without io_uring the
     * bare syscall already returns ENOSYS, so a wrapped-only check would pass for the
     * wrong reason — a false friend that reports the filter working on a machine where
     * nothing was ever filtered. */
    printf("test 11: io_uring_setup -> ENOSYS      ... ");
    fflush(stdout);
    char *cmd11base[] = {io_uring_bin, "setup", NULL};
    st = 0;
    int base = run_quiet(cmd11base, &st) == 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    /*
     * The baseline decides whether this test CAN run, and each outcome means something
     * different. An earlier version treated every non-1 exit as "no io_uring here", which
     * reported a false explanation and kept `make check` green when the precondition was
     * simply broken — a hardened site with kernel.io_uring_disabled=1 returns EPERM, not
     * ENOSYS, and would have been silently skipped with the wrong reason printed.
     */
    if (base == 0) {
        printf("SKIP (kernel has no io_uring: bare syscall already returns ENOSYS)\n");
        skipped++;
    } else if (base == 2) {
        printf("FAIL (bare io_uring_setup failed with a non-ENOSYS errno — probably"
               " kernel.io_uring_disabled; this test cannot tell you anything here)\n");
        failed++;
    } else if (base != 1) {
        printf("FAIL (baseline probe did not run: exit %d)\n", base);
        failed++;
    } else {
        char *cmd11[] = {wrapper, io_uring_bin, "setup", NULL};
        st = 0;
        if (run(cmd11, &st) != 0) {
            printf("FAIL (could not spawn process)\n");
            failed++;
        } else if (WIFSIGNALED(st)) {
            printf("FAIL (signal %d — the probe must RETURN, not die)\n", WTERMSIG(st));
            failed++;
        } else if (WEXITSTATUS(st) != 0) {
            printf("FAIL (exited %d, expected 0 = blocked with ENOSYS)\n", WEXITSTATUS(st));
            failed++;
        } else {
            printf("PASS\n");
        }
    }

    /* --- test 12: io_uring_enter is still FATAL ---------------------------
     * The other half of the asymmetry, and the half that must never move. setup is a
     * capability probe; enter operates on a ring, and no process under this filter can
     * create one — so reaching enter means holding a ring obtained OUTSIDE the cage.
     * That is the case that should die loudly rather than be handed a polite errno. If
     * this test ever goes red because someone widened GRACEFUL_ERRNO_SYSCALLS, the
     * widening is the bug. */
    printf("test 12: io_uring use still killed     ... ");
    fflush(stdout);
    {
        /* BOTH calls, in one test. Reviewed 2026-08-29: with only `enter` covered, adding
         * io_uring_register to GRACEFUL_ERRNO_SYSCALLS left the suite 12/12 green — while
         * the comment here claimed that exact widening would turn it red. A test that names
         * a class must iterate the class. */
        const char *modes[] = {"enter", "register", NULL};
        int bad = 0;
        for (int m = 0; modes[m] != NULL; m++) {
            char *cmd12[] = {wrapper, io_uring_bin, (char *)modes[m], NULL};
            st = 0;
            if (run(cmd12, &st) != 0) {
                printf("FAIL (could not spawn %s) ", modes[m]);
                bad = 1;
            } else if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) {
                if (WIFSIGNALED(st))
                    printf("FAIL (%s: signal %d, expected SIGSYS=%d) ",
                           modes[m], WTERMSIG(st), SIGSYS);
                else
                    printf("FAIL (%s: exited %d — using a ring must stay fatal) ",
                           modes[m], WEXITSTATUS(st));
                bad = 1;
            }
        }
        if (bad) { printf("\n"); failed++; } else { printf("PASS\n"); }
    }

    /* --- test 13: no core dumps from anything the filter kills ------------
     * SIGSYS is core-generating, so every block used to write a full memory image into
     * the cage's writable root. Measured on Santis: one lscpu per rank in a 288-rank job
     * left 288 cores and 325 MB, scaling with rank count — and a loop over a blocked
     * syscall turns that into an amplification primitive the confined side never has to
     * issue a write for. Asserted through the child's OWN view of the limit, because
     * whether a core FILE appears also depends on core_pattern (systemd-coredump pipes
     * it), which would make a file-existence check pass for the wrong reason on this
     * laptop and fail for the wrong reason on a cluster.
     *
     * BOTH LIMITS, and the child tries to RAISE first (B6-3). This asserted `ulimit -c` — the
     * SOFT limit — alone, and mutating .rlim_max to RLIM_INFINITY kept the suite fully green.
     * The soft limit is not a bound: setrlimit is not on the deny-list (correctly, it is
     * needed), so a caged process restores it in one call and the amplification argument the
     * code makes is void. What must hold is that the confined side CANNOT raise it, so the
     * child attempts exactly the escape — `ulimit -c unlimited` — and then reports both
     * limits. Anchoring on the contract, not on the visible artefact of the mechanism
     * (`P15`'s corollary). */
    printf("test 13: no core dumps in the cage     ... ");
    fflush(stdout);
    char *cmd13[] = {wrapper, "sh", "-c",
                     "ulimit -c unlimited 2>/dev/null; echo S=$(ulimit -S -c) H=$(ulimit -H -c)",
                     NULL};
    st = 0;
    int rp[2];
    /*
     * RAISE the limit here first. Without this the test is decoration: the ambient core
     * limit is already 0 on many systems (this laptop included), so the child reports 0
     * whether or not the wrapper did anything — caught by mutation, the same false-friend
     * shape as test 11's baseline. If the hard limit forbids raising it, the precondition
     * cannot be established and that is a SKIP, never a PASS.
     */
    struct rlimit want, had;
    getrlimit(RLIMIT_CORE, &had);
    want.rlim_max = had.rlim_max;
    want.rlim_cur = had.rlim_max == 0 ? 0 : (had.rlim_max == RLIM_INFINITY ? 1048576 : had.rlim_max);
    setrlimit(RLIMIT_CORE, &want);
    getrlimit(RLIMIT_CORE, &want);
    if (want.rlim_cur == 0) {
        printf("SKIP (cannot raise RLIMIT_CORE here, so the wrapper lowering it is unprovable)\n");
        skipped++;
    } else if (pipe(rp) != 0) {
        printf("FAIL (pipe)\n");
        failed++;
    } else {
        pid_t pid = fork();
        if (pid == 0) {
            dup2(rp[1], STDOUT_FILENO);
            close(rp[0]); close(rp[1]);
            execvp(cmd13[0], cmd13);
            _exit(127);
        }
        close(rp[1]);
        char buf[64] = {0};
        ssize_t n = read(rp[0], buf, sizeof(buf) - 1);
        close(rp[0]);
        waitpid(pid, &st, 0);
        /* Exact match, not a prefix. `strncmp(buf, "0", 1)` was also satisfied by "0\n0\n"
         * and by any output that merely begins with a zero, so the stricter assertion had to
         * come with a stricter parse. */
        if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = '\0';
        if (n <= 0 || strcmp(buf, "S=0 H=0") != 0) {
            printf("FAIL (child reports '%.32s', expected 'S=0 H=0' — a caged process that can"
                   " raise RLIMIT_CORE turns every blocked syscall into a"
                   " multi-hundred-megabyte kernel write)\n", n > 0 ? buf : "<none>");
            failed++;
        } else {
            printf("PASS\n");
        }
    }

    /* --- test 14: every name in BLOCKED_SYSCALLS resolves ----------------
     * `lookup_dcookies` was a typo. libseccomp returned __NR_SCMP_ERROR, the rule loop
     * skipped it silently BY DESIGN, and README.md repeated the same misspelling — so the
     * two lists agreed and three review rounds found them consistent (B6-1, `P8`, `P15`).
     *
     * Asserted through `--self-test`, which runs the production build_filter() rather than a
     * second copy of the audit, and prints libseccomp's own verdict per name. The assertion
     * is on `unresolved=0`: NOT on the rule count, which is not an oracle (the skipped entry
     * happened to be offset by the separately-added personality rule, so the total matched
     * the comment claiming it), and NOT on the number of names, which would go stale the
     * first time someone adds one.
     *
     * Against a wrapper with no filter and no such flag this fails on both arms — non-zero
     * exit and no line to read. */
    char st_out[8192];
    printf("test 14: deny-list names all resolve   ... ");
    fflush(stdout);
    char *cmd14[] = {wrapper, "--self-test", NULL};
    st = 0;
    int st14 = run_capture(cmd14, &st, st_out, sizeof(st_out));
    /* Deliberately NOT asserting `--self-test` exited 0: it exits non-zero for any of its
     * checks, so an exit-code assertion would make THIS test red for test 15's finding and
     * vice versa. Each test reads the line that is its own. What is asserted is that the
     * process ran and produced the line — a wrapper without a filter, or without this flag,
     * fails on that alone. */
    if (st14 != 0 || !WIFEXITED(st)) {
        printf("FAIL (--self-test did not run to completion)\n");
        if (st_out[0]) printf("%s", st_out);
        failed++;
    } else if (strstr(st_out, "denylist names=") == NULL) {
        printf("FAIL (--self-test printed no 'denylist names=...' line to read)\n");
        if (st_out[0]) printf("%s", st_out);
        failed++;
    } else if (strstr(st_out, "unresolved=0") == NULL) {
        printf("FAIL (--self-test reports names that libseccomp cannot resolve; each emits no"
               " rule on any arch, so the cage is weaker than the deny-list claims)\n");
        printf("%s", st_out);
        failed++;
    } else {
        printf("PASS\n");
    }

    /* --- test 15: the secondary syscall ABI is covered --------------------
     * Deleting seccomp_arch_add() left this suite `0 failed, 0 skipped` while the boundary
     * moved: `int $0x80 getpid` went from working to SIGSYS (B6-2). Nothing in test/ had ever
     * entered the kernel through the 32-bit table.
     *
     * TWO ARMS, and the line below always says which ones ran.
     *
     *   A (structural, every arch, every environment): --self-test asks libseccomp — via
     *     seccomp_arch_exist(), not via a variable we set beside the call — whether the
     *     secondary arch is in the filter it just built. This is the arm that catches the
     *     deletion, and it is the ONLY regression cover the aarch64 registration can have:
     *     an AArch64 binary cannot execute an AArch32 syscall entry, and Neoverse V2 has no
     *     AArch32 at all. It is a shape assertion about the constructed filter, one level
     *     above the boundary, and it is named as such rather than dressed up.
     *   B (enforcement, x86_64 with a usable int $0x80): the boundary itself — an ALLOWED
     *     32-bit syscall must return (a missing registration KILLS the whole ABI, it does
     *     not leave it "uncovered") and a DENIED one must not.
     *
     * Arm B is baselined uncaged, and NOT ATTEMPTED rather than skipped when the baseline
     * fails, because "int $0x80 does not work here" has at least three causes this probe
     * cannot separate — a kernel without CONFIG_IA32_EMULATION, `ia32_emulation=0`, and an
     * ENCLOSING seccomp filter that registered only the native arch. The last one is not
     * hypothetical: it is what happens when this suite is run inside a husk session or under
     * Anthropic's sandbox, both of which kill `int $0x80` outright. Arm A still runs there,
     * so the test never becomes a no-op, and it never turns a nested run into a release-gate
     * SKIP that an operator has to authorise on every build. */
    printf("test 15: secondary syscall ABI covered ... ");
    fflush(stdout);
    if (strstr(st_out, "secondary-arch") == NULL) {
        printf("FAIL (--self-test printed no 'secondary-arch' line)\n");
        failed++;
    } else if (strstr(st_out, "registered=yes") == NULL) {
        printf("FAIL (the secondary arch is NOT registered — the 32-bit syscall entry path is"
               " refused wholesale, so 32-bit binaries die with SIGSYS. If this build targets"
               " an architecture with no secondary ABI, this test has to learn about it)\n");
        failed++;
    } else {
        /* arm B */
        char *b_allow[] = {ptrace_bin, "int80-allowed", NULL};
        char *b_deny[]  = {ptrace_bin, "int80-denied", NULL};
        const char *why = NULL;
        st = 0;
        int ba = run_quiet(b_allow, &st) == 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        int bd = -1;
        if (ba == 4) {
            why = "this build has no secondary-ABI entry instruction (not x86_64)";
        } else if (ba != 0) {
            why = "int $0x80 is unusable on this machine even uncaged — no IA32 emulation, or"
                  " an enclosing filter registered only the native arch";
        } else {
            st = 0;
            bd = run_quiet(b_deny, &st) == 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
            if (bd != 2)
                why = "uncaged int80 ptrace did not return, so a caged kill would prove"
                      " nothing";
        }
        if (why != NULL) {
            printf("PASS (arch registered; enforcement arm not attempted: %s)\n", why);
        } else {
            int bad = 0;
            char *c_allow[] = {wrapper, ptrace_bin, "int80-allowed", NULL};
            char *c_deny[]  = {wrapper, ptrace_bin, "int80-denied", NULL};
            st = 0;
            if (run(c_allow, &st) != 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                printf("FAIL (an ALLOWED 32-bit syscall died under the cage — the secondary"
                       " arch is not registered in the loaded filter) ");
                bad = 1;
            }
            st = 0;
            if (run_quiet(c_deny, &st) != 0 || !WIFSIGNALED(st) || WTERMSIG(st) != SIGSYS) {
                printf("FAIL (a DENIED 32-bit syscall was not killed — the deny-list rules"
                       " were not translated into the 32-bit table) ");
                bad = 1;
            }
            if (bad) { printf("\n"); failed++; }
            else { printf("PASS (arch registered; int-0x80 allow+deny enforced)\n"); }
        }
    }

    /* --- test 16: personality's sign-extended query, as DECIDED -----------
     * The kernel declares personality's argument `unsigned int`, so 0xffffffffffffffff is the
     * same read-only query as 0x00000000ffffffff — and the natural C spelling
     * `personality(-1)` produces the first. The rule compares the full 64-bit datum, so husk
     * answers EINVAL to a question the kernel would have answered (B6-8).
     *
     * This test does not argue that either way; it PINS it, because the disposition is the
     * one in this file supported by an argument rather than a measurement, and it can drift
     * in two directions with everything else green: widened to allow, or re-broadened to
     * kill. Since 2026-08-31 the false positive is also QUIET — before, such a caller died
     * with SIGSYS. Baselined uncaged, because a machine whose kernel refuses the query would
     * make a caged EINVAL prove nothing. */
    printf("test 16: personality(-1) as decided    ... ");
    fflush(stdout);
    char *cmd16base[] = {personality_qry, "sign-extended", NULL};
    st = 0;
    int b16 = run_quiet(cmd16base, &st) == 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (b16 != 0) {
        printf("SKIP (the bare kernel does not answer personality((unsigned long)-1) here"
               " [probe exit %d], so a caged refusal would prove nothing)\n", b16);
        skipped++;
    } else {
        char *cmd16[] = {wrapper, personality_qry, "sign-extended", NULL};
        st = 0;
        if (run_quiet(cmd16, &st) != 0) {
            printf("FAIL (could not spawn process)\n");
            failed++;
        } else if (WIFSIGNALED(st)) {
            printf("FAIL (signal %d — the personality rule is KILLING again; that is the"
                   " regression that made lscpu die on Santis)\n", WTERMSIG(st));
            failed++;
        } else if (WEXITSTATUS(st) == 0) {
            printf("FAIL (the sign-extended query is now ALLOWED. That may be the right call"
                   " — it is the same kernel operation — but it is a DECISION: change it in"
                   " seccomp_wrapper.c, CAGE-PROFILES.md and here, together)\n");
            failed++;
        } else if (WEXITSTATUS(st) != 1) {
            printf("FAIL (refused with an unexpected errno, probe exit %d — the documented"
                   " disposition is EINVAL, chosen to look like a kernel without that ABI)\n",
                   WEXITSTATUS(st));
            failed++;
        } else {
            printf("PASS (refused with EINVAL, as decided)\n");
        }
    }

    /* A skip is not a pass. build_and_test.sh cannot see the per-test lines, so the
     * count goes on one machine-greppable line. */
    printf("summary: %d failed, %d skipped\n", failed, skipped);
    return failed ? 1 : 0;
}
