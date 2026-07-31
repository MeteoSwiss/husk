/*
 * smoke.c — integration smoke tests for seccomp-wrapper
 *
 * Usage: smoke <path-to-seccomp-wrapper> <path-to-test_ptrace>
 *              <path-to-test_personality_query> <path-to-test_personality_switch>
 *              <path-to-test_af_unix> <path-to-test_cma>
 *
 * Test 1: exec passthrough               — wraps "echo ok", expects clean exit.
 * Test 2: ptrace blocked                 — wraps test_ptrace, expects SIGSYS.
 * Test 3: personality query allowed      — wraps test_personality_query, expects clean exit.
 * Test 4: personality ABI-switch blocked — wraps test_personality_switch, expects SIGSYS.
 * Test 5: AF_UNIX allowed under login   — the default profile must not change behaviour.
 * Test 6: AF_UNIX still ALLOWED under single-node — CUDA requires it (see below).
 * Test 7: an unknown --profile is fatal  — never a silent fallback to a weaker cage.
 * Test 8: CMA read blocked under login   — the exemption must not leak into the default.
 * Test 9: CMA read allowed under single-node — Cray MPICH needs it.
 * Test 10: CMA WRITE still blocked under single-node — read and write are not one
 *          concession; tests 9 and 10 together are the whole point of the delta.
 */
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

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
    if (argc != 7) {
        fprintf(stderr, "usage: smoke <seccomp-wrapper> <test-ptrace>"
                        " <test-personality-query> <test-personality-switch>"
                        " <test-af-unix> <test-cma>\n");
        return 2;
    }
    char *wrapper          = argv[1];
    char *ptrace_bin       = argv[2];
    char *personality_qry  = argv[3];
    char *personality_sw   = argv[4];
    char *af_unix_bin      = argv[5];
    char *cma_bin          = argv[6];
    int failed = 0, st = 0;

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

    /* --- test 4: personality ABI-switch must be killed with SIGSYS ------- */
    printf("test 4: personality ABI-switch blocked ... ");
    fflush(stdout);
    char *cmd4[] = {wrapper, personality_sw, NULL};
    st = 0;
    if (run(cmd4, &st) != 0) {
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

    return failed ? 1 : 0;
}
