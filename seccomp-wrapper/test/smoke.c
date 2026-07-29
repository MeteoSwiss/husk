/*
 * smoke.c — integration smoke tests for seccomp-wrapper
 *
 * Usage: smoke <path-to-seccomp-wrapper> <path-to-test_ptrace>
 *              <path-to-test_personality_query> <path-to-test_personality_switch>
 *              <path-to-test_af_unix>
 *
 * Test 1: exec passthrough               — wraps "echo ok", expects clean exit.
 * Test 2: ptrace blocked                 — wraps test_ptrace, expects SIGSYS.
 * Test 3: personality query allowed      — wraps test_personality_query, expects clean exit.
 * Test 4: personality ABI-switch blocked — wraps test_personality_switch, expects SIGSYS.
 * Test 5: AF_UNIX allowed under login   — the default profile must not change behaviour.
 * Test 6: AF_UNIX refused under single-node, WITHOUT killing the process.
 * Test 7: an unknown --profile is fatal  — never a silent fallback to a weaker cage.
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
    if (argc != 6) {
        fprintf(stderr, "usage: smoke <seccomp-wrapper> <test-ptrace>"
                        " <test-personality-query> <test-personality-switch>"
                        " <test-af-unix>\n");
        return 2;
    }
    char *wrapper          = argv[1];
    char *ptrace_bin       = argv[2];
    char *personality_qry  = argv[3];
    char *personality_sw   = argv[4];
    char *af_unix_bin      = argv[5];
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

    /* --- test 6: AF_UNIX refused under single-node, process SURVIVES ------
     * Exit 1 means EPERM was returned and the probe lived to report it. A SIGSYS
     * death here would also "block" the socket, but would kill any program that
     * merely probes for nscd/sssd before falling back — hence the explicit
     * WIFEXITED check rather than just "did it fail". */
    printf("test 6: AF_UNIX refused (single-node)  ... ");
    fflush(stdout);
    char *cmd6[] = {wrapper, "--profile=single-node", af_unix_bin, NULL};
    st = 0;
    if (run(cmd6, &st) != 0) {
        printf("FAIL (could not spawn process)\n");
        failed++;
    } else if (WIFSIGNALED(st)) {
        printf("FAIL (killed by signal %d; the rule must return EPERM, not kill)\n",
               WTERMSIG(st));
        failed++;
    } else if (WEXITSTATUS(st) != 1) {
        printf("FAIL (exit %d, expected 1 = refused with EPERM)\n", WEXITSTATUS(st));
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

    return failed ? 1 : 0;
}
