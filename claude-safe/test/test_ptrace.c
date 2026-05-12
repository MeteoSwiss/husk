/*
 * test_ptrace.c
 *
 * Calls ptrace on itself. When run under seccomp-wrapper this process
 * should be killed with SIGSYS before ptrace() returns. Reaching main()s
 * return means the filter was not active — that is a test failure.
 */
#include <stdio.h>
#include <sys/ptrace.h>

int main(void)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    puts("ptrace returned — seccomp filter not active (FAIL)");
    return 1;
}
