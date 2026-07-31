/*
 * test_cma.c — probe for the Cross Memory Attach rules.
 *
 * Usage: test_cma read | test_cma write
 *
 * Performs the named CMA syscall against THIS process's own address space and exits 0
 * if it succeeded. Self-attach is always permitted by the kernel's ptrace-attach check,
 * so a failure here is the seccomp filter and nothing else — no second process, no
 * dependence on Yama or on the dumpable flag of some other target.
 *
 * The filter uses KILL_PROCESS, so "blocked" shows up as SIGSYS in the caller
 * (smoke.c), not as a return value. The exit codes only distinguish the outcomes that
 * are reachable when the call is ALLOWED: 0 = the transfer happened, 1 = the syscall
 * ran but moved the wrong number of bytes, 2 = it ran and failed with errno.
 *
 * These two syscalls are deliberately probed separately: the single-node profile
 * permits process_vm_readv and still blocks process_vm_writev, and a probe that ran
 * both would pass while the asymmetry silently collapsed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char src[16] = "cma-probe-data";
    char dst[16] = {0};
    struct iovec local  = { .iov_base = dst, .iov_len = sizeof(src) };
    struct iovec remote = { .iov_base = src, .iov_len = sizeof(src) };
    pid_t self = getpid();
    ssize_t n;

    if (argc != 2) {
        fprintf(stderr, "usage: test_cma read|write\n");
        return 3;
    }

    if (strcmp(argv[1], "read") == 0) {
        n = process_vm_readv(self, &local, 1, &remote, 1, 0);
    } else if (strcmp(argv[1], "write") == 0) {
        /* Write dst <- src, i.e. the local buffer is the source here. */
        local.iov_base  = src;
        remote.iov_base = dst;
        n = process_vm_writev(self, &local, 1, &remote, 1, 0);
    } else {
        fprintf(stderr, "test_cma: unknown mode '%s'\n", argv[1]);
        return 3;
    }

    if (n < 0) {
        fprintf(stderr, "test_cma: %s failed: %s\n", argv[1], strerror(errno));
        return 2;
    }
    if (n != (ssize_t)sizeof(src) || memcmp(src, dst, sizeof(src)) != 0) {
        fprintf(stderr, "test_cma: %s moved %zd bytes, expected %zu\n",
                argv[1], n, sizeof(src));
        return 1;
    }
    return 0;
}
