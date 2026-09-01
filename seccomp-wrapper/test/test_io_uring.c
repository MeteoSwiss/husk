/*
 * test_io_uring.c — probe for the io_uring rules.
 *
 * Usage: test_io_uring setup | test_io_uring enter | test_io_uring register
 *
 * The two modes exist because the filter treats them DIFFERENTLY on purpose, and a probe
 * that ran only one would pass while the asymmetry silently collapsed (same reasoning as
 * test_cma's read/write split):
 *
 *   setup — the capability PROBE. Blocked with ERRNO(ENOSYS), so a caller that handles the
 *           failure (libuv falls back to its threadpool) keeps running. Returns here.
 *   enter,
 *   register — USING a ring. No process under this filter can create one, so reaching
 *           either means holding a ring from outside the cage. Both blocked with
 *           KILL_PROCESS, which shows up as SIGSYS in the caller (smoke.c), never as a
 *           return value. BOTH are probed: a review found that widening the graceful table
 *           to include io_uring_register left the suite fully green while smoke.c claimed
 *           that exact widening would turn it red.
 *
 * Exit codes for `setup`, which are the only outcomes reachable when the call returns:
 *   0 = failed with ENOSYS   — the graceful block, or a kernel without io_uring at all
 *   1 = SUCCEEDED            — the call went through; the filter is not covering it
 *   2 = failed with some other errno
 *
 * `struct io_uring_params` is not used: linux/io_uring.h is absent on older toolchains and
 * this must build wherever the wrapper does. A zeroed buffer at least as large as the
 * kernel's struct is all the syscall needs, and when the call is blocked the kernel never
 * reads it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* Added after the syscall numbers were unified, so these are the same on x86_64 and
 * aarch64. Defined here because a build host's headers may predate them. */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: test_io_uring setup|enter|register\n");
        return 3;
    }

    if (strcmp(argv[1], "setup") == 0) {
        unsigned char params[256];
        long r;

        memset(params, 0, sizeof(params));
        errno = 0;
        r = syscall(__NR_io_uring_setup, 1u, params);

        if (r >= 0) {
            close((int)r);
            fprintf(stderr, "test_io_uring: setup SUCCEEDED (fd %ld)\n", r);
            return 1;
        }
        if (errno == ENOSYS)
            return 0;
        fprintf(stderr, "test_io_uring: setup failed: %s\n", strerror(errno));
        return 2;
    }

    if (strcmp(argv[1], "register") == 0) {
        /* Same contract as `enter`: must not return. */
        errno = 0;
        (void)syscall(__NR_io_uring_register, -1, 0u, (void *)0, 0u);
        fprintf(stderr, "test_io_uring: register RETURNED (%s) — expected SIGSYS\n",
                strerror(errno));
        return 1;
    }

    if (strcmp(argv[1], "enter") == 0) {
        /* Deliberately a bogus ring fd: if this returns at all the filter did not kill
         * us, which is the failure this mode detects. What the kernel would say about
         * the fd never matters, because we must not get that far. */
        errno = 0;
        (void)syscall(__NR_io_uring_enter, -1, 0u, 0u, 0u, (void *)0, (size_t)0);
        fprintf(stderr, "test_io_uring: enter RETURNED (%s) — expected SIGSYS\n",
                strerror(errno));
        return 1;
    }

    fprintf(stderr, "test_io_uring: unknown mode '%s'\n", argv[1]);
    return 3;
}
