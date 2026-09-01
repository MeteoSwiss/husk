/*
 * test_ptrace.c — the deny-list reaches ptrace, on BOTH syscall ABIs.
 *
 * Usage: test_ptrace                  (native ABI: ptrace must not return)
 *        test_ptrace int80-allowed    (secondary ABI: an ALLOWED syscall must return)
 *        test_ptrace int80-denied     (secondary ABI: a DENIED syscall must not return)
 *
 * The two int80 modes are the probe for `B6-2`: deleting seccomp_arch_add(SCMP_ARCH_X86)
 * left the suite 13/13 green while the boundary demonstrably moved, because nothing in
 * test/ had ever issued a syscall through the 32-bit entry path.
 *
 * TWO modes, not one, because the failure they detect are opposites and a single mode
 * cannot tell them apart:
 *
 *   int80-allowed   getpid(2) through `int $0x80`. It must SUCCEED. If the secondary arch
 *                   is not registered, libseccomp appends "invalid architecture action /
 *                   action KILL" and the whole ABI dies with SIGSYS — so this mode failing
 *                   is what a MISSING registration looks like. (The old warning string
 *                   claimed the opposite: that the path would be "uncovered".)
 *   int80-denied    ptrace(2) through `int $0x80`, with a deliberately invalid request so
 *                   the call is harmless if it does execute. It must NOT return. This is
 *                   what checks that the deny-list rules were actually translated into the
 *                   32-bit syscall table (ptrace is 101 on x86_64 and 26 on i386), rather
 *                   than the arch merely being present.
 *
 * Exit codes for the int80 modes:
 *   0 = the syscall returned a sane value        1 = it returned an error
 *   2 = it returned, but the mode expected a kill (only meaningful for int80-denied)
 *   4 = NOT APPLICABLE: this build has no secondary-ABI entry instruction
 *
 * `int $0x80` is x86_64-only. aarch64 has no equivalent an AArch64 binary can execute —
 * reaching AArch32 needs a 32-bit ARM binary, and Santis's Neoverse V2 has no AArch32 in
 * silicon at all. So on aarch64 these modes report 4 and smoke.c says which arms it ran;
 * the registration itself is still asserted there, through `seccomp-wrapper --self-test`.
 */
#include <stdio.h>
#include <sys/ptrace.h>
#include <string.h>
#include <unistd.h>

#if defined(__x86_64__)
#define HAVE_INT80 1
/* i386 syscall numbers — the point of the exercise is that these are NOT the native ones. */
#define I386_NR_GETPID 20
#define I386_NR_PTRACE 26
static long int80(long nr, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile ("int $0x80"
                      : "=a"(ret)
                      : "a"(nr), "b"(a1), "c"(a2), "d"(a3)
                      : "memory");
    return ret;
}
#endif

int main(int argc, char *argv[])
{
    if (argc == 1) {
        /* Native ABI, unchanged: reaching the next line means the filter was not active. */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("ptrace returned — seccomp filter not active (FAIL)");
        return 1;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: test_ptrace [int80-allowed|int80-denied]\n");
        return 3;
    }

#if defined(HAVE_INT80)
    if (strcmp(argv[1], "int80-allowed") == 0) {
        long r = int80(I386_NR_GETPID, 0, 0, 0);
        if (r > 0)
            return 0;
        fprintf(stderr, "test_ptrace: int80 getpid returned %ld — the 32-bit entry path is"
                        " not usable here\n", r);
        return 1;
    }
    if (strcmp(argv[1], "int80-denied") == 0) {
        /* request 0xffff is not a valid ptrace request: if the call DOES execute it fails
         * harmlessly, so this probe cannot attach to anything even when it is not blocked. */
        long r = int80(I386_NR_PTRACE, 0xffff, 0, 0);
        fprintf(stderr, "test_ptrace: int80 ptrace RETURNED %ld — the deny-list did not reach"
                        " the 32-bit syscall table\n", r);
        return 2;
    }
#else
    if (strcmp(argv[1], "int80-allowed") == 0 || strcmp(argv[1], "int80-denied") == 0)
        return 4;
#endif

    fprintf(stderr, "test_ptrace: unknown mode '%s'\n", argv[1]);
    return 3;
}
