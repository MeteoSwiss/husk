/*
 * test_personality_query.c — personality(2)'s read-only QUERY form, both spellings.
 *
 * Usage: test_personality_query                  (0x00000000ffffffff — must be ALLOWED)
 *        test_personality_query sign-extended    (0xffffffffffffffff — see below)
 *
 * The filter allows the query by argument comparison (A0 != 0xffffffff) while refusing every
 * persona change. The kernel declares the argument `unsigned int`, so it truncates: ANY value
 * whose low 32 bits are all ones is the same read-only query. The rule compares the full
 * 64-bit datum, so `personality((unsigned long)-1)` — the natural C spelling, and what
 * `personality(-1)` compiles to — is refused with EINVAL although the kernel would have
 * answered it. `B6-8`.
 *
 * That is a false positive in the safe direction, and it is a DECISION, recorded in
 * seccomp_wrapper.c beside the rule: it is not fixed, because the only way libseccomp can
 * express "deny unless the low 32 bits are all ones" is 32 masked rules (measured 2026-09-01:
 * two conditions on one argument in a single rule -> -EINVAL, and an ALLOW rule on an
 * ALLOW-default filter -> -EPERM), and that is a rebuild of a live control on both clusters
 * to fix a wrong answer to a query rather than a wrong computation.
 *
 * The `sign-extended` mode exists so the decision cannot drift in EITHER direction with the
 * suite green — widened to allow, or re-broadened to kill. Its exit codes report the
 * disposition rather than judging it; smoke.c holds the expectation:
 *
 *   0 = the call returned a value (ALLOWED)
 *   1 = -1 / EINVAL              (refused, with the documented errno — today's decision)
 *   2 = -1 / some other errno
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "sign-extended") == 0) {
        /* syscall(), not glibc's personality(), so the datum in the register is exactly the
         * one this test is about and does not depend on a wrapper's prototype. */
        errno = 0;
        long r = syscall(SYS_personality, (unsigned long)-1);
        if (r >= 0) {
            fprintf(stderr, "test_personality_query: sign-extended query ALLOWED (persona"
                            " 0x%lx)\n", (unsigned long)r);
            return 0;
        }
        if (errno == EINVAL)
            return 1;
        fprintf(stderr, "test_personality_query: sign-extended query refused with %s\n",
                strerror(errno));
        return 2;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: test_personality_query [sign-extended]\n");
        return 3;
    }

    /* CHECK the return value. It was ignored, and that was safe only while a refused query
     * meant SIGSYS — the process died and this test failed by dying. Now that the rule
     * reports EINVAL, a mutation that refuses the query form makes this probe exit 0 and
     * test 3 report PASS while the query is broken (found by review, 2026-08-31). The query
     * must be ALLOWED, and allowed means it answers. */
    if (personality(0xffffffff) == -1) {
        fprintf(stderr, "test_personality_query: the read-only query was refused: %s\n",
                strerror(errno));
        return 1;
    }  /* query current execution domain — must not SIGSYS */
    return 0;
}
