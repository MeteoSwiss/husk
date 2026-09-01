/*
 * test_personality_switch.c — the persona must not MOVE, and the refusal must be husk's
 *
 * The rule exists so a process cannot change its execution domain: PER_LINUX32 selects the
 * 32-bit syscall ABI, ADDR_NO_RANDOMIZE turns ASLR off. Since 2026-08-31 the filter reports
 * EINVAL rather than killing (see GRACEFUL_ERRNO_SYSCALLS and CAGE-PROFILES.md), because
 * lscpu on aarch64 asks for PER_LINUX32 during normal startup and died for it.
 *
 * TWO personas, and the second one is the whole point. Review 2026-08-31 showed that a probe
 * testing only PER_LINUX32 is a TAUTOLOGY on the hardware that motivated the change: an
 * aarch64 node without 32-bit EL0 has the KERNEL return EINVAL and leave the persona
 * unchanged, so the pass condition is met with no seccomp filter present at all —
 * demonstrated with a kernel shim against a null wrapper. The old probe demanded SIGSYS and
 * could not be fooled that way; the rewrite lost that for free.
 *
 * ADDR_NO_RANDOMIZE restores it. Every kernel accepts it uncaged (measured: persona
 * 0 -> 262144), arm64 special-cases only (pers & PER_MASK) == PER_LINUX32, so refusal here
 * can only come from husk. It also documents what the rule actually protects: this is an
 * ASLR control as much as an ABI control.
 *
 * The errno is asserted too. A mutation from EINVAL to EPERM passed the entire suite, so the
 * errno the wrapper argues for at length was free to decay — the same gap test 11 closes by
 * demanding ENOSYS specifically.
 *
 * Exit codes:
 *   0 = every persona refused with EINVAL, and none of them moved   (contract holds)
 *   1 = a switch was ACCEPTED                                       (the control is gone)
 *   2 = it reported failure but the persona MOVED anyway
 *   3 = could not read the persona at all
 *   4 = refused, but with an errno other than EINVAL
 *
 * Under a KILL_PROCESS filter this dies with SIGSYS and never returns a code; smoke.c
 * accepts that too, so the probe stays valid if the action is ever changed back.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/personality.h>

#define PER_LINUX32       0x0008
#define ADDR_NO_RANDOMIZE 0x0040000
#define QUERY             0xffffffff

static int probe(const char *name, unsigned long pers)
{
    int before = personality(QUERY);
    if (before == -1) {
        fprintf(stderr, "test_personality_switch: cannot read the persona: %s\n",
                strerror(errno));
        return 3;
    }

    errno = 0;
    int rc = personality(pers);
    int saved = errno;

    int after = personality(QUERY);
    if (after == -1) {
        fprintf(stderr, "test_personality_switch: cannot re-read the persona: %s\n",
                strerror(errno));
        return 3;
    }

    if (after != before) {
        fprintf(stderr, "test_personality_switch: %s MOVED the persona %d -> %d (rc=%d)\n",
                name, before, after, rc);
        return 2;
    }
    if (rc != -1) {
        fprintf(stderr, "test_personality_switch: %s was ACCEPTED (rc=%d)\n", name, rc);
        return 1;
    }
    if (saved != EINVAL) {
        fprintf(stderr, "test_personality_switch: %s refused with %s, expected EINVAL\n",
                name, strerror(saved));
        return 4;
    }
    return 0;
}

int main(void)
{
    /* PER_LINUX32 is the reported case; ADDR_NO_RANDOMIZE is the one a bare kernel accepts,
     * so it is the only one of the two whose refusal proves the filter is doing it. */
    int rc = probe("PER_LINUX32", PER_LINUX32);
    if (rc != 0)
        return rc;
    return probe("ADDR_NO_RANDOMIZE", ADDR_NO_RANDOMIZE);
}
