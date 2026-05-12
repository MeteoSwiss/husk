/*
 * test_personality_switch.c — personality(PER_LINUX32) must be blocked
 *
 * The filter kills any personality(2) call whose argument differs from the
 * query sentinel (0xffffffff).  On x86_64 this prevents bypassing the
 * SCMP_ARCH_X86 secondary-ABI coverage; on all architectures it prevents
 * unintended execution-domain changes.  This binary verifies that any
 * non-query personality call dies with SIGSYS.
 */
#include <sys/personality.h>

#define PER_LINUX32 0x0008

int main(void)
{
    personality(PER_LINUX32);  /* ABI-switch attempt — must die SIGSYS */
    return 0;                  /* must not be reached */
}
