/*
 * test_personality_query.c — personality(0xffffffff) must be allowed
 *
 * The filter uses argument filtering to allow the query form of personality(2)
 * (argument == 0xffffffff) while killing any ABI-switch attempt.  This binary
 * verifies that the query form exits cleanly under the wrapper.
 */
#include <sys/personality.h>

int main(void)
{
    personality(0xffffffff);  /* query current execution domain — must not SIGSYS */
    return 0;
}
