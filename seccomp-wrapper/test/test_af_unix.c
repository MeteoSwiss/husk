/*
 * test_af_unix.c — probe for the PROFILE_SINGLE_NODE AF_UNIX rule.
 *
 * Exits 0 if socket(AF_UNIX, SOCK_STREAM, 0) succeeded, 1 if it was refused with
 * EPERM, 2 for any other error. The caller (smoke.c) runs this under each profile.
 *
 * The exit code matters as much as the refusal: the rule uses ERRNO(EPERM) rather
 * than KILL_PROCESS, so a caller that merely PROBES for a unix socket (glibc's NSS
 * trying nscd/sssd before falling back to /etc/passwd) keeps running and gets the
 * correct answer. A test that only checked "was it blocked" would pass equally well
 * against a rule that killed the process — which would break real jobs for a benign,
 * self-healing probe.
 */
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        close(fd);
        return 0;   /* allowed */
    }
    if (errno == EPERM) {
        return 1;   /* refused, and we are still alive to say so */
    }
    fprintf(stderr, "test_af_unix: unexpected errno %d\n", errno);
    return 2;
}
