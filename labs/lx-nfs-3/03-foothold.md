# 03 — SSH as `matt`

The vault entry is an SSH login, and the host is listening on `22`.

## 3.1 Log in

```bash
ssh matt@172.16.97.110
```

```text
The authenticity of host '172.16.97.110' can't be established.
ED25519 key fingerprint is SHA256:[redacted].
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
matt@172.16.97.110's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Thu Jul 20 21:58:14 2023 from 10.10.14.47
```

## 3.2 Who am I

```bash
matt@oscp:~$ id
```

```text
uid=1000(matt) gid=1000(matt) groups=1000(matt),1001(adm)
```

```bash
matt@oscp:~$ hostname
oscp
matt@oscp:~$ uname -a
Linux oscp 5.15.0-84-generic #93-Ubuntu SMP Tue Sep 5 12:12:23 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

A normal user with one supplementary group, on an up-to-date Ubuntu 22.04. The kernel is patched past
most public local root exploits, so the escalation will not be a CVE — the group and the services
matter more.

## 3.3 The user flag

```bash
matt@oscp:~$ cat local.txt
[redacted]
```

| Host | File | Value |
|---|---|---|
| `172.16.97.110` | `/home/matt/local.txt` | `[redacted]` |

User half done in four commands. The root half is the NFS export.

## 3.4 Before escalating: what to look at

On a Linux box with a shell, the checklist that matters is short:

```bash
id                     # groups, before anything else
sudo -l                # what the account may run as root
ss -tuln               # services that are only reachable locally
cat /etc/exports       # NFS exports and their options
mount | grep nfs       # what is already mounted
find / -perm -4000 2>/dev/null   # SUID binaries
```

`id` gave the group. `ss -tuln` shows `nfsd` and the Samba stack. `/etc/exports` is the file that
ends the box — see the next chapter.

---

**Next:** [`04-enumeration-nfs.md`](04-enumeration-nfs.md)
