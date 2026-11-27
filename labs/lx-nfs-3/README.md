# Linux — `172.16.97.110` · SMB backup → KeePass → NFS root

The Linux half of the set: a dual-homed Ubuntu server with an anonymous Samba share full of empty
PDFs and one KeePass database. The database cracks to a credential that opens SSH, and the same host
exports a directory over NFS with `no_root_squash`, which turns a local file into a root-owned SUID
binary.

Two misconfigurations, one credential and one export line. No exploit code, no CVE.

> **Status — complete.** `matt` via SSH, `local.txt`, then root through the NFS export and
> `proof.txt`. All flags are masked with `[redacted]`.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `445` | `smbclient -L` — anonymous | share `Backup` ("Backup Files") |
| 02 | `Backup` | nine folders of PDFs, all 0 bytes | one file with content: `keys.kdbx` |
| 03 | local | `keepass2john` → `hashcat -m 13400` | vault master password |
| 04 | local | `pykeepass` | entry for `matt` with an SSH password |
| 05 | `22` | `ssh matt@172.16.97.110` | shell, `local.txt` |
| 06 | host | `uname -a`, LinPEAS | Ubuntu 22.04, kernel 5.15.0-84 |
| 07 | host | `/etc/exports` | `/usr/upload localhost(rw,sync,no_root_squash)` |
| 08 | host | `mount -t nfs` against `172.16.97.110` | `access denied by server` |
| 09 | host | export file is group-writable (`root:adm`) | `insecure` appended to the export |
| 10 | Kali | `ssh -L 2049:localhost:2049` | NFS reachable through the tunnel |
| 11 | Kali | `mount -t nfs 127.0.0.1:/usr/upload /mnt/nfs` | export mounted |
| 12 | Kali | `shell.c` → `gcc` → `cp` → `chmod +s` | SUID binary owned by root on the target |
| 13 | host | `/usr/upload/shell` | `root@oscp`, `proof.txt` |

## Environment

| | |
|---|---|
| Target | `172.16.97.110` — Ubuntu 22.04, hostname `oscp` |
| Second interface | `192.168.97.110` — internal network, not reachable from the exam network |
| Services | `22` SSH · `139`/`445` Samba 4.15.13 · `2049` NFS |
| Attacker | Kali, `10.10.14.47`, working directory `~/exam` |
| Access | `matt` — password recovered from the KeePass vault |

## Credentials

| Account | Secret | Source | Use |
|---|---|---|---|
| `matt` | `[redacted]` | KeePass entry inside `keys.kdbx` | SSH |
| KeePass vault | `[redacted]` | `hashcat -m 13400` against `rockyou.txt` | opening the database |

## Flags

| Host | File | Value |
|---|---|---|
| `172.16.97.110` | `/home/matt/local.txt` | `[redacted]` |
| `172.16.97.110` | `/root/proof.txt` | `[redacted]` |

## Chapters

| # | File | Content |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | anonymous SMB, nine folders, the one file worth keeping |
| 02 | [`02-keepass.md`](02-keepass.md) | `keepass2john`, `hashcat -m 13400`, `pykeepass` |
| 03 | [`03-foothold.md`](03-foothold.md) | SSH as `matt`, `local.txt` |
| 04 | [`04-enumeration-nfs.md`](04-enumeration-nfs.md) | LinPEAS and the export with `no_root_squash` |
| 05 | [`05-mount-failures.md`](05-mount-failures.md) | why every direct mount was refused |
| 06 | [`06-tunnel-and-mount.md`](06-tunnel-and-mount.md) | `ssh -L 2049`, mounting through loopback |
| 07 | [`07-suid-root.md`](07-suid-root.md) | the SUID payload, root, `proof.txt` |

## The one thing to remember

**`no_root_squash` hands out root.** When an export carries it, a client's root can create files that
the server sees as its own root — so a compiled binary placed on the mount can be given the SUID bit
and executed by any local user. The export was also restricted to `localhost`, which is why the mount
had to travel through an SSH tunnel; the restriction changed the route, not the outcome.

## The set

Second and final box of the set. The Active Directory half is [`../ad-ws26/`](../ad-ws26/):
`WS26` → backup share on `.202` → `SRV22` → Domain Admin.
