# 01 — Anonymous SMB and a share full of nothing

The host exposes three services: SSH, Samba and NFS. Samba answers first, and it answers without a
password.

## 1.1 The share list

```bash
smbclient -L //172.16.97.110
```

```text
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        Backup          Disk      Backup Files
        IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available
```

An empty password was accepted. `Backup` is a real share with a comment that describes exactly what
it holds, and the Samba version confirms an Ubuntu 22.04 host — worth noting for the kernel
version later.

The SMB1 warning comes from `smbclient` trying to list the workgroup after the share list. It is not
an error on the target and not a reason to change anything: the share listing already succeeded.

## 1.2 Inside the share

```bash
smbclient //172.16.97.110/Backup
```

```text
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Feb 13 12:27:41 2023
  ..                                  D        0  Tue Jul 21 16:34:09 2023
  folder2                             D        0  Sun Jul 26 16:35:03 2023
  folder1                             D        0  Tue Apr 11 18:39:22 2023
  folder3                             D        0  Mon Feb 13 12:27:41 2023
  folder4                             D        0  Mon Feb 13 12:27:41 2023
  folder5                             D        0  Mon Feb 13 12:27:41 2023
  folder6                             D        0  Mon Feb 13 12:27:41 2023
  folder7                             D        0  Mon Feb 13 12:27:41 2023
  folder8                             D        0  Mon Feb 13 12:27:41 2023
  folder9                             D        0  Mon Feb 13 12:27:41 2023

                42885120 blocks of size 4096. 14881285 blocks available
```

Nine folders, no obvious theme. Pulling the whole tree is cheaper than opening them one by one:

```text
smb: \> tarmode
tarmode is now full, system, hidden, nonroot, noacls
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

## 1.3 What is actually in there

Every PDF in the tree is empty — 0 bytes, all of them:

```text
$ ls -lR
...
./folder1:
total 0
-rw-r--r-- 1 kali kali  0 Feb 13  2023 doc142.pdf
-rw-r--r-- 1 kali kali  0 Feb 13  2023 doc287.pdf
-rw-r--r-- 1 kali kali  0 Feb 13  2023 notes.pdf
...
./folder5:
total 4
-rw-r--r-- 1 kali kali  0 Feb 13  2023 doc345.pdf
-rw-r--r-- 1 kali kali  0 Feb 13  2023 important.pdf
-rw-r--r-- 1 kali kali  0 Feb 13  2023 departments.xlsx
-rw-r--r-- 1 kali kali 3484 Feb 13  2023 keys.kdbx
```

That listing is the whole box in one screen. Nine folders of decoy documents, all zero bytes, and a
single file with content: a KeePass database.

```bash
find . -type f -size +0 -printf '%s\t%p\n'
```

```text
3484	./folder5/keys.kdbx
```

## 1.4 Why the decoys work

A share called `Backup`, nine folders, and files named `important.pdf`, `finances.pdf`,
`departments.xlsx` invite exactly the wrong behaviour: open each one, look for a password, waste the
hour. The files are empty on purpose.

The useful habit is mechanical: **sort by size, ignore the zero-byte noise, and look at what is
left.** One `find -size +0` removes the entire distraction layer.

| Observation | Meaning |
|---|---|
| `Backup` share, anonymous | no credential needed to read the whole thing |
| nine folders of 0-byte PDFs | deliberate noise |
| one 3.4 KB `keys.kdbx` | a KeePass vault — cracking target |

## 1.5 The host itself

The same machine answers on a second address. Once there is a shell on it (chapter 03), the interface
list explains the address the SMB client reported:

```text
matt@oscp:~$ ip -br a
lo               UNKNOWN        127.0.0.1/8
ens160           UP             172.16.97.110/24
ens192           UP             192.168.97.110/24
```

Two interfaces: `172.16.97.110` on the exam network and `192.168.97.110` on an internal one. The SMB
client's warning about `192.168.97.110` was the server reporting its other address, not a second host.

---

**Next:** [`02-keepass.md`](02-keepass.md)
