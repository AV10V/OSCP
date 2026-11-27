# 04 — The export that ends the box

A shell on the host is worth more than any port scan, because the file that decides the privilege
escalation is only readable from inside.

## 4.1 What is listening

```bash
matt@oscp:~$ ss -tuln
```

```text
Netid State  Local Address:Port  Peer Address:Port
udp   UNCONN 0.0.0.0:111         0.0.0.0:*
udp   UNCONN 0.0.0.0:2049        0.0.0.0:*
tcp   LISTEN 0.0.0.0:22          0.0.0.0:*
tcp   LISTEN 0.0.0.0:111         0.0.0.0:*
tcp   LISTEN 0.0.0.0:2049        0.0.0.0:*
tcp   LISTEN 0.0.0.0:139         0.0.0.0:*
tcp   LISTEN 0.0.0.0:445         0.0.0.0:*
```

`2049` is NFS and `111` is `rpcbind`, the portmapper an NFSv3 client asks before it knows where
`mountd` is. Both are worth a look from the outside, but the configuration that matters is a text
file.

## 4.2 LinPEAS finds the line

An automated enumeration run reaches the NFS section quickly:

```bash
matt@oscp:~$ ./linpeas.sh -a 2>/dev/null | tee linpeas.txt
```

```text
╔══════════╣ Analyzing NFS Exports Files (Limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/usr/upload localhost(rw,sync,no_root_squash)
```

One line, and it is the privilege escalation: a directory exported to `localhost` with
`no_root_squash`. LinPEAS prints the export itself, not the permissions of `/etc/exports` — those are
worth checking by hand, and they turn out to matter just as much (§4.6).

## 4.3 Read it directly

Automated output is a pointer, not the evidence. Confirm by hand:

```bash
matt@oscp:~$ cat /etc/exports
```

```text
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/usr/upload localhost(rw,sync,no_root_squash)
```

The stock comment block is untouched; the only live line is the last one. It does not yet carry
`insecure` — that token is added in the next chapter, when the mount has to travel through a tunnel.

## 4.4 What `no_root_squash` does

NFS maps the client's users onto the server's users by UID. By default (`root_squash`) a request that
arrives as UID 0 is rewritten to `nobody`, so a client's root cannot create root-owned files on the
server.

`no_root_squash` turns that mapping off:

| Option | Client UID 0 creates files owned by | Consequence |
|---|---|---|
| `root_squash` (default) | `nobody` / `nogroup` | a client root is harmless on the export |
| `no_root_squash` | `root` (UID 0) on the server | a client root writes files the server treats as its own |

That single difference is the whole escalation: place a binary on the export from a machine where you
are root, set the SUID bit, and the server now holds a root-owned SUID binary.

## 4.5 What `localhost` and `insecure` do

`localhost` is not "any client". It is the address the server sees as the source of the mount request,
so only a mount that originates on the server itself matches the rule.

`insecure` relaxes the reserved-port requirement. NFS by default accepts requests only from source
ports below 1024 (`secure`); a mount forwarded through an SSH tunnel arrives from an ephemeral port, so
without `insecure` the server refuses it even though the address is now `127.0.0.1`.

| Token | Effect on this box |
|---|---|
| `rw` | read and write on the export |
| `sync` | writes acknowledged after they are committed — no exploitation value |
| `no_root_squash` | client root keeps UID 0 on the server |
| `insecure` | not present yet; needed once the mount is tunnelled (chapter 05) |

## 4.6 The other way in: the file is writable

`matt` is in `adm`:

```bash
matt@oscp:~$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt),1001(adm)
```

and `/etc/exports` is `-rw-rw-r-- root adm`. Group `adm` can write it, so `matt` can change the
export options without `sudo` and without touching anything else on the host. That is why the box does
not need a kernel exploit: the misconfiguration is editable by the account we already have.

---

**Next:** [`05-mount-failures.md`](05-mount-failures.md)
