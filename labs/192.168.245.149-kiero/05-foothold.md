# 05 — Foothold: shell as `john`

The key from chapter 04 authenticates as `john`. This chapter establishes the shell and does the
local enumeration that identifies the privilege-escalation path.

---

## 5.1 Getting the shell

```bash
ssh -i id_rsa -o StrictHostKeyChecking=no john@192.168.245.149
```

```
Warning: Permanently added '192.168.245.149' (ED25519) to the list of known hosts.
uid=1000(john) gid=1000(john) groups=1000(john)
lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195
/home/john
```

Shell as `john`, uid 1000. Nothing to upgrade — this is a real interactive shell, not a web
callback, so no TTY juggling is needed (though `python3 -c 'import pty;pty.spawn("/bin/bash")'`
is the standard move if you land through an exploit instead).

## 5.2 Local enumeration

One pass, saved to a script and piped over SSH so it runs in a single connection and produces one
readable report. Writing the script locally and sending it with `bash -s` avoids quoting hell and
leaves no file on the target.

```bash
# on Kali
cat > enum1.sh <<'EOS'
echo "===== ID ====="
id; whoami
echo "===== OS ====="
cat /etc/os-release | head -6; uname -a
echo "===== SUDO ====="
sudo -n -l 2>&1 | head -20
echo "===== HOME ====="
ls -la /home/john
echo "===== FLAGS ====="
find / -name "local.txt" -o -name "proof.txt" 2>/dev/null | head
echo "===== SUID ====="
find / -perm -4000 -type f 2>/dev/null
echo "===== CAPABILITIES ====="
getcap -r / 2>/dev/null | head -20
echo "===== CRON ====="
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null
echo "===== LISTENING ====="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo "===== USERS ====="
cat /etc/passwd | grep -E "sh$|bash$"
echo "===== SUDOERS ====="
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"
echo "===== /opt /srv /var/www ====="
ls -la /opt /srv /var/www 2>/dev/null
EOS

ssh -i ftp_kiero/id_rsa john@192.168.245.149 'bash -s' < enum1.sh
```

### Output — identity and OS

```
===== ID =====
uid=1000(john) gid=1000(john) groups=1000(john)
john

===== OS =====
NAME="Ubuntu"
VERSION="20.04.5 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.5 LTS"
VERSION_ID="20.04"
Linux lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195 5.9.0-050900-generic
  #202010112230 SMP Sun Oct 11 22:34:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

**Reading it:** Focal 20.04.5 with a *mainline* 5.9 kernel (`5.9.0-050900-generic`), not the
Ubuntu-signed `5.4.0-xx`. A mainline kernel on 20.04 usually means it was swapped in deliberately —
worth noting, but `dirtypipe` (CVE-2022-0847) needs kernels before 5.16.11, so only if we needed a
kernel exploit, which we will not.

No supplementary groups at all — `groups=1000(john)` only. So no `docker`, `lxd`, `disk`,
`adm`, or `sudo` group shortcuts.

### Output — sudo and home directory

```
===== SUDO =====
sudo: a password is required

===== HOME =====
total 64
drwxr-xr-x 4 john john  4096 Nov 22  2022 .
drwxr-xr-x 5 root root  4096 Nov 14 18:33 ..
lrwxrwxrwx 1 root root     9 Nov 21  2022 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 john john  3771 Feb 25  2020 .bashrc
drwx------ 2 john john  4096 Nov  2  2022 .cache
-rw------- 1 john john    33 Nov 17  2022 .lesshst
-rw-r--r-- 1 john john   807 Feb 25  2020 .profile
drwx------ 2 john john  4096 Nov 21  2022 .ssh
-rw------- 1 john john   816 Nov 22  2022 .viminfo
-rw-rw-r-- 1 john john   257 Nov 22  2022 .wget-hsts
-rwsrwsr-x 1 root root 16792 Nov 21  2022 RESET_PASSWD
-rw-r--r-- 1 john john    33 Nov 14 18:35 local.txt
```

Two things jump out immediately:

1. **`-rwsrwsr-x 1 root root 16792 RESET_PASSWD`** — setuid **and** setgid root, owned by root,
   executable by everyone, sitting in a user's writable home directory. This is the binary named in
   the SNMP extend. It is the intended privesc.
2. `.bash_history -> /dev/null` — history is deliberately discarded, so there is no shell history
   to mine for credentials. This box has been cleaned.

Also note `local.txt` exists already (33 bytes, modified `Nov 14 18:35` — the box writes it on
first boot/redeploy).

### Output — SUID inventory (filtered)

```
===== SUID =====
/home/john/RESET_PASSWD
/usr/bin/mount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/su
/usr/bin/chfn
/usr/bin/at
/usr/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/snap/core18/... (snap duplicates of the above)
/snap/core20/... (snap duplicates of the above)
```

**Reading it:** everything except the first line is stock Ubuntu — `mount`, `su`, `passwd`,
`sudo`, `pkexec` are all setuid by default. `pkexec` is CVE-2021-4034 (`PwnKit`) but this
`policykit-1` build on patched 20.04 does not respond to the standard PoC; more importantly, the
box is handing us a blatant custom SUID binary, so there is no reason to bother.

The `find / -perm -4000` output is long because of the snap mounts. Filter it next time:

```bash
find / -perm -4000 -type f 2>/dev/null | grep -v "^/snap"
```

### Output — capabilities and cron

```
===== CAPABILITIES =====
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Nothing interesting — no `cap_setuid` on a user-writable binary, which is the other classic
one-liner.

```
===== CRON =====
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

Only the stock `run-parts` jobs, and `/etc/cron.hourly` contains just `.placeholder`. No writable
cron script, no root cron in a user directory. Cron is not the path.

### Output — listeners, users, sudoers

```
===== LISTENING =====
LISTEN 0 511        0.0.0.0:80        0.0.0.0:*
LISTEN 0 4096 127.0.0.53%lo:53       0.0.0.0:*
LISTEN 0 128        0.0.0.0:22        0.0.0.0:*
LISTEN 0 32               *:21              *:*
LISTEN 0 128           [::]:22           [::]:*

===== USERS =====
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:john:/home/john:/bin/bash
kiero:x:1001:1001::/home/kiero:/bin/bash
ubuntu:x:1002:1003:Ubuntu:/home/ubuntu:/bin/bash
```

**Reading it:**

- Only the three services already known, all on all interfaces. No localhost-only service to
  tunnel to — this box has no internal-only attack surface.
- `127.0.0.53:53` is `systemd-resolved`, not a real DNS server.
- **`kiero` is a real local account** (uid 1001, shell `/bin/bash`), confirming the SNMP hint was
  about a genuine login. Its home is `/home/kiero` — which is *not* where the FTP login lands, since
  vsftpd is configured with `/srv/ftp`. That is why `kiero`'s FTP session exposed a shared
  directory containing `john`'s key.
- `ubuntu` (uid 1002) is the cloud-image default account.

`cat /etc/sudoers` produced no output at all — `john` cannot read it, which is itself the answer:
no readable sudoers rules and `sudo -n -l` needed a password. No sudo path.

### Output — application directories

```
===== /opt /srv /var/www =====
/opt:
total 8
drwxr-xr-x  2 root root 4096 Jul 31  2020 .
drwxr-xr-x 19 root root 4096 Nov 14 18:33 ..

/srv:
total 12
drwxr-xr-x  3 root root 4096 Nov 21  2022 .
drwxr-xr-x 19 root root 4096 Nov 14 18:33 ..
drwxr-xr-x  2 ftp  ftp  4096 Nov 22  2022 ftp

/var/www:
total 12
drwxr-xr-x  3 root root 4096 Nov 21  2022 .
drwxr-xr-x 15 root root 4096 Nov 21  2022 ..
drwxr-xr-x  2 root root 4096 Nov 21  2022 html
```

Empty `/opt`, `/var/www/html` is the stock page, and `/srv/ftp` is the FTP root we already looted.
No third-party application anywhere on the filesystem.

## 5.3 Triage summary

| Vector | Result |
|---|---|
| sudo | password required, sudoers unreadable → dead |
| SUID | **custom `/home/john/RESET_PASSWD`, setuid+setgid root** → live candidate |
| Capabilities | only stock `ping`/`mtr` → dead |
| Cron | stock `run-parts` only, nothing writable → dead |
| Kernel | 5.9 mainline; no need |
| Local services | none beyond the known three |
| Credentials in files | `.bash_history` → `/dev/null`, nothing to mine |

The box is pointing at one thing. → [06 — Privilege escalation](06-privilege-escalation.md)
