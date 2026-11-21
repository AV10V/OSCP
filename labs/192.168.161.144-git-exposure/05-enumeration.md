# 05 — Enumeration

Goal: from a standard user on Ubuntu 22.04.1, find the shortest path to root — and, just as
importantly, produce a written record of every candidate that was checked and ruled out, so the
escalation chapter starts from evidence instead of guesswork.

---

## 5.1 The five-minute checks

```bash
id; uname -r; sudo -l
```

```
uid=1000(stuart) gid=1000(stuart) groups=1000(stuart),4(adm),24(cdrom),30(dip),46(plugdev)
5.15.0-53-generic
[sudo] password for stuart: Sorry, user stuart may not run sudo on lab-pwk2-student-cl4-144-ubuntu2204-crystal-240-111.
```

`may not run sudo` — not a password prompt loop, an outright denial. `stuart` has no sudo entry at
all, and `sudoers.d` is not even listable:

```bash
ls -la /etc/sudoers.d/
```

```
ls: cannot open directory '/etc/sudoers.d/': Permission denied
```

Next, the classic trio: SUID binaries, file capabilities, and cron.

```bash
find / -perm -4000 -type f 2>/dev/null | wc -l
```

```
39
```

Thirty-nine is the stock Ubuntu 22.04 set plus `snap-confine` and `fusermount3`. Nothing
hand-rolled, nothing in `/opt`, nothing in `/home`. Enumerating all 39 costs two minutes and finds
nothing on this box, but it is the check that lets you *stop* looking there.

```bash
getcap -r / 2>/dev/null
```

Empty — no file capabilities anywhere, so there is no `cap_setuid` binary to abuse.

```bash
crontab -l; cat /etc/crontab | tail -8; ls -la /etc/cron.d /etc/cron.daily
```

Nothing but the vendor `apache2`, `apt-compat`, `dpkg`, `logrotate`, `man-db` jobs, all `root`-owned
`0755`. No writable script in a root-run directory. Cron is a dead end.

Also worth closing: the systemd `sudo.service` symlink points to `/dev/null`, `admin` group is empty,
and `/var/backups/` holds only `apt.extended_states.0`.

---

## 5.2 Kernel version is the finding

```
5.15.0-53-generic
```

Ubuntu 22.04.1, GA kernel, built **2022-10-31**. That date is the whole argument: the GA kernel for
22.04 received security updates through `linux-image-5.15.0-xx-generic`, and `-53` is the October
2022 build. Anything disclosed after that — and fixed only in a later `-xx` — is live.

This is the one place where a standard user on a fully-patched-looking Ubuntu can win, because the
kernel is the only component whose patch level is visible from inside and is genuinely behind.

Three candidates, in order of how easy the public exploit is:

| CVE | Component | Public exploit | Precondition |
|---|---|---|---|
| CVE-2021-4034 **PwnKit** | `pkexec` | One binary + `GCONV_PATH` | `pkexec` is the pre-patch build |
| CVE-2023-2640 **GameOver(lay)** | overlayfs + `setcap` | Shell script | Kernel honours the network-namespace `setcap` |
| CVE-2023-0386 | overlayfs copy-up | Needs FUSE | Unprivileged `unshare` + mount overlayfs |

`policykit-1` is worth one command:

```bash
dpkg -l policykit-1 | tail -1
```

```
policykit-1 0.105-33
```

`0.105-33` is the Ubuntu 22.04 **GA** version. The fix shipped as `0.105-33ubuntu0.1`. So the package
version says *vulnerable*, and `pkexec` is setuid root:

```
-rwsr-xr-x 1 root root 30872 Feb 26  2022 /usr/bin/pkexec
```

Everything about PwnKit looks alive. Whether it actually is gets decided in the next chapter — and
the answer is no. This is exactly the sort of "looks vulnerable by version" signal that has to be
*tested*, not assumed.

---

## 5.3 Things that looked promising and were not

### `/opt/backup/` — three site archives, owned by `stuart`

```bash
ls -la /opt/backup/
```

```
-rw-r--r-- 1 stuart stuart 26890 Apr  5  2018 sitebackup1.zip
-rw-r--r-- 1 stuart stuart 24701 Nov 18  2022 sitebackup2.zip
-rw-r--r-- 1 stuart stuart 25312 Mar  5  2020 sitebackup3.zip
```

`sitebackup3.zip` lists a Joomla tree, including `joomla/configuration.php`. That is the single most
valuable file a Joomla backup can contain — `$user`, `$password`, `$secret`, database host.

It does not come out:

```bash
7z l sitebackup3.zip | head -8
```

```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-03-05 09:14:22 D....            0            0  joomla
2020-03-05 09:14:22 D....            0            0  joomla/administrator
…
```

Listing works; extraction does not:

```bash
7z x sitebackup3.zip -oext
```

```
ERROR: Wrong password : joomla/administrator/cache/index.html
```

All three archives are AES-encrypted, and `stuart` does not know the password. `BreakingBad92`,
blank, `sitebackup`, `chloe`, `carla` — all fail. The 2018 and 2020 timestamps suggest these were
carried over from an older build rather than generated for this box.

Recorded as a dead end: **encrypted archives, no password, no oracle.**

### The Joomla install is not the way in

The live site has a CMS at `/cms/`, and the installer is still reachable:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.161.144/cms/installation/
```

```
200
```

A reachable Joomla installer is normally a fast win — it lets you rewrite `configuration.php` and
point the site at a database you control. Here it does not, because:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.161.144/cms/configuration.php
```

```
404
```

`configuration.php` is not on disk. The installer is a leftover directory from the build, on a site
whose configuration file was deleted after installation. There is no secret in it and nothing to
rewrite. (And over FTP, `RETR /var/www/html/cms/configuration.php` returns `550` — same conclusion
from the other direction.)

Also relevant: `/var/www/html` is owned by `root:root` and is not writable by `stuart`, so even the
`export.php` file-write — if that endpoint existed — could not be pointed at a web root.

### `chloe`'s password is not `stuart`'s password

`stuart` is not in `sudo`; `chloe` is. The obvious move is password reuse. SSH cannot answer the
question (`DenyUsers chloe` rejects before authentication), so use FTP, which does not consult
`DenyUsers`:

```bash
for u in chloe carla thato; do
  printf '%-7s ' "$u"
  curl -s --max-time 10 -u "$u:BreakingBad92" ftp://192.168.161.144/ -o /dev/null -w '%{http_code}\n'
done
```

```
chloe   530
carla   530
thato   530
```

`530 Login incorrect` for all three. The password is not reused to the privileged account. Box
design again: the `sudo` group is a decoy that costs one query to close.

---

## 5.4 What `adm` actually buys

`stuart` is in `adm`, which reads `/var/log`:

```bash
grep -aiE 'chloe' /var/log/auth.log /var/log/auth.log.1 | head
```

```
Nov 18 22:18:48 oscp su[1213]: (to chloe) root on pts/0
Nov 21 20:28:53 … sshd[10777]: User chloe from 192.168.45.158 not allowed because listed in DenyUsers
```

The build-time journal is even more revealing — `journalctl` shows the whole image preparation:

```
Nov 18 22:18:40 oscp passwd[1210]: pam_unix(passwd:chauthtok): password changed for chloe
Nov 18 22:18:48 oscp su[1213]: (to chloe) root on pts/0
```

So `chloe`'s password was set by root at build time, and then `su`'d into once. The *value* is not
logged — PAM never logs the credential. `adm` gives you a timeline, not a secret.

Same conclusion for the cloud-init logs: they show `useradd ubuntu … --groups …,sudo,…` and
`cc_set_passwords` running, but the data it applied is `0600 root` in
`/var/lib/cloud/instance/`, and the config-drive ISO at `/dev/sr0` — which `stuart` *can* read via
the `cdrom` group — contains only network configuration.

```bash
dd if=/dev/sr0 of=/tmp/cd.iso bs=1M
7z x -ocdext /tmp/cd.iso
grep -riE 'passw|chpasswd|ssh_authorized' cdext/openstack/latest/user_data
```

No hits. `user_data` is `write_files` for `/root/set-net.sh` and a `runcmd`, nothing more.

---

## 5.5 Summary of the enumeration pass

| Vector | Result |
|---|---|
| `sudo -l` | denied, no entry |
| SUID (39 files) | stock Ubuntu set, nothing unusual |
| File capabilities | none |
| Cron | vendor jobs only, nothing writable |
| `/opt/backup/*.zip` | AES-encrypted, password unknown |
| Joomla installer | reachable, but `configuration.php` absent |
| Password reuse → `chloe` | `530 Login incorrect` |
| `adm` / cloud-init logs | timeline, no credentials |
| `/dev/sr0` config-drive | network config only |
| **Kernel `5.15.0-53-generic`** | **open — three candidates** |

The box has exactly one live surface left: a GA kernel from October 2022. Next chapter tests all
three candidates in order and explains why the first two fail.
