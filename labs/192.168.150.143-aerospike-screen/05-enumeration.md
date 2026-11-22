# 05 — Enumeration as aero

A service account with no sudo, no group memberships and no writable system paths — on paper. What
follows is the list of things that were checked, including the three that looked promising and were
not, because the fourth one is only credible if the other three are documented.

---

## 5.1 The account

```
uid=1000(aero) gid=1000(aero) groups=1000(aero)
```

One group, its own. No `sudo`, no `adm`, no `docker`, no `lxd`. Nothing to inherit.

```bash
sudo -n -l
```

```
sudo: a password is required
```

`aero` is not in `/etc/sudoers` and there is no passwordless rule. Sudo is a dead end at this level.

---

## 5.2 setuid inventory

```bash
find /usr/bin /usr/sbin /bin /sbin /opt /home /usr/local -perm -4000 -type f 2>/dev/null | sort
```

```
/usr/bin/at
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/screen-4.5.0
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
```

Eleven of those thirteen are the stock Ubuntu set and are not interesting in isolation. Two are:

- `pkexec` — the PwnKit binary (CVE-2021-4034).
- `screen-4.5.0` — a **versioned** binary, sitting beside `screen.old`, with `/usr/bin/screen`
  symlinked to it.

The second is the anomaly. Ubuntu ships `screen` unversioned; a file called `screen-4.5.0` that is
setuid and reachable through the normal name means someone rebuilt and installed an old release by
hand. And `4.5.0` is the last version affected by **CVE-2017-5618**.

---

## 5.3 The refutations

### PwnKit — patched binary, not just a patched version string

```bash
dpkg -l | grep -E "^ii  policykit"
```

```
ii  policykit-1  0.105-26ubuntu1.3  amd64  framework for managing administrative policies and privileges
```

`0.105-26ubuntu1.3` is the Ubuntu security update that carries the CVE-2021-4034 fix. On an Ubuntu
20.04 box this is the difference between "PwnKit might work" and "PwnKit will not". It was checked
and discarded; chapter 06 does not spend time on it.

### Dirty Pipe — kernel too old

```
5.4.0-104-generic
```

CVE-2022-0847 requires **5.8+**. This kernel is 5.4. The bug does not exist here, and no amount of
PoC porting will create it.

### The root cron

```bash
cat /etc/crontab | grep -v '^#' | grep -v '^$'
```

```
17 *  * * *  root  cd / && run-parts --report /etc/cron.hourly
25 6  * * *  root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6  * * 7  root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6  1 * *  root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/1 * * * *  root  /root/aerospike.sh
```

A **root job every minute** running a script in `/root`. That is a textbook cron hijack — if the
script, or anything it calls, is writable by us.

```bash
ls -la /root/aerospike.sh
```

```
ls: cannot access '/root/aerospike.sh': Permission denied
```

The script itself is unreadable and unwritable. But its *content* is what matters, and there is a
strong hint available without reading it: the Aerospike installation directory is owned by `aero`.

```bash
ls -ld /opt/aerospike /opt/aerospike/bin
```

```
drwxr-xr-x 9 aero aero 4096 May 10  2021 /opt/aerospike
drwxr-xr-x 2 aero aero 4096 May 10  2021 /opt/aerospike/bin
```

`/opt/aerospike/bin` is fully writable by `aero` and contains `asadm`, `asinfo`, `aql` and the rest
of the tool suite — any of which a root health-check script might plausibly call. Replacing one is a
plausible second path to root.

It was **not taken**. Watching the cron requires either a persistent file-watcher or a `ps` loop
sampled across a minute boundary, and this channel (chapter 04) has an 8 s ceiling per call with no
TTY to detach cleanly from. The setuid `screen` binary was simpler, deterministic, and did not
depend on guessing what an unreadable script does. The cron remains a valid alternate route and is
recorded here as such — not as tested.

---

## 5.4 The toolchain question

```bash
which gcc cc make
```

Nothing. There is no compiler on the target, and no toolchain worth fetching (chapter 04: egress is
limited to the lab's allowlisted ports, so there is no `apt` and no `wget` back to Kali). Every
binary payload for this box has to be **built on Kali and pushed through the database socket**.

That has one hard consequence: **glibc version**. Kali ships a much newer glibc than Ubuntu 20.04
(2.31). A shared object built against Kali's headers will refuse to load on the target with a symbol
version error. Compile against the oldest ABI that will run:

```bash
gcc -Os -fPIC -shared -o libhax.so libhax.c
strip --strip-unneeded libhax.so
objdump -T libhax.so | grep -oE 'GLIBC_[0-9.]+' | sort -uV
```

```
GLIBC_2.2.5
```

`GLIBC_2.2.5` only. That single line is the difference between a payload that preloads and one that
prints `version 'GLIBC_2.34' not found` and aborts. Check it *before* uploading — there is no
compiler on the far side to fix it.

---

## 5.5 What is left

| Path | State |
|---|---|
| `sudo` | closed — not in sudoers |
| groups | closed — only `aero` |
| PwnKit | refuted — `0.105-26ubuntu1.3` |
| Dirty Pipe | refuted — kernel 5.4 |
| root cron via `/opt/aerospike/bin` | plausible, **not tested** |
| **setuid `screen-4.5.0`** | **CVE-2017-5618 — next chapter** |

One setuid binary on a five-year-old release, installed by hand, in a box whose package database
claims `screen 4.8.0`. That contradiction is the finding.
