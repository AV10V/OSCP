# 05 — The 91-byte key that could never work

This is the chapter that saves an hour on a similar box. Everything about the SSH access was
correct — the key, the file, the mode, the ownership, the password. sshd refused anyway, and the
reason was in a log line the account could read all along.

---

## 5.1 The failure

```bash
ssh -i ~/.ssh/charlie -o IdentitiesOnly=yes cassie@192.168.161.157
```

```text
cassie@192.168.161.157's password:
Permission denied, please try again.
cassie@192.168.161.157's password:
Permission denied, please try again.
cassie@192.168.161.157's password:
cassie@192.168.161.157: Permission denied (publickey,password).
```

The `(publickey,password)` at the end is the important part: both methods were *offered*, so neither
`AuthenticationMethods` nor `PubkeyAuthentication no` is in play. The server accepted the key as a
method and then rejected the attempt.

Naturally, you check the obvious things. All of them are correct:

```text
lftp cassie@192.168.161.157:~/ > cat .ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILOcuCxOF3FuY0pG7yuezyTFZhjbqZO48gCqsIo/L+B2 kali@kali
91 bytes transferred
```

```text
-rw-------    1 cassie    cassie          91 Nov 24 22:50 authorized_keys
```

- correct key, byte for byte, including the `kali@kali` comment;
- 91 bytes — one line, no trailing junk;
- mode `600`, owner `cassie`, directory owned by `cassie`;
- `~/.ssh` is where sshd looks.

And the password fails too, with the same message. Two independent, individually valid
credentials, both rejected — that is not a credential problem. That is a policy problem.

## 5.2 Read the log, not the error

`cassie` is in the `adm` group, so `/var/log/auth.log` is readable without any privilege escalation.
That is the whole reason this chapter exists:

```bash
grep -i cassie /var/log/auth.log | tail -n 5
```

```text
Nov 24 22:45:03 lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111 sshd[46282]: User cassie from 192.168.45.158 not allowed because listed in DenyUsers
Nov 24 22:45:03 lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111 sshd[46282]: Connection closed by invalid user cassie 192.168.45.158 port 51234 [preauth]
```

`not allowed because listed in DenyUsers`. Note `[preauth]` on the second line.

```bash
grep -vE '^[[:space:]]*#' /etc/ssh/sshd_config | grep -vE '^[[:space:]]*$'
```

```text
Port 22
PermitRootLogin yes
UsePAM yes
KbdInteractiveAuthentication no
DenyUsers cassie
```

`DenyUsers` is evaluated **before** authentication. sshd never looks at the key and never checks the
password; it decides the account is not allowed and closes the connection with the same generic
message it uses for a bad password. That is deliberately uninformative to the client — and it is
fully explained in the server log.

> **If a key is provably correct and still fails, check in this order:**
> `DenyUsers`/`AllowUsers` in the main config, `Match` blocks and their `DenyUsers`, `Include`
> directives (Ubuntu ships `/etc/ssh/sshd_config.d/*.conf`), then PAM (`/etc/pam.d/sshd`,
> `pam_access`, `account required`). All of these reject *before* the key is ever tried.

## 5.3 Why the password path looked broken too

Because it was blocked by the same line. `DenyUsers` does not care which method you use — publickey,
password, keyboard-interactive are all refused for that account. This is the trap: two failures that
look like two independent credential problems, when in fact there is one config line and the
credentials were never evaluated.

The tell that distinguishes them: **a correct password fails identically to an incorrect one, and a
correct key fails identically to a missing one.** When failure is independent of credential quality,
the decision is being made before the credential is read.

## 5.4 Removing the line requires root — which is why the order matters

`/etc/ssh/sshd_config` is root-owned. `cassie` cannot edit it, and `sudo -l` is a dead end:

```text
Sorry, user cassie may not run sudo on lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111.
```

So the box is deliberately ordered: **privesc first, SSH second.** The cron job in chapter 06 gives
root (and a SUID `rootbash`), and *then* the SSH block can be lifted.

[`scripts/unblock_sshd_7f3a.sh`](scripts/unblock_sshd_7f3a.sh) does it safely — backup, in-place
rewrite, `sshd -t` before restart:

```bash
/home/cassie/rootbash -p -c 'bash /home/cassie/unblock_sshd_7f3a.sh'
```

```text
[+] backup: /home/cassie/sshd_config.bak
[+] removed DenyUsers cassie from /etc/ssh/sshd_config
[+] sshd -t: config OK
[+] ssh restarted
PermitRootLogin yes
UsePAM yes
KbdInteractiveAuthentication no
```

Three details that matter:

- **`cat "$tmp" > "$CONF"`, not `mv`.** Overwriting in place keeps the file's owner, mode and inode.
  `mv` from `/tmp` would leave a root-owned `644` file in the right place by luck, but can trip
  SELinux contexts or an `sshd_config.d` include ordering on other hosts.
- **`sshd -t` before `systemctl restart ssh`.** A bad config plus a restart is how you lose access to
  a box you already own.
- **Only the `DenyUsers` line naming `cassie` is removed.** `PermitRootLogin yes` stays, which is
  convenient — it means root over SSH is available as a fallback once the password is set.

## 5.5 The session

```bash
ssh -i ~/.ssh/charlie -o IdentitiesOnly=yes cassie@192.168.161.157
```

```text
cassie@lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111:~$
```

A real TTY, finally. And with it, `/home/cassie/rootbash` from chapter 06:

```bash
/home/cassie/rootbash -p -i
```

```text
rootbash-5.1# cat proof.txt
06fc3530c91d86d66a81d84a116f4eb0
rootbash-5.1#
```

`-p` is the whole trick: bash drops its effective UID on start unless it is given `-p`, so a SUID
`bash` without it returns you to `cassie`. With it, the effective UID stays `root` — and because
bash was started SUID, it does not reset the saved UID either. Verify with `id`: you want
`uid=1000(cassie)` next to `euid=0(root)`.

## 5.6 What chapter 05 established

- SSH was never a credential problem: `DenyUsers cassie` rejected the account before authentication.
- A correct key and a correct password both fail identically — that is the signature of a pre-auth
  policy decision, not a bad secret.
- `/var/log/auth.log` names the cause, and `cassie` could read it all along via `adm`.
- Fixing it needs root, so the intended order on this box is **privesc → SSH**, not the reverse.
