# 07 — Flags, cleanup, and what would have stopped this

Two flags, both captured, and then the part most walkthroughs skip: putting the box back and writing
down what actually fixed it.

---

## 7.1 The flags

| Flag | Path | Captured as | Value |
|---|---|---|---|
| `local.txt` | `/home/cassie/local.txt` | `cassie` — read over anonymous FTP, no shell required | `9c3006bdea469fa32aace984f50acc19` |
| `proof.txt` | `/root/proof.txt` | `root` — via SUID `rootbash` from the cron job | `06fc3530c91d86d66a81d84a116f4eb0` |

The root proof, from the session that ended the engagement:

```text
cassie@lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111:~$ /home/cassie/rootbash -p -i
rootbash-5.1# cat proof.txt
06fc3530c91d86d66a81d84a116f4eb0
rootbash-5.1#
```

## 7.2 The chain, end to end

```text
21/tcp anonymous FTP  ──►  5 PDFs  ──►  exiftool dc:creator  ──►  cassie / mark / robert
                                                                        │
                                                                        ▼
                                              cassie:cassie  ──►  local.txt (FTP read)
                                                                        │
                                                                        ▼
20000/tcp Usermin 1.820  ──►  /gnupg/secret.cgi name  ──►  edit_key.cgi
                                                                        │
                                              gpg --fingerprint "<name>" │  (shell)
                                                                        ▼
                                              RCE as cassie  ──►  write .ssh/authorized_keys
                                                                        │
                                       sshd DenyUsers cassie  ◄──────────┘
                                                                        │
/opt/admin owned by cassie  +  root cron tar  ──►  --checkpoint-action=exec
                                                                        │
                                                                        ▼
                                              root  ──►  remove DenyUsers  ──►  SSH  ──►  proof.txt
```

Three separate "you would have stopped here" moments: the PDF metadata, the unescaped key name, and
the bare `*` in the cron job. Each is a one-line fix, and each was left undone on purpose.

## 7.3 Cleanup

The tar payload is the only part of this that keeps firing. Every two minutes the cron job re-runs
`pwn.sh` as root, recreating `rootbash` and re-copying the flag. Left in place it will do that until
the box is rebuilt.

```bash
rm -f /opt/admin/--checkpoint=1 '/opt/admin/--checkpoint-action=exec=sh pwn.sh' /opt/admin/pwn.sh
ls -A /opt/admin
```

```text
$ ls -A /opt/admin
$
```

No output is the success condition: the directory is empty again, so the next tick has nothing to
act on.

If you also want to remove the artefacts you created elsewhere:

```bash
rm -f /home/cassie/rootbash /home/cassie/proof.txt /home/cassie/exec_test.txt \
      /home/cassie/ts.txt /home/cassie/sshfix.txt /home/cassie/unblock_sshd_7f3a.sh \
      /home/cassie/privesc_tar_wildcard_7f3a.sh
```

Restoring the SSH block is optional and it will lock you out again:

```bash
/home/cassie/rootbash -p -c 'cp /home/cassie/sshd_config.bak /etc/ssh/sshd_config && systemctl restart ssh'
```

Do that **last**, and only if the engagement requires the box be returned to its original state. Once
`DenyUsers cassie` is back, the key in `authorized_keys` stops working again — that is the point of
the line.

The `authorized_keys` entry and the Usermin-side GPG key created by the exploit are also artefacts.
The key is harmless (a public key for a keypair you keep) but it is visible in the panel:

```bash
# leave it, or delete the keyring you created:
rm -rf /home/cassie/.gnupg
```

`rm -rf ~/.gnupg` removes every key in that account's keyring, including any the user actually had.
On a lab box that is fine; on a real engagement, do not delete data — record it.

> **Order of cleanup matters.** Remove the cron arguments first. If you remove `rootbash` while the
> checkpoint files are still planted, the next tick recreates it and you will think your cleanup
> failed.

## 7.4 Remediation

| # | Finding | Fix |
|---|---|---|
| 1 | Anonymous FTP exposes a `backup` share with staff documents | `anonymous_enable=NO`; if anonymous access is required, keep personal metadata out of the share |
| 2 | Document metadata leaks usernames | strip `dc:creator`, `Author`, `LastModifiedBy` before publishing; Word: *Inspect Document → Remove Personal Information* |
| 3 | Password equals username (case variants) | a password policy that rejects username-derived secrets, plus MFA on the panel |
| 4 | Usermin 1.820 GnuPG RCE (`open(GPG, "... \"<name>\" ...")`) | upgrade Usermin; the fix is quoting/`list` form on the `gpg` invocation |
| 5 | `DenyUsers cassie` used as an access control | remove the account or lock it properly; do not rely on a pre-auth deny list as a compensating control — it silently breaks legitimate key access and hides the real state |
| 6 | Root cron runs `tar -zxf /tmp/backup.tar.gz *` in a user-writable directory | `tar -zxf /tmp/backup.tar.gz -C /opt/admin .` — or better, `./*`; never let a wildcard reach `tar` as options |
| 7 | `/opt/admin` writable by a non-root account | root-owned, `755`, and the archive path outside any user-writable directory |

The two that matter most are 4 and 6: the first is remote code execution as a user, the second is
root. Either one alone is a full compromise on this box because the flags are readable by their
respective accounts.

## 7.5 What to take to the next box

**Read the banner, then doubt it.** `MiniServ/1.820` was labelled `Webmin httpd` by nmap. The port
(20000) and the CGI paths said Usermin. Chasing CVE-2019-15107 would have burned the box's whole
budget on a product that is not installed.

**Metadata is a user list.** Five PDFs on an anonymous share produced three usernames. No wordlist
required. `exiftool -a -G1` on every document you find is ten seconds and often the difference between
a 3420-guess brute force that fails and a nine-guess login that works.

**Verify the primitive before you ask it for a shell.** `id > file` and read it back. It took one
request and it made the whole difference between "the exploit does not work" and "egress is blocked,
the exploit is fine". A `ConnectionError` on a FIFO payload is not a verdict.

**When a correct credential fails, stop testing the credential.** `DenyUsers` rejects before
authentication, so no amount of re-keying or password retrying was ever going to work. `/var/log/auth.log`
said so, and `cassie` could read it via `adm`. The failure was independent of credential quality — that
is the tell.

**Reproduce the privesc before planting it.** A ten-line sandbox test of the exact `tar` command shape
proved the checkpoint action fires as `uid=0`, and proved it fires even without the archive. Two
minutes of local work removed all the guesswork from a two-minute-delay cron job.

## 7.6 References

- EDB 50234 — Usermin 1.820 authenticated RCE (GnuPG key name).
- `gnupg-lib.pl` — `open(GPG, "$gpgpath --fingerprint \"$_[0]->{'name'}->[0]\" 2>/dev/null |")`.
- GTFO / tar wildcard injection — `--checkpoint=1` + `--checkpoint-action=exec=`.
- `ssh_config(5)` / `sshd_config(5)` — `DenyUsers` is evaluated before authentication.
- MITRE ATT&CK T1053.003 (Scheduled Task/Job: Cron) and T1548.001 (Setuid and Setgid).
