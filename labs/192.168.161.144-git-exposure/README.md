# 192.168.161.144 — `git-exposure` (Ubuntu 22.04.1)

| | |
|---|---|
| **IP** | `192.168.161.144` (reached over `tun0`, attacker `192.168.45.158`) |
| **OS** | Ubuntu 22.04.1 LTS, kernel `5.15.0-53-generic` |
| **Open ports** | `21/tcp` vsftpd 3.0.5 · `22/tcp` OpenSSH 8.9p1 · `80/tcp` Apache 2.4.52 |
| **Difficulty** | Easy–medium — one information leak, one credential reuse, one kernel CVE |
| **Result** | `stuart` → `root` (via CVE-2023-0386) |
| **Flags** | `local.txt` — `bb8e8b0b546a972d8280c494463cbf93` · `proof.txt` — `fffa8aa85fea084e31de521432d8e8b9` |

---

## TL;DR — the chain

```
TCP/80  Apache → gobuster → /.git/  (301 → 200, full repo readable)
  └─ git-dumper → working tree + history
     .git/config  → remote URL with a personal access token
     git show 44a055d  → "Security Update" blanked two passwords…
     git show 80ad5fe  → …but the previous commit still had them
        │
        ▼
stuart@challenge.lab : BreakingBad92   (and dean@challenge.pwk, same password)
        │  password reuse onto the system account
        ▼
TCP/21 FTP + TCP/22 SSH → shell as stuart
  └─ FTP chroot = "/" → read the whole filesystem: /etc/passwd, sshd_config, /opt/backup
     local.txt
        │
        ▼
sudo -l → nothing.  groups: adm, cdrom, dip, plugdev
  └─ kernel 5.15.0-53-generic
     PwnKit  CVE-2021-4034  → patched build, GCONV_PATH stripped under AT_SECURE
     GameOver(lay) CVE-2023-2640 → xattr written rev3 rootid=1000, setuid → EPERM
     CVE-2023-0386 overlayfs SUID copy-up → works
        │  target only ships libfuse3 → port the FUSE2 PoC
        ▼
SUID root shell → proof.txt
```

Three things make this box worth writing up:

1. **The leak was the `.git` directory, not a page.** Every PHP file in the repo returns `404` on the live host. There is no `order.php`, no `export.php`, no `search.php` — those are only reachable *through* the git objects. A scanner that stops at "404 on the found paths" would have called this box empty.
2. **`git log` is an archive, not a changelog.** The commit literally named `Security Update` is the one that tells you credentials existed, and `git show` on its parent recovers them verbatim. Deleting a secret in a later commit does not delete it from the repository.
3. **Two of the three obvious kernel privilege escalations are dead.** PwnKit looks alive (`policykit-1 0.105-33`) but the box carries the patched binary; GameOver(lay) looks alive (`5.15.0-53`) but the capability xattr is written in revision 3 with a non-zero rootid, which defeats it. The third one — the overlayfs copy-up bug — needs a FUSE filesystem, and the target has no FUSE2 at all, so the published PoC does not build. That is where the actual work was.

---

## Chapters

| | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | Full TCP scan, service fingerprint, and closing out the UDP/70 dead end |
| 02 | [Web enumeration](02-web-enumeration.md) | Why `/.git/` answers `301`, and how to confirm it is real |
| 03 | [Dumping the repository](03-git-dump.md) | `git-dumper`, reading `config`, mining history for credentials |
| 04 | [Foothold](04-foothold.md) | Credential reuse into FTP and SSH, and the chroot-to-`/` mistake |
| 05 | [Enumeration](05-enumeration.md) | `sudo -l`, group memberships, kernel version, the unreadable backups |
| 06 | [Privilege escalation](06-privilege-escalation.md) | Three kernel CVEs, two refuted, one ported to FUSE3 and landed |
| 07 | [Flags & cleanup](07-flags-and-cleanup.md) | Proof, removal, lessons |

---

## Corrections to the obvious reading

| Tempting conclusion | What was actually true |
|---|---|
| `vsftpd 3.0.5` → find the RCE | vsftpd 3.0.5 has no public RCE. The `USER :)` backdoor on `:6200` is **2.3.4 only**. FTP was the *foothold*, reached with recovered credentials, not exploited. |
| `linux/remote/84.c` is the FTP exploit | It is `UMN gopherd`'s FTP-gateway overflow. It talks to gopher **port 70** and needs a fake FTP server on your own `:21`. Port 70 is closed here — and the published file is corrupted (every `*` stripped). |
| `GCONV_PATH=` under pkexec | The module never loads: `pkexec` is the fixed build and secure-exec strips `GCONV_PATH`. Proven by running the same payload against a non-setuid copy, where it did work. |
| `/opt/backup/*.zip` holds the config | All three are AES-encrypted. `configuration.php` does not exist on the live filesystem. |
| `chloe` is a squashed user | `DenyUsers chloe` in `sshd_config`. Her password is different from `stuart`'s (checked over FTP, which does not honour `DenyUsers`). |

---

## Defensive notes

- **Serve `.git` from nowhere.** Deny `/.git` at the web server; `RedirectMatch 404 /\.git` is one line and removes this entire box.
- **A token in a remote URL is a credential in a file.** `git remote set-url` after cloning, and never clone with `https://token@…` on a host you do not control. Audit with `git config --list | grep -i url`.
- **Rotating a secret is not deleting it.** Rewrite history (`git filter-repo`) *and* revoke the credential. Blanking it in a new commit leaves it one `git show` away.
- **`chroot_local_user=NO` on a read-only account is a filesystem disclosure.** A "just FTP" account read `/etc/passwd`, `/etc/group`, `sshd_config`, and the backup directory.
- **`vsftpd` accepted a system login.** `pam_service_name=vsftpd` against system accounts means every shell account is an FTP account. Prefer a dedicated `nologin` user for file transfer.
