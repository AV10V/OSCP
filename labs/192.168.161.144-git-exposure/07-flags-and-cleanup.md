# 07 — Flags & cleanup

---

## 7.1 Proof

```bash
/tmp/.rb161 -p -c 'id; cat /root/proof.txt'
```

```
uid=1000(stuart) gid=1000(stuart) euid=0(root) groups=1000(stuart),4(adm),24(cdrom),30(dip),46(plugdev)
fffa8aa85fea084e31de521432d8e8b9
```

```bash
/tmp/.rb161 -p -c 'ls -la /root/'
```

```
drwx------ 6 root root 4096 Nov 21 19:04 .
lrwxrwxrwx 1 root root    9 Nov 18  2022 .bash_history -> /dev/null
-rw------- 1 root root   20 Oct 31  2022 .lesshst
-rw-r--r-- 1 root root   33 Nov 21 19:06 proof.txt
```

| Flag | Value | Location | Obtained as |
|---|---|---|---|
| `local.txt` | `bb8e8b0b546a972d8280c494463cbf93` | `/home/stuart/local.txt` | `stuart` (and over FTP with the same credentials) |
| `proof.txt` | `fffa8aa85fea084e31de521432d8e8b9` | `/root/proof.txt` | `root`, via CVE-2023-0386 |

Note `proof.txt` is `0644` while the directory is `0700` — so the flag is only as protected as
`/root` itself, which is the normal arrangement.

---

## 7.2 Cleanup

Everything the escalation dropped is removable with the root shell itself, before giving it up:

```bash
/tmp/.rb161 -p -c '
  rm -f /tmp/.rb161 /tmp/ovl161.tar.gz
  pkill -x fuse3mnt
  sleep 1
  fusermount3 -uz /tmp/ovl/ovlcap/lower 2>/dev/null
  rm -rf /tmp/ovl
  echo cleanup_done'
```

```
cleanup_done
```

Verify — do not assume:

```bash
ls -la /tmp/.rb161          # No such file or directory
pgrep -x fuse3mnt           # (nothing)
ls -d /tmp/ovl              # No such file or directory
grep -c '/tmp/ovl' /proc/mounts   # 0
```

The `pkill -x` deserves a warning. Use `-x` (exact process name). `pkill -f fuse3mnt` matches the
**command line**, and the cleanup SSH command itself contains the string `fuse3mnt` — so
`pkill -f` kills the shell running the cleanup, halfway through, and the session dies with no output.
That happened once here and produced a confusing empty result before the cause was obvious.

A leftover FUSE mount is worth hunting rather than ignoring: if `fuse3mnt` is killed without
unmounting, `/tmp/ovl/ovlcap/lower` is a stale mountpoint, and anything that traverses `/tmp` can
block on it. `fusermount3 -uz` (lazy unmount) is the fix.

Also worth removing, though low-risk:

```bash
rm -rf /tmp/g /tmp/pk161 /tmp/pk2 /tmp/cd.iso
```

The PwnKit scaffolding (`GCONV_PATH=.`, `pwnkit.so`, `gconv-modules`) is inert without a setuid
`pkexec` that honours it, but leaving a directory named `GCONV_PATH=.` on a box is untidy at best.

---

## 7.3 The chain, end to end

```
Apache serves /.git  ──────────────────────►  full source disclosure
  git-dumper                                 7 files + 10 commits
    .git/config                              GitHub PAT in the remote URL
    git show 44a055d                         "Security Update" — deleted the creds
    git show 44a055d^                        stuart@challenge.lab : BreakingBad92
    git show 80ad5fe                         dean@challenge.pwk   : BreakingBad92
        │
        │  password reuse (the email username was a decoy)
        ▼
ssh stuart:BreakingBad92  ─────────────────►  shell, uid 1000
  FTP, chroot_local_user=NO, pwd=/            read-only filesystem browser
  local.txt
        │
        │  enumeration: no sudo, 39 stock SUIDs, no caps, no cron,
        │  encrypted backups, Joomla without configuration.php, chloe denied
        ▼
kernel 5.15.0-53-generic
  PwnKit          ✗  patched pkexec + AT_SECURE
  GameOver(lay)   ✗  cap xattr rev3, rootid=128
  CVE-2023-0386   ✓  FUSE3 lower layer → overlayfs copy-up → SUID root
        │
        ▼
proof.txt
```

---

## 7.4 What this box actually teaches

**1. `.git` is a backup, not a directory.** The web root contained no application at all — every
PHP file returned `404`. The repository inside `/.git/` contained the whole history, and the history
contained the passwords. Treat a served `.git` as a full source disclosure, and treat `git log` as an
archive of every secret that has ever been committed.

**2. "Fixed" and "removed" are different verbs.** `Security Update` blanked the credentials and even
left a comment explaining why. It did not rewrite history, so the secret remained in the object
database. When a secret has been committed, the only real remediation is revoke the credential *and*
rewrite history — in that order.

**3. A username can be a decoy.** `stuart@challenge.lab` is not a UNIX account; `stuart` is. The
`@challenge.lab` suffix cost one attempt and taught nothing. Strip the domain, try the local part.

**4. `DenyUsers` is not a credential check.** `chloe` is in `sudo` and `DenyUsers chloe` blocks SSH
*before* authentication — so a `Permission denied` against her says nothing about her password. Any
test of her credential has to go through a different service. Here the same test over FTP answered
`530`, which is a real answer.

**5. A version string is a hypothesis.** `policykit-1 0.105-33` and kernel `5.15.0-53` both say
"vulnerable" and both were wrong for two of the three candidates. The method that resolved it was a
**positive control**: run the identical payload against a non-setuid `pkexec`, where it worked. That
one test converted "PwnKit doesn't work here" into "PwnKit is patched here" — a defensible
conclusion instead of a shrug.

**6. Read the xattr and believe it.** GameOver(lay) failed with `EPERM` while `getcap` happily
reported `cap_setuid=eip`. The resolution was not in `getcap` but in the raw xattr: revision 3,
`rootid=128`. `0x03000001` versus `0x02000001` is the entire difference between an exploitable
capability and a namespaced one.

**7. Porting a PoC is normal work.** The overlayfs exploit assumed libfuse 2; the target shipped only
FUSE3 and had no compiler. Writing a 90-line FUSE3 adapter and cross-building it statically was
faster than hunting a different exploit — and it is the kind of adaptation that a real engagement
demands. Two build gotchas worth remembering: `FUSE_ARGS_INIT(0, NULL)` is rejected by `fuse_new`,
and Kali's glibc 2.38 does not run on Ubuntu 22.04's glibc 2.35, so build `-static`.

---

## 7.5 Remediation for this host

| Finding | Fix |
|---|---|
| `/.git/` served by Apache | `RedirectMatch 404 /\.git` in the vhost; deploy with `git archive`, not the working copy |
| PAT embedded in `git remote` | Revoke the token; `git remote set-url` without credentials; audit `git config --list \| grep -i url` |
| Credentials in git history | `git filter-repo` to rewrite, then rotate every secret that was ever committed |
| Password reuse: DB → UNIX | Distinct credentials per layer; no shared password between application and system accounts |
| `chroot_local_user=NO` | Set `YES` (or `chroot_local_user=YES` + `allow_writeable_chroot=YES`); give file-transfer accounts their own tree |
| FTP accepts system accounts | Dedicated `nologin` account with `pam_service_name=vsftpd` scoped to it |
| Kernel `5.15.0-53` | Upgrade to `linux-image-5.15.0-70` or later (CVE-2023-0386), and patch `pkexec` in the same pass |
