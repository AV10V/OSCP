# 07 — Flags, cleanup and lessons

## 7.1 Flags

| File | Access | Value |
|---|---|---|
| `/home/john/local.txt` | as `john` (uid 1000) | `af540ac8ffa61d312756f2f4a3877d1d` |
| `/root/proof.txt` | as `root` only | `9e7f4ce50acc525d577abfc26aebfd1e` |

```bash
# user flag
cat /home/john/local.txt
# af540ac8ffa61d312756f2f4a3877d1d

# root flag
cat /root/proof.txt
# 9e7f4ce50acc525d577abfc26aebfd1e
```

The root flag was captured through the PATH-hijack payload rather than an interactive shell, which
keeps the evidence self-documenting:

```bash
cat /tmp/root_proof.txt
# 9e7f4ce50acc525d577abfc26aebfd1e
```

Both values are recorded in the evidence files committed alongside this chapter:
[`evidence/evidence_foothold.txt`](evidence/evidence_foothold.txt) and
[`evidence/evidence_privesc.txt`](evidence/evidence_privesc.txt).

## 7.2 Cleanup

Anything written to a target — especially as root — gets removed and the removal verified. Leaving
a root-executed payload script behind is both sloppy and, on an exam, a way to lose points if the
proctor inspects the host.

Because the only way to root was the setuid binary, cleanup used the same mechanism:

```bash
D=$(mktemp -d /tmp/ppc.XXXXXX)
cat > "$D/chpasswd" <<'EOF'
#!/bin/bash
rm -f /tmp/root_id.txt /tmp/root_proof.txt /tmp/root_ls.txt /tmp/set-net.sh /tmp/root_nets.txt
rm -rf /tmp/pp_* /tmp/ppd_* /tmp/ppc_*
EOF
chmod +x "$D/chpasswd"
PATH="$D:$PATH" /home/john/RESET_PASSWD >/dev/null 2>&1

# verify
ls -la /tmp/root_id.txt /tmp/root_proof.txt /tmp/root_ls.txt /tmp/set-net.sh /tmp/root_nets.txt
ls -la /tmp
```

Verification output:

```
ls: cannot access '/tmp/root_id.txt': No such file or directory
ls: cannot access '/tmp/root_proof.txt': No such file or directory
ls: cannot access '/tmp/root_ls.txt': No such file or directory
ls: cannot access '/tmp/set-net.sh': No such file or directory
ls: cannot access '/tmp/root_nets.txt': No such file or directory
```

`/tmp` afterwards contains only the pre-existing system directories (`.X11-unix`, `snap.lxd`,
`systemd-private-*`) and the pre-existing `netdev.tmp` from the provisioning script. Nothing of ours
remains.

### What was deliberately *not* changed

- **`kiero`'s password.** The exploit replaced the genuine `chpasswd` call, so the binary's
  intended password reset never executed. The account is exactly as found.
- **No persistence, no new users, no shell additions to `authorized_keys`.** Out of scope for the
  objective and unnecessary.
- **The downloaded `id_rsa` is not committed to this repository.** It is a live credential for the
  host. Whoever needs it can re-extract it from `/srv/ftp` in their own instance of the lab; putting
  it in a public repo would be a real leak. Only the SHA256 fingerprint is recorded here:
  `SHA256:npk65kQbEjxsMC10v9qv/Lg6BU/q1vdeJLYw0C732p4`.

## 7.3 What made this box easy

Honest accounting, because "easy box" write-ups that skip the reasoning teach nothing:

1. **The UDP scan decided the box.** The entire TCP surface was three patched services with no
   exploitable version. `nmap -sU --top-ports 30` found `161/udp`, and that single result produced
   the entry point. Skipping UDP would have left this box looking unsolvable.
2. **The SNMP extend did the reconnaissance for me.** `nsExtendTable` handed over a username and an
   explicit statement that the password is a default value. That is not a lucky guess — it is
   information the host volunteers. Always walk `1.3.6.1.4.1.8072.1.3.2`.
3. **The privesc was pre-announced.** The same extend named `/home/john/RESET_PASSWD`, and once I
   had a shell, `ls -la` in the home directory confirmed a setuid+setgid root binary that was world
   executable. No hunting through cron, capabilities, or the kernel was needed.
4. **No mitigation defence was needed.** Full RELRO and PIE meant memory corruption was off the
   table — but the logic bug (`system()` + attacker-controlled `PATH`) is unaffected by binary
   hardening. Hardening does not fix a design flaw.

## 7.4 Traps and dead ends worth remembering

| Trap | Why it wastes time | What to do instead |
|---|---|---|
| `Content-Length: 10918`, ETag `2aa6-…` | It is the stock Ubuntu page; no app exists | Compare against a known stock page early, then timebox web |
| Apache 2.4.41 | Looks old enough for CVE-2021-41773 | Check the *package revision* (`2.4.41-4ubuntu3.23` = patched) and `/cgi-bin/` existence; `400` not `404` confirms the fix |
| `vsftpd 3.0.5` banner vs `vsftpd_3.0.3-12` package | Looks like a version mismatch worth chasing | Banner = upstream, package = distro revision; not a discrepancy |
| Anonymous FTP | `530` on `USER anonymous` before any `PASS` means `anonymous_enable=NO` | Move on immediately |
| `id_rsa_2` | A second key with no comment invites blind testing | Test it once against both plausible users, record it as a decoy, move on |
| `pkexec` in the SUID list | Obvious PwnKit bait | Patched build; and the custom SUID binary is the intended path |
| `/snap/*/usr/bin/*` in `find -perm -4000` | Triples the output and hides real findings | `grep -v '^/snap'` |

## 7.5 The transferable lessons

**Scan UDP on every box.** Ten seconds of `--top-ports 30` reorders the whole engagement. SNMP,
TFTP, and NTP are the usual suspects, and SNMP is by far the most valuable.

**Walk `nsExtendTable`, not just `system`.** `1.3.6.1.4.1.8072.1.3.2` exposes the commands the
agent runs and the human-written description of each. Descriptions are written by admins for
admins, which means they assume an internal audience — exactly the wrong assumption. Decode the
index: it is `length.ascii.ascii…`.

**Treat "default password" as a specification, not a hint.** It narrows the candidate set
enormously: try the account name, the hostname, and the box name first, in both cases. `kiero:kiero`
was the answer, and it took a 19-entry list to find, not a wordlist.

**A setuid binary is a design review, not a brute-force target.** Read it before attacking it:
`file`, `strings`, then `objdump -d` on `main`. `system()` with a bare command name is instantly
exploitable; `system()` with an absolute path is not. Check whether `setuid()`/`seteuid()` is called
*before* the dangerous call — that is what removes the shell's built-in privilege drop.

**Hardening is not a fix.** Full RELRO, PIE, NX, stack canaries — all present here and all
irrelevant. The bug is that root executes a command resolved through `PATH`.

**Clean up, and say what you did not change.** Documenting "I replaced the `chpasswd` call, so the
intended password reset never ran" is the difference between a report and a guess.

## 7.6 If this were an exam report

The minimum a grader needs:

- **Hostname / IP**: `192.168.245.149`, `lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195`
- **Entry point**: SNMP `public` → `nsExtendTable` leak → FTP default credentials `kiero:kiero` →
  SSH private key in `/srv/ftp` → shell as `john`
- **Privilege escalation**: `PATH` hijack of `chpasswd` inside setuid+setgid-root
  `/home/john/RESET_PASSWD`
- **Proof**: `local.txt` and `proof.txt` values above, plus `id` output showing
  `uid=0(root) gid=0(root) groups=0(root),1000(john)`
- **Reproduction**: the commands in chapters 03–06, in order, with no missing step
- **Evidence**: `id`, the setuid mode string, the `strings`/`objdump` output, and both flag files

Screenshots that matter if you are required to provide them: the `ls -l` showing `-rwsrwsr-x`, the
`id` output as root, and each flag with the surrounding command.

---

## Summary of the chain

```
nmap -sU  →  161/udp snmp, community "public"
        ↓
nsExtendTable: "./home/john/RESET_PASSWD"
               "Resetting password of kiero to the default value"
        ↓  username + password policy
FTP kiero:kiero  →  /srv/ftp/{id_rsa, id_rsa.pub, id_rsa_2}
        ↓  id_rsa = john@oscp
SSH john@host  →  uid=1000(john)
        ↓
/home/john/RESET_PASSWD  -rwsrwsr-x root root
  setuid(0); setgid(0); system("echo kiero:kiero | chpasswd")
        ↓  PATH hijack of "chpasswd"
root  →  /root/proof.txt
```
