# 192.168.245.149 — `kiero` (Ubuntu 20.04.5)

| | |
|---|---|
| **Hostname** | `lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195` |
| **OS** | Ubuntu 20.04.5 LTS, kernel `5.9.0-050900-generic` |
| **Open ports** | `21/tcp` vsftpd 3.0.5 · `22/tcp` OpenSSH 8.2p1 · `80/tcp` Apache 2.4.41 · `161/udp` snmpd |
| **Difficulty** | Easy — the intended path, no exploit code needed |
| **Result** | root, `local.txt` and `proof.txt` |
| **Flags** | `af540ac8ffa61d312756f2f4a3877d1d` (user) · `9e7f4ce50acc525d577abfc26aebfd1e` (root) |

---

## TL;DR — the chain

```
UDP/161 snmpd with community "public"
  └─ extend "RESET" → "./home/john/RESET_PASSWD"
     description: "Resetting password of kiero to the default value"
        │  → tells us the username (kiero) and that its password is a default
        ▼
FTP  kiero:kiero  (account name = password)
  └─ directory contains id_rsa, id_rsa.pub, id_rsa_2
     id_rsa → john@oscp
        ▼
SSH  john@192.168.245.149  using the downloaded key
  └─ uid=1000(john), no sudo rights
        │
        ▼
/home/john/RESET_PASSWD — setuid AND setgid root, world-executable
  └─ strings: setuid, system, "echo kiero:kiero | chpasswd"
     setuid(0) happens BEFORE system(), so PATH is still attacker-controlled
        ▼
PATH=/tmp/pp:$PATH /home/john/RESET_PASSWD   →  uid=0(root)
```

Two independent mistakes compound here:

1. **The host advertises its own weak credential.** SNMP `public` doesn't just leak sysDescr — it
   leaks a custom extend whose *description string* names the account and states the password is
   reset to a default value. That turns "try defaults" from a guessing game into a directed step.
2. **A setuid-root binary uses `system()` with an unqualified command name.** `chpasswd` is
   resolved through the caller's `PATH`, so any local user controls which binary executes — with
   full root, because `setuid(0)` already ran.

---

## Chapters

| # | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | `ping`, full TCP scan, `-sV -sC`, UDP sweep that found SNMP |
| 02 | [Web enumeration](02-web-enumeration.md) | feroxbuster, nikto, vhost fuzzing, CVE-2021-41773 — all negative, and why that mattered |
| 03 | [SNMP](03-snmp.md) | community brute force, `snmpwalk`, the `nsExtendTable` leak |
| 04 | [FTP](04-ftp.md) | anonymous denied, default creds, key material in the data directory |
| 05 | [Foothold](05-foothold.md) | using `id_rsa`, first shell, local enumeration |
| 06 | [Privilege escalation](06-privilege-escalation.md) | binary analysis, PATH hijack, root |
| 07 | [Flags and cleanup](07-flags-and-cleanup.md) | proof capture, removing artifacts, lessons |

---

## Timeline

| Time | Action | Result |
|---|---|---|
| 18:07 | `nmap -p-` | 21, 22, 80 |
| 18:07 | `nmap -sV -sC` | vsftpd 3.0.5, OpenSSH 8.2p1, Apache 2.4.41 |
| 18:08 | anonymous FTP | `530 Permission denied` |
| 18:09 | feroxbuster + nikto + vhosts | nothing |
| 18:12 | `nmap -sU --top-ports 30` | **161/udp open** |
| 18:19 | `snmpwalk -c public` | hostname + extend leak |
| 18:25 | `hydra` FTP | `kiero:kiero` |
| 18:25 | FTP listing + key download | `id_rsa` (john@oscp) |
| 18:26 | SSH as john | `uid=1000(john)` |
| 18:27 | SUID analysis + PATH hijack | `uid=0(root)` |
| 18:27 | flags | both captured |
| 23:28 | cleanup | artifacts removed, verified |

Roughly 20 minutes of wall-clock time, of which most was waiting on the full TCP scan. The
UDP scan is what broke the box open — the TCP surface alone was three well-patched services.
