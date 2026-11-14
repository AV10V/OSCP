# OSCP Lab Walkthroughs

Step-by-step documentation of my OSCP lab machines: every command as executed, why it was
chosen, the raw output, and what it told me. Written as I work, not retrofitted afterwards.

> **Scope note** — everything here was performed against my own authorized lab environment
> (an isolated OSCP-style subnet). Hosts are ephemeral and are rebuilt between attempts.
> Flags and IPs are lab-specific and have no value outside it. Credentials that would be
> reusable outside the lab (SSH private keys) are deliberately **not** committed.

---

## Lab map

Subnet `192.168.245.0/24`, attacker box Kali at `192.168.45.158` (VPN `tun0`).

| Host | Identity | Status | Walkthrough |
|---|---|---|---|
| `192.168.245.147` | Windows Server 2019 / Win10 build 19041, `MS01.oscp.exam` | owned (SYSTEM) — separate engagement | — |
| **`192.168.245.149`** | **Ubuntu 20.04.5, `kiero`** | **owned (root), both flags** | **[→ walkthrough](machines/192.168.245.149-kiero/README.md)** |
| `192.168.245.150` | Linux, SSH + 8080 | not started | — |
| `192.168.245.151` | Windows, 80 + RDP (heavily filtered) | not started | — |
| `192.168.245.254` | gateway | infrastructure | — |

Live-host discovery command for reference:

```bash
nmap -sn 192.168.245.0/24 -oG - | grep -i up | awk '{print $2}'
```

---

## Completed machines

### 192.168.245.149 — `kiero` (Ubuntu 20.04.5)

**Root via a setuid helper that calls `system()` with an unqualified binary name.**

| | |
|---|---|
| Entry point | unauthenticated SNMP (`public`) → hints at a default password → FTP with default creds → SSH key → shell |
| Privilege escalation | `PATH` hijack of `chpasswd` inside the setuid-root `/home/john/RESET_PASSWD` |
| `local.txt` | `af540ac8ffa61d312756f2f4a3877d1d` |
| `proof.txt` | `9e7f4ce50acc525d577abfc26aebfd1e` |

Chapters:

1. [Reconnaissance — port scan and service fingerprint](machines/192.168.245.149-kiero/01-reconnaissance.md)
2. [Web enumeration — and why it was a dead end](machines/192.168.245.149-kiero/02-web-enumeration.md)
3. [SNMP — the leak nobody scans for](machines/192.168.245.149-kiero/03-snmp.md)
4. [FTP — default credentials and exposed SSH keys](machines/192.168.245.149-kiero/04-ftp.md)
5. [Foothold — SSH as `john`](machines/192.168.245.149-kiero/05-foothold.md)
6. [Privilege escalation — setuid `RESET_PASSWD` PATH hijack](machines/192.168.245.149-kiero/06-privilege-escalation.md)
7. [Flags, cleanup and lessons](machines/192.168.245.149-kiero/07-flags-and-cleanup.md)

---

## Reference

- [Methodology checklist](docs/methodology.md) — the repeatable loop I run on every box
- [Command cheat sheet](docs/cheatsheet.md) — the commands I actually reuse

---

## Repo layout

```
OSCP/
├── README.md                     # this file
├── docs/
│   ├── methodology.md
│   └── cheatsheet.md
└── machines/
    └── 192.168.245.149-kiero/
        ├── README.md             # summary + TL;DR chain
        ├── 01-reconnaissance.md
        ├── 02-web-enumeration.md
        ├── 03-snmp.md
        ├── 04-ftp.md
        ├── 05-foothold.md
        ├── 06-privilege-escalation.md
        ├── 07-flags-and-cleanup.md
        └── evidence/
            ├── evidence_foothold.txt
            └── evidence_privesc.txt
```
