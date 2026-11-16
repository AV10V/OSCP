# OSCP Lab Walkthroughs

**▶ Interactive version: <https://av10v.github.io/OSCP/>** — same content as a single-page site with
collapsible sections, copy-to-clipboard commands, chapter progress and search. Built from the
markdown in this repo by [`build.py`](build.py); regenerate with `python3 build.py`.

Step-by-step documentation of my OSCP lab machines: every command as executed, why it was
chosen, the raw output, and what it told me. Written as I work, not retrofitted afterwards.

> **Scope note** — everything here was performed against my own authorized lab environment
> (an isolated OSCP-style subnet). Hosts are ephemeral and are rebuilt between attempts.
> Flags and IPs are lab-specific and have no value outside it. Credentials that would be
> reusable outside the lab (SSH private keys) are deliberately **not** committed.

---

## Lab map

Subnets `192.168.245.0/24` and `192.168.237.0/24`, attacker box Kali at `192.168.45.158` (VPN `tun0`).

| Host | Identity | Status | Walkthrough |
|---|---|---|---|
| `192.168.245.147` | Windows Server 2019 / Win10 build 19041, `MS01.oscp.exam` | owned (SYSTEM) — separate engagement | — |
| **`192.168.245.149`** | **Ubuntu 20.04.5, `kiero`** | **owned (root), both flags** | **[→ walkthrough](machines/192.168.245.149-kiero/README.md)** |
| **`192.168.237.150`** | **Ubuntu 22.04.1, `text4shell`** | **owned (root), both flags** | **[→ walkthrough](machines/192.168.237.150-text4shell/README.md)** |
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

### 192.168.237.150 — `text4shell` (Ubuntu 22.04.1)

**Root via a blind Commons Text RCE, then an unauthenticated JDWP agent on a root JVM.**

| | |
|---|---|
| Entry point | `GET /search?query=` interpolated by Commons Text **1.8** — CVE-2022-42889 |
| Blind | the response echoes the raw parameter and always returns `result: ""`, so the bug was proved with an SSRF callback and a timing oracle |
| Foothold | `${script:javascript:…ProcessBuilder…}` → reverse shell as `dev` (uid 1001) |
| Privilege escalation | `-Xdebug -Xrunjdwp:…:8000` on a **root** JVM → JDI breakpoint on `String.getBytes` → `Runtime.exec` |
| `local.txt` | `6851d85c0e1e82991b98fa6e146532fd` |
| `proof.txt` | `43d31153587be5031d1db3f9a934eb46` |

Chapters:

1. [Reconnaissance — three ports, one input surface](machines/192.168.237.150-text4shell/01-reconnaissance.md)
2. [Web enumeration — one route, one parameter, no feedback](machines/192.168.237.150-text4shell/02-web-enumeration.md)
3. [Text4Shell — CVE-2022-42889, proved blind](machines/192.168.237.150-text4shell/03-text4shell.md)
4. [Foothold — shell as `dev` via `ProcessBuilder`](machines/192.168.237.150-text4shell/04-foothold.md)
5. [Host enumeration — the root JVM on port 8000](machines/192.168.237.150-text4shell/05-enumeration.md)
6. [Privilege escalation — JDWP breakpoint → root](machines/192.168.237.150-text4shell/06-privilege-escalation.md)
7. [Flags, cleanup and lessons](machines/192.168.237.150-text4shell/07-flags-and-cleanup.md)

---

## Reference

### Rebuilding the site

```bash
pip install markdown pygments      # only dependencies
python3 build.py                   # writes one page per machine
```

Each entry in `MACHINES` (top of `build.py`) renders its markdown into a self-contained page:
`index.html` for the root box, and `machines/<dir>/index.html` for the rest. The generated HTML is
committed, so GitHub Pages needs no build step. Edit the markdown, not the HTML.

### Reference

- [Methodology checklist](docs/methodology.md) — the repeatable loop I run on every box
- [Command cheat sheet](docs/cheatsheet.md) — the commands I actually reuse

---

## Repo layout

```
OSCP/
├── README.md                     # this file
├── index.html                    # interactive site for the root box (generated)
├── build.py                      # markdown -> one page per machine
├── docs/
│   ├── methodology.md
│   └── cheatsheet.md
└── machines/
    ├── 192.168.245.149-kiero/
    │   ├── README.md             # summary + TL;DR chain
    │   ├── 01-reconnaissance.md
    │   ├── 02-web-enumeration.md
    │   ├── 03-snmp.md
    │   ├── 04-ftp.md
    │   ├── 05-foothold.md
    │   ├── 06-privilege-escalation.md
    │   ├── 07-flags-and-cleanup.md
    │   └── evidence/
    │       ├── evidence_foothold.txt
    │       └── evidence_privesc.txt
    └── 192.168.237.150-text4shell/
        ├── README.md
        ├── 01-reconnaissance.md
        ├── 02-web-enumeration.md
        ├── 03-text4shell.md
        ├── 04-foothold.md
        ├── 05-enumeration.md
        ├── 06-privilege-escalation.md
        ├── 07-flags-and-cleanup.md
        ├── index.html            # this machine's interactive page (generated)
        ├── evidence/             # raw command output
        └── tools/                # JdiBreakExec.java, JdiVmSuspend.java, t4s_probe.py, cap_server.py
```
