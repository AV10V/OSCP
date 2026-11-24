# OSCP Lab Walkthroughs

**▶ Live site: <https://av10v.github.io/OSCP/>** — [`main.html`](main.html) is the lab index:
pick a lab from the dropdown or a card and it opens that lab's walkthrough. Every lab has its own
self-contained page under [`labs/`](labs/) with collapsible sections, copy-to-clipboard commands,
chapter progress and search. Built from the markdown in this repo by [`build.py`](build.py);
regenerate with `python3 build.py`. The root `index.html` is a one-line redirect to `main.html` so
the GitHub Pages URL keeps working. You can also open `main.html` from a local clone.

Step-by-step documentation of my OSCP lab machines: every command as executed, why it was
chosen, the raw output, and what it told me. Written as I work, not retrofitted afterwards.

> **Scope note** — everything here was performed against my own authorized lab environment
> (an isolated OSCP-style subnet). Hosts are ephemeral and are rebuilt between attempts.
> Flags and IPs are lab-specific and have no value outside it. Credentials that would be
> reusable outside the lab (SSH private keys) are deliberately **not** committed.

---

## Lab map

Subnets `192.168.245.0/24`, `192.168.237.0/24`, `192.168.118.0/24`, `192.168.137.0/24` and `192.168.161.0/24`, attacker box Kali at `192.168.45.158` (VPN `tun0`).

| Host | Identity | Status | Walkthrough |
|---|---|---|---|
| `192.168.245.147` | Windows Server 2019 / Win10 build 19041, `MS01.oscp.exam` | owned (SYSTEM) — separate engagement | — |
| **`192.168.118.147`** | **AD set `oscp.exam` — MS01, dual-homed into `10.10.118.0/24`** | **MS01 owned (SYSTEM); MS02 / DC01 pending** | **[→ walkthrough](labs/ad-oscp-exam/README.md)** |
| **`192.168.245.149`** | **Ubuntu 20.04.5, `kiero`** | **owned (root), both flags** | **[→ walkthrough](labs/192.168.245.149-kiero/README.md)** |
| **`192.168.237.150`** | **Ubuntu 22.04.1, `text4shell`** | **owned (root), both flags** | **[→ walkthrough](labs/192.168.237.150-text4shell/README.md)** |
| **`192.168.137.151`** | **Windows 10 21H2, `gust` (host `OSCP`)** | **owned (SYSTEM), both flags** | **[→ walkthrough](labs/192.168.137.151-gust/README.md)** |
| **`192.168.103.145`** | **Windows, `snmp-mouse` — SNMP → Mouse Server → PrintNightmare** | **owned (SYSTEM), both flags** | **[→ walkthrough](labs/192.168.103.145-snmp-mouse/README.md)** |
| **`192.168.161.144`** | **Ubuntu 22.04.1, `git-exposure`** | **owned (root), both flags** | **[→ walkthrough](labs/192.168.161.144-git-exposure/README.md)** |
| **`192.168.150.143`** | **Ubuntu 20.04.4, `aerospike-screen`** | **owned (root), both flags** | **[→ walkthrough](labs/192.168.150.143-aerospike-screen/README.md)** |
| **`192.168.161.156`** | **Ubuntu 18.04, `vesta` — SNMP extend leak → VestaCP 0.9.8-27 → root** | **owned (root), both flags** | **[→ walkthrough](labs/192.168.161.156-vesta-snmp/README.md)** |
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

1. [Reconnaissance — port scan and service fingerprint](labs/192.168.245.149-kiero/01-reconnaissance.md)
2. [Web enumeration — and why it was a dead end](labs/192.168.245.149-kiero/02-web-enumeration.md)
3. [SNMP — the leak nobody scans for](labs/192.168.245.149-kiero/03-snmp.md)
4. [FTP — default credentials and exposed SSH keys](labs/192.168.245.149-kiero/04-ftp.md)
5. [Foothold — SSH as `john`](labs/192.168.245.149-kiero/05-foothold.md)
6. [Privilege escalation — setuid `RESET_PASSWD` PATH hijack](labs/192.168.245.149-kiero/06-privilege-escalation.md)
7. [Flags, cleanup and lessons](labs/192.168.245.149-kiero/07-flags-and-cleanup.md)

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

1. [Reconnaissance — three ports, one input surface](labs/192.168.237.150-text4shell/01-reconnaissance.md)
2. [Web enumeration — one route, one parameter, no feedback](labs/192.168.237.150-text4shell/02-web-enumeration.md)
3. [Text4Shell — CVE-2022-42889, proved blind](labs/192.168.237.150-text4shell/03-text4shell.md)
4. [Foothold — shell as `dev` via `ProcessBuilder`](labs/192.168.237.150-text4shell/04-foothold.md)
5. [Host enumeration — the root JVM on port 8000](labs/192.168.237.150-text4shell/05-enumeration.md)
6. [Privilege escalation — JDWP breakpoint → root](labs/192.168.237.150-text4shell/06-privilege-escalation.md)
7. [Flags, cleanup and lessons](labs/192.168.237.150-text4shell/07-flags-and-cleanup.md)

### `oscp.exam` — AD set (MS01 → MS02 → DC01)

**A domain behind one dual-homed member server; `SeImpersonate` on a plain domain user is the whole
way in.**

| | |
|---|---|
| Entry point | `OSCP\eric.wallows` over WinRM (`5985`) — valid, **not** a local admin |
| Privilege escalation | `SeImpersonatePrivilege` → PrintSpoofer → `nt authority\system` |
| Credentials | LSASS on MS01, read as SYSTEM — **no Domain Admin material** |
| Pivot | chisel reverse SOCKS (`R:socks` → `127.0.0.1:1080`) into `10.10.118.0/24` |
| MS01 flags | none issued — verified: no `local.txt` / `proof.txt` under `C:\Users` |
| DC01 `proof.txt` | *pending capture* |

Chapters:

1. [Reconnaissance — one routable host, two networks](labs/ad-oscp-exam/01-reconnaissance.md)
2. [Foothold — WinRM as `eric.wallows`](labs/ad-oscp-exam/02-foothold.md)
3. [Privilege escalation — `SeImpersonate` → SYSTEM](labs/ad-oscp-exam/03-privilege-escalation.md)
4. [Credentials — what LSASS would and would not give](labs/ad-oscp-exam/04-credentials.md)
5. [Pivot — chisel into `10.10.118.0/24`](labs/ad-oscp-exam/05-pivot.md)
6. [MS02 — the second hop](labs/ad-oscp-exam/06-ms02.md) *(placeholder)*
7. [DC01 — domain admin and the flag](labs/ad-oscp-exam/07-dc01.md) *(placeholder)*

### 192.168.137.151 — `gust` (Windows 10 21H2)

**SYSTEM via the FreeSWITCH event socket on its default password, then a service account holding
`SeImpersonatePrivilege`.**

| | |
|---|---|
| Entry point | `8021/tcp` FreeSWITCH `mod_event_socket` (ESL) — `auth ClueCon` accepts the shipped default password, and no inbound ACL is configured |
| Primitive | `api system <cmd>` → command execution as `OSCP\chris`, an `NT AUTHORITY\SERVICE` logon at high integrity |
| Interface quirk | only stdout is captured, returned as `-ERR no reply` when a command prints nothing — so stderr and exit status are invisible |
| Privilege escalation | `SeImpersonatePrivilege` enabled → **GodPotato-NET4** → RPCSS SYSTEM token → `cmd.exe` as SYSTEM |
| Why the obvious payloads failed | a `.bat`, a nested `cmd /c` and a PowerShell script all failed as GodPotato children; `nc64.exe -e cmd.exe` worked first try |
| Independent SYSTEM proof | `reg query HKLM\SECURITY\Policy\PolAdtEv` succeeds as SYSTEM and returns `Access is denied` for `chris` |
| `local.txt` | `9d05eefc0447258ceab32e91e3b54aac` |
| `proof.txt` | `46586fc8f483adc13d76335768bf0a4c` |

Chapters:

1. [Reconnaissance — thirteen ports, one product](labs/192.168.137.151-gust/01-reconnaissance.md)
2. [The event socket — default password on a control interface](labs/192.168.137.151-gust/02-esl.md)
3. [Foothold — command execution as `chris`](labs/192.168.137.151-gust/03-foothold.md)
4. [Enumeration — one `whoami /all` decides the box](labs/192.168.137.151-gust/04-enumeration.md)
5. [Privilege escalation — GodPotato, and four ways it failed first](labs/192.168.137.151-gust/05-privilege-escalation.md)
6. [Flags — both values, with the account that read them](labs/192.168.137.151-gust/06-flags.md)
7. [Cleanup and lessons](labs/192.168.137.151-gust/07-cleanup-and-lessons.md)

### 192.168.150.143 — `aerospike-screen` (Ubuntu 20.04.4)

**Unauthenticated Aerospike on its default port, then a setuid `screen` from 2017 that the package
database insisted was patched.**

| | |
|---|---|
| Entry point | `3000/tcp` Aerospike CE `5.1.0.1` — no authentication, no TLS, no ACL |
| Primitive | `udf_put` a Lua module that calls `io.popen`, then `client.apply()` → command execution as `aero` |
| Tool trap | Exploit-DB `49067.py` treats `5.1.0.0` as fixed and bails; the real fix is `5.1.0.3` — the client library works where the wrapper refuses |
| Network constraint | egress is a **destination-port allowlist**, not a dead route: `4444`/`8080`/`8834` are dropped, `22`/`53`/`80`/`443`/`3000` are permitted — a listener on `3000` gets a pty reverse shell. Binaries still move over the database socket as chunked base64 with a remote `sha256sum` |
| Privilege escalation | setuid `/usr/bin/screen-4.5.0` → **CVE-2017-5618**: `umask 000` + `-L` creates a root-owned `0666` `/etc/ld.so.preload`, which the terminal logger writes as **CRLF** and must be rewritten |
| Package-vs-binary | `dpkg -l screen` reports `4.8.0-1ubuntu0.1`; the setuid binary on `$PATH` is `4.5.0` |
| Refuted | PwnKit (`policykit-1 0.105-26ubuntu1.3`), Dirty Pipe (kernel 5.4 < 5.8) |
| `local.txt` | `8d0b2414df3c73b491d05711c000a9d6` |
| `proof.txt` | `7fd0bd2e18b52d791a6600fbd8e622b7` |

Chapters:

1. [Reconnaissance — ten ports, and why `filtered` is not `closed`](labs/192.168.150.143-aerospike-screen/01-reconnaissance.md)
2. [Web enumeration — Pico CMS under `/index/`, and a vhost that lies](labs/192.168.150.143-aerospike-screen/02-web-enumeration.md)
3. [Aerospike — naming the daemon and reading `5.1.0.1`](labs/192.168.150.143-aerospike-screen/03-aerospike.md)
4. [Foothold — Lua that runs shell, and the port allowlist that gives it a TTY](labs/192.168.150.143-aerospike-screen/04-foothold.md)
5. [Enumeration — two refutations, one unreadable cron, no compiler](labs/192.168.150.143-aerospike-screen/05-enumeration.md)
6. [Privilege escalation — setuid screen 4.5.0, CRLF and the rewrite](labs/192.168.150.143-aerospike-screen/06-privilege-escalation.md)
7. [Flags & cleanup](labs/192.168.150.143-aerospike-screen/07-flags-and-cleanup.md)

### 192.168.161.156 — `vesta` (Ubuntu 18.04, VestaCP 0.9.8-27)

**A hosting panel that publishes its own password over SNMP, then runs a customer's mailbox
forwarding address as root.**

| | |
|---|---|
| Entry point | `161/udp` snmpd, community `public` — `nsExtendConfigTable` stores an extend's **command line**, and the argument is `echo \"jack:3PUKsX98BMupBiCf\" \| chpasswd` |
| Confirmation | `nsExtendOutputFull` returns `Changing password for jack.` — the hook had already run, so the password was live |
| Panel | Vesta **0.9.8-27** (React SPA, `webpackJsonpreact-control-panel`) — every well-known panel CVE is too old |
| Foothold | `/api/v1/add/web` + `/api/v1/upload/?dir=…/public_html` → webshell as the vhost owner (`jack`), because Apache runs `mod_fcgid` |
| Privilege escalation | `v_fwd` on `/api/v1/edit/mail` → `';bash<cmdtoexec>cmdresult;A='` → `/usr/bin/sudo /usr/local/vesta/bin/v-edit-mail-account` → **root** |
| Injection class | **Second-order** — the value is legal where it is stored and only dangerous where it is used |
| Forensic tell | `pwd` in the root shell returned `/usr/local/vesta/web/api/v1/edit/mail`, the cwd of the PHP handler that fired the injection |
| False positive | `/` and `/upload/index.php` both return **2586 bytes** — the latter is a 66-byte stub that `include`s the SPA shell |
| Refuted | Remote Exim CVE-2019-10149: `550 Restricted characters in address` is Debian's stock ACL, and stock Debian ships without `local_part_suffix` |
| `local.txt` | `9cfca959e54738e70905a4024d16a44a` |
| `proof.txt` | `d4640a77ca31e0ab126751f98e819888` |

Chapters:

1. [Reconnaissance — sixteen TCP ports, and the UDP one that mattered](labs/192.168.161.156-vesta-snmp/01-reconnaissance.md)
2. [Web enumeration — two servers, one panel, one false positive](labs/192.168.161.156-vesta-snmp/02-web-enumeration.md)
3. [SNMP — the host publishes its own password](labs/192.168.161.156-vesta-snmp/03-snmp.md)
4. [Panel access — a session, and what a session is worth](labs/192.168.161.156-vesta-snmp/04-panel-access.md)
5. [Foothold — file write into a docroot as the vhost user](labs/192.168.161.156-vesta-snmp/05-foothold.md)
6. [Privilege escalation — a forwarding address that runs as root](labs/192.168.161.156-vesta-snmp/06-privilege-escalation.md)
7. [Flags & cleanup](labs/192.168.161.156-vesta-snmp/07-flags-and-cleanup.md)

---

## Reference

### Rebuilding the site

```bash
pip install markdown pygments      # only dependencies
python3 build.py                   # main.html + one page per lab
```

Each entry in `LABS` (top of `build.py`) renders its markdown into a self-contained page at
`labs/<dir>/index.html`. The root **`main.html`** is the entry point: a lab picker that redirects to
those pages, plus a card per lab; `index.html` is a redirect to it for the folder root. The generated
HTML is committed, so a clone is ready to read with no build step. Edit the markdown, not the HTML.

Adding a lab means: create `labs/<name>/` with `README.md` + numbered chapters, add one `LABS` entry
in `build.py`, then run `python3 build.py`. The build warns if a folder under `labs/` is not listed.

### Reference

- [Methodology checklist](docs/methodology.md) — the repeatable loop I run on every box
- [Command cheat sheet](docs/cheatsheet.md) — the commands I actually reuse

---

## Repo layout

```
OSCP/
├── README.md                     # this file
├── main.html                     # lab index: picker + one card per lab (generated)
├── index.html                    # redirect -> main.html (local folder root)
├── build.py                      # markdown -> main.html + one page per lab
├── docs/
│   ├── methodology.md
│   └── cheatsheet.md
└── labs/
    ├── 192.168.245.149-kiero/
    │   ├── README.md             # summary + TL;DR chain
    │   ├── 01-reconnaissance.md
    │   ├── 02-web-enumeration.md
    │   ├── 03-snmp.md
    │   ├── 04-ftp.md
    │   ├── 05-foothold.md
    │   ├── 06-privilege-escalation.md
    │   ├── 07-flags-and-cleanup.md
    │   ├── index.html            # this lab's interactive page (generated)
    │   └── evidence/
    │       ├── evidence_foothold.txt
    │       └── evidence_privesc.txt
    ├── 192.168.237.150-text4shell/
    │   ├── README.md
    │   ├── 01-reconnaissance.md
    │   ├── 02-web-enumeration.md
    │   ├── 03-text4shell.md
    │   ├── 04-foothold.md
    │   ├── 05-enumeration.md
    │   ├── 06-privilege-escalation.md
    │   ├── 07-flags-and-cleanup.md
    │   ├── index.html            # this lab's interactive page (generated)
    │   ├── evidence/             # raw command output
    │   └── tools/                # JdiBreakExec.java, JdiVmSuspend.java, t4s_probe.py, cap_server.py
    ├── ad-oscp-exam/             # MS01 -> MS02 -> DC01
    │   ├── README.md             # chain table + domain facts + flags
    │   ├── 01-reconnaissance.md
    │   ├── 02-foothold.md
    │   ├── 03-privilege-escalation.md
    │   ├── 04-credentials.md
    │   ├── 05-pivot.md
    │   ├── 06-ms02.md
    │   ├── 07-dc01.md
    │   └── index.html            # this set's interactive page (generated)
    └── 192.168.137.151-gust/     # FreeSWITCH ESL -> SYSTEM
        ├── README.md
        ├── 01-reconnaissance.md
        ├── 02-esl.md
        ├── 03-foothold.md
        ├── 04-enumeration.md
        ├── 05-privilege-escalation.md
        ├── 06-flags.md
        ├── 07-cleanup-and-lessons.md
        ├── index.html            # this lab's interactive page (generated)
        ├── evidence/             # nmap, ESL handshake, whoami /all, escalation log, shells
        └── tools/                # 1.py (ESL client)
```
