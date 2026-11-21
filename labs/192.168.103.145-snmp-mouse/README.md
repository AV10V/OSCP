# 192.168.103.145 — `snmp-mouse` (Windows 10 2004)

| | |
|---|---|
| **Hostname** | `zachary` (SNMP `sysName` / `sysContact`); computer name reported by Windows: `OSCP` |
| **OS** | Windows 10 version 2004, build **19041** (`sysDescr` reports kernel 6.3) |
| **Open ports** | `161/udp` SNMP (v1, community `public`) · `1978/tcp` Mouse Server · `3389/tcp` RDP |
| **Difficulty** | Easy–medium — one CVE for the foothold, one for the escalation |
| **Result** | local admin `adm1n` → RDP → `proof.txt` |
| **Flags** | `local.txt` — not pursued (the foothold was already interactive) · `proof.txt` — see chapter 07 |

---

## TL;DR — the chain

```
UDP/161 snmpd, community "public"
  └─ hrSWInstalledTable → "Mouse Server version 1.7.8.5"
     hrSWRunTable      → MouseServer.exe + explorer.exe + dwm.exe + sihost.exe
        │  ⇒ vulnerable remote-control server AND an interactive desktop session
        ▼
TCP/1978  WiFi Mouse Server 1.7.8.5 — CVE-2022-3218
  └─ authentication is enforced by the *client*, not the server
     openfile /C/Windows/System32/cmd.exe
     utf8 <command>
     key  3RTN
        ▼
shell as OSCP\offsec  (standard user, no SeImpersonate)
  └─ getsystem → "Operation failed: 1346"
        ▼
PrintNightmare — CVE-2021-1675 / CVE-2021-34527
  └─ Invoke-Nightmare → creates local admin adm1n:P@ssw0rd
        ▼
xfreerdp /u:adm1n → proof.txt
```

Three things make this box teach something:

1. **The TCP scan came back entirely filtered.** Every port the first scan asked for was `filtered`,
   so the box looked dead. It was not dead — UDP/161 answered. A filtered TCP scan is a statement
   about the firewall, not about the host.
2. **SNMP told us the exploit *and* its precondition.** `hrSWInstalledName` named the vulnerable
   package; `hrSWRunName` proved a desktop session was live. That second fact is what makes a
   keystroke-injection exploit viable, and it is invisible to a port scan.
3. **The first escalation attempt could never have worked.** `getsystem` failed with 1346 because
   `offsec` has no `SeImpersonatePrivilege`. Every potato variant needs that privilege; the fix was
   to change primitive, not to change tooling.

---

## Chapters

| # | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | the all-filtered TCP scan, why it lies, finding UDP/161 |
| 02 | [SNMP enumeration](02-snmp-enumeration.md) | community, `sysGroup`, processes, software, the 8072 dead end |
| 03 | [Vulnerability analysis](03-vulnerability-analysis.md) | CVE-2022-3218 and the interactive-session precondition |
| 04 | [Foothold](04-foothold.md) | Metasploit `wifi_mouse_rce`, shell as `offsec`, the 50972 route |
| 05 | [Enumeration & dead ends](05-enumeration.md) | `getsystem` 1346, why potatoes fail, what was ruled out |
| 06 | [Privilege escalation](06-privilege-escalation.md) | PrintNightmare from a standard user |
| 07 | [Flags & cleanup](07-flags-and-cleanup.md) | RDP, proof, removing the account you created |

---

## Timeline

| Time | Action | Result |
|---|---|---|
| 18:37 | `nmap -Pn -sV -O --script=vuln*` on 21,80,135,139,161,445,1978,3389,5986,7680 | **every port `filtered`** |
| — | `snmpwalk` with no `-v` | `Timeout` — net-snmp defaulted to SNMPv3 |
| — | `snmpwalk -v1 -c public` | host fingerprint: Windows build 19041, `zachary` |
| — | community guessing (9 words) | all silent; `public` was already the answer |
| — | `snmpwalk … 1.3.6.1.4.1.8072.1.3.2` | `End of MIB` — net-snmp tree, not present on Windows |
| — | `hrSWRunTable` + `hrSWInstalledTable` | `MouseServer.exe`, `explorer.exe`, `Mouse Server 1.7.8.5` |
| — | re-scan after lab refresh | **1978/tcp open** |
| 02:0x | `msfconsole` → `wifi_mouse_rce` | shell as `OSCP\offsec` |
| 02:07 | `sessions -u` → meterpreter | session 14 |
| 02:0x | `getsystem` | `Operation failed: 1346` |
| 02:1x | `Invoke-Nightmare` | local admin `adm1n:P@ssw0rd` |
| 02:2x | `xfreerdp /u:adm1n` | desktop → `proof.txt` |

---

## Files

- `evidence/` — curated excerpts the writeup is built from (SNMP walks, MSF session, PrintNightmare
  transcript). Raw scan dumps stay local per `.gitignore`; the chapters quote them inline.
- `tools/mouseserver_poc.py` — the no-Metasploit route: `openfile` / `utf8` / `key 3RTN` with a
  `--check` mode and `--dry-run`.
- Each chapter keeps the exact commands and the output as it came back, including the failures.
