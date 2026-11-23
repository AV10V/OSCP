# 192.168.133.155 — `oscp` (Windows 10 Pro 19045.2251)

| | |
|---|---|
| **Hostname** | `oscp` (workgroup `OSCP`) |
| **OS** | Windows 10 Pro, build **19045.2251** (November 2022 patch level) |
| **Open ports** | `80/tcp` IIS · `5986/tcp` WinRM TLS · `7680/tcp` Delivery Optimization · `9099/tcp` Mobile Mouse · `9999/tcp` unknown · `35913/tcp` Mobile Mouse WebSocket |
| **Initial access** | Mobile Mouse Server 3.6.4 — **CVE-2023-31902** on TCP 9099, no authentication |
| **Foothold** | `OSCP\Tim` — standard user, medium integrity, no `SeImpersonate` |
| **Escalation** | `GPGOrchestrator` (LocalSystem) — `BUILTIN\Users:(I)(M)` on `GPGService.exe` **and** `DC/RP/DT` in the service ACL |
| **Result** | `NT AUTHORITY\SYSTEM` → local admin `hacker` → WinRM over 5986 |
| **Flags** | `proof.txt` — chapter 06 (`local.txt` was not present for this account) |

---

## TL;DR — the chain

```
TCP 9099  nmap calls it "unknown", fingerprint-strings says:
          Server: Mobile Mouse Server          ← product, not port, is the finding
            └─ Seatbelt -group=all → InstalledProducts → Mobile Mouse 3.6.4
                 ▼
          exploit/windows/misc/mobile_mouse_rce   (CVE-2023-31902, no auth)
            └─ types into the logged-on desktop → certutil → payload → shell
                 ▼
          shell as OSCP\Tim   (standard user, medium integrity)
            └─ Seatbelt TokenPrivileges: no SeImpersonate → potatoes are out
                 ▼
          PowerUp Get-ModifiableServiceFile
            └─ GPGOrchestrator · "C:\Program Files\MilleGPG5\GPGService.exe"
               ModifiableFileIdentityReference: BUILTIN\Users
               CanRestart: True                       ← this is the escalation
                 ▼
          icacls → BUILTIN\Users:(I)(M)   |   sc sdshow → BU DC RP DT WD
            └─ sc config binPath= "cmd.exe /c ..."  →  runs as LocalSystem (1053 = it ran)
                 ▼
          net user hacker /add → Administrators
            └─ LocalAccountTokenFilterPolicy=1  (no RDP here; network logons are filtered)
                 ▼
          evil-winrm -S -P 5986 → oscp\hacker → proof.txt
```

Three things make this box worth writing up:

1. **The foothold was found in the version probe of a port nmap could not name.** `9099/tcp unknown`
   is easy to walk past; the `fingerprint-strings` block underneath it says `Mobile Mouse Server`, and
   that is what turned into CVE-2023-31902.
2. **`TokenPrivileges` decided the escalation before any exploit was tried.** Five benign privileges
   and no `SeImpersonate` means the entire potato family is unavailable — the writable service is not
   the *better* option, it is the *only* one.
3. **The service object was as weak as the file.** The binary is writable (`Users:(M)`), and the
   service ACL independently grants `BUILTIN\Users` `DC`+`RP`+`DT`, so `binPath` can be repointed with
   no payload on disk at all.

## Chapters

| # | Topic | What it settles |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | six ports; the `unknown` one is the target |
| 02 | [Mobile Mouse, CVE-2023-31902](02-mobile-mouse.md) | the product, the exploit, and its real precondition |
| 03 | [Foothold](03-foothold.md) | `mobile_mouse_rce` → shell as `OSCP\Tim` |
| 04 | [Local enumeration](04-enumeration.md) | **Seatbelt** for identity, **PowerUp** for the service |
| 05 | [Privilege escalation](05-privilege-escalation.md) | `sc config binPath=`, 1053, and the quoting trap |
| 06 | [Loot and admin shell](06-loot-and-admin-shell.md) | `proof.txt`, token filtering, `evil-winrm` |
| 07 | [Cleanup and lessons](07-cleanup-and-lessons.md) | restoring the service; what found what |

Reference chapters 08 (methodology) and 09 (cheat sheet) are appended by `build.py`.

## Evidence

[`evidence/service-scan.txt`](evidence/service-scan.txt) — the port table and banner that identified
Mobile Mouse, extracted from the `-sCV` XML.
