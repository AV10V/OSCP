# 07 — Cleanup and lessons

Goal: put the service back exactly as it was, remove the accounts and artefacts this box was made to
leave behind, and record what actually found the way in.

---

## 7.1 Restore the service — order is not optional

`GPGOrchestrator` currently points at a `reg add` command line, and (if the binary route was used) the
executable in `Program Files` is a payload. The hijacked service **cannot** start, so restore the
binary first, then the configuration, then start:

```cmd
copy /y "C:\Users\Tim\AppData\Local\Temp\GPGService.exe.bak" "C:\Program Files\MilleGPG5\GPGService.exe"
sc.exe config GPGOrchestrator binPath= "\"C:\Program Files\MilleGPG5\GPGService.exe\""
sc.exe start GPGOrchestrator
sc.exe query GPGOrchestrator
```

```
SERVICE_NAME: GPGOrchestrator
        STATE              : 4  RUNNING
```

If it still returns 1053, check `Get-MpThreatDetection`: Defender may have quarantined the payload
that was copied over the legitimate binary, in which case re-copy the backup and start again.

## 7.2 Revert the changes made for access

```cmd
sc.exe config GPGOrchestrator binPath= "cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f"
sc.exe start GPGOrchestrator

net user hacker /delete
del C:\Users\Tim\AppData\Local\Temp\Seatbelt.exe C:\Users\Tim\AppData\Local\Temp\PowerUp.ps1
del C:\Users\Tim\AppData\Local\Temp\proof.txt
```

Then point `binPath` back one last time and confirm the service is on the real binary:

```cmd
sc.exe config GPGOrchestrator binPath= "\"C:\Program Files\MilleGPG5\GPGService.exe\""
sc.exe qc GPGOrchestrator
```

| Artefact | Where | Removed by |
|---|---|---|
| `hacker` local admin | SAM | `net user hacker /delete` |
| `LocalAccountTokenFilterPolicy=1` | HKLM Policies\System | `/d 0` via the service |
| hijacked `binPath` | service config | `sc config binPath=` |
| overwritten `GPGService.exe` | `Program Files\MilleGPG5` | `copy /y` from the `.bak` |
| Seatbelt / PowerUp | `%TEMP%` | `del` |
| proof copy | `%TEMP%` | `del` |

## 7.3 What found what

The question worth answering for the next box is not "what was the CVE" but "which command put me in
front of it":

| Discovery | Command that produced it |
|---|---|
| 9099 open at all | `nmap -Pn -n -p- --min-rate 2000` |
| 9099 = **Mobile Mouse Server** | `nmap -sV` → `fingerprint-strings`; `curl -i :9099` |
| version **3.6.4** | Seatbelt `InstalledProducts` |
| exploit exists | `searchsploit mobile mouse`, `msf> search mobile_mouse_rce` |
| shell as `Tim` | `exploit/windows/misc/mobile_mouse_rce` |
| not admin, medium IL | Seatbelt `OSInfo`, `whoami /groups` |
| no `SeImpersonate` → potatoes out | Seatbelt `TokenPrivileges` |
| **SYSTEM service with writable binary** | PowerUp **`Get-ModifiableServiceFile`** (`CanRestart: True`) |
| same service, weak object ACL | Seatbelt `Services` → `ServiceSDDL` |
| `Users:(M)` confirmed | `icacls "C:\Program Files\MilleGPG5\GPGService.exe"` |
| `DC/RP/DT` for Users confirmed | `sc.exe sdshow GPGOrchestrator` |
| SYSTEM command execution | `sc.exe config ... binPath=` + `sc.exe start` |
| flag | `type proof.txt` through the service |
| usable admin session | `LocalAccountTokenFilterPolicy=1` + `evil-winrm -S -P 5986` |

## 7.4 Lessons

- **A version number beats a port number.** `9099` was `unknown` to nmap, but the version probe still
  captured the banner that named the product. Never discard a port because the service DB has no
  entry for it.
- **Read your own token first.** `TokenPrivileges` in Seatbelt retired the potato family in one
  glance. Skipping it means trying five exploits that cannot work.
- **`CanRestart` is the discriminator.** A writable service binary you cannot restart is a
  file-upload problem; with restart rights it is SYSTEM. Read that flag before planning.
- **Service ACLs are a second, quieter door.** `DC` + `RP` for `BUILTIN\Users` allows repointing
  `binPath` with nothing written to disk — no payload for antivirus to inspect, no backup to restore.
- **1053 means "your process is not a service".** For a one-shot `cmd.exe` that is success. Verify by
  effect, not by exit code.
- **Know which shell you are in.** Single quotes under `cmd.exe` silently produce a usage banner and
  no change — and a later `sc start` then re-runs the previous command line.
- **Admin is not a usable admin.** Local admin accounts other than RID 500 are filtered over the
  network until `LocalAccountTokenFilterPolicy` is set. That is why WinRM said "access denied" to a
  password that was correct.
- **Inherited ACLs are systemic.** `BUILTIN\Users:(I)(M)` on an installer's service binary is not a
  one-off misconfiguration on this host — it is what that installer ships to every deployment.
