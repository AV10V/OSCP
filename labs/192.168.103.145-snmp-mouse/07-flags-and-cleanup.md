# 07 — Flags and cleanup

Goal: capture the proof, then remove every artefact this box was made to leave behind.

---

## 7.1 Where the flags live on an OSCP-style Windows box

| File | Owner | Needs |
|---|---|---|
| `local.txt` | the foothold user | your shell as `offsec` |
| `proof.txt` | `Administrator` | local admin / SYSTEM |

Standard locations:

```cmd
type C:\Users\offsec\Desktop\local.txt
type C:\Users\Administrator\Desktop\proof.txt
```

The usual alternates, in the order worth trying:

```cmd
dir C:\proof.txt C:\Users\Public\Desktop\proof.txt C:\Users\Administrator\Desktop\proof.txt 2>nul
```

From Meterpreter (recursive search — slow on a full volume, but thorough):

```
search -f proof.txt -d C:\
search -f local.txt -d C:\
```

## 7.2 Reading proof.txt

Over RDP as `adm1n`, open `C:\Users\Administrator\Desktop\proof.txt`. Because `adm1n` is a local
administrator, the profile's ACLs do not stop you; if a file is stubborn, Explorer → Properties →
Security → take ownership, or from an admin `cmd`:

```cmd
icacls C:\Users\Administrator\Desktop\proof.txt /grant adm1n:F
type C:\Users\Administrator\Desktop\proof.txt
```

> **Flag values are deliberately not reproduced in this writeup.** Copy the hash into your own notes
> and the score sheet — publishing a live exam flag is both useless to a reader and a rules problem
> on the platform it came from.

---

## 7.3 Cleanup — the part people skip

You created an account, dropped a DLL, and opened a console window on somebody's desktop. Undo it.

**1. Remove the account you created** (as an administrator):

```cmd
net user adm1n /delete
net localgroup administrators
```

**2. Remove the scripts and stages:**

```cmd
del C:\Users\offsec\AppData\Local\Temp\cve-2021-1675.ps1
del C:\Users\offsec\AppData\Local\Temp\s.exe
del C:\Users\offsec\AppData\Local\Temp\nightmare.dll
```

`Invoke-Nightmare` deletes its own DLL, but only on the success path — check anyway.

**3. Check for leftover print drivers.** PrintNightmare loads a driver into the Spooler; a failed run
can leave a package behind:

```cmd
dir C:\Windows\System32\spool\drivers\x64\3\
rundll32 printui.dll,PrintUIEntry /s /t2
```

Remove anything you did not find before you started.

**4. Close the sessions** — `sessions -K` on the MSF side — and revert the snapshot if the lab is
snapshot-based. On this box uptime was 48 minutes at first contact, so the image was freshly booted;
a revert is a legitimate and complete cleanup.

**5. Report the side effect you cannot undo:** the console window on the desktop. It is the visible
artefact of a keystroke-injection exploit and should be in the report's "detection opportunities"
section.

---

## 7.4 What this box teaches

**1. `filtered` is not `closed`, and TCP is not everything.**
Ten ports came back `filtered` and the box looked dead. It was alive on UDP/161 the whole time. A
port scan describes a firewall's opinion, not a host's services — and `1978/tcp` flipped from
`filtered` to `open` after a snapshot refresh, so ports must be re-verified, not remembered.

**2. SNMP answers "what is installed" and "who is logged in".**
`hrSWInstalledName` named the vulnerable package; `hrSWRunName` proved an interactive desktop existed.
The second fact is invisible to any port scan and is the *precondition* for a keystroke exploit. That
is why `snmpwalk` on `1.3.6.1.2.1.25.4.2.1.2` is worth more than the ports it costs.

**3. A filtered port is not a reason to abandon the CVE.**
`1978` was filtered on first contact. The right response is to re-scan, then to look for a way to
reach it (IIS, pivot, loopback) — not to pick a different exploit.

**4. Read the escalation error, do not retry the tool.**
`1346 ERROR_BAD_IMPERSONATION_LEVEL` means "no `SeImpersonatePrivilege`". Running `getsystem` five
more times, or swapping PrintSpoofer for GodPotato, changes nothing: potatoes *consume* a privilege,
they do not create one. Change class of attack instead.

**5. Patch level is not version.**
Build 19041 is a release, not a hotfix level. `systeminfo`/`wmic qfe` decides whether
PrintNightmare is available, and SNMP can never tell you.

**6. Escalate to the level the objective needs.**
A local admin read the flag. SYSTEM would have been more work for no additional proof.

---

## 7.5 Detection notes (for the report)

| Action | Where it shows up |
|---|---|
| SNMP walk | `snmp.exe` request counters; UDP/161 from an unexpected host |
| CVE-2022-3218 | a console window on the desktop; the MouseServer process spawning `cmd.exe` |
| `certutil -urlcache` | `Microsoft-Windows-CertUtil`/PowerShell script-block logs; the URL in proxy logs |
| PrintNightmare | Spooler `AddPrinterDriverEx` events, a new local account, Security 4720/4732 |
| `adm1n` creation | Security event **4720** (user created) + **4732** (added to Administrators) |
| RDP logon | Security **4624** type 10 from an unusual source |

The last two are the loudest things on this box. A blue team that only alerts on those would still
have caught the escalation — which is worth saying in the report, because it separates "exploitable"
from "undetectable".
