# 02 — Foothold

`celia.almeda` authenticates over WinRM and lands on MS02 with a shell. The point of this chapter is
not the shell — it is proving what the token does **not** contain, because that decides whether the box
falls here or somewhere else.

---

## 2.1 The connection

```bash
evil-winrm -i 10.10.152.142 -u celia.almeda -p '7k8XHk3dMtmpnC7'
```

```
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\celia.almeda\Documents>
```

A domain user over WinRM on a member server. Nothing exotic — the interesting part is the token.

---

## 2.2 The token

```powershell
whoami /all
```

```
USER INFORMATION
----------------
User Name         SID
================= ============================================
oscp\celia.almeda S-1-5-21-2610934713-1581164095-2706428072-1105

GROUP INFORMATION
-----------------
Everyone                              Well-known group S-1-1-0
BUILTIN\Remote Management Users       Alias            S-1-5-32-580
BUILTIN\Users                         Alias            S-1-5-32-545
NT AUTHORITY\NETWORK                  Well-known group S-1-5-2
NT AUTHORITY\Authenticated Users      Well-known group S-1-5-11
NT AUTHORITY\This Organization        Well-known group S-1-5-15
NT AUTHORITY\NTLM Authentication      Well-known group S-1-5-64-10
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

PRIVILEGES INFORMATION
----------------------
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

Read it in three steps.

**`BUILTIN\Remote Management Users`** is the only reason this works. That group — not local
Administrators — is what authorises WinRM. It is an explicit, deliberate grant on MS02, and it is the
whole foothold.

**The privilege list is the standard five.** `SeShutdown`, `SeChangeNotify`, `SeUndock`,
`SeIncreaseWorkingSet`, `SeTimeZone`. Nothing else. In particular:

- no `SeImpersonatePrivilege`
- no `SeAssignPrimaryTokenPrivilege`
- no `SeDebugPrivilege`
- no `SeBackupPrivilege`

**`Medium Mandatory Level`** confirms it: a normal user token, not a filtered administrator token.

---

## 2.3 Why this is a proof, not an assumption

The temptation is to say "no SeImpersonate, so no potato" and move on. The stronger argument is that
this token could not have been an administrator's in the first place, whatever its privileges looked
like.

UAC remote restrictions (`LocalAccountTokenFilterPolicy`) apply to **local** accounts. A **domain**
account that sits in the machine's local `Administrators` group, authenticating over WinRM, receives a
**full privileged token** — no filtering. So if celia were a local admin on MS02, either
`BUILTIN\Administrators` would appear in the group list, or the privileges would include the
admin set.

Neither is true. Therefore:

> celia.almeda is not a local administrator on MS02, and the potato family
> (`PrintSpoofer`, `GodPotato`, `JuicyPotato`) has nothing to abuse here.

That closes the route that took MS01 in the previous leg. It is worth stating plainly because the same
technique is the obvious reflex, and on this host it is a dead end.

---

## 2.4 What WinRM is not going to give us

Evil-WinRM runs commands as a **network logon** (type 3). That has a specific consequence for
credential hunting:

- no `NL$` cached credential is created for this logon, so there is nothing new to dump;
- no Kerberos TGT is issued into the session, so `sekurlsa::tickets` has nothing to show;
- `sekurlsa::logonpasswords` on this host would show *other* users' material if it existed, but LSASS
  was already proven empty on MS01 in the previous leg.

So the runbook here is files, not memory:

```powershell
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattend" /s
Get-ChildItem C:\Users\celia.almeda -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.txt','.xml','.config','.ini','.ps1' } |
  Select-Object -First 40 FullName
```

Those are candidates, not results — nothing from that list is yet confirmed, and this chapter does not
claim otherwise.

---

## 2.5 Position after this chapter

| Item | Value |
|---|---|
| Access | interactive shell on MS02 |
| Integrity | medium — standard user |
| Local admin | no |
| SeImpersonate | no |
| Escalation from this token | **none available** |
| Session type | network logon — no cache, no TGT |

The WinRM shell is now a **reconnaissance platform and nothing more**. Any further progress has to come
from a service running in a different security context, which is what the next chapter tests.
