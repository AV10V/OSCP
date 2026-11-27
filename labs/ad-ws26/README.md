# AD set 2 · `WS26` → `SRV22` · `oscp.exam`

An Active Directory set with three hosts, one reachable entry point and an unbroken path to Domain
Admin. A domain credential opens WinRM on `WS26`, `SeDebugPrivilege` in the token turns that shell
into local Administrator, and a ligolo-ng tunnel opens the `172.16.97.0/24` segment that holds the
domain controller and the second server.

The first pass ends at what looks like a wall. The second pass walks through it: a `Backup` share on
the second server holds a SAM/SYSTEM pair, the local Administrator hash in that backup is reused on
the domain controller, a NetExec `lsassy` run reads a domain logon out of LSASS, and the account it
finds owns the `ForceChangePassword` right over a Domain Admin.

> **Status — complete.** Local Administrator and `local.txt` on `WS26`, Domain Admin and `proof.txt`
> on `SRV22`. Every flag is masked; every command and output below is the one that produced the next
> step.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `172.16.97.206` | `nmap -sV -p-` on the reachable host | XAMPP on `80/443/8080`, SMB, RDP, WinRM |
| 02 | WinRM | exam credential for `p.andrew` | shell as `oscp\p.andrew` on `WS26` |
| 03 | `WS26` | `whoami /priv` | `SeDebugPrivilege` and `SeImpersonatePrivilege` enabled |
| 04 | `WS26` | `Invoke-Mimikatz.ps1 "privilege::debug" "sekurlsa::logonpasswords"` | local `Administrator` NTLM |
| 05 | `WS26` | pass-the-hash, `--local-auth` | local Administrator, `local.txt` |
| 06 | `WS26` | ligolo-ng agent → tunnel | route into `172.16.97.0/24` |
| 07 | `172.16.97.200` | `nmap -sV -p-` through the tunnel | `SRV22`, Server 2022 domain controller |
| 08 | internal | Kerberos, MySQL, RDCMan, SMB shares, backups | five dead ends |
| 09 | BloodHound | DA path identified | `A.NEWMAN` → `ForceChangePassword` → `A.BETTY` |
| 10 | `172.16.97.202` | `smbclient` with the domain in `-U` | `Backup` share → `SystemBackup\SAM` + `SYSTEM` |
| 11 | offline | `impacket-secretsdump -sam SAM -system SYSTEM local` | local `Administrator` NTLM |
| 12 | `SRV22` | `nxc smb --local-auth -M lsassy` | `A.NEWMAN` clear-text password |
| 13 | `SRV22` | `net rpc password` | `A.BETTY` (Domain Admin) password changed |
| 14 | WinRM | `evil-winrm -u A.BETTY` | `proof.txt` |

## Environment

| | |
|---|---|
| Domain | `oscp.exam` (NetBIOS `OSCP`) |
| In-scope addresses | `172.16.97.200` · `172.16.97.202` · `172.16.97.206` |
| First machine | `WS26` — `172.16.97.206`, Server 2019, XAMPP + WinRM |
| Domain controller | `SRV22` — `172.16.97.200`, Server 2022, WinRM exposed |
| Second server | name `[redacted]` — `172.16.97.202`, Server 2019, `Backup` share |
| Attacker | `kali@kali`, `192.168.49.97` on the exam network, ligolo-ng `11601` |
| Entry credential | `oscp.exam\p.andrew` — provided at the start of the set |

## Credentials along the chain

| Account | Secret | How it was obtained | Used for |
|---|---|---|---|
| `oscp.exam\p.andrew` | `[redacted]` | provided at the start of the set | WinRM on `WS26`, SMB on `172.16.97.202` |
| `WS26\Administrator` | NTLM `[redacted]` | LSASS dump on `WS26` | pass-the-hash, `local.txt` |
| local `Administrator` (backup) | NTLM `[redacted]` | `SAM` + `SYSTEM` from the `Backup` share | `--local-auth` on `.202` and `SRV22` |
| `OSCP.EXAM\A.NEWMAN` | `[redacted]` | `lsassy` against `SRV22` | `ForceChangePassword` over `A.BETTY` |
| `OSCP.EXAM\A.BETTY` | `[redacted]` | set by `net rpc password` | Domain Admin → `proof.txt` |

## Flags

| Host | File | Value |
|---|---|---|
| `WS26` | `C:\Users\Administrator\Desktop\local.txt` | `[redacted]` |
| `SRV22` | `C:\Users\Administrator\Desktop\proof.txt` | `[redacted]` |

## How the set is put together

`172.16.97.206` is the only address that answers from the exam network: XAMPP on three HTTP ports,
SMB, RDP and WinRM. `172.16.97.200` and `172.16.97.202` are filtered until the tunnel is up, and
from `WS26` they present as a Server 2022 domain controller and a Server 2019 member server with an
SMB share called `Backup`.

The design is a chain of three credentials, each one only visible from the previous position:

1. the provided domain user opens `WS26` and its LSASS gives a **local** Administrator;
2. that local Administrator is the network position that reaches the domain controller;
3. a **backup** on the second server leaks the local Administrator hash of the image, reused on the DC;
4. the DC's LSASS leaks a **domain** logon, `A.NEWMAN`, whose only power is over `A.BETTY`;
5. `A.BETTY` is the Domain Admin.

Every obvious alternative — Kerberos, the MySQL database, the RDCMan profile, the SMB share sweep,
the phpMyAdmin dump — is a decoy, and chapter 05 is the record of walking into each one.

## Chapters

| # | Chapter | What it covers |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | the three addresses, the reachable host, the DC behind it |
| 02 | [`02-foothold-ws26.md`](02-foothold-ws26.md) | WinRM as `p.andrew`, `whoami /priv` |
| 03 | [`03-privilege-escalation.md`](03-privilege-escalation.md) | Mimikatz over WinRM, pass-the-hash, `local.txt` |
| 04 | [`04-pivot.md`](04-pivot.md) | ligolo-ng, routes, the DC and the second server |
| 05 | [`05-dead-ends.md`](05-dead-ends.md) | Kerberos, database, RDCMan, shares — five wrong turns |
| 06 | [`06-bloodhound-and-the-wall.md`](06-bloodhound-and-the-wall.md) | the DA path, and why it looked unreachable |
| 07 | [`07-backup-share.md`](07-backup-share.md) | the `Backup` share, SAM + SYSTEM, `secretsdump` |
| 08 | [`08-lsass-and-a-newman.md`](08-lsass-and-a-newman.md) | `--local-auth`, `lsassy`, `A.NEWMAN` |
| 09 | [`09-forcechangepassword.md`](09-forcechangepassword.md) | `net rpc password`, `A.BETTY`, `proof.txt` |
