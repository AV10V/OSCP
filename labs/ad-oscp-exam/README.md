# oscp.exam — MS01 → MS02 → DC01

An Active Directory set rather than a single box: a dual-homed member server in front of an internal
network that holds a second member server and the domain controller. Kali can only see the first
hop; everything after it has to travel through MS01.

**Chain:** authenticated WinRM foothold on MS01 → `SeImpersonatePrivilege` → SYSTEM → LSASS
harvest (no domain-tier material) → reverse SOCKS pivot into `10.10.118.0/24` → kerberoast `SQL_SVC`
→ MSSQL `sysadmin` → `xp_cmdshell` → GodPotato → local admin → `secretsdump` → DC01 domain admin.

> **Status** — all seven chapters are written. A later pass on the same set chose a shorter route
> (MS01's cached domain Administrator); that one is in [`../ad-oscp-ms02/`](../ad-oscp-ms02/), and the
> comparison between the two is the useful part: same directory, different position, different way in.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.118.147` | SMB and WinRM fingerprint, host discovery | `MS01.oscp.exam`, SMB signing off |
| 02 | MS01 | WinRM as `OSCP\eric.wallows` | shell — High IL, **not** local admin |
| 03 | MS01 | `SeImpersonatePrivilege` → PrintSpoofer | `nt authority\system` |
| 04 | MS01 | LSASS with mimikatz, as SYSTEM | no Domain Admin material |
| 05 | MS01 | chisel reverse SOCKS + proxychains | route into `10.10.118.0/24` |
| 06 | MS02 | kerberoast `SQL_SVC` → MSSQL → `xp_cmdshell` → GodPotato → local admin → `secretsdump` | SYSTEM, then a domain credential |
| 07 | DC01 | the credential from MS02, on the DC | `oscp\administrator`, shell on `10.10.118.146` |

## Environment

| | |
|---|---|
| Domain | `oscp.exam` (NetBIOS `OSCP`) |
| Domain SID | `S-1-5-21-2610934713-1581164095-2706428072` |
| Domain GUID | `e7448cc9-434a-4130-90b0-812d3d0c5a96` |
| MS01 | `192.168.118.147` (Kali-facing) · `10.10.118.147` (internal) · Server 2019 build 19041 |
| MS02 | internal only — address printed by the `10.10.118.0/24` sweep, not preserved in these notes |
| DC01 | `10.10.118.146` — PDC, GC, LDAP, KDC |
| Attacker | Kali `192.168.45.158`, kit served on `:8000` |

## Flags

| Host | File | Value |
|---|---|---|
| MS01 | `local.txt` / `proof.txt` | **none issued** — no flag files anywhere under `C:\Users` |
| MS02 | — | none issued — the host's value is the credential it cached |
| DC01 | `proof.txt` | read as `oscp\administrator` — value not preserved in these notes |

## Credentials used

| Account | Secret | Rights |
|---|---|---|
| `OSCP\eric.wallows` | `EricLikesRunning800` | domain user, `BUILTIN\Remote Management Users`, `SeImpersonatePrivilege`, **not** local admin |
| `OSCP\SQL_SVC` | `<cracked>` (kerberoast, 6.2) | MSSQL `sysadmin` on MS02; local `Administrators` after 6.8 |
| `OSCP\Administrator` | `<dc01 password>` (from MS02's LSA/DCC2 cache, 6.9) | domain administrator |

## Chapters

1. [Reconnaissance — one routable host, two networks](01-reconnaissance.md)
2. [Foothold — WinRM as `eric.wallows`](02-foothold.md)
3. [Privilege escalation — `SeImpersonate` → SYSTEM](03-privilege-escalation.md)
4. [Credentials — what LSASS would and would not give](04-credentials.md)
5. [Pivot — chisel into `10.10.118.0/24`](05-pivot.md)
6. [MS02 — kerberoast, MSSQL, and GodPotato](06-ms02.md)
7. [DC01 — domain admin, and the last step](07-dc01.md)

## Note on the output blocks

Scan output, dumps and potfiles are deliberately **not** committed. Where a block is a condensed
reading of the session rather than a verbatim capture, the prose says so; nothing here is
reconstructed from memory and presented as raw output.

Chapters 06–07 are written from the resolution of this lab: the sequence is reproduced as used, the
secret values it produces are not, and the flag value is the one thing the page says it does not have.
