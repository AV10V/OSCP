# oscp.exam — MS01 → MS02 → DC01

An Active Directory set rather than a single box: a dual-homed member server in front of an internal
network that holds a second member server and the domain controller. Kali can only see the first
hop; everything after it has to travel through MS01.

**Chain:** authenticated WinRM foothold on MS01 → `SeImpersonatePrivilege` → SYSTEM → LSASS
harvest (no domain-tier material) → reverse SOCKS pivot into `10.10.118.0/24` → MS02 → DC01.

> **Status** — chapters 01–05 are written from the run. Chapters 06 (MS02) and 07 (DC01) are
> placeholders until the capture for those legs is added; the page says so instead of guessing.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.118.147` | SMB and WinRM fingerprint, host discovery | `MS01.oscp.exam`, SMB signing off |
| 02 | MS01 | WinRM as `OSCP\eric.wallows` | shell — High IL, **not** local admin |
| 03 | MS01 | `SeImpersonatePrivilege` → PrintSpoofer | `nt authority\system` |
| 04 | MS01 | LSASS with mimikatz, as SYSTEM | no Domain Admin material |
| 05 | MS01 | chisel reverse SOCKS + proxychains | route into `10.10.118.0/24` |
| 06 | MS02 | second hop | *pending capture* |
| 07 | DC01 | domain admin, flag | *pending capture* |

## Environment

| | |
|---|---|
| Domain | `oscp.exam` (NetBIOS `OSCP`) |
| Domain SID | `S-1-5-21-2610934713-1581164095-2706428072` |
| Domain GUID | `e7448cc9-434a-4130-90b0-812d3d0c5a96` |
| MS01 | `192.168.118.147` (Kali-facing) · `10.10.118.147` (internal) · Server 2019 build 19041 |
| DC01 | `10.10.118.146` — PDC, GC, LDAP, KDC |
| Attacker | Kali `192.168.45.158`, kit served on `:8000` |

## Flags

| Host | File | Value |
|---|---|---|
| MS01 | `local.txt` / `proof.txt` | **none issued** — no flag files anywhere under `C:\Users` |
| MS02 | — | pending |
| DC01 | `proof.txt` | pending |

## Credentials used

| Account | Secret | Rights |
|---|---|---|
| `OSCP\eric.wallows` | `EricLikesRunning800` | domain user, `BUILTIN\Remote Management Users`, `SeImpersonatePrivilege`, **not** local admin |

## Chapters

1. [Reconnaissance — one routable host, two networks](01-reconnaissance.md)
2. [Foothold — WinRM as `eric.wallows`](02-foothold.md)
3. [Privilege escalation — `SeImpersonate` → SYSTEM](03-privilege-escalation.md)
4. [Credentials — what LSASS would and would not give](04-credentials.md)
5. [Pivot — chisel into `10.10.118.0/24`](05-pivot.md)
6. [MS02 — the second hop](06-ms02.md)
7. [DC01 — domain admin and the flag](07-dc01.md)

## Note on the output blocks

Scan output, dumps and potfiles are deliberately **not** committed. Where a block is a condensed
reading of the session rather than a verbatim capture, the prose says so; nothing here is
reconstructed from memory and presented as raw output.
