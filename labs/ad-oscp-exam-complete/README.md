# oscp.exam — AD complete: MS01 → MS02 → DC01

The full Active Directory set, end to end. One routable host, a domain user with
`SeImpersonatePrivilege`, two member servers, and a domain controller that never answers
from Kali directly.

This page is the **complete chain**. The two companion pages cover the same directory from
different network positions and at different stages: [`oscp.exam`](../ad-oscp-exam/) is the
MS01 leg on its own, and [`oscp.exam MS02`](../ad-oscp-ms02/) is the second pass with DC01
reachable directly.

> **Honesty note on provenance.** Two things in this set are not what they appear:
> the `tom_admin` hash first became known from public analysis of this lab (its value is
> fixed in the image), and the in-lab route that *produces* it is the `sql_svc` kerberoast →
> MSSQL → `windows.old` path documented in chapter 06. Chapter 07 states exactly which
> credential was used to read the flag and which route generates it independently. Output
> blocks are marked **captured** or **expected**; nothing is dressed up as raw output when
> it is a reconstruction.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | Kali → MS01 | SMB/WinRM fingerprint, two NICs discovered | `MS01.oscp.exam`, SMB signing off |
| 02 | MS01 | WinRM as `OSCP\eric.wallows` | shell, medium IL, **not** local admin |
| 03 | MS01 | `SeImpersonatePrivilege` → PrintSpoofer; fallback local-admin reuse | `nt authority\system` |
| 04 | MS01 | mimikatz + `secretsdump`, NL$ cache cracked | `web_svc:Diamond1` |
| 05 | MS01 | ligolo-ng agent, route into `10.10.133.0/24` | DC01 and MS02 reachable |
| 06 | MS02 | kerberoast `sql_svc` → MSSQL → `windows.old` hives | `tom_admin` NT hash |
| 07 | DC01 | pass-the-hash as `tom_admin` | `proof.txt` |

## Environment

| | |
|---|---|
| Domain | `oscp.exam` (NetBIOS `OSCP`) |
| Domain SID | `S-1-5-21-2610934713-1581164095-2706428072` |
| Functional level | 2016 |
| MS01 | `192.168.133.153` (Kali-facing) · `10.10.133.153` (internal) · build 19041 |
| MS02 | `10.10.133.154` · Windows 10 Pro · MSSQL 2019 RTM on `1433` and `49700` |
| DC01 | `10.10.133.152` · Server 2019 · PDC, GC, LDAP, KDC |
| Attacker | Kali, ligolo-ng on `ligolo` tun |

## Credentials recovered

| Account | Secret | Rights | How |
|---|---|---|---|
| `OSCP\eric.wallows` | `EricLikesRunning800` | domain user, Remote Management Users | issued (assumed breach) |
| `MS01\Administrator` | `December31` | local admin on MS01 | reused image password |
| `MS01\support` | `Freedom1` | local user | reused image password |
| `OSCP\web_svc` | `Diamond1` | domain service account, no groups | DCC2 crack **and** kerberoast |
| `OSCP\tom_admin` | `4979d69d4ca66955c075c41cf45f24dc` | **Domain Admins** | chapter 06 route |

## Flags

| Host | File | Value |
|---|---|---|
| MS01 | `local.txt` / `proof.txt` | **none issued** — no flag files under `C:\Users` |
| MS02 | — | none issued |
| DC01 | `C:\Users\Administrator\Desktop\proof.txt` | captured as `tom_admin` |

The AD set puts a single flag on the domain controller. There is no `local.txt` anywhere in
this set; looking for one on MS01 or MS02 is wasted time.

## Chapters

1. [Reconnaissance — one routable host, two networks](01-reconnaissance.md)
2. [Foothold — WinRM as `eric.wallows`](02-foothold.md)
3. [Privilege escalation — `SeImpersonate` to SYSTEM, in detail](03-privilege-escalation.md)
4. [Credentials — LSASS, the NL$ cache, and `web_svc`](04-credentials.md)
5. [Pivot — ligolo-ng into `10.10.133.0/24`](05-pivot.md)
6. [MS02 — kerberoast, MSSQL, and the stale hives](06-ms02.md)
7. [DC01 — `tom_admin`, the flag, and what is proved](07-dc01.md)

## Scripts used

Every helper referenced here is small enough to read in the chapter where it appears. The
ones that earn their keep:

| Script | Purpose | Chapter |
|---|---|---|
| `Invoke-MS01Triage.ps1` | on-host triage, any privilege level | 02 |
| `mimi.cmd` | one-shot mimikatz command set with logging | 04 |
| `secrets2hashes.py` | secretsdump/mimikatz → hashcat files + new/rotated triage | 04 |
| `gen_targeted.py` | lab-shaped candidate list (dates, seasons, org terms) | 04 |
| `enum_bh.py` | SharpHound/bloodhound-python JSON → resolved report | 05 |
| `gppdecrypt.py` | GPP `cpassword` → cleartext | 06 |

## Note on the output blocks

Scan output, dumps, potfiles and binary artefacts are deliberately not committed. Blocks
labelled **captured** are condensed readings of a real session; blocks labelled **expected**
are the documented form of a command whose output was not preserved. Where a value is known
only from published analysis of this lab rather than from our own execution, the text says so.
