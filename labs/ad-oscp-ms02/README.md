# ad-oscp-ms02 — `oscp.exam` from 10.10.152.0/24

Second pass at the same `oscp.exam` directory, from a network position where **DC01 answers directly**
(`10.10.152.140`) instead of sitting behind an MS01 SOCKS tunnel.

Same domain SID (`S-1-5-21-2610934713-1581164095-2706428072`) and GUID
(`e7448cc9-434a-4130-90b0-812d3d0c5a96`) as [`../ad-oscp-exam`](../ad-oscp-exam/) — one directory, two
network positions.

| Property | Value |
|---|---|
| MS02 | `10.10.152.142` — Windows 10 / Server 2019 build 19041, SMB signing **off** |
| DC01 | `10.10.152.140` — Server 2019 build 17763, SMB signing **on** |
| Access | WinRM as `OSCP\celia.almeda` (medium integrity) |
| Result | **foothold only** — no SYSTEM, no domain admin, no flag |

## Chapters

| # | Chapter | What it establishes |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | the network position, and that `web_svc` is not a local admin |
| 02 | [Foothold](02-foothold.md) | WinRM shell; why the token proves no potato path exists |
| 03 | [MSSQL](03-mssql.md) | two SQL logins, `sysadmin = 0` for both |
| 04 | [Domain reconnaissance](04-domain-recon.md) | DC01 located, `Users` share found, Kerberoast blocked on DNS + clock |
| 05 | [Reading the graph](05-bloodhound.md) | zero outbound ACEs, no LAPS, no sessions — `sql_svc` is the target |
| 06 | [What is ruled out](06-ruled-out.md) | seven paths closed, each with the evidence that closed it |
| 07 | [Next actions](07-next-actions.md) | why `sql_svc`, and the plan (not yet executed) |

## Ruled out with evidence

`ADMIN$`/`C$` on MS02 · WinRM escalation (no `SeImpersonate`) · SQL sysadmin (`0`/`0`) · ACL abuse
(zero outbound rights) · delegated group membership · LAPS · session theft.

## Open

Kerberoast `sql_svc` · DC01 `Users` share · SYSVOL GPP sweep · `xp_dirtree` NetNTLMv2 capture ·
Kerberos-backed BloodHound re-collection.

## Evidence notes

- BloodHound export analysed locally; the chapter records findings, not the raw JSON.
- Credentials are lab credentials and are published as captured.
- Nothing in chapter 07 is written as complete — it is the plan the evidence points to.
