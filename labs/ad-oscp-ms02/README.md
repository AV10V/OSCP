# ad-oscp-ms02 — `oscp.exam`: MS02 → DC01

The `oscp.exam` directory followed from the MS02 side. The page now records **two positions** on
the same set, because they end differently:

- **Pass 2 — `10.10.152.0/24`** (chapters 01–06): DC01 reachable directly, WinRM as
  `celia.almeda`, MSSQL and BloodHound close every path. A foothold, not a win. Chapter 07 is
  the plan it produced — correct for that position, never executed.
- **Pass 3 — `10.10.131.0/24`** (chapters 08–12): the set re-instantiated behind MS01. SYSTEM on
  MS01, a cached **domain Administrator** verifier in the `SECURITY` hive, a ligolo pivot, and
  `proof.txt` on DC01 read as `nt authority\system`.

| Property | Value |
|---|---|
| MS02 | `10.10.152.142` (pass 2) · `10.10.131.148` (pass 3) |
| DC01 | `10.10.152.140` (pass 2) · `10.10.131.146` (pass 3) |
| Access | WinRM `celia.almeda` (pass 2) · WinRM `eric.wallows` → PrintSpoofer SYSTEM (pass 3) |
| Result | **completed** — DC01 `proof.txt` |

---

## How the set finished

| Step | Where | What happened |
|---|---|---|
| 1 | MS01 | `SeImpersonatePrivilege` → PrintSpoofer → SYSTEM |
| 2 | MS01 | `net localgroup administrators /add Eric.Wallows`, so the dump can run remotely |
| 3 | MS01 | `secretsdump` → SAM + **DCC2 cache**: `OSCP.EXAM/Administrator` from 2022 |
| 4 | Kali | `hashcat -m 1000` → `December31`, `Freedom1`; DCC2 → `7Tg9M9MZbzAokR9` (`-m 2100`, not in the capture) |
| 5 | MS01 → DC01 | ligolo-ng route into `10.10.131.0/24`; `psexec` as `Administrator` → SYSTEM → flag |

The short version: **the domain Administrator had logged on to MS01 in 2022, and the cached
verifier was still there.** LSASS held nothing domain-tier; the `SECURITY` hive did.

## Chapters

| # | Chapter | What it establishes |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | the 152.x position; `web_svc` is not a local admin on MS02 |
| 02 | [Foothold](02-foothold.md) | WinRM as `celia.almeda`; the token proves no potato path exists |
| 03 | [MSSQL](03-mssql.md) | two SQL logins, `sysadmin = 0` for both |
| 04 | [Domain reconnaissance](04-domain-recon.md) | DC01 direct, `Users` share, Kerberoast blocked on DNS + clock |
| 05 | [Reading the graph](05-bloodhound.md) | zero outbound ACEs, no LAPS, no sessions — `sql_svc` is the target |
| 06 | [What is ruled out](06-ruled-out.md) | seven paths closed, each with the evidence that closed it |
| 07 | [Next actions](07-next-actions.md) | the `sql_svc` plan — **superseded**, never executed |
| 08 | [MS01: SYSTEM](08-ms01-system.md) | PrintSpoofer, and the local-admin add that makes the dump possible |
| 09 | [Credentials and cracks](09-credentials-and-cracks.md) | SAM, LSA secrets, DCC2 — and the domain Administrator |
| 10 | [Pivot with ligolo-ng](10-pivot-ligolo.md) | a route into `10.10.131.0/24` |
| 11 | [MS02 through the tunnel](11-ms02-through-the-tunnel.md) | ports, signing, the 26-minute skew — and why MS02 is not the way in |
| 12 | [DC01: `proof.txt`](12-dc01-proof.md) | the cached credential is domain-tier; flag read |

## Ruled out in pass 2, with evidence

`ADMIN$`/`C$` on MS02 · WinRM escalation (no `SeImpersonate`) · SQL sysadmin (`0`/`0`) · ACL abuse
(zero outbound rights) · delegated group membership · LAPS · session theft.

## Open

None for this set — the flag is read.

The `sql_svc` plan in chapter 07 was never executed: it belonged to the `10.10.152.x` position,
where DC01 was direct and MS02 was the only escalatable host. Pass 3 found a shorter route through
MS01's cache. That is a result about position, not a refutation of the plan.

## Evidence notes

- Pass 3 output is the captured scrollback from the run. Where a block is trimmed or a step is not
  in it (the `psexec` service lines, the `-m 2100` invocation), the text says so.
- The DCC2 `Administrator` hash → `7Tg9M9MZbzAokR9` mapping was re-checked with `hashcat -m 2100`
  against the captured hash, not taken from memory.
- Credentials and hashes are lab values and are published as captured.
- MS02 was enumerated; the capture contains no authentication attempt against it. A follow-up scan
  found `1433`/`5986` open on MS02 (the all-port sweep missed both) and `eric.wallows` authenticates
  to MSSQL — but that login's role was never measured, and MS02 was not used to finish the set.
