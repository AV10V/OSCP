# AD Fantom 1 — `WS01` → `SRV22` → `DC20` · oscp.exam

An Active Directory set behind a dual-homed Windows 11 workstation. One provided credential gets a
WinRM shell on `WS01`; a `winPEAS` environment variable makes that box local admin; LSASS hands over a
domain user; an ACL misconfiguration makes that user local admin on `SRV22`; a KeePass database on
`SRV22`'s desktop holds a Domain Admin's password; and `DC20` falls to it over WinRM.

> **Status — complete.** All three hosts are written up, including the
> domain proof. Open items are listed in [`07-set-summary.md`](07-set-summary.md#75-gaps-in-these-notes).

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.91.206` | `nmap -A -T4 -p-` — web, SMB/RPC, MySQL, RDP, WinRM | `WS01.oscp.exam`, Win 11 build 22000 |
| 02 | WS01 | provided credential → `nxc smb` / `nxc winrm` / `evil-winrm` | shell as `oscp.exam\andrew` |
| 03 | WS01 | `config.php` → MySQL `offsec_user` → `offsec_db` | bcrypt table (decoy) + plaintext app secret |
| 04 | WS01 | `winPEASx64.exe` → environment variables | local `Administrator` password, cleartext |
| 05 | WS01 | `--local-auth`, `evil-winrm` as Administrator | `proof.txt` + second NIC `172.16.91.206/24` |
| 06 | WS01 | ligolo-ng proxy/agent + one route | `172.16.91.0/24` reachable |
| 07 | WS01 | `nxc -M lsassy` as local admin | perry's NT hash **and** cleartext |
| 08 | domain | `bloodhound-python -c All` as perry | `perry --WriteMembers--> HELPDESK USERS` |
| 09 | DC20 | `bloodyAD` / `net rpc group addmem` | perry added to `HELPDESK USERS` |
| 10 | SRV22 | `nxc smb` as perry | `(Pwn3d!)` — lateral movement |
| 11 | SRV22 | `Confidential.kdbx` → `keepasscracker` + rockyou | KeePass master password |
| 12 | — | KeePassXC: 4 entries, BloodHound: Domain Admins | `GALLAGHER` + `BackupPassword2024` |
| 13 | DC20 | `nxc winrm` spray → `evil-winrm` | Domain Admin, `proof.txt` on DC20 |

---

## Environment

| | |
|---|---|
| Domain | `oscp.exam` (NetBIOS `OSCP`) |
| WS01 (edge) | `192.168.91.206` — Windows 11, build 22000, dual-homed |
| WS01 (internal) | `172.16.91.206/24`, gateway `192.168.91.254` |
| SRV22 | Windows Server 2022, build 20348 — internal address not captured in these notes |
| DC20 | `172.16.91.200` — Windows Server 2022, build 20348, PDC |
| Internal network | `172.16.91.0/24` — reachable only through WS01 |
| Attacker | Kali, working dir `~/Desktop/oscp.exam/AD_SET`, home `/home/kali` |
| Tunnel | ligolo-ng, endpoint `192.168.49.91:11601`, tun device `ligolo` |

## Credentials

| Account | Secret | Source | Use |
|---|---|---|---|
| `oscp.exam\andrew` | `BussOff@theRiv3r` | provided at start | SMB → WinRM shell on WS01 |
| `offsec_user` (MySQL) | `OffSec_2024` | `config.php` | `offsec_db` enumeration |
| `WS01\Administrator` | `Work3sValueable444` | winPEAS env var | local admin → proof → LSA dump |
| `oscp.exam\perry` | `SurfaceConditionMove441` | lsassy / secretsdump | BloodHound, ACL write, SRV22 |
| `oscp.exam\perry` (NTLM) | `0acba8f16de9d8d6b0d6c725356c3c2` | lsassy | pass-the-hash (`bloodyAD --hashes`) |
| `Confidential.kdbx` | `12/05/2015` (date; year uncertain) | keepasscracker + rockyou | opens the KeePass vault |
| `oscp.exam\GALLAGHER` | `BackupPassword2024` | KeePass `AD` entry | **Domain Admin** → DC20 |

## Flags (masked)

| Host | Path | Flag |
|---|---|---|
| WS01 | `C:\Users\Administrator\Desktop\proof.txt` | `****************` |
| DC20 | `C:\Users\Administrator\Desktop\proof.txt` | `********************************` |

## Chapters

| # | File | Content |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | full-port nmap, SMB/WinRM fingerprint |
| 02 | [`02-foothold.md`](02-foothold.md) | provided credential, WinRM, `config.php`, MySQL |
| 03 | [`03-privilege-escalation.md`](03-privilege-escalation.md) | winPEAS → local Administrator → proof |
| 04 | [`04-pivot-and-loot.md`](04-pivot-and-loot.md) | ligolo-ng tunnel, lsassy output |
| 05 | [`05-lessons.md`](05-lessons.md) | what the set teaches about the exam itself |
| 06 | [`06-dc20.md`](06-dc20.md) | pass-the-hash, BloodHound, ACL abuse, KeePass, domain admin |
| 07 | [`07-set-summary.md`](07-set-summary.md) | full chain, credential map, traps, gaps |

## The set as a whole

This is box 1 of 4 in the same set: **AD set**, **Linux 1 (mail)**, **Linux 2 (portal)** and **Windows**.
The other three are [`../lx-mail-1/`](../lx-mail-1/), [`../lx-portal-2/`](../lx-portal-2/) and
[`../win-oscp-1/`](../win-oscp-1/).
