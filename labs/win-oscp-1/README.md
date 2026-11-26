# Windows 1 — `OSCP` · 192.168.91.111

Windows Server 2019 with IIS, an SMB share named *"Anne's Automatic BackUps"*, and **Windows PowerShell
Web Access**. The chain is short: a null SMB session hands over `emails.zip`, rockyou opens it, one
email gives a default password, and the WAC login page opens a PowerShell console. The only thing that
stands between you and that console is knowing that a **local account must be typed `.\username`**.

> **Status — partial.** The box was solved up to `local.txt`; no privilege escalation was found and
> `proof.txt` was not obtained.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.91.111` | `nmap -A -T4 -p-` | IIS 10 + SMB + RDP, `OSCP`, build 17763 |
| 02 | 445 | `smbclient -L //… -U ''` | shares: `ADMIN$`, `AnneAuto`, `C$`, `IPC$` |
| 03 | `AnneAuto` | null session → `emails.zip` (70052 bytes) | downloaded |
| 04 | local | `zip2john` → `hashcat` mode `13600` (WinZip) | zip password (rockyou) |
| 05 | mailbox | Anne Howard → Sasha Payne, "Access" | **`Welcome1`** for `sasha` |
| 06 | `https://…/powershell` | Windows PowerShell Web Access | login page |
| 07 | WAC | `sasha` fails → **`.\sasha`** works | PowerShell as `oscp\sasha` |
| 08 | host | `cat local.txt` | **local flag** (masked) |
| 09 | host | PowerUp / manual enumeration | nothing → box not completed |

## Environment

| | |
|---|---|
| Host | `192.168.91.111` — `OSCP`, Windows 10.0.17763 (Server 2019) |
| Website | IIS 10 (`Microsoft-HTTPAPI/2.0`), Nicepage 5.5.4 template, "LaunchIt - MVP" landing page |
| Ports | 80 (→ HTTPS redirect) · 443 · 445 · 3389 |
| SMB | null session (guest) allowed; share `AnneAuto` — *Anne's Automatic BackUps* |
| Admin surface | **Windows PowerShell Web Access** at `https://192.168.91.111/powershell` |
| Attacker | Kali Linux, working dir `~/Desktop/oscp_exam/SECOND` |

## Credentials

| Account | Secret | Source | Use |
|---|---|---|---|
| *(SMB guest)* | *(empty)* | `-U ''` | list shares, read `AnneAuto` |
| `emails.zip` | *(cracked)* | hashcat 13600 + rockyou | attachment |
| `sasha` | `Welcome1` | email "Access" from Anne Howard | WAC login as `.\sasha` |

⚠ The password is `Welcome1`; if it is rejected, try `Welcome1!` or `Welcome1)`.

## Flags (masked)

| Host | Path | Flag |
|---|---|---|
| `.111` | `C:\Users\sasha\Desktop\local.txt` | `6cc351e3e4f2572432************` |
| `.111` | `proof.txt` | **not obtained** |

## Chapters

| # | File | Content |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | nmap, IIS/Nicepage, SMB, WAC |
| 02 | [`02-smb-emails-zip.md`](02-smb-emails-zip.md) | null session, `AnneAuto`, `zip2john`, hashcat |
| 03 | [`03-wac-login.md`](03-wac-login.md) | PowerShell Web Access and the `.\user` lesson |
| 04 | [`04-local-flag-and-dead-end.md`](04-local-flag-and-dead-end.md) | shell, `local.txt`, what was missing |

## The one thing to remember

Not the ZIP, not the null session — the **username format**. The expensive part is a login page that
works perfectly and rejects `sasha`, because a local account on a workgroup-joined box has to be
written `.\sasha` (or `OSCP\sasha`).

## The set

This is box 4 of 4 in the same set: **AD set** ([`../ad-fantom-1/`](../ad-fantom-1/)),
**Linux 1 — mail** ([`../lx-mail-1/`](../lx-mail-1/)), **Linux 2 — portal** ([`../lx-portal-2/`](../lx-portal-2/))
and **Windows** (this box).
