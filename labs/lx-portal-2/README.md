# Linux 2 — Job Application Portal · `192.168.91.112`

A PHP site with a CV upload form, an anonymous FTP holding its backups, and a `sudo` list full of
pagers. The upload filter checks the `Content-Type` header instead of the file, a Chankro payload gets
around `disable_functions`, the `.env` on disk hands over a password that is reused as an OS login, and
`sudo git` finishes the box.

> **Status — complete.** `www-data` → `gari` → root. `local.txt` is masked below; the root flag at
> `/root/proof.txt` is `[redacted]`.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.91.112` | `nmap -sC -sV -p-` — FTP, SSH, HTTP, MySQL | four ports, no versions worth exploiting |
| 02 | FTP `21` | `anonymous` login, four monthly backups | `applications_dec22.zip` (33,080 bytes) |
| 03 | HTTP `80` | `feroxbuster` → `/applications` with `Options +Indexes` | `upload.php` |
| 04 | `/applications/upload.php` | `.php` file sent as `Content-Type: application/pdf` | shell written to `/applications/chan.php` |
| 05 | same | `system()` disabled → Chankro payload | `www-data` shell |
| 06 | `/opt/dev/new-site/.env` | `DB_PASSWORD=Lam0)vM@ch1n3!` | password candidate |
| 07 | SSH `22` | spray against `/etc/passwd` users | `gari:Lam0)vM@ch1n3!` |
| 08 | `/home/gari` | `cat local.txt` | user flag |
| 09 | `sudo -l` | five `NOPASSWD` binaries, two of them pagers | `sudo git -p help config` → `!/bin/sh` |
| 10 | `/root` | `cat proof.txt` | root |

---

## Environment

| | |
|---|---|
| Target | `192.168.91.112` — Ubuntu 24.04.2 LTS, hostname `oscp` |
| Open ports | `21` FTP · `22` SSH · `80` HTTP · `3306` MySQL |
| Web root | `/var/www/html`, application also in `/opt/dev/new-site` |
| Attacker | Kali, working dir `~/Desktop/oscp_exam/THIRD` |
| Callback | `192.168.49.91:443` |

## Credentials

| Account | Secret | Source | Use |
|---|---|---|---|
| `web_admin` (MySQL) | `Lam0)vM@ch1n3!` | `/opt/dev/new-site/.env` | database only — a dead end |
| `gari` (SSH) | `Lam0)vM@ch1n3!` | same `.env`, sprayed against `/etc/passwd` | user shell, `local.txt`, `sudo` |

## Flags (masked)

| Host | Path | Flag |
|---|---|---|
| `192.168.91.112` | `/home/gari/local.txt` | `eb8bcdb8e5b8ad0c****************` |
| `192.168.91.112` | `/root/proof.txt` | `[redacted]` |

## Chapters

| # | File | Content |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | ports, feroxbuster, the `/applications` listing |
| 02 | [`02-ftp-anonymous.md`](02-ftp-anonymous.md) | anonymous FTP, the four backups, reading `upload.php` |
| 03 | [`03-upload-portal.md`](03-upload-portal.md) | the PDF filter and the `Content-Type` bypass |
| 04 | [`04-chankro-rce.md`](04-chankro-rce.md) | `disable_functions` and a Chankro reverse shell |
| 05 | [`05-credentials-and-gari.md`](05-credentials-and-gari.md) | `.env`, password spray, SSH, `local.txt` |
| 06 | [`06-privilege-escalation.md`](06-privilege-escalation.md) | `sudo -l`, GTFOBins, root |

## Why this box matters

It is the cleanest web box of the set. Every step is a standard technique and none of them needs a
CVE:

1. **Anonymous FTP as reconnaissance** — the backup names the directory the site lives in.
2. **Directory listing as reconnaissance** — `Index of /applications` enumerates the app.
3. **A MIME check is not a file check** — the upload filter trusts a header the client controls.
4. **`disable_functions` is not a boundary** — Chankro turns `putenv` + `mail` into execution.
5. **Password reuse** — the application's database password is the SSH password of a real account.
6. **`sudo` on a pager** — `git` and `bzmore` both end in `!/bin/sh`.

## The set

This is box 3 of 4 in the same set: **AD set** ([`../ad-fantom-1/`](../ad-fantom-1/)),
**Linux 1 — mail** ([`../lx-mail-1/`](../lx-mail-1/)), **Linux 2 — portal** (this box) and
**Windows** ([`../win-oscp-1/`](../win-oscp-1/)).
