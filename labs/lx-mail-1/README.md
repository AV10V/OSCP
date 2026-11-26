# Linux 1 — mail (`.119`) → Nexus (`.110`)

The first Linux box of the set is two hosts. The **mail server** on `192.168.91.119` looks empty: no
web app, no share, nothing to exploit. It answers a **WHOIS registry on port 25** that leaks an account
name, and the mailbox behind Dovecot contains the credentials for the next machine. The **application
server** on `192.168.91.110` runs Sonatype Nexus on `8005`; its Swagger API has a file-read primitive,
and root's SSH key sits four directories up.

> **Status — complete.** Both hosts, root included (`/root/proof.txt` masked).
> No `local.txt` was found on `.119`.

---

## TL;DR

| Step | Where | What happened | Result |
|---|---|---|---|
| 01 | `192.168.91.119` | `nmap -A -T4 -p-` | 22, 25, 110, 143, 587, 993 — no web |
| 02 | port 25 | the "SMTP" service is a **WHOIS registry** | records list `sysad@oscp.exam` |
| 03 | port 143 | `telnet` → `a LOGIN sysad sysad` | mailbox access |
| 04 | mailbox | provisioning mail → SSH credentials | shell on `192.168.91.110` |
| 05 | `.110` | `linpeas` | `/opt/nexus` readable, service on **8005** |
| 06 | `.110:8005` | Swagger `ApiKeyAuth` → `artifacts/download?path=…` | `/root/.ssh/id_rsa` (code 200) |
| 07 | `.110` | `chmod 600 id_rsa; ssh -i id_rsa root@…` | **root**, `proof.txt` |

## Environment

| | |
|---|---|
| Mail host | `192.168.91.119` — Ubuntu, OpenSSH 9.6p1, Dovecot (pop3d/imapd) |
| Open TCP (mail) | `22` ssh · `25` smtp (fake WHOIS) · `110` pop3 · `143` imap · `587` smtp · `993` imaps |
| App host | `192.168.91.110` — Ubuntu 24.04 LTS, kernel `6.8.0-31-generic`, hostname `oscp` |
| App | Sonatype Nexus Repository, Swagger UI on **8005** ("Nexus Platform API") |
| Attacker | Kali Linux (`kali@kali`), working dir `~/Desktop/oscp_exam/FIRST` |

## Credentials

| Account | Secret | Source | Use |
|---|---|---|---|
| `sysad` | `sysad` | WHOIS records on port 25 | IMAP/POP3 mailbox |
| *(dev account)* | *(from email #9)* | mailbox | SSH to `192.168.91.110` |
| Nexus API key | *(from Nexus config, readable as the user)* | `/opt/nexus/...` | Swagger `ApiKeyAuth` |
| `root` | *(no password — key)* | `id_rsa` via LFI | `ssh -i id_rsa root@192.168.91.110` |

## Flags (masked)

| Host | Path | Flag |
|---|---|---|
| `.110` | `/root/proof.txt` | `2fa72f9ec5d211700b82e4799b22f********` |

## Chapters

| # | File | Content |
|---|---|---|
| 01 | [`01-reconnaissance.md`](01-reconnaissance.md) | full nmap, and why "nothing open" is the point |
| 02 | [`02-whois-on-port-25.md`](02-whois-on-port-25.md) | the registry service and the account it leaks |
| 03 | [`03-imap-and-mail.md`](03-imap-and-mail.md) | `sysad:sysad`, the mailbox, the account email |
| 04 | [`04-ssh-and-nexus.md`](04-ssh-and-nexus.md) | SSH to `.110`, linpeas, `/opt/nexus`, port 8005 |
| 05 | [`05-nexus-root.md`](05-nexus-root.md) | API key → Swagger → `id_rsa` → root |

## Why this box matters

It is the counter-example to the AD set. The AD set rewards tooling (BloodHound, ACL abuse, Kerberos);
this box rewards **reading what a service says** — a WHOIS record gives a username, a mail gives a
password, a Swagger parameter gives a file. No exploit code anywhere in the chain.

## The set

This is box 2 of 4 in the same set: **AD set** ([`../ad-fantom-1/`](../ad-fantom-1/)),
**Linux 1 — mail** (this box), **Linux 2 — portal** ([`../lx-portal-2/`](../lx-portal-2/)) and
**Windows** ([`../win-oscp-1/`](../win-oscp-1/)).
