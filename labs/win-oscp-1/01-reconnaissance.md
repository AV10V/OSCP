# 01 — Reconnaissance: `192.168.91.111`

This is the only Windows **standalone** box in the set. It is not domain-joined, it has no AD
infrastructure behind it, and it exposes exactly four things: a website, SMB, RDP, and — hidden in the
site's path space — **Windows PowerShell Web Access**.

## 1.1 Full TCP scan

```bash
nmap -A -T4 -p- 192.168.91.111 -oN nmap/windows.txt
```

The scan completes quickly, which is itself information: a filtered host takes far longer than a
host with four open ports. The result:

```
Nmap scan report for 192.168.91.111
Host is up (0.00xxs latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
443/tcp  open  ssl/https?
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
...
OS: Windows 10.0.17763 (Server 2019)
Computer name: OSCP
```

| Port | Service | Note |
|---|---|---|
| 80 | IIS 10.0 | redirects to HTTPS |
| 443 | HTTPS | the actual site |
| 445 | SMB | **null session allowed** |
| 3389 | RDP | open, not used |

`-p-` matters here. A default top-1000 scan still finds all four, but it also hides how *few* services
there are — and that shapes the plan: there is no second application to pivot to, so the share and the
website are the whole attack surface.

## 1.2 The website

`whatweb` and the TLS certificate agree on the stack:

```bash
whatweb https://192.168.91.111
```

```
https://192.168.91.111 [200 OK]
  Title[LaunchIt - MVP]
  Microsoft-HTTPAPI/2.0
  X-Powered-By[...]
  HTML5, Bootstrap, jQuery
  Nicepage 5.5.4
```

- **`Microsoft-HTTPAPI/2.0`** is the `http.sys` response header. It means the listener may not be IIS
  itself but a kernel-mode HTTP service bound to the port — worth remembering when a virtual host or a
  path behaves oddly.
- **Nicepage 5.5.4** is a site-builder template, not a CMS. There is no `/admin`, no login, no
  database behind it. It is a static "LaunchIt" landing page.
- The landing page is a decoy in the literal sense: it exists so that `443` is open and looks
  uninteresting, while the real entry point is a **path**, not a page.

## 1.3 The path that matters

```
https://192.168.91.111/powershell
```

**Windows PowerShell Web Access** — a Remote Desktop Gateway-style feature that runs a PowerShell
console *inside the browser*. It is not enabled by default; somebody turned it on, which is exactly the
kind of "misconfiguration as intended path" this box is built around.

No directory brute force was needed against this host: the path came from the mail. If you are
approaching the box cold, the standard move is:

```bash
feroxbuster -u https://192.168.91.111 -k \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

Expect `/powershell` to answer with a redirect to `/powershell/` and a login form. (Reconstructed
command — not part of the original attempt.)

## 1.4 SMB in one line

The share list is worth taking before touching the web app, because a null session on `445` is a
complete compromise of confidentiality on its own:

```bash
smbclient -L //192.168.91.111 -U '' -N
```

Details in [`02-smb-emails-zip.md`](02-smb-emails-zip.md). The short version:

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
AnneAuto        Disk      Anne's Automatic BackUps
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

## 1.5 What the scan tells you to do next

| Finding | Next move |
|---|---|
| null SMB session | list and read every share before anything else |
| `AnneAuto` = "Anne's Automatic BackUps" | a *person's* backups → mail archives, credentials |
| `/powershell` | you will need a username and a password, in that order |
| IIS + Nicepage only | no web exploit; stop looking for one |

The order is not arbitrary. The share gives you the **username** (from mail headers) and the
**password** (from a mail body). The web app consumes both. Nothing in this box requires an exploit.

---

**Next:** [`02-smb-emails-zip.md`](02-smb-emails-zip.md)
