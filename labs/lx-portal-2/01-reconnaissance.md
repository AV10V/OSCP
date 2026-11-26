# 01 — Reconnaissance: `192.168.91.112`

A four-port Linux box: FTP, SSH, HTTP and MySQL. The web root and the FTP hold the same application,
which is what makes the box solvable without guessing a single filename.

## 1.1 Ports

```bash
nmap -sC -sV -p- 192.168.91.112 -oN nmap/portal.txt
```

```text
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

| Port | Service | Note |
|---|---|---|
| 21 | FTP | **anonymous login works** — see [`02-ftp-anonymous.md`](02-ftp-anonymous.md) |
| 22 | SSH | no credentials yet; becomes the way in after the `.env` leak |
| 80 | HTTP | PHP site with a CV upload portal |
| 3306 | MySQL | reachable, no credentials; never needed |

The version column does not change the plan: anonymous FTP first, then the web root, then the database
only if the application hands you a credential. It never does — the credential that matters is in a
`.env` file on disk, not in MySQL.

## 1.2 HTTP

`http://192.168.91.112/` is a small corporate site: `about.php`, `contact.php`, stock images, a
looping background media file. Nothing on the front page is interactive.

`feroxbuster` against it:

```bash
feroxbuster -u http://192.168.91.112 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

The banner confirms the defaults in use:

```text
feroxbuster 2.13.1
Target Url       | http://192.168.91.112
Threads          | 200
Wordlist         | /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
Status Codes     | [200]
Timeout          | 7s
User-Agent       | feroxbuster/2.13.1
Extract Links    | true
```

The findings that matter:

```text
200      GET   ...  http://192.168.91.112/about.php
200      GET   ...  http://192.168.91.112/contact.php
301      GET   ...  http://192.168.91.112/applications  =>  /applications/
```

The rest of the nine hits are static assets (`.jpg`, `.mp4`, `.js`). The scan was stopped early with
`Ctrl-C`; the directory that matters had already appeared.

| Path | Why |
|---|---|
| `/about.php`, `/contact.php` | plain pages — no parameters worth testing |
| **`/applications`** | directory exists and returns an Apache **directory listing** |

## 1.3 The directory listing

`http://192.168.91.112/applications/` answers with `Index of /applications` — `Options +Indexes` is on.
That single misconfiguration turns the web server into a file browser and makes the whole application
enumerable: source files, uploads, backups, all of it.

Among the entries is the portal itself:

```text
/applications/upload.php
```

## 1.4 The shape of the box

```text
21/tcp anonymous ──▶ backup archive ──▶ names the app directory
80/tcp  ferox    ──▶ /applications  ──▶ directory listing ──▶ upload.php
```

FTP and the web root describe the *same* application: the archive is a backup of the site, and the site
exposes an upload form. Reading `upload.php` — from the archive or from the listing — is what turns the
form from a guess into a bypass, and it is the subject of the next two chapters.

---

**Next:** [`02-ftp-anonymous.md`](02-ftp-anonymous.md)
