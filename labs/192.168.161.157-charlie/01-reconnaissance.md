# 01 — Reconnaissance: four ports, one wrong product name

The box is called `charlie` and it is a Linux host with a short port list. Nothing here needs a
fuzzer. Every decision in this walkthrough comes from reading four banners correctly, and one of
those banners is mislabelled by the scanner.

---

## 1.1 The scan

```bash
nmap -p21,22,80,20000 -T4 --min-rate 10000 --max-retries 2 -n -Pn -sC -sV -A 192.168.161.157
```

```text
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 114      120          4096 Nov 02  2022 backup
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 26:aa:39:5a:05:88:98:d7:e3:ae:26:cb:fe:4b:1c:dc (ECDSA)
|_  256 83:46:c9:90:ca:7e:16:77:4a:1a:78:90:e6:60:77:20 (ED25519)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
20000/tcp open  http    MiniServ 1.820 (Webmin httpd)
|_http-server-header: MiniServ/1.820
|_http-title: Site doesn't have a title (text/html; Charset=utf-8).
```

Four ports. Three of them are the Ubuntu default install. The fourth is the box.

| Port | Service | What it tells us |
|---|---|---|
| 21 | vsftpd 3.0.5 | `ftp-anon: Anonymous FTP login allowed`, and a `backup` directory exists |
| 22 | OpenSSH 8.9p1 | `publickey,password` — both methods offered |
| 80 | Apache 2.4.52 | The stock Ubuntu page. Nothing hosted |
| 20000 | MiniServ 1.820 | A webmin-family panel, on the **user** port |

The FTP line is the only one that volunteers something: an anonymous login and a directory that
was not there by default. That is where the enumeration budget goes.

This was a targeted scan: the four ports came from the service list this range uses, not from a
blind sweep. Sweep the full range anyway before you commit — it costs a minute and it is the only
way to be sure nothing else is listening:

```bash
nmap -p- -T4 --min-rate 2000 -n -Pn 192.168.161.157
```

## 1.2 Port 80 is a dead end, and that is information

The two lines worth having from the scan are the server header and the page title:

```text
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

`/var/www/html` is untouched. No vhost, no CMS, no upload form. A default page is worth thirty
seconds of `whatweb`, not a `gobuster` run — and it tells you the box author did not intend HTTP/80
to be the way in.

## 1.3 Port 20000: the banner says Webmin, the port says Usermin

`MiniServ` is the HTTP daemon that both Webmin and Usermin use. `nmap` sees the string `Webmin` in
the banner and labels the service `Webmin httpd`. That label is wrong here, and it is wrong in a
way that costs time:

| Product | Default port | What it is |
|---|---|---|
| **Webmin** | **10000** | System administration — runs as root, manages the whole host |
| **Usermin** | **20000** | Per-user webmail/account panel — runs as the logged-in user |

Two consequences:

1. **CVE-2019-15107 is not this box.** That is the Webmin 1.890–1.920 backdoor in
   `password_change.cgi`. Version 1.820 is outside the range and Usermin does not have that
   endpoint. Searching "MiniServ 1.820 exploit" lands on it anyway.
2. **The right hit is authenticated.** EDB 50234, *Usermin 1.820 — Remote Code Execution
   (Authenticated)*, needs a username and a password before it does anything. So the panel is not
   the entry point either — it is the second half of a two-step chain.

The confirmation is not in the banner either — it is in the CGI paths. Every request the exploit
makes exists on this host: `/session_login.cgi`, `/gnupg/list_keys.cgi`, `/gnupg/secret.cgi`,
`/gnupg/edit_key.cgi`. `gnupg` is a Usermin module, and 20000 is the Usermin port. Note also that
nmap reported `_http-title: Site doesn't have a title` for 20000 — the login page is a frameset, so
there is no title string to read. Use the paths, the port and the version.

That leaves a single question: where do credentials for a per-user panel come from on a box with
one anonymous service?

## 1.4 Host identity

Confirmed later, from the shell, so it belongs in the notes rather than in the scan:

```bash
uname -a; lsb_release -d
```

```text
Linux lab-pwk2-student-cl6-157-ubuntu2204-charlie-240-111 5.15.0-52-generic #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
Description:    Ubuntu 22.04.1 LTS
```

Ubuntu 22.04.1 with a 5.15 kernel. Modern enough that kernel exploits are a waste of the remaining
budget, and patched enough that the intended path has to be a configuration or application flaw.
It is.

## 1.5 What chapter 01 decided

- **21/tcp** — the only unauthenticated service, and it hands out a directory called `backup`.
- **22/tcp** — noted, not tested yet. It will matter in chapter 05 for the wrong reason.
- **80/tcp** — default page, no content, closed.
- **20000/tcp** — Usermin 1.820, exploitable *after* authentication.

Next: read the backup directory and see what the authors left in the document metadata.
