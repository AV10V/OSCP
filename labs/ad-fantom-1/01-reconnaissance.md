# 01 — Reconnaissance

One routable host in the set. The interesting part is not the port list but the shape of it:
a **Windows** box serving an **Apache/PHP** stack on 80 and **MySQL** on 3306 — i.e. a workstation
running a web application, not a hardened server — plus RDP and WinRM. That combination is the whole
box in one line: web app → database → local users.

## 1.1 Full-port scan

```bash
nmap -A -T4 -p- 192.168.91.206 --min-rate 1200
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-19 06:20 CEST
Warning: 192.168.91.206 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.91.206
Host is up (0.11s latency).
Not shown: 65500 closed tcp ports (conn-refused)

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.58 ((Ubuntu) OpenSSL/3.1.3 PHP/8.2.12)
| http-cookie-flags:
|   /
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.58 ((Ubuntu) OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Home - OffSec SOC
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MySQL 8.0.35-3.13 or earlier (unauthorized)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WS01.oscp.exam
| Not valid before: 2026-07-18T06:19:52
| Not valid after:  2027-07-17T06:19:52
5985/tcp  open  wsman
Service Info: Host: OSCP; OS: Windows
```

Notes on the scan itself:

- `-p-` with `--min-rate 1200` is what you want under exam time pressure, but **read the warnings**.
  This one says a port was given up on (`retransmission cap hit`) — 5985/WinRM still showed up, but
  the lesson is to re-scan anything the script reports as `filtered` or that you expect and do not see.
- The TLS block under 3389/3306 is a self-signed cert with `CN=WS01.oscp.exam`, which is the first
  confirmation of the hostname before SMB even answers.
- `5985/tcp` is the one that matters: this is a **WinRM** box, not an RDP-first box.

## 1.2 Identity — SMB and domain

`nmap`'s SMB scripts already give the domain shape:

```
Host script results:
| smb-os-discovery:
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: WS01.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.22000
|_  System_Time: 2026-07-19T06:42:53+00:00
```

Cross-checked with netexec:

```bash
nxc smb 192.168.91.206
```

```
SMB  192.168.91.206  445  WS01  [*] Windows 11 Build 22000 x64 (name:WS01) (domain:oscp.exam) (signing:False) (SMBv1:None)
```

What this tells us:

| Fact | Why it matters |
|---|---|
| `WS01.oscp.exam`, build 22000 | Windows 11 **workstation**, not a server |
| `signing:False` | SMB relay is theoretically on the table (not needed on this box) |
| domain `oscp.exam`, NetBIOS `OSCP` | every credential is `OSCP\user` / `oscp.exam\user` |
| port 80 serving an app called *OffSec SOC* | the box's real attack surface is the web app |

## 1.3 Web surface

The title `Home - OffSec SOC` and the PHP/MySQL stack point at a small asset/helpdesk-style
application. No browser session is needed: the chain goes straight to WinRM with the provided
credential and reads `config.php` from disk instead of attacking the app.
That is the faster path on this box: the source is already on the filesystem once you have a shell.

## 1.4 Hosts file habit

Add the name early; every later command reads better and avoids certificate/SMB name mismatches:

```bash
echo '192.168.91.206  WS01.oscp.exam WS01' | sudo tee -a /etc/hosts
```

---

**Next:** [`02-foothold.md`](02-foothold.md)
