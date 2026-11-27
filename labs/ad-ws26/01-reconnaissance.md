# 01 — Reconnaissance

Three addresses, one domain, and only one of them answers from the exam network. The other two sit
behind it, which is why this box is a pivot before it is anything else.

## 1.1 The target list

```text
172.16.97.200
172.16.97.202
172.16.97.206
```

Domain: `oscp.exam` (NetBIOS `OSCP`). Two host names show up once shells start: `WS26`, the member
server that is reachable from the start, and `SRV22`, the domain controller behind it.

| Address | Host | Role | Reachable from Kali |
|---|---|---|---|
| `172.16.97.206` | `WS26` | member server, XAMPP, WinRM | yes |
| `172.16.97.200` | `SRV22` | domain controller, Server 2022 | only through `WS26` |
| `172.16.97.202` | `[redacted]` | second member server | only through `WS26`, never breached |

## 1.2 The scan that matters

```bash
sudo nmap -sV -p- -T4 --min-rate 2000 172.16.97.206 -oN nmap/WS26.txt
```

```text
Nmap scan report for 172.16.97.206
Host is up (0.046s latency).
Not shown: 65527 filtered tcp ports (no-response)

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp open  http          Apache httpd 2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
```

`5985` is the door: WinRM is exposed on a member server, and the set hands over a domain credential
before the scan even finishes.

The SMB script fills in the identity:

```bash
nmap -sV -p445 --script smb-os-discovery 172.16.97.206
```

```text
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: WS26
|   NetBIOS computer name: WS26
|   Domain name: oscp.exam
|   Forest name: oscp.exam
|   FQDN: WS26.oscp.exam
|   NetBIOS domain name: OSCP
|_  System time: 2026-07-16T06:41:12+00:00
```

## 1.3 The web root

Three HTTP ports on the same host is the XAMPP bundle, and the title says so:

```bash
curl -sI http://172.16.97.206/
curl -s http://172.16.97.206/ | head -20
```

```text
HTTP/1.1 200 OK
Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
X-Powered-By: PHP/8.2.12
Content-Type: text/html; charset=UTF-8
```

```html
<title>XAMPP</title>
...
<h1>XAMPP</h1>
<h2>Welcome to XAMPP for Windows 8.2.12</h2>
```

`/phpmyadmin/` answers with the phpMyAdmin login page, and `443` serves the same application over
TLS. A MySQL-backed application on a domain-joined server means a database full of credentials is one
`config.inc.php` away — and that is exactly the trap this box sets.

## 1.4 The domain controller

`172.16.97.200` does not answer from the exam network. It is reached after the tunnel is up
(see [`04-pivot.md`](04-pivot.md)), and the scan there is unambiguous:

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

```text
| smb-os-discovery:
|   OS: Windows Server 2022 Standard 20348
|   Computer name: SRV22
|   NetBIOS computer name: SRV22
|   Domain name: oscp.exam
|   Forest name: oscp.exam
|   FQDN: SRV22.oscp.exam
|   NetBIOS domain name: OSCP
| ssl-cert: Subject: commonName=SRV22.oscp.exam
|_Subject Alternative Name: DNS:SRV22.oscp.exam
```

That is a full domain controller: DNS, Kerberos, LDAP on `389` and the global catalog on `3268`,
LDAPS, `kpasswd`, and the AD Web Services endpoint on `9389`. WinRM is open there too, which is worth
remembering for later — a domain credential that reaches a DC over WinRM would be the end of the set,
and this credential does not.

## 1.5 Reading the scan correctly

| Observation | What it means | What to do |
|---|---|---|
| `5985` on the member server | WinRM is exposed | validate the given credential there first |
| XAMPP on `80/443/8080` | a PHP application with MySQL behind it | enumerate it, but expect a decoy |
| `445` open on every host | SMB is the shared surface | credential validation and share enumeration |
| DC ports only behind `WS26` | the domain is not directly reachable | a tunnel is mandatory before Kerberos or LDAP work |
| `3389` on the member server | RDP is available once a local admin exists | alternative access, not an entry point |

## 1.6 Order of work

1. **Validate the given credential over SMB, then WinRM, on `172.16.97.206`.** It costs a minute and
   it is the intended door.
2. **Read the token before attacking anything** — `whoami /priv` decides the whole box
   (see [`03-privilege-escalation.md`](03-privilege-escalation.md)).
3. **Pivot before touching Kerberos.** `SRV22` is not reachable without the tunnel, so every
   domain-level attack waits for [`04-pivot.md`](04-pivot.md).
4. **Leave the web application for last.** A credential dump from phpMyAdmin looks like progress and
   usually is not.

---

**Next:** [`02-foothold-ws26.md`](02-foothold-ws26.md)
