# 01 — Reconnaissance: sixteen TCP ports, one UDP port that mattered

The target is a hosting server. Sixteen TCP ports, a full mail stack, a control panel, and — as it
turned out — one UDP port that decided the whole box.

---

## 1.1 Full TCP scan

Never trust a top-1000 sweep on a hosting box; the interesting panel is usually in the 8000s.

```bash
nmap -p- -sV --min-rate 3000 -oN nmap_full.txt 192.168.161.156
```

Sixteen ports, and every one of them is a real service:

```text
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
25/tcp   open  smtp     Exim smtpd 4.90_1
53/tcp   open  domain   ISC BIND 9.11.3-1ubuntu1.18
80/tcp   open  http     nginx
110/tcp  open  pop3     Dovecot pop3d
143/tcp  open  imap     Dovecot imapd
465/tcp  open  smtps    Exim smtpd 4.90_1
587/tcp  open  submission  Exim smtpd 4.90_1
993/tcp  open  imaps    Dovecot imapd
995/tcp  open  pop3s    Dovecot pop3d
2525/tcp open  smtp     Exim smtpd 4.90_1
3306/tcp open  mysql    MySQL 5.7.40-0ubuntu0.18.04.1
8080/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
8083/tcp open  http     nginx
8443/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
```

**Reading it:**

- **80 and 8083 are nginx; 8080 and 8443 are Apache.** Two web servers on one host, with nginx in
  front. That is a reverse-proxy layout, not a single site.
- **`mod_fcgid`** means PHP-FPM-style execution under Apache. On a hosting panel that usually means
  PHP runs as the **vhost owner**, not `www-data` — a PHP file you control is a real user shell.
- **Four SMTP listeners** (25, 465, 587, 2525) and a complete Dovecot stack. This is a mail server.
- **`3306` reachable from the network** is notable on its own. Panel installers bind MySQL to
  `127.0.0.1`; a remote handshake means somebody changed `bind-address`.
- No `88`, `389`, `636`, `445`. **Standalone host, not a domain member.** AD tooling is wasted here.

## 1.2 The TLS certificate names the product

Every mail port and FTP present the same certificate. That is free fingerprinting — read it before
you fuzz anything.

```bash
nmap -p21,25,110,143,465,587,993,995 --script ssl-cert 192.168.161.156
```

```text
Subject: commonName=oscp.example.com
         organizationName=Vesta Control Panel
         stateOrProvinceName=California
         countryName=US
Not valid before: 2022-11-08T08:16:51
Not valid after:  2023-11-08T08:16:51
```

**Reading it:**

- `O=Vesta Control Panel` is the answer to "what is on 8083" before you ever open it.
- A **2022-11-08** build date sets the patch baseline. Ubuntu 18.04 with a late-2022 image means
  most 2018–2019 CVEs are patched; anything from 2021 onward may still be live.
- `CN=oscp.example.com` is the vhost the panel was installed for. Remember it — the panel's upload
  handler compares `HTTP_ORIGIN` against exactly this name and dies on a mismatch.
- The certificate expired in 2023. Nobody renewed it, which is a small signal that the box is
  unmaintained.

## 1.3 The scan that was missing

The whole TCP surface is a distraction. The entry point was on **UDP/161**, and no TCP scan can
see it.

```bash
sudo nmap -sU -p 53,69,123,137,161,500,623 --script snmp-info,snmp-sysdescr 192.168.161.156
```

```text
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   snmpEngineBoots: 15
|_  snmpEngineTime: 55m02s
53/udp  open  domain  ISC BIND 9.11.3-1ubuntu1.18
```

**Reading it:**

- `SNMPv1 server ... (public)` — the NSE script has already told us the community string is
  `public` and that v1 is accepted. That is unauthenticated read access to the entire MIB tree.
- `snmpEngineBoots: 15` means the daemon has been up a while and is not being restarted defensively.
- v1 matters: SNMPv1 has no per-user authentication, so a community string is the *only* control.

`-p-` on TCP is not a port scan. It is a TCP port scan. The distinction cost more time on this box
than any other single mistake.

## 1.4 What the shape of the box implies

Before touching an exploit, the layout constrains the answer:

| Observation | Implication |
|---|---|
| Vesta panel on 8083, Apache back-end on 8080/8443 | Hosting control plane — it runs privileged shell commands for users |
| `mod_fcgid` | PHP runs as vhost owner, so webshell = user shell |
| Full Exim + Dovecot + Roundcube stack | Mailboxes will hold credentials and mail |
| MySQL on the network | Either an exposed database or a deliberately weakened one |
| `O=Vesta Control Panel`, expired cert | Unmaintained install, panel-era vulnerabilities plausible |
| `161/udp public` | Free unauthenticated read of the host's MIB tree |

The intended path on a panel box is almost never "exploit the web server". It is **get any account,
then abuse the panel's own privilege**. Chapter 03 is where the account comes from.
