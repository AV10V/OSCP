# 01 — Reconnaissance: a box with nothing on it

```bash
nmap -A -T4 -p- 192.168.91.119
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-19 15:26 CEST
Nmap scan report for 192.168.91.119
Host is up (0.13s latency).
Not shown: 65528 filtered tcp ports (no-response)

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b8:17:53:3d:09:be:a8:9c:3c:3e:82:4b:4c:9c:22:c2 (ECDSA)
|   256 9f:47:53:a9:2f:08:48:cd:b5:8b:35:4e:af:df:ca:6b (ED25519)
25/tcp  open  smtp
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest, SSLSessionReq:
|     % OSCP.EXAM Domain Registry
|     entries found for the queried object:
|     attendance, contact: d.oscp.exam
|     ERROR: no entries found
|     match was found in the registry database.
|     WHOIS query
|_  NoDup: closed help
110/tcp open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=mail
| Subject Alternative Name: DNS:mail
| Not valid before: 2026-02-27T18:13:19
| Not valid after:  2026-02-28T18:13:19
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN LOGIN) STLS USER TOP RESP-CODES CAPA AUTH-RESP-CODE PIPELINING USER
143/tcp open  imap     Dovecot imapd
| ssl-cert: Subject: commonName=mail
| Subject Alternative Name: DNS:mail
| Not valid before: 2026-02-27T18:13:19
| Not valid after:  2026-02-28T18:13:19
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: SASL-IR post-login ENABLE have OK listed AUTH=+LOGIN+A0001 capabilities LITERAL+ Pre-login S... PREAUTH? more STARTTLS IDLE LOGIN-REFERRALS
587/tcp open  smtp?
993/tcp open  imaps?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 1.1 Reading the scan

| Port | Claimed service | What it actually is |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 — no version to exploit, so credentials or keys |
| 25 | SMTP | **not SMTP**: the fingerprint is a WHOIS registry ("OSCP.EXAM Domain Registry", "WHOIS query") |
| 110 | POP3 | Dovecot — mailbox |
| 143 | IMAP | Dovecot — mailbox |
| 587 | SMTP submission | part of the same mail stack |
| 993 | IMAPS | part of the same mail stack |

This is what "nothing open" looks like on an OSCP-style Linux box. There is no HTTP, no writable
share, no file service, no version with a public CVE. Every path either needs credentials or ends in
a mail protocol.

## 1.2 The one anomaly worth following

`nmap` says port 25 speaks SMTP, but the `fingerprint-strings` block is a **directory lookup**:

```
% OSCP.EXAM Domain Registry
entries found for the queried object:
attendance, contact: d.oscp.exam
ERROR: no entries found
match was found in the registry database.
WHOIS query
```

Three things follow from that text:

1. The service is a **WHOIS-style registry**, not a mail transfer agent.
2. It answers with "entries found for the queried object" — so it takes a **query argument**.
3. It is a Linux box pretending to be an SMTP server, which means the box wants you to talk to it
   by hand.

The TLS certificate (`CN=mail`, valid for exactly **24 hours**) is there to reinforce the mail
disguise. A one-day cert is also a hint that the box was built fresh for the exam attempt.

## 1.3 Reading the scan

Nothing is open that can be used without an account — except the mail stack, which needs
credentials, and the WHOIS service, which does not.

So the intended order is: read the WHOIS service → get an account → use it on the mail service, not
on SSH. Brute-forcing SSH here is the time sink — exactly the trap the box is built around.

---

**Next:** [`02-whois-on-port-25.md`](02-whois-on-port-25.md)
