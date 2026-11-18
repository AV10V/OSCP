# 01 — Reconnaissance

A Windows host that firewalls almost everything, but leaves an entire telephony platform
answering on thirteen ports. The useful discovery is not a port number — it is a *version*.

| Step | Runs on |
|---|---|
| 1.1 Full TCP scan | Kali |
| 1.2 Service fingerprint | Kali |
| 1.3 Port 80 | Kali |
| 1.4 Triage | Kali |

---

## 1.1 Full TCP scan

**On Kali**

```bash
nmap -Pn -p- --min-rate 1000 -T4 --max-retries 2 -oN full_tcp.txt 192.168.137.151
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-18 14:38 -0500
Nmap scan report for 192.168.137.151
Host is up (0.070s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
2855/tcp open  msrp
2856/tcp open  cesdinv
3389/tcp open  ms-wbt-server
5060/tcp open  sip
5066/tcp open  stanag-5066
5080/tcp open  onscreen
5986/tcp open  wsmans
7443/tcp open  oracleas-https
7680/tcp open  pando-pub
8021/tcp open  ftp-proxy
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 70.73 seconds
```

**Reading it:** `65522 filtered (no-response)` is the headline. This is not a host with thirteen
services — it is a host with a **filtering firewall that drops** everything except thirteen ports.
That changes strategy in two ways:

- A negative result on any other port proves nothing, so there is no point sweeping further.
- The thirteen open ports are open *on purpose*. Somebody wrote allow rules for them.

## 1.2 Service fingerprint

**On Kali**

```bash
nmap -Pn -sV -sC -p80,2855,2856,3389,5060,5066,5080,5986,7443,7680,8021,8081,8082 \
     --version-intensity 5 -oN services.txt 192.168.137.151
```

```
PORT     STATE SERVICE             VERSION
80/tcp   open  http                Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
2855/tcp open  msrp?
2856/tcp open  ssl/cesdinv?
| ssl-cert: Subject: commonName=FreeSWITCH/countryName=US
| Not valid before: 2022-10-28T14:47:12
|_Not valid after:  1986-09-04T08:18:56
3389/tcp open  ms-wbt-server       Microsoft Terminal Services
| ssl-cert: Subject: commonName=OSCP
| rdp-ntlm-info:
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.19041
5060/tcp open  sip-proxy           FreeSWITCH mod_sofia 1.10.1~64bit
|_sip-methods: INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, UPDATE, REGISTER, REFER, NOTIFY, PUBLISH, SUBSCRIBE
5080/tcp open  sip-proxy           FreeSWITCH mod_sofia 1.10.1~64bit
5986/tcp open  ssl/wsmans?
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
7443/tcp open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=FreeSWITCH/countryName=US
8021/tcp open  freeswitch-event    FreeSWITCH mod_event_socket
8081/tcp open  websocket           (WebSocket version: 13)
8082/tcp open  ssl/websocket       (WebSocket version: 13)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
```

**Reading it:** the box is a **FreeSWITCH PBX**, and it names its own build twice:

- `5060/tcp` and `5080/tcp` → `FreeSWITCH mod_sofia 1.10.1~64bit`
- `8021/tcp` → `FreeSWITCH mod_event_socket`

Four other ports (2856, 7443, 8082 and the SIP pair) carry a self-signed certificate with
`commonName=FreeSWITCH` and a `notAfter` date of **1986** — an expired, placeholder certificate
shipped with the installer, not a real deployment artefact.

Two independent facts identify the host without touching a vulnerable endpoint:

- `rdp-ntlm-info` leaks `Target_Name: OSCP`, `Product_Version: 10.0.19041` → Windows 10 21H2 class.
- The `notBefore` dates of the RDP and WinRM certificates are the *same day* the box was built
  (`2026-11-18`), which is the lab provisioning timestamp.

`mod_event_socket` on **8021** is the interesting one. It is FreeSWITCH's control interface: a
line-based text protocol that, once authenticated, lets a client run internal API commands —
including `api system <command>`. That is a documented feature, and it is exactly what makes
this box exploitable when the default password is left in place.

## 1.3 Port 80

**On Kali**

```bash
curl -sS -i --max-time 10 http://192.168.137.151/
```

```
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 04 Nov 2022 21:26:41 GMT
Accept-Ranges: bytes
ETag: "fd1b6c2194f0d81:0"
Server: Microsoft-IIS/10.0
Date: Thu, 19 Nov 2026 02:44:04 GMT
Content-Length: 696

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows</title>
```

**Reading it:** the stock IIS landing page. `Last-Modified: 2022` matches the FreeSWITCH installer
date, so this is the untouched default site that ships with the Windows image — not an application.
`TRACE` being enabled is noted and discarded: TRACE is a cross-site tracing curiosity, not an
escalation path, and there is no cookie worth stealing yet.

No vhost fuzzing, no directory brute force. On a default IIS page there is nothing to find, and
chapter 02 is where the real surface is.

## 1.4 Triage

| Port | Service | Verdict |
|---|---|---|
| 80/tcp | IIS 10.0 default page | untouched default site — no application, ignore |
| 2855/tcp | unidentified | nmap could not fingerprint it; no useful banner returned |
| 2856/tcp | TLS, FreeSWITCH certificate | same expired 2022 certificate as the SIP ports — part of the PBX |
| 3389/tcp | RDP | leaks hostname `OSCP`, build `19041`. Credentials unknown, keep for later |
| 5060, 5080/tcp | FreeSWITCH mod_sofia **1.10.1** | **version identified** — the SIP surface |
| 5986/tcp | WinRM over TLS | Cloudbase-Init certificate. Needs credentials, none held |
| 7443, 8082/tcp | TLS, FreeSWITCH certificate | 8082 answers as WebSocket; 7443 did not identify — both present the PBX certificate |
| **8021/tcp** | **FreeSWITCH mod_event_socket** | **the control plane — everything goes here** |
| 7680/tcp | Delivery Optimization | Windows default, no interaction |
| 8081/tcp | WebSocket | FreeSWITCH websocket, same product |

The version matters more than the port list: **FreeSWITCH 1.10.1** is the release that ships with
the well-known default event-socket password `ClueCon`, and `mod_event_socket` is designed to run
API commands. One product, one version, one exposed control interface.

→ [02 — The event socket](02-esl.md)
