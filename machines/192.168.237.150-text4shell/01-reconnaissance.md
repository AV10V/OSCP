# 01 — Reconnaissance

Three open ports, one of which is the only thing on the box that accepts input. This chapter
establishes the attack surface and rules the rest of it out.

| Step | Runs on |
|---|---|
| 1.1 Host discovery | Kali |
| 1.2 Full TCP scan | Kali |
| 1.3 Service fingerprint | Kali |
| 1.4 Port 5000 by hand | Kali |
| 1.5 The web service | Kali |

---

## 1.1 Host discovery

**On Kali**

```bash
ping -c 3 192.168.237.150
```

```
PING 192.168.237.150 (192.168.237.150) 56(84) bytes of data.
64 bytes from 192.168.237.150: icmp_seq=2 ttl=61 time=67.6 ms
64 bytes from 192.168.237.150: icmp_seq=3 ttl=61 time=67.5 ms

--- 192.168.237.150 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1998ms
rtt min/avg/max/mdev = 67.464/68.884/71.614/1.930 ms
```

TTL 61 → the packet left the target with TTL 64 and crossed three hops, so this is a Linux host
(the VPN gateway counts). The ~68 ms round trip is the tunnel, not the host — it matters later when
timing is used as an oracle, so it is worth measuring now.

## 1.2 Full TCP scan

**On Kali**

```bash
nmap -Pn -p- --min-rate 1000 -T4 -oN full_tcp.txt 192.168.237.150
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-15 20:41 -0500
Nmap scan report for 192.168.237.150
Host is up (0.067s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 40.22 seconds
```

**Reading it:** three ports, all TCP — no UDP sweep needed at this stage. `65532 closed ... (reset)`
means the host answers RST rather than dropping, so there is no firewall filtering the port range;
what the scan shows is the complete TCP surface.

Port **5000** is labelled `upnp` only because 5000/udp is IANA-registered to UPnP; nmap is guessing
from the port number alone. Never trust that label — 1.4 shows what it really is.

## 1.3 Service fingerprint

**On Kali**

```bash
nmap -Pn -sV -sC -p22,5000,8080 -oN services.txt 192.168.237.150
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
|_http-favicon: Spring Java Framework
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint:
SF-Port5000-TCP:...%r(NULL,4A,"Available\x20Processors:\x201\r\nFree\x20Memory:\x2024903408\r\n
SF:Total\x20Memory:\x2032440320\r\n\r\n")...
```

Three things fall out of this:

- **`OpenSSH 8.9p1 Ubuntu 3`** on an Ubuntu 22.04.1 kernel — a fully patched distro. No version-based
  sshd exploit is going to be relevant, and there are no credentials yet anyway.
- **`Apache Tomcat` + `Spring Java Framework` favicon** on 8080. Nmap says Tomcat because Spring
  Boot embeds it; the favicon fingerprint is the useful part. This is a Java application server.
- **Port 5000 answers every probe with the same 74 bytes** of text about processors and memory. That
  is not a protocol — nmap gave up and dumped its fingerprint because the service replies to
  everything identically.

## 1.4 Port 5000 by hand

**On Kali**

```bash
printf 'hello\n' | nc -w 5 192.168.237.150 5000 | cat -v
```

```
Available Processors: 1^M
Free Memory: 24814256^M
Total Memory: 32440320^M
^M
```

**Reading it:** it is not HTTP either — sending a GET gets the same banner:

**On Kali**

```bash
curl -sS -i http://192.168.237.150:5000/
```

```
curl: (1) Received HTTP/0.9 when not allowed
Available Processors: 1
```

The service reads nothing, validates nothing, and writes three lines from a Java `Runtime` object
(`availableProcessors()`, `freeMemory()`, `totalMemory()` — the exact method names in chapter 05
confirm this). It is a JVM that likes to talk about itself.

Value to us: **the host runs Java**, and someone deliberately exposed JVM internals on a socket.
Without a source read it stays a dead end — it never accepts input, so there is nothing to inject
into. Noted and moved on.

## 1.5 The web service

**On Kali**

```bash
curl -sS -i http://192.168.237.150:8080/
curl -sS -i "http://192.168.237.150:8080/search?query=test"
```

```
HTTP/1.1 200 
Content-Type: text/plain;charset=UTF-8
Content-Length: 19

{"api-status":"up"}

HTTP/1.1 200 
Content-Type: text/plain;charset=UTF-8
Content-Length: 25

{"query":"test","result":""}
```

**Reading it:**

- `Content-Type: text/plain` with a JSON body, no framework HTML anywhere. This is an API, not a UI.
- The root is a health check. `/search` is the only real endpoint seen so far.
- `query` is echoed **verbatim** and `result` is an empty string regardless of input.

That last point is the important one, and chapter 02 is entirely about it. A parameter that is
reflected unchanged and a result that never changes is exactly what a *blind* injection looks like.

## 1.6 Triage

| Port | Service | Verdict |
|---|---|---|
| 22/tcp | OpenSSH 8.9p1 | patched; no credentials yet — keep for later, nothing to attack |
| 5000/tcp | JVM stats printer | unauthenticated but write-only; information disclosure only |
| 8080/tcp | Spring Boot JSON API | **only input surface on the box** — all effort goes here |

One endpoint, one parameter, one echo. → [02 — Web enumeration](02-web-enumeration.md)
