# 01 — Reconnaissance

Goal: confirm the host is reachable, enumerate every open TCP port, fingerprint the services,
and then — because TCP came back sparse — check UDP as well.

---

## 1.1 Connectivity

```bash
ping -c 2 -W 2 192.168.245.149
```

```
PING 192.168.245.149 (192.168.245.149) 56(84) bytes of data.
64 bytes from 192.168.245.149: icmp_seq=1 ttl=61 time=64.5 ms
64 bytes from 192.168.245.149: icmp_seq=2 ttl=61 time=64.3 ms
```

**Reading it:** TTL 61 means the packet started at 64 and crossed three hops, which on this lab
subnet means a Linux kernel with the default `net.ipv4.ip_default_ttl=64` sitting behind a couple
of routers. Already a hint the box is Linux before a single port is touched. The ~64 ms RTT
confirms it is reachable over the VPN tunnel rather than on-link.

---

## 1.2 Full TCP port scan

Scan all 65535 ports first — never trust a "top 1000" scan on an exam box.

```bash
mkdir -p /tmp/box149 && cd /tmp/box149
nmap -p- --min-rate 3000 -T4 -oN full_tcp.txt 192.168.245.149
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-14 18:07 -0500
Nmap scan report for 192.168.245.149
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 23.54 seconds
```

**Reading it:**

- `65532 closed tcp ports (reset)` — the host answers with RST rather than dropping, so there is
  **no packet filter** in front of it. Every port result here is trustworthy.
- Only three services. That is a deliberately small attack surface, which usually means the
  intended path is a *service misconfiguration* rather than a memory-corruption exploit.
- 23 seconds for a full sweep is the payoff from `--min-rate 3000` on a LAN-speed target.

---

## 1.3 Service and version detection

```bash
nmap -sV -sC -p21,22,80 -oN services.txt 192.168.245.149
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 23:d9:09:5d:d8:89:6d:09:63:e4:b5:5d:b3:ab:45:e6 (RSA)
|   256 d0:e4:e4:db:0b:75:7e:d6:35:f5:e7:b5:d0:c4:aa:90 (ECDSA)
|_  256 3b:9e:f9:d2:46:50:ee:f0:80:ed:eb:c0:7f:d0:e7:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

**Reading it, service by service:**

| Service | Version | Assessment at this point |
|---|---|---|
| FTP | vsftpd 3.0.5 | Recent (3.0.3 > 2.3.4, so the 2011 backdoor is irrelevant). No known RCE. The realistic weakness is **credentials**, not the daemon. |
| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 | Current patched Ubuntu build of 8.2. `regreSSHion` (CVE-2024-6387) affects 8.5p1–9.7p1, so **not** applicable here. Password auth appears enabled (we test that later). |
| HTTP | Apache 2.4.41 Ubuntu | Old, but Ubuntu backports fixes. Worth checking CVE-2021-41773/42013 path traversal, which is *the* classic 2.4.49/2.4.50 bug — note 2.4.41 is outside the officially affected range, but the check costs one request. |

Also note `http-title: Apache2 Ubuntu Default Page: It works` — the stock page. That suggests no
application is deployed, at least not at the document root.

The `ssh-hostkey` fingerprints are worth recording: if the same host reappears on another IP in
the lab, the keys prove it is the same machine.

---

## 1.4 UDP — the step that actually matters

A TCP-only scan finds three well-patched services and the box looks like a wall. UDP is where
OSCP boxes hide their easiest wins, and SNMP is the usual reason.

```bash
nmap -sU --top-ports 30 -T4 --max-retries 1 --host-timeout 180s 192.168.245.149
```

```
53/udp    open|filtered domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
111/udp   open|filtered rpcbind
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open          snmp
162/udp   open|filtered snmptrap
445/udp   closed        microsoft-ds
500/udp   open|filtered isakmp
514/udp   closed        syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
```

**Reading it:** almost everything is `open|filtered`, which is UDP's way of saying "no reply
arrived, and that is not proof of anything". The one word that is not hedged is
**`161/udp open snmp`** — an actual response came back. That is the only solid UDP finding, and it
is the one that leads to root on this box.

> **Lesson worth internalising:** on this host, a complete TCP scan plus a version scan produced
> zero exploitable leads. Thirty UDP ports produced the entire entry point. Budget the extra
> 2–3 minutes.

---

## 1.5 Neighbourhood check

Before committing to a host, confirm what else is on the subnet — sometimes a box is only
solvable after pivoting from a neighbour, and sometimes a neighbour exposes something this host
does not.

```bash
nmap -sn 192.168.245.0/24 -oG - | grep -i up | awk '{print $2}'
```

```
192.168.245.147
192.168.245.149
192.168.245.150
192.168.245.151
192.168.245.254
```

`.254` is the gateway. `.147`, `.149`, `.150`, `.151` are targets. **`.149` has a single network
interface and a default route via `.254`, so it is not a pivot host** — the whole box is reachable
directly from Kali, and nothing has to be tunnelled.

Quick sanity check on the neighbours for later:

```bash
for h in 192.168.245.147 192.168.245.150 192.168.245.151; do
  echo "=== $h ==="
  nmap -Pn -p21,22,80,135,139,443,445,3389,5985,8080 -T4 --max-retries 1 $h \
    | grep -E "^[0-9]+/tcp"
done
```

```
=== 192.168.245.147 ===
21/tcp   open   ftp
22/tcp   open   ssh
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
5985/tcp open   wsman
8080/tcp open   http-proxy
=== 192.168.245.150 ===
22/tcp   open   ssh
8080/tcp open   http-proxy
=== 192.168.245.151 ===
80/tcp   open     http
3389/tcp open     ms-wbt-server
```

`.147` is clearly Windows (RPC/SMB/WinRM); `.151` looks like Windows with a firewall dropping
everything except HTTP and RDP. Recorded for later — not needed for this box.

---

## Findings so far

| # | Observation | Weight |
|---|---|---|
| 1 | vsftpd 3.0.5 with (later confirmed) password auth | **high** — credentials are the weak point |
| 2 | Apache 2.4.41 stock default page | low — probably nothing deployed |
| 3 | **snmpd on UDP/161** | **critical** — unexplored, historically very leaky |
| 4 | No packet filter, RST on closed ports | informational |
| 5 | Single NIC, not a pivot | informational |

Next: [02 — Web enumeration](02-web-enumeration.md), where I confirm the obvious `80/tcp`
candidate is a waste of time before spending more on it.

Next actionable target: **SNMP**, chapter 03.
