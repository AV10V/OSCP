# 01 — Reconnaissance

Goal: find every reachable service, then identify the **product** behind each one. A port number is
only a door; the version behind it decides whether the door opens.

---

## 1.1 The full TCP scan

```bash
export TARGET=192.168.133.155
nmap -Pn -n -p- --min-rate 2000 --max-retries 2 -T4 \
     -oN exam.$TARGET/${TARGET}_discovery.nmap $TARGET
```

```
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
5986/tcp  open  wsmans
7680/tcp  open  pando-pub
9099/tcp  open  unknown
9999/tcp  open  abyss
35913/tcp open  unknown
```

Six ports out of 65535, and every other port answers `closed (reset)` rather than `filtered`. That
distinction is worth a sentence: `closed` means the host replied with RST, so a firewall is **not**
dropping traffic here — this is a workstation with a handful of services, not a hardened perimeter.

## 1.2 Version and default scripts

```bash
nmap -Pn -n -sS -sC -sV -p 80,5986,7680,9099,9999,35913 -T4 \
     -oA exam.192.168.133.155/192.168.133.155_full 192.168.133.155
```

```
80/tcp    open  http       Microsoft IIS httpd 10.0
| http-methods: Potentially risky methods: TRACE
| http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
5986/tcp  open  wsmans
| ssl-cert: Subject: commonName=Cloudbase-Init WinRM
|_Not valid before: 2026-11-23T04:07:57   Not valid after: 2036-11-21T04:07:57
| tls-alpn: h2, http/1.1
7680/tcp  open  pando-pub
9099/tcp  open  unknown
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, NCP, SSLSessionReq:
|     HTTP/1.0 200 OK
|     Server: Mobile Mouse Server
|     Content-Type: text/html
|     Content-Length: 321
|     <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width...
9999/tcp  open  abyss
35913/tcp open  unknown
```

| Port | Service | Reading |
|---|---|---|
| 80 | IIS 10.0, `TRACE` enabled | default page — no application, but TRACE is a finding |
| 5986 | WinRM over HTTPS | cert issued by `Cloudbase-Init`; remote management ships enabled in the image |
| 7680 | Delivery Optimization | Windows default, ignore |
| **9099** | **Mobile Mouse Server** | a remote-control server answering the network |
| 9999 | `abyss` (nmap guess) | unidentified, low priority |
| 35913 | Mobile Mouse WebSocket | same product, second interface |

## 1.3 The port nmap could not name

`9099` has no entry in nmap's service database, so `-sV` prints `unknown`. That does **not** mean the
probe learned nothing: the `fingerprint-strings` block recorded the server's own reply, and the reply
names the product — `Server: Mobile Mouse Server`. Two cheap confirmations:

```bash
curl -s -i http://192.168.133.155:9099/
nmap -Pn -p 9099 -sV --version-all --script=banner 192.168.133.155
```

```
HTTP/1.0 200 OK
Server: Mobile Mouse Server
Content-Type: text/html
Content-Length: 321

<HTML><HEAD><TITLE>Success!</TITLE>...
```

**Reading it:** an HTTP-shaped 321-byte page titled `Success!` on a port that is not a web server is
the signature of a desktop application's control channel, exposed to the LAN. Port 35913 is the same
product's WebSocket listener — nmap called it `unknown` too, and it is the second documented vector.

> **Method note.** When `-sV` says `unknown`, do not drop the port. Grep the XML for
> `fingerprint-strings` before re-scanning; the product name is usually in the banner, the TLS
> certificate, or the 404 body.
