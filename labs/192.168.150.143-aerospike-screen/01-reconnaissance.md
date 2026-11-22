# 01 — Reconnaissance

Goal: establish what the host actually exposes, and write down what it does not, so that later
rabbit holes can be closed with evidence rather than with a feeling.

---

## 1.1 Full TCP sweep

```bash
mkdir -p ~/Desktop/192.168.150.143 && cd ~/Desktop/192.168.150.143
sudo nmap -Pn -p- --min-rate 3000 --max-retries 1 -T4 192.168.150.143 \
  -oN nmap_full.txt
```

```
Nmap scan report for 192.168.150.143
Host is up (0.073s latency).
Not shown: 65525 filtered tcp ports (no-response)

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
81/tcp   open  hosts2-ns
443/tcp  open  https
3000/tcp open  ppp
3001/tcp open  nessus
3003/tcp open  cgms
3306/tcp open  mysql
5432/tcp open  postgresql
```

Read the first line again: `filtered`, not `closed`. Ten ports answer, and 65525 do not — they are
*swallowed*. Compare with a box that resets: there you can say "nothing else is listening". Here you
can only say "nothing else is reachable from this network position". That distinction matters
because it means the host may well be running services that this path cannot see.

That is not a hypothetical on this box. Port `3002` is `filtered` in this very scan, yet it is part of
the same daemon that owns `3000`, `3001` and `3003` — the information port simply is not exposed to
us. A scan is a view, not an inventory.

Ten open ports and no name for four of them. That is the interesting part of this machine.

---

## 1.2 Service versions

```bash
sudo nmap -Pn -sV -p21,22,80,81,443,3000,3001,3002,3003,3306,5432 192.168.150.143 \
  -oN nmap_services.txt
```

```
PORT     STATE    SERVICE    VERSION
21/tcp   open     ftp        vsftpd 3.0.3
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
81/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open     http       Apache httpd 2.4.41
3000/tcp open     ppp?
3001/tcp open     nessus?
3002/tcp filtered exlm-agent
3003/tcp open     cgms?
3306/tcp open     mysql      MySQL (unauthorized)
5432/tcp open     postgresql PostgreSQL DB 12.9 - 12.13
```

`OpenSSH 8.2p1 Ubuntu 4ubuntu0.4` with `Apache 2.4.41` dates the image: **Ubuntu 20.04**, Focal. A
later shell confirms it exactly — `5.4.0-104-generic`, Ubuntu 20.04.4 LTS.

There is also a small tell in the service line:

```
Service Info: Host: 192.168.131.143
```

The daemon reports a hostname that is not the address we connected to. The machine's own name is
set to whatever address it held when the image was built, and it has since been re-addressed. It is
noise, but it is a useful reminder that banners and self-reports drift while the binary stays put.

Also worth noting what is *not* here: **no Windows**, no SMB, no WinRM. This is a Linux box and the
whole engagement will be Linux primitives.

---

## 1.3 Four ports with no name

`ppp?`, `nessus?`, `cgms?` are nmap shrugs — it matched nothing it recognises and left the guess it
had. 3000/3001/3002/3003 in a contiguous block is a signature in itself. Pull the fingerprints nmap
collected:

```bash
grep -A3 "Port3003" nmap_services.txt | head -20
```

```
SF-Port3003-TCP:V=7.99%I=7%D=11/22%Time=6B0281D5%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1,"\n")%r(GetRequest,1,"\n")%r(HTTPOptions,1,"\n")%r(RTSPRe
SF:quest,1,"\n")%r(Help,1,"\n")%r(SSLSessionReq,1,"\n")%r(TerminalServerCo
SF:okie,1,"\n")%r(Kerberos,1,"\n")%r(FourOhFourRequest,1,"\n")%r(LPDString
SF:,1,"\n")%r(LDAPSearchReq,1,"\n")%r(SIPOptions,1,"\n")
```

Every probe answers with a single bare newline. That is not HTTP, not TLS, not a login banner —
it is a binary protocol that says "wrong packet" and waits. A service that answers *every*
protocol identically with one byte is speaking something that is not text.

The block `3000-3003` is the published default port range of **Aerospike**:

| Port | Role |
|---|---|
| 3000 | service (client API) |
| 3001 | fabric (cluster internals) |
| 3002 | info (ASCII admin) |
| 3003 | heartbeat |

`3000` answering a client protocol and `3002` being filtered fit perfectly: the customer-facing port
is open, the administrative one is not. Confirm it by asking port 3002 a question the way the info
protocol does — key, newline, read:

```bash
printf 'build\nversion\nnamespaces\n' | nc -w 4 192.168.150.143 3002
```

From outside this often returns nothing at all (filtered), which is why the confirmation has to be
done properly with the client later, over 3000. Chapter 03 does exactly that and gets
`build=5.1.0.1`.

---

## 1.4 The web stack, briefly

Three Apache listeners on 80, 81 and 443, all `2.4.41`. Two of them do not serve the same thing.

```bash
curl -sI http://192.168.150.143/
curl -s  http://192.168.150.143/ | grep -i "<title>"
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
...
<title>Apache2 Ubuntu Default Page: It works</title>
```

Port 80 root is the untouched Ubuntu placeholder — the box's real content lives somewhere else. Ask
for `robots.txt` and you get the default `Allow /`; ask for a directory that does not exist and you
get the stock 404. The default page is a decoy, not a target.

Port 81 is much more interesting:

```bash
curl -s http://192.168.150.143:81/ | grep -oiE "<title>[^<]*|nginx[^<]{0,20}" | head -3
```

```
<title>Test Page for the Nginx HTTP Server on Fedora</title>
nginx
```

An **nginx-on-Fedora** test page, served by **Apache on Ubuntu**. That combination does not happen
by accident. Either a reverse proxy is in front of an nginx instance, or an nginx default document
has been dropped into an Apache docroot to make a vhost look like something it is not. Both readings
say the same thing: there is a second application surface here that nobody finished configuring.

That mismatch is worth chasing — it is exactly the shape of configuration where `ProxyPass` lives,
and `mod_proxy` on this version has a known SSRF (CVE-2021-40438). Chapter 02 tests it and reports
the result honestly; it did not pan out. It is recorded anyway, because "I tried the proxy bug" is
part of the evidence that the real entry point was elsewhere.

---

## 1.5 What we owe the rest of the engagement

Two negatives are already established, and both are load-bearing:

- **The default page is not the application.** Port 80 `/` is stock Apache. The content is at
  `/index/` (chapter 02).
- **The unnamed ports are a database.** `3000-3003` is Aerospike's default layout, and the box is
  running a five-year-old minor version of it.

The second one is the one that matters. `vsftpd 3.0.3` is a version with no public RCE, `OpenSSH
8.2p1` and `Apache 2.4.41` are Ubuntu-patched builds, and MySQL/PostgreSQL both demand credentials
we do not have. A database that ships an unauthenticated command-execution primitive needs neither
credentials nor a memory-corruption exploit. That is where the next chapter goes.

> FTP was left untested on this run. It is not a dead end that was refuted — it is a path that was
> never needed. Recording the difference keeps later readers from believing it was checked.
