# 01 — Reconnaissance

Goal: establish what the host actually exposes, and — just as important — write down what it
*doesn't*, so later rabbit holes can be closed with evidence instead of vibes.

---

## 1.1 Full TCP sweep

```bash
mkdir -p ~/Desktop/192.168.161.144 && cd ~/Desktop/192.168.161.144
sudo nmap -Pn -p- --min-rate 3000 --max-retries 1 -T4 192.168.161.144 \
  -oN nmap_full.txt
```

```
Nmap scan report for 192.168.161.144
Host is up (0.069s latency).
Not shown: 65532 closed tcp ports (reset)

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

`65532 closed` — not `filtered`. That matters. A `reset` means the host's stack is answering
RFC-compliantly: there is no packet filter in front of this box, so anything that is not listed is
genuinely not listening. There is no hidden service waiting on a non-standard port.

Three services, and a name for each. Time to fingerprint them.

---

## 1.2 Service versions

```bash
sudo nmap -Pn -sV -p21,22,80 192.168.161.144 -oN nmap_services.txt
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

`OpenSSH 8.9p1 Ubuntu 3` plus `Apache 2.4.52` dates the release: **Ubuntu 22.04.1 LTS**. That single
inference is more useful than the FTP banner, because it tells us the kernel family we will be
auditing later (`5.15.0-x-generic`).

The FTP banner is worth a note:

```bash
nc -vn 192.168.161.144 21
```

```
220 (vsFTPd 3.0.5)
```

`3.0.5` is the current upstream release. There is no published remote code execution for it. The
only famous vsftpd bug — the `USER :)` smiley backdoor on port `6200` — shipped in **2.3.4**
(2011) and was removed in 2.3.5. Anyone who tells you "vsftpd 3.0.5, go get the backdoor exploit"
is repeating a version number without reading it.

So the FTP service is not going to be *exploited*. It may still be *used*, with credentials we do
not have yet.

---

## 1.3 The dead end that has to be documented

A `searchsploit ftp 3.0.5` on a box like this surfaces
`linux/remote/84.c — Gopherd 3.0.5 FTP Gateway Remote Overflow`. It matches on the version string
and nothing else.

What that exploit actually is:

- It targets **UMN gopherd**, a Gopher server — not vsftpd.
- It connects to gopher **port 70** and sends `ftp://x:x@<attacker>`, abusing gopherd's *FTP
  gateway*.
- It then forks a fake FTP daemon bound to the **attacker's port 21**, to answer gopherd's callback.
- The overflow is in gopherd's `strlen()` on a `LIST` line; the shellcode binds port `45295`.

On this host, port 70 is not open:

```bash
nmap -Pn -p70 --host-timeout 20s 192.168.161.144
```

```
PORT   STATE  SERVICE
70/tcp closed gopher
```

Which produces exactly this when the exploit is run:

```
[] target: 192.168.161.144:70 - localhost: 192.168.45.158 - offset: 0xbfffe29b(+0)
[] starting ftp daemon. (background)
[] attempting to connect: 192.168.161.144:70.
[!] gopher connection failed.
[!] exploit failed.
```

Closed, with evidence. That chapter is over — and it is worth writing down that it was closed,
because "the FTP exploit didn't work" is not the same statement as "there is no gopherd here".

> A note on the file itself: the copy shipped in the Kali `exploitdb` package is corrupted. Every
> `*` character in the C source has been stripped, so `/* … */` becomes `/ … /` and `char *buf`
> becomes `char buf`. It will not compile until about thirty sites are repaired. Do not read a
> compiler error on that file as "the exploit is broken" — the *file* is broken.

---

## 1.4 What the host sees about itself

A listener that nmap did not report showed up later, once we had a shell:

```
LISTEN 0  4096        127.0.0.53%lo:53    0.0.0.0:*
LISTEN 0  128               0.0.0.0:22    0.0.0.0:*
LISTEN 0  511                     *:80              *:*
LISTEN 1  1  [::ffff:192.168.161.144]:10673       *:*
LISTEN 0  32                     *:21              *:*
```

`10673` is bound to the host's own external IP — and it is `filtered` from the outside, invisible in
the full scan. It is the lab platform's guest agent (the VM runs under QEMU, and `qemu-ga` is in the
process list). It is lab infrastructure, not a target, and it belongs in the "ruled out" column.

The useful line is `53` on `127.0.0.53` — `systemd-resolved`'s stub. Nothing new.

---

## 1.5 First look at the web server

```bash
curl -sI http://192.168.161.144/
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
```

The root serves a static page. `robots.txt` is unremarkable:

```
User-agent: *
Allow /
```

`Allow /` for every agent is a mild hint that nobody has thought about this directory at all — which
is the kind of host where enumeration finds things. It did.

Next: brute the directory listing properly, with a wordlist that knows about source-control
artefacts.
