# 02 — Web enumeration

Three Apache listeners, and none of them is the box's real application. This chapter records what
the web surface actually is, why it was closed as a path, and — importantly — what was *not* tested
so that nobody later assumes it was.

---

## 2.1 Finding the real document root

`/` is the Ubuntu placeholder. The obvious next move is a directory brute force, but the fastest
result here came from following the one path that a default page does not have:

```bash
curl -si http://192.168.150.143/index/ | head -20
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```

The body is not a directory listing and not an error — it is a rendered site. Fingerprint it:

```bash
curl -s http://192.168.150.143/index/ | grep -oiE "pico[^\"<]{0,20}|3\.0\.0[^\"<]{0,12}" | sort -u
```

```
3.0.0-alpha.2
3.0.0-alpha.2.
Pico 1.0 and later can be enabled and
Pico 2.0, refer to the
```

**Pico CMS 3.0.0-alpha.2**, installed under `/index/` rather than at the root. That explains the
whole shape of the box: the vhost's `DocumentRoot` is the stock Apache directory and the CMS sits
one level below it, so every scan of `/` returns "default page" and stops.

Two useful facts fall out immediately:

1. The version is an **alpha**, and it is published in the page footer. Nobody sanitised the build.
2. The installation is *live* — the pages render, the theme assets load. It is not a leftover
   directory.

---

## 2.2 What the CMS does and does not give

Pico is a flat-file CMS: content lives as Markdown in `content/`, configuration in `config/`,
templates in `themes/`. The interesting artefacts on an installation like this are the usual three:

```bash
for u in config/config.yml composer.json .git/HEAD content/index.md CHANGELOG.md; do
  printf '%-20s ' "$u"
  curl -s -o /dev/null -w '%{http_code}\n' --max-time 8 "http://192.168.150.143/index/$u"
done
```

The result is the ordinary one for a correctly configured Pico: those files are not served. The
`.htaccess` that ships with Pico denies `config/`, `vendor/` and the dot-directories, and the
document root is not the installation root, so path juggling does not walk out of it either.

There is a second directory at the top level:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.150.143/api/
```

```
403
```

`403` — present, but refusing a listing. That is an authorisation response, not a missing file, so
`/api/` is a real path with an index it will not hand over. It was left alone: guessing endpoints
under a `403` on a CMS with no authentication story is a long walk with no evidence at the end, and
by the time it was noticed the database path in chapter 03 was already live.

> **Honest accounting.** No public exploit exists for Pico CMS `3.0.0-alpha.2` that this engagement
> could find, and none was developed. The web surface was closed as *not needed*, not as *proven
> safe*. If you are reproducing this box and the Aerospike port is closed, this is the chapter you
> would have to reopen.

---

## 2.3 The vhost that lies about itself

Port 81 is the only genuinely strange web finding:

```bash
curl -s http://192.168.150.143:81/ | grep -oiE "<title>[^<]*|nginx[^<]{0,20}" | head -3
```

```
<title>Test Page for the Nginx HTTP Server on Fedora</title>
nginx
```

An **nginx-on-Fedora** welcome page, served by **Apache 2.4.41 on Ubuntu 20.04**. Only one of those
can be true of the running server, and it is not nginx — the `Server:` header on that port says
Apache.

So the page is *content*, not a banner: an nginx default document has been placed in an Apache
docroot, or an Apache vhost is proxying to a backend that serves it. Both readings point at
`mod_proxy` being configured, and `mod_proxy` on **2.4.41** is inside the affected range of
**CVE-2021-40438** — a `ProxyPass`-style SSRF where a crafted request path makes the server proxy to
an attacker-chosen host.

That test was considered and **not executed on this run**: the Aerospike primitive was already
giving a shell, and sending 4 KB of padding at a proxy to prove an SSRF that leads to a network we
can already reach is work without a payoff. It remains the most interesting unexplored thread on
this host, and the one to try if the database is patched:

```bash
# CVE-2021-40438 shape — NOT run in this engagement, recorded for completeness
curl -s "http://192.168.150.143:81/?unix:$(printf 'A%.0s' {1..4000})|http://127.0.0.1:3002/" \
  -o /dev/null -w '%{http_code}\n'
```

Note the destination in that example: if the proxy really is reachable, the thing worth reaching
from inside is `3002` — the Aerospike info port that the outside scan showed as `filtered`. A proxy
that runs on the host can talk to a localhost-only administrative port. That is the chain the box
*almost* offers, and chapter 03 takes the shorter road to the same daemon.

---

## 2.4 Closing the chapter

What the web gave us:

- confirmation that the real content is at `/index/` (Pico CMS, alpha build, version disclosed),
- confirmation that `/api/` exists and refuses listings,
- a strong hint that `mod_proxy` is configured on 81, with an SSRF candidate left untested.

What it did not give us: credentials, a file read, or a code path. Nothing on 80/81/443 was
exploited on this engagement.

The one thing the web *did* contribute is the reason to look at the port block from chapter 01 with
suspicion. A host that runs a half-configured CMS and a mislabelled vhost is a host assembled by
hand — and hand-assembled hosts tend to leave a daemon listening on its default port with its
default settings. Which is precisely what `3000` turned out to be.
