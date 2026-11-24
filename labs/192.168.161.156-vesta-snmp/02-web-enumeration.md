# 02 — Web enumeration: two servers, one panel, one false positive

Four HTTP services. Three of them turned out to be the same application seen through different
listeners, and one "endpoint" turned out to be a file that was already there.

---

## 2.1 nginx on 80 — the placeholder site

```bash
curl -s http://192.168.161.156/ | head -40
curl -s http://192.168.161.156/robots.txt
```

```text
# robots.txt (65 bytes)
User-agent: *
Disallow: /phpmyadmin/
Disallow: /webmail/
```

The site itself is a **1055-byte "Coming Soon" page** — a stock Vesta placeholder. `robots.txt`
is more useful than the page: it names the two applications a hosting box always ships.

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  http://192.168.161.156/phpmyadmin/ \
  http://192.168.161.156/webmail/ \
  http://192.168.161.156/roundcube/
```

Both `/phpmyadmin/` and `/webmail/` are served, and `/webmail/` is Roundcube. On a mail host that
is a mailbox-login surface, and mailboxes are where onboarding credentials live.

## 2.2 Apache on 8080 and 8443 — the back-end

The Apache listeners sit behind nginx and serve the same vhosts. Two things are worth checking:

```bash
curl -s -o /dev/null -w 'server-status: %{http_code}\n' http://192.168.161.156/server-status
curl -s -o /dev/null -w '8443 root:     %{http_code} %{size_download}\n' -k https://192.168.161.156:8443/
```

```text
server-status: 502
8443 root:     200 1055
```

`502` means nginx proxies `/server-status` to Apache and Apache refuses — the status handler is not
enabled. `8443` returns the same 1055-byte placeholder, confirming the Apache listeners are the
*same* vhosts, not a separate application. There is no second web app here.

## 2.3 The panel on 8083

```bash
curl -sk https://192.168.161.156:8083/ | grep -iE 'title|static/js'
```

```html
<title>Vesta</title>
<script src="/static/js/2.5dc90ea3.chunk.js"></script>
<script src="/static/js/main.57f35a42.chunk.js"></script>
```

`<div id="root">` and a webpack bundle named **`webpackJsonpreact-control-panel`** mean this is the
**React single-page frontend**, which Vesta shipped in **0.9.8-27** (Nov 2021). The old PHP/XHTML
login page is gone.

That single fact rewrites the exploit table:

| CVE | Affects | Status on a 0.9.8-27 build |
|---|---|---|
| CVE-2019-9859 | ≤ 0.9.8-23 | dead — panel is newer |
| CVE-2020-10786 | ≤ 0.9.8-26 | dead |
| CVE-2020-10807 / CVE-2020-10808 | ≤ 0.9.8-26 | dead |
| CVE-2020-10966 | ≤ 0.9.8-25 | dead |
| CVE-2021-28379 | ≤ 0.9.8-27 | **live**, but needs an authenticated admin session |
| API-key LPE (#2045) | any build with `v-generate-api-key` | **live**, post-foothold |

The React frontend does **not** mean the PHP API was hardened. `web/api/` and
`web/upload/UploadHandler.php` are still underneath. But every remaining panel bug is
*authenticated* — so the panel stops being the front door and becomes a credential-reuse target.

## 2.4 The false positive worth remembering

Probing for the upload handler produced this:

```bash
for p in /upload/index.php /upload/ /api/index.php /api/ /manifest.json /; do
  printf '%-22s ' "$p"
  curl -sk -m 10 -o /dev/null \
    -w 'http=%{http_code} size=%{size_download}\n' "https://192.168.161.156:8083$p"
done
```

```text
/upload/index.php      http=200 size=2586
/upload/               http=200 size=2586
/api/index.php         http=200 size=0
/api/                  http=200 size=0
/manifest.json         http=404 size=1254
/                      http=200 size=2586
```

`/upload/index.php` looks like a live endpoint. It is not. **It returns exactly the same 2586 bytes
as `/`** because it is the same file: a 66-byte stub.

```bash
curl -s https://raw.githubusercontent.com/outroll/vesta/master/web/upload/index.php
```

```php
<?php include($_SERVER['DOCUMENT_ROOT'].'/static/index.html'); ?>
```

That is the entire file. It includes the SPA shell and returns 2586 bytes — identical to `/`,
because it *is* `/`. **Identical response sizes across "different" endpoints mean one file, not
two.** The real handler is `web/upload/UploadHandler.php` (54,838 bytes), and it is gated:

```php
include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");   // -> session_start()
if ((!isset($_SESSION['user'])) && (!defined('NO_AUTH_REQUIRED'))) {
    header("Location: /login/"); exit;
}
```

So unauthenticated upload is out. The `/api/` paths return `200` with a **zero-byte body** — the
directory exists, the index is empty. Not an endpoint either.

## 2.5 Read the JS bundle instead of fuzzing

The React app has to name every API route it calls. That is cheaper than a wordlist.

```bash
curl -sk https://192.168.161.156:8083/static/js/main.57f35a42.chunk.js -o main.js
grep -oE '(api|upload)/[a-zA-Z0-9_./?=-]*' main.js | sort -u | head -40
grep -oE 'v-[a-z0-9-]+' main.js | sort -u | head -40
```

The `v-*` hits matter: every panel action is a wrapper around a script in
`/usr/local/vesta/bin/`, invoked as `/usr/bin/sudo /usr/local/vesta/bin/<script>`. That design is
the entire privilege story of the box — chapter 06.

## 2.6 Where this leaves us

The web surface is fully mapped and fully useless without a credential:

- No unauthenticated upload path.
- No reachable `server-status`.
- phpMyAdmin and Roundcube both present, both want a login.
- All remaining panel CVEs require a session.

**The box is a credential problem, not an exploit problem.** Chapter 03 gets the credential from a
protocol that has no authentication at all.
