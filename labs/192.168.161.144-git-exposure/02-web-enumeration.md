# 02 — Web enumeration

Goal: turn "Apache serves a static page" into a list of real paths, then recognise the one path that
is not a page.

---

## 2.1 Directory brute force

```bash
feroxbuster -u http://192.168.161.144 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,html -o ferox_161_144.txt
```

The interesting rows, with the noise removed:

```
301 - 317B - /.git           -> http://192.168.161.144/.git/
200 - 709B - /.git/
200 -  21B - /.git/HEAD
200 - 306B - /.git/config
200 - 730B - /.git/index
200 - 112B - /.git/packed-refs
200 - 335B - /.git/logs/HEAD
200 - 184B - /.git/logs/refs/remotes/origin/HEAD
301 - 328B - /.git/refs/heads -> http://192.168.161.144/.git/refs/heads/
403 - 280B - /.htaccess.bak1
403 - 280B - /.htaccess.orig
```

**Reading it:** every `/.htaccess*` path is `403`, which is a hardening rule doing its job — those
files are not there. But every path under `/.git/` is `200` with a plausible, non-zero body.

Two details separate a real finding from a soft-404:

1. `/.git/` itself is `200` at `709B`. A directory with `Options -Indexes` would be `403`; a real
   directory listing would be far larger. `709B` is the size of git's default placeholder
   `index.html` — the file `git init` drops so the directory does not render.
2. `/.git/HEAD` is `200` at `21B`. Twenty-one bytes is exactly `ref: refs/heads/main\n` for a
   five-letter branch name. That is not a byte count you get from a catch-all handler.

The `301` on `/.git` (no trailing slash) is just Apache's directory redirect, and it confirms the
directory exists.

---

## 2.2 Confirming by hand

Never build an exploit chain on a scanner's byte count. Two requests settle it:

```bash
curl -s http://192.168.161.144/.git/HEAD
```

```
ref: refs/heads/main
```

```bash
curl -s http://192.168.161.144/.git/config
```

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://<REDACTED-TOKEN>@github.com/PWK-Challenge-Lab/dev.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

That is two findings in one response.

**The `.git` directory is being served.** Apache is handing out the repository's object database,
refs, index and config to anyone who asks. The entire source tree — and its full history — is
downloadable. This is not a `/.git/HEAD` curiosity, it is a complete source disclosure.

**The remote URL contains a personal access token.** `https://<token>@github.com/…` is what you get
when someone runs `git clone https://ghp_xxx@github.com/org/repo`. Git stores that credential in
`.git/config` in clear text, and Apache hands it over. The token belongs to an account with access
to `PWK-Challenge-Lab/dev`.

Both are worth recording. The token is a credential for a *different* system (GitHub), so it gets
noted and left alone — the lab is the target, not GitHub. The repository itself is enough.

---

## 2.3 Why this is worse than a directory listing

Worth being precise about the impact, because it is routinely under-rated:

| Exposed | Consequence |
|---|---|
| `.git/objects/**` | Every file that ever existed, compressed but trivially unpacked |
| `.git/refs/**`, `packed-refs` | Every branch and tag — including deleted ones |
| `.git/logs/HEAD` | The reflog: what was committed, when, by whom |
| `.git/index` | The exact file list of the checked-out tree |
| `.git/config` | Remote URLs, and any credential embedded in them |

The critical property: **git history is append-only by design.** A secret that was committed and
then removed in a later commit still lives in the object database, still reachable by hash, still
one `git show` away. Deleting a file does not delete it from the repository.

That is exactly the shape of this box. We do not need a vulnerability in any application — we need
to read what the developer already published, then read it again one commit earlier.

---

## 2.4 What the application is *not*

Before dumping, a reality check on the deployed PHP. The `.git/index` lists five PHP files:

```
api/export.php
api/index.php
api/order.php
configuration/database.php
orders/search.php
```

None of them are served:

```bash
for p in /api/index.php /api/order.php /api/export.php /orders/search.php \
         /configuration/database.php; do
  printf '%-30s ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' "http://192.168.161.144$p"
done
```

```
/api/index.php                 404
/api/order.php                 404
/api/export.php                404
/orders/search.php             404
/configuration/database.php    404
```

All `404`. The application was never deployed — the document root is a static site, and the only
copy of this code anywhere on the host is inside `/.git/`.

That single result decides the box. There is no SQL injection to find, because there is no
`search.php` to inject into. `api/export.php` contains a genuine arbitrary-file-write
(`file_put_contents($_POST['location'] . $fname . $ext, …)`) and it is completely unreachable.
Reading that code and then hunting for the endpoint would have burned hours.

The finding is the repository. So dump the repository.
