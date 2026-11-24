# 04 — Panel access: a session, and what a session is worth

`jack` is a regular panel user. Not an admin. Everything in chapters 05 and 06 happens from that
unprivileged account, which is the point of the box.

---

## 4.1 The login is not a form

The React frontend talks to a PHP API under `/api/v1/`. Two requests are needed: one to obtain a
CSRF token, one to authenticate with it.

```bash
# 1. token
curl -sk https://192.168.161.156:8083/api/v1/login/session.php
```

```json
{"token":"a1b2c3d4e5f6..."}
```

```bash
# 2. authenticate (form-encoded, not JSON, and not HTTP basic auth)
TOK=$(curl -sk https://192.168.161.156:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)
curl -sk -c cookies.txt -o /dev/null -w '%{http_code}\n' \
  -d "user=jack&password=3PUKsX98BMupBiCf&token=$TOK" \
  https://192.168.161.156:8083/api/v1/login/index.php
```

The exploit script reports the outcome explicitly:

```text
[INFO] Attempting login to https://192.168.161.156:8083 as jack
[+] Logged in as jack
```

**Reading it:**

- The token is issued **before** authentication. It is a CSRF control, not a credential — anyone can
  get one.
- The session lands in a `PHPSESSID` cookie. Every later call needs `-b cookies.txt`.
- The status code is **not** a reliable signal here. Check that a `PHPSESSID` was set and that a
  follow-up authenticated call returns data instead of a redirect to `/login/`.

`inc/main.php` is the gate every authenticated page includes:

```php
session_start();
if ((!isset($_SESSION['user'])) && (!defined('NO_AUTH_REQUIRED'))) {
    header("Location: /login/"); exit;
}
```

It also pins the session to the client IP:

```php
if($_SESSION['user_combined_ip'] != $user_combined_ip && $_SERVER['REMOTE_ADDR'] != '127.0.0.1'){
    session_destroy(); header("Location: /login/"); exit;
}
```

So the cookie only works from the IP that created it — and `127.0.0.1` is exempt. Remember that
exemption if you ever get local access; it is how the panel's own cron/CLI calls authenticate.

## 4.2 What jack can reach

The API is a flat set of verbs, each mapping to one panel script:

```text
/api/v1/list/web/index.php      /api/v1/add/web/index.php
/api/v1/list/mail/index.php     /api/v1/add/mail/index.php
/api/v1/edit/mail/index.php     /api/v1/delete/mail/index.php
/api/v1/upload/?dir=<path>
/api/v1/login/session.php       /api/v1/logout/index.php
```

Two of these are the whole exploit: **`add/web` + `upload`** give file write into a served docroot,
and **`edit/mail`** reaches a privileged shell. Chapter 05.

Note what is *not* here: nothing in the list is an admin-only verb. `jack` is allowed to create web
domains, create mail domains, add mailboxes, and upload files — because that is what a hosting
customer does. The bug is not the authorisation check. The bug is what the panel does *with* the
values a customer supplies.

## 4.3 The design that makes it exploitable

Every panel action is a thin PHP wrapper over a shell script in `/usr/local/vesta/bin/`:

```php
define('VESTA_CMD', '/usr/bin/sudo /usr/local/vesta/bin/');
```

That single line explains the entire privilege model: **the panel runs `/usr/local/vesta/bin/v-*`
as root on behalf of a normal user.** Argument construction is string concatenation. Any field that
reaches a `v-*` script is a root-context substring, and quoting is the only thing standing between a
customer and root.

So the question on a Vesta box is never *"is there an injection"*. It is *"which field reaches a
`v-*` script, and is it quoted?"*

## 4.4 What we did not get

Worth recording, because it constrains the write-up:

- No `admin` panel account. The escalation does not need one.
- No MySQL credential. `3306` completed a handshake but no login was obtained — and none was
  needed for this path.
- No SSH shell as `jack` was required. The panel route reached the same account with fewer steps.

The next chapter turns the session into code execution as `jack`, and then into root.
