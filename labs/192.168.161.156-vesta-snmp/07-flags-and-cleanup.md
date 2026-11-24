# 07 — Flags, cleanup, and what this box teaches

Two flags, one root shell, and a non-trivial amount of debris to remove.

---

## 7.1 Flags

```bash
# whoami && ifconfig
root

# cat /root/proof.txt
d4640a77ca31e0ab126751f98e819888

# cat /home/jack/local.txt
9cfca959e54738e70905a4024d16a44a
```

| Flag | Path | Context |
|---|---|---|
| `local.txt` | `/home/jack/local.txt` | the panel user the SNMP extend leaked |
| `proof.txt` | `/root/proof.txt` | root, via the mailbox injection |

`local.txt` sitting in `jack`'s home is consistent with the intended path: the box expects you to
land as `jack` first. The SNMP leak is the intended front door, and it hands you exactly that
account.

## 7.2 What the exploit left behind

The script creates real state on the target. If this were a client engagement rather than a lab,
each of these would need to be documented and removed:

| Artifact | Location |
|---|---|
| web domain | `4wfarbc2dg.poc` — `/home/jack/web/4wfarbc2dg.poc/` |
| webshell | `/home/jack/web/4wfarbc2dg.poc/public_html/ownwebshell.php` |
| command channel | `/home/jack/web/4wfarbc2dg.poc/public_html/iamroot/` |
| mail domain | `4wfarbc2dg.poc` |
| mail account | random account under that domain |
| mailbox forwarding | the injected payload, stored in the mail config |
| DNS records | vhost + mail records created by `v-add-web-domain` / `v-add-mail-domain` |

The mailbox forwarding entry is the one people forget. It is **stored** — it persists after you drop
the shell, and it re-executes the payload every time the mailbox is saved.

## 7.3 Cleanup

Remove the domain through the panel (the panel cleans up its own nginx/Apache/DNS state, which is
safer than `rm -rf`):

```bash
TOK=$(curl -sk https://192.168.161.156:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)

# 1. delete the mail domain (removes the account and its forwarding)
curl -sk -b cookies.txt \
  "https://192.168.161.156:8083/api/v1/delete/mail/index.php?domain=4wfarbc2dg.poc&token=$TOK"

# 2. delete the web domain (removes public_html, the webshell and iamroot/)
curl -sk -b cookies.txt \
  "https://192.168.161.156:8083/api/v1/delete/web/index.php?domain=4wfarbc2dg.poc&token=$TOK"
```

Then verify — from the shell, not from the panel's response:

```bash
ls -la /home/jack/web/           # 4wfarbc2dg.poc must be gone
ls -la /etc/exim4/domains/       # no 4wfarbc2dg.poc
grep -r 4wfarbc2dg /etc/nginx/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null
```

If the forwarding entry survives in `/etc/exim4/domains/*/aliases`, the injection is still live even
after the domain is deleted. Check it explicitly.

## 7.4 Defensive remediation

In priority order:

1. **Do not interpolate user input into `v-*` shell calls.** Pass arguments as an array, quote with
   `"$@"`, and stop the blanket `sudo` rule that lets a panel user run every `v-*` script as root.
2. **Fix SNMP.** Non-default community, ACL to management hosts, or disable the daemon. Then audit
   `nsExtendConfigTable` for every secret that has ever appeared in an extend argument — those
   secrets are compromised, not merely exposed.
3. **Rotate `jack`.** A credential published over SNMP for months is burned.
4. **Constrain the upload API.** Absolute `dir` parameters should not be client-controlled; enforce
   an allow-list and keep writable paths outside any docroot.
5. **Bind MySQL to `127.0.0.1`** and restrict 8083 to VPN or source-IP allow-lists.
6. **Migrate off VestaCP.** Upstream stalled for years and this class of injection is endemic to
   its design. HestiaCP is the maintained fork.

## 7.5 Lessons

**Run a UDP scan first.** This box was decided by `nmap -sU -p 161`. The full TCP sweep, the four
SMTP listeners, the panel version — all of it was noise until a UDP packet returned a password.

**Version banners are hints, not gates.** Time went into `Exim 4.90_1` / CVE-2019-10149 on the
strength of a banner string that cannot distinguish a patched Ubuntu build from a vulnerable one. The
config answered faster than the version did: `550 Restricted characters in address` is Debian's
stock ACL, and stock Debian has no `local_part_suffix`, so the remote path was never reachable.

**Stop when a service says no twice.** SMTP gave a syntax error, then an ACL denial. That was the
answer. Everything after was sunk cost.

**Identical response sizes mean one file.** `/` and `/upload/index.php` both returned 2586 bytes
because `upload/index.php` is a 66-byte stub that includes the SPA shell. Two "endpoints" with the
same length are one endpoint.

**On a panel box, read the `v-*` surface.** The question is not whether an injection exists, but
which field reaches a `v-*` script. `v_fwd` is an email forwarding address — free text by design,
evaluated as root by design.

**Second-order beats first-order.** The value was legal where it was stored and only dangerous where
it was used. Input validation at the API was never going to catch it.
