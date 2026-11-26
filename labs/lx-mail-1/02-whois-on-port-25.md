# 02 — The "SMTP" service is a WHOIS registry

The registry on port 25 returns domain records in WHOIS format. The value in them is not the domain
data — it is the **contact**, which is the account used on the mail service.

## 2.1 Query it

```bash
whois -h 192.168.91.119 oscp.exam
```

The `whois`-style record set returned by the service:

```
Name: Administrator
...
OSCP Infrastructure Division
External Network Operations
+1-555-0142
sysad@oscp.exam
2023-06-12T09:30:00Z
...
O=OSCP-REGISTRY

Name: Operations Team
...
OSCP Infrastructure Division
...
```

| Field | Value |
|---|---|
| Registrant name | `Administrator` (and other records: `Operations Team`) |
| Organisation | `OSCP Infrastructure Division` — `External Network Operations` |
| Phone | `+1-555-0142` |
| Contact e-mail | **`sysad@oscp.exam`** |
| Created | `2023-06-12T09:30:00Z` |
| Registry object | `O=OSCP-REGISTRY` |

The important line is the contact address: it gives a **username**. The domain of that address is the
domain you already know, so the local part — `sysad` — is what the mail service wants.

> If `whois` is not installed, the same answer comes from talking to the port:
> `nc 192.168.91.119 25` and typing the query (`WHOIS oscp.exam`, `HELP`), as the banner suggests.

## 2.2 The reasoning, stated plainly

The record looks like ordinary registration data, and that is exactly why it is easy to skip. The
account name in it is a mail account, and the account logs in with its own name as the password.

Two habits come out of this moment:

1. **Read every service that produces text.** A WHOIS record is a directory entry; directories contain
   owners; owners are accounts.
2. **Re-use the name as the password.** On an exam box built for a human, a service account named
   `sysad` very often ships with `sysad` as its password. It is the cheapest guess in the book, and
   here it is the intended path.

> This is the step that costs hours: `sysad` looks like an SSH account, but it is a mail login.
> Testing it against SSH first goes nowhere.

---

**Next:** [`03-imap-and-mail.md`](03-imap-and-mail.md)
