# 03 — IMAP: `sysad` and the mailbox

No shell is needed for this step. IMAP is a text protocol and `telnet` is enough.

## 3.1 Log in

```bash
telnet 192.168.91.119 143
```

```
Trying 192.168.91.119...
Connected to 192.168.91.119.
Escape character is '^]'.
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.
```

A first attempt with the obvious admin name fails — worth keeping in the notes because it shows the
account was not `administrator`:

```
1 LOGIN "administrator" "administrator"
1 NO [AUTHENTICATIONFAILED] Authentication failed.
```

The account from the WHOIS record succeeds:

```
a LOGIN sysad sysad
a OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
```

| Attempt | Result |
|---|---|
| `administrator` / `administrator` | `NO [AUTHENTICATIONFAILED]` |
| **`sysad` / `sysad`** | `OK … Logged in` |

## 3.2 Read the mailbox

A GUI mail client (a three-pane reader) is faster than IMAP by hand. With `telnet`
the minimum is:

```
a LIST "" "*"                 → which mailboxes exist
b SELECT INBOX                → message count
c FETCH 1:* (ENVELOPE)        → subjects, senders, dates
d FETCH <n> BODY[]            → the message you want
```

The message list holds about **nine** messages of ordinary internal correspondence. The one that
matters is the **account-provisioning notice**, the ninth mail.

## 3.3 The email that gives the next host

The body of that message:

```
... has been configured.

... [assigned, imaging complete]

... [standard dev permissions]
... [tooling - only (dev group)]

Hi,

... change his password after first login
... procedure. Could you verify his access
... get a chance? The dev team needs him
... staff meeting on Tuesday.
```

Reading it as a provisioning ticket:

| Line | What it tells you |
|---|---|
| "has been configured" | a **new account** was created |
| "imaging complete" | a machine was built for that person |
| "standard dev permissions" | the account is in a developers group |
| "change his password after first login" | the password in the ticket is **still valid** |
| "the dev team needs him" | the account is in active use, not a decoy |

Inside that message (or attached to the same thread) are the **SSH credentials** for the account.
That mail is the first foothold: SSH in as the provisioned user.

> The credential string: `[redacted]`. The username is `james`.
> Treat the *pattern* as the finding: provisioning mail → initial password → SSH.

## 3.4 Why this is the intended path

Everything here is a **credential flow**, not an exploit:

```
WHOIS record ──▶ sysad ──▶ mailbox ──▶ provisioning mail ──▶ new dev account ──▶ SSH
```

No CVE, no brute force, no exploit code. The box tests whether you treat a mail server as a source of
credentials. The rule that solves this box: try every credential you are given against every service
that accepts one, however unlikely it looks.

---

**Next:** [`04-ssh-and-nexus.md`](04-ssh-and-nexus.md)
