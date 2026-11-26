# 03 — Windows PowerShell Web Access: `sasha` vs `.\sasha`

This is the chapter the whole box exists to teach. The exploit chain takes minutes; the login format
is what costs time.

## 3.1 The page

```
https://192.168.91.111/powershell
```

A plain form, no branding beyond the product name:

| Field | Value used |
|---|---|
| User name | `sasha` |
| Password | `Welcome1` |
| Connection type | `Windows PowerShell` (the other option is *Windows PowerShell ISE*) |
| Computer name | *(blank — defaults to the gateway host)* |
| Configuration name | *(blank)* |

The page is served over a self-signed certificate, so the browser shows the usual interstitial before
the form. Accept it and continue.

## 3.2 The failure

```
User name:  sasha
Password:   Welcome1
```

```
The user name or password is incorrect.
```

No lockout counter, no delay, no hint about *which* half is wrong. The natural conclusion is that the
password is wrong, so the next move is to try variants. Every combination of:

- `sasha`, `Sasha`, `SASHA`
- `OSCP\sasha`, `WORKGROUP\sasha`, `192.168.91.111\sasha`
- the password with and without a trailing `!`, `1`, `)`

All rejected — and none of those variants is the problem.

> The exact error string and the full list of variants are not reproduced here. What is certain is
> that the bare username failed and `.<backslash>sasha` succeeded.

## 3.3 The fix — one character pair

```
User name:  .\sasha
Password:   Welcome1
```

Accepted. The console loads.

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\sasha\Documents>
```

## 3.4 Why `.\` is required

`.\` is shorthand for **"the local machine"**. It is the same prefix you type in `cmd.exe` when you want
to run an executable from the current directory instead of letting `%PATH%` decide.

In a logon name, the grammar is:

```
[domain or computer]\[user]
```

- `OSCP\sasha` → the local SAM database of the computer named `OSCP`.
- `.\sasha` → the local SAM database of *this* computer, whatever its name is.
- `sasha` → **no domain part**. Windows has to guess. In an interactive console it guesses the local
  machine; through a remote logon API it can guess the *domain*, and on a workgroup machine that guess
  resolves to nothing, so authentication fails even with a correct password.

That is the trap: **the credential is valid, the name format is not.** Nothing in the error message
distinguishes "wrong password" from "wrong namespace", which is why the format is so easy to miss.

The same rule applies to every remote Windows logon that takes a bare username:

| Tool | Local account syntax |
|---|---|
| `evil-winrm` | `-u 'sasha' -p '...'` usually works; if not, `-u '.\sasha'` or `-u 'OSCP\sasha'` |
| `nxc` / `crackmapexec` | `-u sasha --local-auth` |
| `wmiexec` / `psexec` | `-u 'OSCP/sasha'` |
| RDP | `OSCP\sasha` |
| **WAC** | **`.\sasha`** |

## 3.5 The meta-lesson: read the documentation, then time-box

The lesson is expensive and simple: Windows PowerShell Web Access does not document the local-account
format anywhere obvious, and no error message points at it. That is exactly the class of problem that
eats hours — nothing is broken, the syntax is just unknown.

Two rules come out of it, and they are worth more than the box:

1. **When a credential you obtained from a reliable source is rejected, suspect the format — not the
   credential.** Try `.\user`, `HOST\user`, `DOMAIN\user` and `--local-auth` before you try a wordlist.
   Brute-forcing a working password is pure loss.
2. **Time-box any single step to 20–30 minutes.** At the 30-minute mark on a login page, stop and read
   the product documentation (here: the WAC help page, which documents the `computer\user` format), or
   move to another box and come back. Hours lost on a 20-minute box is how an exam is lost.

## 3.6 What WAC actually is

Worth knowing for the report, because "a PowerShell console in a browser" sounds exotic:

- A **Windows Server feature** (`WindowsPowerShellWebAccess`), installed with
  `Install-WindowsFeature WindowsPowerShellWebAccess -IncludeManagementTools`.
- Runs as an IIS application (`/powershell`) using `http.sys` on 443.
- It is a **gateway**: it authenticates the user, then opens a WinRM/PSRP session to the *target
  computer* named in the form. That is why the credentials must be valid **on the target**, and why the
  domain prefix matters.
- `Install-PswaWebApplication -UseTestCertificate` is the standard setup, which explains the self-signed
  certificate.

The defensive note writes itself: WAC is a full remote shell exposed to the web tier, protected by
nothing but a password and whatever network ACL sits in front of 443.

---

**Next:** [`04-local-flag-and-dead-end.md`](04-local-flag-and-dead-end.md)
