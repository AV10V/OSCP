# 02 — Anonymous FTP: the application backups

The first service on the box is the easiest one: FTP with anonymous access, holding four months of
application backups.

## 2.1 Login

```bash
ftp 192.168.91.112
```

```text
Connected to 192.168.91.112.
220 (FTP server ready)
Name (192.168.91.112:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

`anonymous` with an empty password is accepted. Listing and download are enough — no write access is
needed for this box.

## 2.2 Listing

```text
ftp> ls
229 Entering Extended Passive Mode (|||10096|)
150 Here comes the directory listing.
-rw-r--r--    1 110      110         33080 Jan 01  2023 applications_dec22.zip
-rw-r--r--    1 110      110         73065 Mar 04  2023 applications_feb23.zip
-rw-r--r--    1 110      110         63842 Feb 02  2023 applications_jan23.zip
drwxr-xr-x    2 110      110          4096 Dec 02  2021 applications_nov22.zip
226 Directory send OK.
```

Four entries, all owned by uid/gid `110` — the FTP account, not root and not the web server. Somebody
copied their monthly backups onto the FTP root and never cleaned up.

| Entry | Type | Size | Reading |
|---|---|---|---|
| `applications_dec22.zip` | file | 33,080 | the oldest archive, and the one downloaded |
| `applications_jan23.zip` | file | 63,842 | January backup |
| `applications_feb23.zip` | file | 73,065 | February backup, the largest |
| `applications_nov22.zip` | **directory** | 4,096 | a directory that carries a `.zip` suffix — a naming habit, not an archive |

The `.zip` suffix on a directory is the detail that catches people out: `get` on it fails, `cd` into it
works.

## 2.3 Download

```text
ftp> get applications_dec22.zip
local: applications_dec22.zip remote: applications_dec22.zip
229 Entering Extended Passive Mode (|||10097|)
150 Opening BINARY mode data connection for applications_dec22.zip (33080 bytes).
226 Transfer complete.
33080 bytes received in 00:41 (79.28 KiB/s)
```

## 2.4 What the archive gives you

Unpack it and read the source rather than fuzzing the live form:

```bash
unzip -o applications_dec22.zip -d backup/
find backup -type f | head -50
```

What matters is `upload.php` — the file the portal runs. Two questions decide the entire box:

```bash
grep -nE "move_uploaded_file|\$_FILES|mime|finfo|pathinfo|exif_imagetype|in_array|strtolower" \
  backup/**/upload.php 2>/dev/null || grep -rn "move_uploaded_file" backup/
```

1. **Where does the file land?** `move_uploaded_file($tmp, "uploads/" . $name)` means the file is
   reachable from the web root, which is what makes execution possible.
2. **What does the filter check?** A filename extension check, a `finfo` MIME sniff, or nothing at all
   beyond what the browser sent.

On this box the answer to (2) is *the client-supplied `Content-Type`* — a header the browser sets and
the attacker controls — and the answer to (1) is the web-accessible `/applications/` directory. Both
are demonstrated in [`03-upload-portal.md`](03-upload-portal.md).

## 2.5 Why anonymous FTP is a finding in its own right

| Impact | Detail |
|---|---|
| Source disclosure | a full copy of the web app, including files not linked from the site |
| Credential disclosure | config files with DB users and passwords (`config.php`, `.env`) |
| Path disclosure | directory names that shortcut the web brute force (`applications`) |
| Write access | not present here; if `STOR` were allowed it would be direct web-shell upload |

On this box FTP is a **hint service**: it hands over the source of the upload form. Two minutes on
every Linux target, before any web fuzzing.

---

**Next:** [`03-upload-portal.md`](03-upload-portal.md)
