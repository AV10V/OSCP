# 01 — Reconnaissance

Goal: establish what this network position actually gives us, and separate what is *reachable* from
what is *owned*. This leg starts with credentials in hand — the work is proving what they are worth.

---

## 1.1 Where this leg sits

This is the same `oscp.exam` directory as the earlier AD page, seen from a different network:

| Property | Earlier AD leg | This leg |
|---|---|---|
| Domain SID | `S-1-5-21-2610934713-1581164095-2706428072` | identical |
| Domain GUID | `e7448cc9-434a-4130-90b0-812d3d0c5a96` | identical |
| DC01 | `10.10.118.146` | `10.10.152.140` |
| MS01 | `10.10.118.147` | present in the directory, address not captured |
| Reachability | DC only through the MS01 SOCKS tunnel | DC answers directly |

The SID and GUID matching is the useful part: it is one directory database, not a second forest that
happens to share a name. Whether DC01 is dual-homed onto both networks or the set was re-addressed is
**not established** — only that it now answers on `10.10.152.140`.

That single change removes the chapter 05 problem entirely. There is no pivot to build, no
`proxychains` wrapper on every command, and Kerberos talks to a KDC we can actually reach. Everything
below is direct.

---

## 1.2 Starting position

| Account | Secret | Where it came from |
|---|---|---|
| `OSCP\celia.almeda` | `7k8XHk3dMtmpnC7` | in hand when this leg began |
| `OSCP\web_svc` | `Diamond1` | in hand when this leg began |
| `OSCP\eric.wallows` | `EricLikesRunning800` | carried over from the earlier AD leg |

The first two were already captured before this session started; that acquisition step is not in these
notes and is therefore not reconstructed here. `eric.wallows` is the domain user from the MS01 leg —
the same password still works, which is itself a finding.

---

## 1.3 First contact with MS02

```bash
nxc smb 10.10.152.142 -u web_svc -p 'Diamond1' --shares
```

```
SMB  10.10.152.142  445  MS02  [*] Windows 10 / Server 2019 Build 19041 x64
                                  (name:MS02) (domain:oscp.exam) (signing:False) (SMBv1:None)
SMB  10.10.152.142  445  MS02  [+] oscp.exam\web_svc:Diamond1
SMB  10.10.152.142  445  MS02  [*] Enumerated shares
SMB  10.10.152.142  445  MS02      Share           Permissions     Remark
SMB  10.10.152.142  445  MS02      -----           -----------     ------
SMB  10.10.152.142  445  MS02      ADMIN$                          Remote Admin
SMB  10.10.152.142  445  MS02      C$                              Default share
SMB  10.10.152.142  445  MS02      IPC$            READ            Remote IPC
```

Three facts, and two of them are about what we cannot do.

**`signing:False`** — MS02 does not require SMB signing, so it is a valid relay target in principle.
Park that; it only matters if something can be coerced into authenticating to us, and nothing has been
coerced yet.

**`ADMIN$` and `C$` are blank** — not "denied", blank. The share exists and is enumerated, but this
account holds no access. `web_svc` is not a local administrator on MS02, and no amount of share
enumeration will change that. The whole `--shares` avenue is closed in one line.

**`IPC$` is `READ`** — every authenticated account has that. It is the null session's authenticated
cousin: useful for RPC enumeration, meaningless as access.

Build `19041` on a host named `MS02` while DC01 reports `17763` is a mismatch worth noticing: the member
server is a newer build than the domain controller.

---

## 1.4 The address the prompt was hiding

The MSSQL prompt in the next chapter reads `guest@master`, and it would be easy to assume `guest` is a
separate database server. It is not:

- `nxc` authenticates `oscp.exam\web_svc` against `10.10.152.142` and gets `MS02`;
- the same account opens a SQL session on a host whose NetBIOS name is `guest`.

Same account, same box, two protocols. There is no pivot between them, which means the SQL work and the
WinRM work are two views of one machine. That matters for the escalation logic in chapter 03: a SQL
escalation lands on MS02, not somewhere new.

---

## 1.5 What this chapter leaves open

| Question | Status |
|---|---|
| Is `web_svc` a local admin on MS02? | **No** — `ADMIN$`/`C$` empty |
| Can we relay to MS02? | possible, `signing:False` — no coercion attempted |
| Is the DC reachable without a pivot? | **Yes** — `10.10.152.140` |
| Are these credentials still current? | **Yes** — both authenticate |

The remaining surface is identity, not transport: WinRM on MS02 (chapter 02), MSSQL on MS02 (chapter
03), and the directory itself (chapter 04).
