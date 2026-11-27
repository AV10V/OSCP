# 09 — `ForceChangePassword` → Domain Admin

Everything the first pass could only describe is now executable. `A.NEWMAN` has a clear-text
password, and BloodHound says that account holds one right over one user:

```text
A.NEWMAN  ──ForceChangePassword──▶  A.BETTY   (Domain Admin)
```

`ForceChangePassword` is an extended right on the user object: the holder may set the target's
password without knowing the old one. No session as `A.BETTY` is needed, no hash, no cracking — only
the ability to speak SAMR to a domain controller as `A.NEWMAN`.

## 9.1 Changing the password over SAMR

```bash
net rpc password "A.BETTY" '[redacted]' -U 'oscp.exam/A.NEWMAN%[redacted]' -S 172.16.97.200
```

The command is silent on success. `net rpc password` authenticates as `A.NEWMAN`, opens the SAMR
pipe on `SRV22` and issues `SamrSetInformationUser2` with the new password for `A.BETTY` — the same
operation an administrator performs from `dsa.msc`, minus the console.

Two details make it work where a login would not:

| Detail | Why it matters |
|---|---|
| `-U 'oscp.exam/A.NEWMAN%...'` | the domain prefix, for the same reason as the SMB share in chapter 07 |
| `-S 172.16.97.200` | the change is made on the DC that holds the account, not on the member server |

## 9.2 Domain Admin

`A.BETTY` is a member of `Domain Admins`, so the new password is a Domain Admin credential. WinRM is
open on `SRV22`, which the first pass noted as "tempting and useless with the accounts in hand" — with
this account it is neither:

```bash
evil-winrm -i 172.16.97.200 -u A.BETTY -p '[redacted]'
```

```text
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt
[redacted]
```

That is the domain half of the set. The full chain, in one line:

```text
Backup share (.202) → SAM + SYSTEM → local Administrator hash
      → --local-auth on SRV22 → LSASS → A.NEWMAN cleartext
      → ForceChangePassword → A.BETTY → Domain Admin → proof.txt
```

## 9.3 What the box was actually testing

Nothing in this chain is exotic. Each step is in the OSCP syllabus, and each one was already visible
in the first pass:

| Step | The trap |
|---|---|
| `Backup` share | the domain prefix in `-U` — without it the share looks empty |
| SAM + SYSTEM | recognising that a file-share backup is a credential store |
| `--local-auth` | reading "local Administrator" as a position, not a trophy |
| LSASS | a domain logon on a member server leaks a domain identity |
| `ForceChangePassword` | an ACL edge is a credential path, not a curiosity |

The wall in the first pass was real in the sense that no amount of enumeration on `WS26` would have
produced the hash. It was not real in the sense that the path was blocked: it was one share away, on
a host that was already reachable.

---

**Back to:** [`README.md`](README.md) · **Previous:** [`08-lsass-and-a-newman.md`](08-lsass-and-a-newman.md)
