# 06 — BloodHound, and the wall

Everything up to here is enumeration. BloodHound is the first tool that answers the only question that
matters on a domain: *which account can reach Domain Admin, and do I hold it?*

## 6.1 Collect

With the tunnel up, `SRV22` is reachable over LDAP and `p.andrew` can read the directory.

```bash
rusthound-ce -d oscp.exam -u p.andrew -p '[redacted]' -dc SRV22.oscp.exam -z
```

```text
[+] Connecting to SRV22.oscp.exam:389
[+] Authenticated as oscp.exam\p.andrew
[+] Collecting users
[+] Collecting groups
[+] Collecting computers
[+] Collecting ACLs
[+] Collecting sessions
[+] Saving to 20260716204535_oscp_exam.zip
```

```bash
# alternative collector, same data
bloodhound-python -u p.andrew -p '[redacted]' -d oscp.exam -ns 172.16.97.200 -c All
```

Import the zip into BloodHound and mark `p.andrew` as owned.

## 6.2 What the graph says

The shortest path to Domain Admin does not run through anything in hand. It runs through two
accounts, and only the second one is privileged:

```text
p.andrew ──▶ (no path)
A.NEWMAN ──ForceChangePassword──▶ A.BETTY ──MemberOf──▶ DOMAIN ADMINS
```

`A.NEWMAN` is an ordinary user, not a Domain Admin. What makes it valuable is a single extended
right on the `A.BETTY` user object: `ForceChangePassword` lets the holder set that account's password
without knowing the old one. `A.BETTY` is a Domain Admin, so the graph is a two-step path — if the
first account's password is known:

```bash
# what the path looks like with the account in hand
net rpc password "A.BETTY" '[redacted]' -U 'oscp.exam/A.NEWMAN%[redacted]' -S 172.16.97.200
```

That is the wall as it looked from `WS26`: the graph is complete, the edge is real, and the vertex is
missing.

## 6.3 Where the missing credential is

The account is not a service account with an SPN, so Kerberoasting does not touch it. It is not in the
SQL dump. It is not in the RDCMan profile. The one place it must be is `172.16.97.202` — the second
member server, the only host in the set that was never entered.

The reasoning is structural, not a guess:

| Host | State at this point | Contents |
|---|---|---|
| `WS26` | owned, local Administrator | XAMPP, MySQL, RDCMan profile, default shares — all exhausted |
| `SRV22` | reachable, not owned | the directory itself; no credential material without an admin |
| `172.16.97.202` | reachable, not owned | the only unexamined disk in the set |

A domain user's credential does not live on a domain controller in a readable form; it lives on the
workstation or server where that user logs in. The second server is that machine. It has no web
application and no WinRM — just SMB, RDP and one share that a domain user can read. That share is the
way in, and it only appears when the domain is spelled out in the credential string: the subject of
chapter 07.

## 6.4 The decision to stop

At this point in the sitting the box is worth one flag and no more:

| Item | State |
|---|---|
| `local.txt` on `WS26` | obtained, masked |
| `proof.txt` on `SRV22` | not obtained |
| Domain Admin | not obtained |
| Remaining path | a credential on `172.16.97.202` — reachable, no way in yet |

Continuing at that moment means attacking a host with no identified entry point, on the clock, with
the rest of the exam still to sit. The correct call is to bank the flag, write the notes, and come
back with a different idea — which is what happened, and chapter 07 is the return visit.

## 6.5 What would have opened it

Worth writing down, because the next set may differ by one detail:

- **A readable backup share.** This is what actually opened it: `172.16.97.202` exposed a `Backup`
  share to a normal domain user, and it held `SAM` and `SYSTEM`. A share sweep that stops at the
  default shares never sees it.
- **A domain account in the SQL dump.** One row with `OSCP\` in front of it would have changed
  everything; the dump was checked for exactly that and had none.
- **A Kerberoastable service account on the second server.** Its SPNs would have been in the same
  `GetUserSPNs` output; nothing there cracked.
- **A writable share or a scheduled task.** The share sweep covered `WS26` only, because the hash was
  local. On the second server the readable `Backup` share was there all along and was skipped: the
  listing without the domain prefix made it look empty.

## 6.6 What the box teaches

1. **Read the token first.** `whoami /priv` turned a normal user into local Administrator in one step;
   everything else in this lab follows from that line.
2. **Pivot before you enumerate the domain.** `SRV22` was invisible until the tunnel existed. On a
   three-host set, the first host is a doorway, not a destination.
3. **Loot is not access — until it is.** A database of hashes and an RDP profile produced nothing.
   A backup share produced a local Administrator hash, and that hash was the way in.
4. **BloodHound is for confirmation, not for hope.** It told the truth — the path exists — and it also
   told the truth that the path needs an account that was not available.
5. **Bank what you have.** One flag and a clear write-up beats a half-finished domain and no notes.

---

The wall was real from `WS26`, and only from `WS26`. The next chapter picks the same second server up
with a domain-qualified credential, and the share that produced nothing here produces the hash that
finishes the set.

**Next:** [`07-backup-share.md`](07-backup-share.md) · [README.md](README.md)
