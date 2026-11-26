# 07 — The set, end to end

## 7.1 Full chain

```
provided creds ─ WinRM ─▶ WS01 (andrew)
      │
      ├─ config.php ─▶ MySQL (offsec_user) ─▶ bcrypt table       ✗ decoy
      └─ winPEAS ────▶ env var *_PASSWORD ─▶ local Administrator
                            │
                            ├─ proof.txt  (WS01)
                            └─ secretsdump ─▶ OSCP.EXAM\perry : SurfaceConditionMove441
                                              (and perry's NT hash)
                            │
                    ligolo-ng route 172.16.91.0/24
                            │
                            ├─ BloodHound ─▶ perry --WriteMembers--> HELPDESK USERS
                            ├─ bloodyAD / net rpc group addmem ─▶ perry added
                            └─ SRV22 (Pwn3d!) ─▶ Confidential.kdbx
                                      │
                              keepasscracker + rockyou
                                      │
                              KeePassXC: 4 entries
                                      │
                     BloodHound: Domain Admins ─▶ GALLAGHER
                                      │
                     nxc winrm spray ─▶ BackupPassword2024 (Pwn3d!)
                                      │
                              evil-winrm on DC20
                                      │
                              C:\Users\Administrator\Desktop\proof.txt
```

## 7.2 What each credential was actually for

| Credential | Where it came from | What it unlocked |
|---|---|---|
| `andrew:BussOff@theRiv3r` | provided at start | WinRM on WS01 |
| `offsec_user:OffSec_2024` | `config.php` | MySQL — dead end |
| `WS01\Administrator:Work3sValueable444` | winPEAS env var | local admin, WS01 proof, LSASS/LSA dump |
| `perry:SurfaceConditionMove441` (+ hash) | lsassy / secretsdump | BloodHound, ACL write, SRV22 |
| `Confidential.kdbx` password `12/05/2015` | keepasscracker + rockyou | the KeePass vault |
| `GALLAGHER:BackupPassword2024` | KeePass `AD` entry | Domain Admin, DC20 proof |

## 7.3 The three "traps" in this set

1. **The database.** `offsec_db.users` is a wall of bcrypt. It is there to eat an hour. The box's real
   weakness is an environment variable.
2. **The Administrator password.** It is a *local* password. It gets you WS01 and its LSA secrets —
   not the domain. Testing it as `oscp.exam\administrator` goes nowhere, which is why the next step is perry's account.
3. **The KeePass entries.** All four look like they belong to `administrator@oscp.exam`. None works
   for the domain `administrator`. The correct move is to check who the Domain Admins actually are,
   then re-try the same four passwords against *that* account.

## 7.4 What made the box fast

| Step | Time cost | Why it pays |
|---|---|---|
| `winPEAS` first | 2 min | replaced a full manual privesc enumeration |
| `nxc -M lsassy` right after admin | 2 min | hash + cleartext for the next hop |
| BloodHound after the first domain user | 5 min | found the `WriteMembers` edge nobody would guess |
| `net rpc group addmem` | 1 min | membership change instead of a password attack |
| `keepasscracker` + rockyou | 3 min | a human-chosen date, not a random password |
| Domain Admins check before spraying | 1 min | turned 4 useless passwords into a DA login |

## 7.5 Gaps in these notes

Honest list of what these notes do **not** pin down:

- SRV22's IP address (the SMB output line is cut on the left).
- The exact `smbclient` / `--get-file` command used to pull `Confidential.kdbx`.
- The keepasscracker repository's full URL (only the tail is readable).
- The KeePass master password's year (`2015` vs `2005` vs `2013`).
- Whether the `bloodyAD` run or the `net rpc` run is the one that actually added the member — both
  appear; `net rpc` is the one that succeeds cleanly with the password.
