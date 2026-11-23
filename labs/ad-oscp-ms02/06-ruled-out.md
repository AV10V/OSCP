# 06 — What is ruled out

This page is published **at the state of the engagement, not at the end of it.** This chapter is the
negative half: everything that has been tested and closed, each with the evidence that closed it. The
next chapter is the plan.

Recording negatives properly is not bookkeeping. Seven paths were eliminated here, and each one
cost a command; without this page they get re-tested.

---

## 6.1 What is owned

| Item | Evidence |
|---|---|
| WinRM shell on MS02 as `celia.almeda` | chapter 02 |
| Three domain credentials | chapters 01, 04 |
| Read access to DC01 `NETLOGON` / `SYSVOL` / `Users` | chapter 04 |
| A complete map of the directory | chapter 05 |

No host is at SYSTEM. No domain admin has been obtained. `proof.txt` has not been read.

---

## 6.2 The closed list

| Path | Evidence it is closed |
|---|---|
| SMB share access on MS02 | `ADMIN$` and `C$` return **no permissions** for `web_svc` |
| WinRM privilege escalation | token is **medium integrity**, not local admin — see 6.3 |
| Potato family (`PrintSpoofer`/`GodPotato`) | requires `SeImpersonate` — **absent** from the token |
| SQL sysadmin | `IS_SRVROLEMEMBER('sysadmin')` = **`0`** for both SQL logins |
| `xp_cmdshell` | needs `sysadmin`/`CONTROL SERVER` — unavailable at `0` |
| ACL abuse | **zero** outbound ACEs across the entire directory |
| Delegated group membership | none of our accounts is in `ADMIN`, `IT`, `FINANCE`, `HR`, `MARKETING`, `IIS_IUSRS` |
| LAPS | not deployed — `haslaps=false` on all three computers |
| Session theft / relay | **no sessions observed** on any computer |

---

## 6.3 The most important negative

The WinRM one deserves its own paragraph, because it is the reflex that would otherwise be tried
first — it is what took MS01 in the previous leg.

`whoami /priv` on MS02 shows exactly five privileges: `SeShutdown`, `SeChangeNotify`, `SeUndock`,
`SeIncreaseWorkingSet`, `SeTimeZone`. No `SeImpersonatePrivilege`.

That alone is enough. But the stronger form of the argument is that the token *could not* have been an
administrator's: UAC remote restrictions filter only **local** accounts, so a **domain** account in the
machine's local `Administrators` group would receive a full privileged token over WinRM. Neither
`BUILTIN\Administrators` nor the admin privilege set appears. Therefore `celia.almeda` is not a local
administrator on MS02, and no privilege-escalation primitives exist in this token.

---

## 6.4 Two mechanical blockers

Both remaining actions are blocked by the same pair of host misconfigurations, not by anything in the
target:

```bash
# 1. name resolution - Kerberos needs a name, not an IP
echo '10.10.152.140 DC01.oscp.exam oscp.exam' | sudo tee -a /etc/hosts

# 2. clock skew - Kerberos rejects >5 minutes' drift
sudo ntpdate -u 10.10.152.140
date -u
```

Until both are fixed, every roast fails with `KRB_AP_ERR_SKEW` and every collection silently degrades to
NTLM — which is exactly what happened in chapter 04, and why the session data in chapter 05 is empty.

---

## 6.5 Status

| Host | Address | State |
|---|---|---|
| MS02 | `10.10.152.142` | **foothold** — WinRM as `celia.almeda`, medium integrity |
| DC01 | `10.10.152.140` | **unowned** — reachable, shares readable, no escalation |
| MS01 | — | known to the directory, address not captured in this leg |

| Objective | State |
|---|---|
| Local admin on MS02 | not obtained |
| SYSTEM on MS02 | not obtained |
| Domain admin | not obtained |
| `proof.txt` | not read |

The engagement is a credential problem now. Everything that could be done with the tokens in hand has
been done and closed; what remains requires an account we do not have, and chapter 07 is where that
account is expected to come from.
