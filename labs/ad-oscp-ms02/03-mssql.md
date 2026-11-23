# 03 — MSSQL: two logins, no sysadmin

MS02 runs SQL Server, and two of the accounts we hold are SQL logins on it. This chapter records the
test that decides whether SQL is an escalation path or a dead end — and, because it came back negative,
what that rules out precisely.

---

## 3.1 Who we are in SQL

The prompt itself is the first finding:

```
SQL (OSCP\web_svc  guest@master)>
```

Read right to left: database `master`, host `guest`, login `OSCP\web_svc`. And `guest` is MS02 — the
same box the WinRM shell is on, not a separate database server. The same session run as the other
account gives the mirror image:

```
SQL (OSCP\celia.almeda  guest@master)>
```

Two independent domain accounts, both with a SQL login on the same instance.

---

## 3.2 The only question that matters

```sql
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
```

```
-   -
0   0
```

And as celia:

```sql
SQL (OSCP\celia.almeda  guest@master)> SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-   0
```

The decisive column is `IS_SRVROLEMEMBER('sysadmin')` — **`0` for both logins.** Neither is a member of
`sysadmin`.

One note on reading this output: the first column came back as `0` rather than the login name, and the
prompt (`OSCP\web_svc`, `OSCP\celia.almeda`) is the authoritative statement of identity here. The
sysadmin answer is unaffected by that quirk — it is the second value, and it is zero in both cases.

---

## 3.3 What `sysadmin = 0` actually closes

This is worth being exact about, because "not sysadmin" is not "no SQL attack surface".

Closed:

- `xp_cmdshell` execution — it requires `sysadmin` or `CONTROL SERVER`;
- `sp_configure` changes — same requirement;
- reading other databases' data — a login without `sysadmin` only sees what it has been granted;
- `EXECUTE AS LOGIN = 'sa'` — impersonation needs an explicit `IMPERSONATE` grant.

Still open, and deliberately not yet exercised:

- **`xp_dirtree` / `xp_fileexist`** — executable by `public` by default. Pointing `xp_dirtree` at an
  SMB listener coaxes the **SQL service account** into an outbound NTLM authentication, which is a
  credential from a different security context than either login we hold. This is the single most
  promising remaining SQL primitive, and it requires no privilege at all.
- **`IMPERSONATE` grants** — checked per-login, not per-role; a specific grant could exist even with
  role membership at zero.
- **Linked servers** — `sp_linkedservers` may expose a second instance with different rights.

Both of those are queries to run, not findings. This chapter does not claim either returned anything.

---

## 3.4 The escalation that would have mattered

Had either login been `sysadmin`, the chain would have been:

```
sysadmin → xp_cmdshell → runs as the MSSQL service account → whoami /priv
         → SeImpersonate on the service account? → SYSTEM on MS02
```

Note the shape of it: `xp_cmdshell` does not run as *you*. It runs as the account the SQL service is
configured with. That is why a SQL login is worth more than its own rights suggest — it is a way to
borrow someone else's token. With `sysadmin = 0` for both accounts, that borrowing is unavailable.

---

## 3.5 Position after this chapter

| Path | Result |
|---|---|
| SQL sysadmin (`web_svc`) | **no** |
| SQL sysadmin (`celia.almeda`) | **no** |
| `xp_cmdshell` | unavailable without sysadmin |
| `xp_dirtree` hash capture | **untested** — available to `public` |
| Linked servers / IMPERSONATE | **untested** |

Combined with chapter 02, the local picture on MS02 is now:

| Local path | Status |
|---|---|
| SMB shares (`web_svc`) | dead — `ADMIN$`/`C$` empty |
| WinRM privesc (`celia.almeda`) | dead — no `SeImpersonate`, medium integrity |
| SQL sysadmin (either login) | dead — `0` / `0` |

MS02 does not fall from anything we can do **on** MS02. Whatever remains is in the directory, which is
chapter 04.
