# 05 — Local enumeration and the dead ends

Goal: find out *why* the reflexive escalation fails, and pick the primitive that actually fits this
token.

---

## 5.1 The reflexive attempt, and its exact failure

```
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: 1346 The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

```
meterpreter > getuid
Server username: OSCP\offsec
```

**1346 is `ERROR_BAD_IMPERSONATION_LEVEL`** — "either a required impersonation level was not
provided, or the provided impersonation level is invalid". In practice, for `getsystem`, it means the
current token cannot impersonate a SYSTEM token because it does not hold
**`SeImpersonatePrivilege`**. Every one of the six techniques in that list needs the same thing, which
is why all six failed identically.

This is the single most useful error in the whole box. It is not "try harder with the same tool" —
it is "this primitive is unavailable, change class of attack".

---

## 5.2 Confirm it from the token itself

```cmd
whoami /priv
whoami /groups
net localgroup administrators
```

Read three things:

| Look for | Meaning |
|---|---|
| `SeImpersonatePrivilege` present | a potato (PrintSpoofer / GodPotato / JuicyPotatoNG) works — one step to SYSTEM |
| `BUILTIN\Administrators` in `whoami /groups` | you are an admin; the only obstacle is UAC (`Medium Mandatory Level`) |
| Neither | standard user: you need a *local privilege escalation*, not a token theft |

On this host it was the third case: `offsec` is a plain local user, no impersonate privilege, not a
member of the local administrators group. That is also why `getsystem` printed 1346 rather than
succeeding on the RPCSS variant.

> If you only remember one thing from this box: **potatoes are not a privilege-escalation technique,
> they are a way to use a privilege you already have.** Without `SeImpersonate*`, skip them entirely.

---

## 5.3 What was checked and came back empty

These are the standard first-pass checks on a Windows foothold. They are listed because "I looked" is
not evidence — each one has a specific *reading* that closes it off.

```cmd
whoami /priv
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
type "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log"
```

| Check | What a hit looks like | Why it did not help here |
|---|---|---|
| Unquoted service paths | a path with spaces, unquoted, in a directory `Users` can write | no such service on this image |
| `AlwaysInstallElevated` | `0x1` under **both** HKLM and HKCU | not set |
| PowerShell history | typed credentials or admin commands | nothing usable |
| PuTTY sessions | hostnames and usernames for lateral movement | no saved sessions with credentials |
| Cloudbase-Init log | the image's injected admin password | present on the box, but not the shortest path once PrintNightmare was confirmed |

Note what is *not* on that list and why:

- **Hijacking MouseServer's own DLLs** (`lum_sdk32.dll` on the sibling image) is pointless. The
  process runs in `offsec`'s session, so a hijacked DLL gives you `offsec` again.
- **`w3wp.exe`** is interesting but needs the port, and the web app was never identified. A `tcpConnTable`
  walk from SNMP (chapter 02) would have named it; that is the faster route than guessing.

---

## 5.4 Enumerate patches, not versions

Build 19041 tells you "Windows 10 2004". It does not tell you whether the June/July 2021 cumulative
updates are installed, and that single fact decides whether PrintNightmare works.

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"
wmic qfe list brief | findstr /i "5004945 5004954 5005565"
```

- `KB5005565` (September 2021) and later contain the Point-and-Print hardening that breaks the
  standard exploit path.
- `KB5004945` / `KB5004954` (July 2021) are the out-of-band PrintNightmare patches.
- **An empty `Hotfix` list on a build-19041 image** is the answer you want: nothing was ever applied.

Metasploit automates this triage:

```
background
use post/multi/recon/local_exploit_suggester
set SESSION 14
run
```

It returns named modules — `exploit/windows/local/cve_2021_1675_printnightmare`, various
`bypassuac_*`, and so on — with a confidence marker per module. Use it to *confirm* the theory you
already formed, not instead of forming one.

---

## 5.5 The decision

| Route | Requirement | Status on this box |
|---|---|---|
| Potato (`SeImpersonate`) | the privilege | **not held** — 1346 proves it |
| UAC bypass | membership in Administrators | not a member |
| Unquoted path / writable service | a misconfigured service | none found |
| `AlwaysInstallElevated` | both registry keys | not set |
| **PrintNightmare** | Spooler running + unpatched | **`spoolsv.exe` confirmed via SNMP, 19041 unpatched** |

One column is green, and it was green before the shell ever landed: SNMP had already told us
`spoolsv.exe` was running. That is the payoff of enumerating processes properly in chapter 02.
