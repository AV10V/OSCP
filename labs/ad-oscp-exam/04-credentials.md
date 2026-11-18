# 04 — Credentials: what LSASS would and would not give

SYSTEM on a member server is usually worth a domain credential, and a domain credential is usually
worth a hop. This chapter is the check that decides whether that assumption holds.

## 4.1 The failure that explains itself

Before escalating, mimikatz was run from the unprivileged WinRM session:

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

It failed with `0xC0000061` — `STATUS_PRIVILEGE_NOT_HELD`. `sekurlsa` needs to open `lsass.exe` with
`PROCESS_VM_READ`, and that needs `SeDebugPrivilege`. Chapter 02 already showed the privilege was
absent from the token, so this was never a tooling problem: `privilege::debug` had nothing to enable.

That is the useful part of the error. A `0xC0000061` is not "mimikatz is blocked"; it is "this token
cannot read LSASS", and the fix is a token that can.

## 4.2 The same command as SYSTEM

From the `nt authority\system` shell:

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

`privilege::debug` now succeeds, `lsass.exe` opens, and the dump completes. The result, recorded
honestly:

| Looked for | Found |
|---|---|
| Domain Admin NTLM hash | **no** |
| Domain Admin cleartext | **no** |
| `krbtgt` material | no |
| Reusable service-account credential | nothing that granted new rights |

No credential with domain-wide rights came out of LSASS on MS01.

## 4.3 Why that is a real answer, not a bad dump

It is worth ruling out the boring explanations before concluding anything:

- The dump ran **as SYSTEM**, so the handle to LSASS was not the blocker (4.1 proved that).
- `sekurlsa::logonpasswords` enumerates every logon session the host knows about. A DC that has
  never logged on to MS01 cannot leave a DA credential there.
- MS01 is a member server with a single interactive user (`eric.wallows`). Nothing in the set's
  design puts a Domain Admin on it.

So the negative is structural: MS01 is a **stepping stone, not a vault**. The domain tier has to be
reached from a host that actually holds domain-tier material, or through a misconfiguration in AD
itself.

## 4.4 If mimikatz is blocked

The fallback that avoids touching LSASS with a signed binary at all is a full dump and an offline
read:

```powershell
.\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

```powershell
.\mimikatz.exe "sekurlsa::minidump C:\Windows\Temp\lsass.dmp" "sekurlsa::logonpasswords" exit
```

The dump is large and it is a credential artefact — it stays on the host and is deleted during
cleanup. It is never copied back to Kali or committed anywhere.

## 4.5 What the negative changes

- Do not spend time cracking MS01's local hashes hoping for reuse; the useful next step is the
  **network behind MS01**, not its SAM.
- Do not assume DA lives on the DC only — a second member server (MS02) is the more likely holder of
  a privileged session, because administrators log on to servers they manage.
- BloodHound becomes the tool of choice: `AdminTo`, `CanPSRemote`, and ACL edges from
  `ERIC.WALLOWS` describe the intended path through the domain without guessing.

Chapter 05 builds the route to the hosts that can answer those questions.
