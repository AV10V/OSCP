# 07 — Cleanup and lessons

Nothing on this box needed a patch, and nothing needed a reboot. One configuration line and one
privilege assignment were the entire attack surface — which makes both the cleanup and the
recommendation short.

| Step | Runs on |
|---|---|
| 7.1 Remove what was staged | Kali → target |
| 7.2 Close listeners | Kali |
| 7.3 Remediation for the host owner | — |
| 7.4 Lessons | — |

---

## 7.1 Remove what was staged

Five files were created during the engagement. Everything else in `chris`'s temp directory was
already there before the box was touched and is left alone.

**On Kali**

```bash
python3 1.py 192.168.137.151 "cmd /c del /q C:\Users\chris\AppData\Local\Temp\proof_out.txt C:\Users\chris\AppData\Local\Temp\rev4446.ps1 C:\Users\chris\AppData\Local\Temp\run4446.bat C:\Users\chris\AppData\Local\Temp\id.txt C:\Users\chris\AppData\Local\Temp\sys_out.txt 2>&1"
```

`del` prints nothing on success, so the reply is `-ERR no reply` — which, as chapter 02 established,
is what a successful silent command looks like. Verify instead of assuming:

**On Kali**

```bash
python3 1.py 192.168.137.151 "cmd /c dir /b C:\Users\chris\AppData\Local\Temp\proof_out.txt 2>&1"
```

```
File Not Found
```

`File Not Found` is the correct answer here, and it is the same string an empty directory produces —
which is precisely why the verification has to name the file rather than a directory.

The SYSTEM shell on port 4448 is closed by killing the listener, which terminates the `cmd.exe`
holding the connection:

**On Kali**

```bash
pkill -f "nc -lvnp 4448"
```

## 7.2 Close listeners

```bash
pkill -f "nc -lvnp"
ss -ltnp | grep -E ':44(4[0-9])'
```

No process survived the engagement: GodPotato's children were started by `CreateProcessAsUser` and
died with their parent shell, and no scheduled task, service or Run key was created. There is nothing
to remove from the target beyond the files in 7.1.

## 7.3 Remediation for the host owner

| Issue | Fix |
|---|---|
| ESL reachable from the network with the default password | set a strong `password` in `conf/autoload_configs/event_socket.conf.xml` |
| No source restriction on 8021 | uncomment and set `apply-inbound-acl`, or bind `listen-ip` to `127.0.0.1` |
| The PBX service account holds `SeImpersonatePrivilege` | remove the privilege from `OSCP\chris`; a PBX service has no legitimate need for it |
| The PBX runs as a normal user account | run it as a dedicated low-privilege service account with no interactive logon |
| Full offensive toolset present in a user profile | remove it; its presence shortened the escalation to a single command |

The first two are the ones that matter. Even with a strong password, a service account holding
`SeImpersonatePrivilege` on an unpatched-ACL host is a SYSTEM shell waiting for a local invocation —
but it would have required code execution first, which is exactly what the default password handed
over for free.

## 7.4 Lessons

**Read the protocol before reading the exploit.** Two hours of this box were spent on `-ERR no
reply` — a string that means "no stdout", not "failed". Every failed payload in chapter 05 was
diagnosed correctly only after the wrapper's output semantics were understood. When a management
interface answers in a fixed vocabulary, learn the vocabulary first.

**A successful exploit log is not a successful exploit.** GodPotato printed
`CurrentUser: NT AUTHORITY\SYSTEM` and `Find System Token : True` on four attempts that produced
nothing. The token was obtained every time; the child process was the failure. Log lines describe
what the tool did, not what the operator got.

**Choose the simplest child process.** `nc64.exe -e cmd.exe` worked on the first try after a
PowerShell script, a batch file and a nested `cmd /c` all failed. `.exe` launching `.exe` with
positional arguments has the fewest moving parts, and it is the one form `CreateProcessAsUser`
reliably executes.

**`%VAR%` describes the wrong process.** `%USERNAME%` was expanded by the outer `cmd.exe` before the
escalation ran, so a SYSTEM-written file reported `USERNAME=chris`. Identity claims have to come from
the elevated process itself, or from an access control decision it can make and `chris` cannot — the
`HKLM\SECURITY` read in chapter 05 is a better proof than any `whoami`.

**Verify with output, not with silence.** `del`, `cd` and `dir /b` on an empty directory all produce
no stdout or `File Not Found`, and over a stdout-only interface those are indistinguishable from a
typo. Every verification step in this walkthrough names a file, prints a value, or redirects `2>&1`.

**Escalation by privilege is quieter than escalation by exploit.** No CVE was used on this box. The
foothold was a default password, and the escalation was a privilege the account already held —
`SeImpersonatePrivilege` on a high-integrity service token. Both are configuration decisions, and
neither appears in a patch list.
