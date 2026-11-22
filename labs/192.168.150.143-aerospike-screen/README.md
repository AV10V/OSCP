# 192.168.150.143 — `aerospike-screen` (Ubuntu 20.04.4)

| | |
|---|---|
| **IP** | `192.168.150.143` (reached over `tun0`, attacker `192.168.45.158`) |
| **Host** | `lab-pwk2-student-cl4-143-ubuntu20-aero-242-100` |
| **OS** | Ubuntu 20.04.4 LTS, kernel `5.4.0-104-generic` |
| **Open ports** | `21` vsftpd 3.0.3 · `22` OpenSSH 8.2p1 · `80/81/443` Apache 2.4.41 · `3000/3001/3003` Aerospike · `3306` MySQL · `5432` PostgreSQL 12.9–12.13 |
| **Difficulty** | Easy — one unauthenticated database, one setuid binary from 2017 |
| **Result** | `aero` → `root` (via CVE-2020-13151, then CVE-2017-5618) |
| **Flags** | `local.txt` — `8d0b2414df3c73b491d05711c000a9d6` · `proof.txt` — `7fd0bd2e18b52d791a6600fbd8e622b7` |

---

## TL;DR — the chain

```
nmap -p- → 10 open, 65525 *filtered*
  3000/3001/3003 unnamed + 3002 filtered  →  Aerospike default port block
        │  client.info_all("build") → 5.1.0.1   (fix: 5.1.0.3)
        ▼
CVE-2020-13151 — unauthenticated UDF registration
  udf_put(lua: io.popen) → client.apply() → command execution
        │
        ▼
uid=1000(aero)   ·   local.txt readable immediately
        │  no egress: /dev/tcp to attacker = BLOCKED, no wget, no reverse shell
        │  → move payloads over the database socket (chunked base64, hash-verified)
        ▼
SUID /usr/bin/screen-4.5.0      (dpkg says screen 4.8.0 — the *file* is 4.5.0)
  CVE-2017-5618: setuid screen creates its -L logfile without dropping privileges
     cd /etc && umask 000 && screen -D -m -L ld.so.preload …
        →  -rw-rw-rw- root:aero /etc/ld.so.preload
        →  but CRLF from the terminal logger → ld.so ignores '/…/libhax.so\r'
        →  mode 0666 lets us rewrite it clean, one LF
     screen -ls  →  preload loads libhax.so as root → constructor → rootcmd.sh
        │
        ▼
uid=0(root) → proof.txt   (+ ed25519 key for a TTY)
```

Four things make this box worth writing up:

1. **`filtered` is not `closed`, and the scan lies by omission.** 65525 ports are swallowed, including `3002` — which is part of the very daemon we exploit. A "nothing else is listening" reading of that output is wrong here.
2. **The published exploit refuses the box and calls it patched.** Exploit-DB 49067 gates on `5.1.0.0` and bails; the target is `5.1.0.1` against a `5.1.0.3` fix. Four lines of client code succeed where the wrapper fails closed.
3. **`dpkg -l screen` reports `4.8.0-1ubuntu0.1`; the setuid binary on the path is `screen-4.5.0`.** Every package-database-driven scanner will call this host clean. `ls -la /usr/bin/screen*` is the check that matters.
4. **The exploit worked and did nothing, twice.** screen's logger writes `\r\n`, so `ld.so` was asked to open `libhax.so\r` and silently ignored it. Only `cat -A` reveals it, and only the `0666` mode from `umask 000` allows the corrective rewrite.

> **Lab note.** This box was rebuilt twice during the engagement (`192.168.161.143` → `192.168.92.143` → `192.168.150.143`) while the VPN session kept being provisioned for the previous subnet. `192.168.150.143` is the address that was actually reachable, and it is the one all commands here were run against.

---

## Chapters

| | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | Full TCP sweep, the `filtered` distinction, service fingerprint, naming the unnamed port block |
| 02 | [Web enumeration](02-web-enumeration.md) | Pico CMS `3.0.0-alpha.2` under `/index/`, `/api/` 403, the nginx-on-Fedora vhost on 81, and what was left untested |
| 03 | [Aerospike](03-aerospike.md) | Identifying the daemon, reading `build=5.1.0.1`, CVE-2020-13151, and the broken version gate in 49067.py |
| 04 | [Foothold](04-foothold.md) | The Lua UDF, `client.apply()`, `local.txt`, and moving files over the database socket when the target cannot reach back |
| 05 | [Enumeration](05-enumeration.md) | setuid inventory, PwnKit refuted, Dirty Pipe refuted, the root cron, and the missing compiler |
| 06 | [Privilege escalation](06-privilege-escalation.md) | CVE-2017-5618 end to end — `umask 000`, `ld.so.preload`, the CRLF trap, the root constructor |
| 07 | [Flags & cleanup](07-flags-and-cleanup.md) | Proof, artefact removal, lessons, defensive notes |

---

## Corrections to the obvious reading

| Tempting conclusion | What was actually true |
|---|---|
| `ppp`, `nessus`, `cgms` on 3000/3001/3003 | nmap fallback guesses. It is Aerospike: service / fabric / (filtered info) / heartbeat. |
| "The exploit won't run → it's patched" | 49067's guard treats `5.1.0.0` as fixed. `5.1.0.1 < 5.1.0.3`, so the box is vulnerable and the wrapper is wrong. |
| `dpkg -l screen` → `4.8.0` → patched | The setuid binary is `screen-4.5.0`, symlinked as `/usr/bin/screen`. Package metadata ≠ on-disk program. |
| PwnKit is setuid, so it will land | `policykit-1 0.105-26ubuntu1.3` is the fixed build. Refuted. |
| Kernel 5.4 → Dirty Pipe | CVE-2022-0847 requires 5.8+. Refuted. |
| The root cron every minute is the path | Plausible — `/opt/aerospike/bin` is `aero`-owned — but **not tested**. Recorded as an alternate, not as solved. |
| `screen -L` wrote the file, so we are done | It wrote **CRLF**; `ld.so` ignored every entry. The `0666` mode allowed a clean rewrite, which is what made it work. |
| `/etc/ld.so.preload` is gone → exploit failed | The payload deletes it on purpose, so child processes cannot re-enter `system()`. Absence is success. |
| Reverse shell first, always | No egress: `/dev/tcp` to the attacker is blocked and there is no compiler. Files travelled over the Aerospike socket. |

---

## Defensive notes

- **Aerospike 3000 had no authentication.** Enable security, create users, and keep 3000–3003 off any untrusted network. Upgrade past `5.1.0.3`, where the Lua runtime is sandboxed.
- **`udf_put` is a code-upload interface.** Anything that can reach it can run code as the daemon's user. Restrict who can call it and alert on new module names.
- **`/etc/ld.so.preload` should not exist on a normal host.** Its creation is a compromise indicator; a setuid binary creating it is the exploit.
- **Do not ship a setuid `screen`** — and never an old one. `chmod u-s /usr/bin/screen*`. If setuid is unavoidable, drop privileges before honouring a caller-controlled path or umask.
- **Reconcile package metadata against on-disk binaries.** `dpkg -l` would have called this host patched while a 2017 setuid binary sat on `$PATH`.
- **Keep `local.txt` out of service accounts' reach.** A database daemon's user could read it, which handed over half the flags on the first foothold.
