# 07 — Flags, cleanup and lessons

| Step | Runs on |
|---|---|
| 7.1 Proof capture | target |
| 7.2 Cleanup | target, then Kali |
| 7.3 Lessons | — |
| 7.4 Remediation | — |

---

## 7.1 Proof capture

**On the target** — both flags in one pass, each read by the identity that is allowed to read it:

```bash
echo "user : $(cat /home/dev/local.txt)"
echo "root : $(cat /tmp/r_proof)"
ls -la /home/dev/local.txt /root/proof.txt
```

```
user : 6851d85c0e1e82991b98fa6e146532fd
root : 43d31153587be5031d1db3f9a934eb46
-rw-r----- 1 dev  dev  33 Nov 15 23:34 /home/dev/local.txt
-rw-r--r-- 1 root root 33 Nov 15 23:34 /root/proof.txt
```

`/root/proof.txt` was read through the JDWP invocation in chapter 06 — the `cat` ran as root, not as
`dev`, which is why the file's `root:root` ownership was never an obstacle.

| Flag | Value | Obtained as |
|---|---|---|
| `local.txt` | `6851d85c0e1e82991b98fa6e146532fd` | `dev` (uid 1001), from the Text4Shell shell |
| `proof.txt` | `43d31153587be5031d1db3f9a934eb46` | root (uid 0), from `Runtime.exec` inside the root JVM |

## 7.2 Cleanup

Everything the exploit dropped lives in `/tmp` and is owned by `dev`. The root JVM only ever wrote
files we named explicitly, so there is nothing to hunt for outside those paths.

**On the target**

```bash
rm -f /tmp/JdiBreakExec.java /tmp/JdiBreakExec.class /tmp/jdwp_rce.py \
      /tmp/r_id /tmp/r_proof /tmp/r_ls /tmp/r_flag \
      /tmp/v_id /tmp/v_proof /tmp/jdwp_probe /tmp/jdwp_probe3 \
      /tmp/jdwp_local_ok /tmp/jdi_touch_ok /tmp/jdwp_touch_ok /tmp/jdwp_bash_ok \
      /tmp/jdb_out /tmp/ev_all.txt /tmp/ev_app.txt

ls -la /tmp | grep -E 'Jdi|jdwp|r_id|r_proof|ev_' || echo "clean"
```

**On Kali**

```bash
# stop the listeners started in chapters 03, 04 and 06
#   ncat -lv 4445            (reverse shell)
#   python3 cap_server.py    (OOB capture)
#   python3 -m http.server   (payload delivery)
pkill -f 'ncat -lv 4445'
pkill -f 'cap_server.py'
pkill -f 'http.server 8888'

rm -rf ~/t4s ~/jdwp
```

One thing that is **not** cleaned, because it cannot be: the root JVM on port 8000 still has its
debug agent open, and the shell we came in through is a child of the application. Killing that
process would take the box's service down; the lab is rebuilt between attempts, so it was left
alone deliberately.

## 7.3 Lessons

**1. A blind injection needs a side effect, not a reflection.**
`{"query":"…","result":""}` was identical for every payload. Six classic in-band probes returned
nothing. The bug was found by making the server *do* something (fetch a URL) and *take time*
(sleep). When the response is a fixed shape, stop looking at the response.

**2. An echo is not an evaluation.**
The endpoint prints the parameter it received, not the string it interpolated. Those are two
different strings, and the one that mattered was the one that never came back. "My payload appears
verbatim in the response" proves nothing about whether it was also handed to a template engine.

**3. Version defaults are the vulnerability.**
`commons-text-1.8` is not "outdated" in the usual sense — it is a released, correct library whose
*default* interpolator includes `script`, `url` and `dns`. Nothing was misconfigured in code; the
mistake was using a default that is dangerous when the input is untrusted. The CHANGELOG in
`/opt/dev` says it was added for "String Interpolation", which is exactly what made it exploitable.

**4. JDWP invocation has a precondition nobody states.**
`isSuspended() == true`, `frameCount() == 9`, and `INVALID_THREAD` anyway. The thread must be
suspended **by an event**. This is the difference between `jdb`, a hand-written protocol client and
`VirtualMachine.Suspend` all failing and a breakpoint succeeding.

**5. Breakpoints only fire on *entry*.**
`ServerSocket.accept` was the perfect breakpoint and never fired, because the thread was already
inside it. Driving the code path — one TCP connection to port 5000 — is part of the exploit, not a
workaround.

**6. Compile for the runtime, not the compiler.**
`javac 18.0.2-ea` on a `java 11.0.16` target produces class file 62 against a maximum of 55. The
error is explicit (`UnsupportedClassVersionError`), but only if you actually read it; `--release 11`
is the fix. Check `javac -version` **and** `java -version` on any Java target before building
anything.

**7. Loopback services belong in the enumeration.**
`nmap` from outside saw 22, 5000 and 8080. `ss -ltnp` from inside added `127.0.0.1:8000` — the only
thing on the host that turns a user shell into root. Every post-foothold checklist should include a
listener sweep, and every loopback listener should be explained before it is dismissed.

## 7.4 Remediation

| Issue | Fix |
|---|---|
| CVE-2022-42889 | Upgrade Commons Text to **1.10.0+**, or build the sub­stitutor with an explicit lookup allow-list and no `script`/`url`/`dns` |
| Untrusted input interpolated | Never pass request parameters to `StringSubstitutor.replace()`; validate and reject `${…}` on search input |
| JDWP exposed | Remove `-Xdebug -Xrunjdwp:…` from production launch flags |
| Debug agent running as root | If remote debugging is genuinely required: bind to a management interface behind a firewall, keep `suspend=n`, never run it as root |
| Root service with a debug port | Run the stats service as an unprivileged user, so a debug agent (or any RCE in it) is not an instant root |

The deeper point: either of these alone is a finding, but the pair is a full compromise. A
vulnerable library got an unprivileged shell; a debug flag on a root process turned it into root.
Neither was a "misconfiguration" in the sense of a setting someone changed — both were defaults
someone accepted.
