# 02 — Web enumeration

One application, one route that matters, one parameter. The interesting part of this chapter is not
finding the parameter — it is working out that **the response tells you nothing**, and that every
in-band test is therefore worthless.

| Step | Runs on |
|---|---|
| 2.1 Route sweep | Kali |
| 2.2 Parameter discovery | Kali |
| 2.3 Response shape | Kali |
| 2.4 In-band probes | Kali |
| 2.5 Framework identification | Kali |

---

## 2.1 Route sweep

A quick loop over the paths worth trying on any Spring Boot target — actuator endpoints, Swagger,
a versioned API, the error controller:

**On Kali**

```bash
for u in "" api api/search search search/ actuator health info swagger-ui/index.html v3/api-docs error; do
  printf "%-22s " "/$u"
  curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' -m 8 "http://192.168.237.150:8080/$u"
done
```

```
/                      200 19
/api                   404 124
/api/search            404 131
/search                200 25
/search/               200 25
/actuator              404 129
/health                404 127
/info                  404 125
/swagger-ui/index.html 404 142
/v3/api-docs           404 132
/error                 500 105
```

**Reading it:**

- Only `/` and `/search` exist. `/search/` also answers — Spring MVC matches a mapped route with a
  trailing slash, which is a useful tell that this is a controller mapping and not a static file.
- No actuator (`/actuator`, `/health`, `/info` all 404). So no `env`, no `heapdump`, no
  `/actuator/gateway` — the easy Spring Boot wins are closed.
- No Swagger. No `/api` prefix. The whole API is one route.

Direct access to `/error` returns 500 rather than the usual 999-status whitelabel page:

**On Kali**

```bash
curl -sS "http://192.168.237.150:8080/error"
```

```
{"timestamp":"2026-11-16T01:47:05.883+0000","status":999,"error":"None","message":"No message available"}
```

`status: 999` is Spring Boot's `ErrorController` default for a direct hit — confirms Spring Boot,
adds nothing exploitable.

## 2.2 Parameter discovery

`/search` clearly wants something. Guessing the usual names and looking for which one changes the
echo:

**On Kali**

```bash
for p in q query search term name s text input keyword; do
  printf "%-8s -> " "$p"
  curl -sS -m 8 "http://192.168.237.150:8080/search?$p=zzMARKERzz"
  echo
done
```

```
q        -> {"query":"*","result":""}
query    -> {"query":"zzMARKERzz","result":""}
search   -> {"query":"*","result":""}
term     -> {"query":"*","result":""}
name     -> {"query":"*","result":""}
s        -> {"query":"*","result":""}
text     -> {"query":"*","result":""}
input    -> {"query":"*","result":""}
keyword  -> {"query":"*","result":""}
```

**Reading it:** exactly one name is consumed — `query`. Everything else is ignored and the handler
falls back to a default of `*` (which is why the "echo" is `*` for the misses). Two facts worth
keeping:

- The parameter name is `query`, not the `q` you would guess.
- **The default is `*`**, so `GET /search` with no parameters returns `{"query":"*","result":""}` —
  a wildcard search, presumably.

## 2.3 Response shape

Every request returns the same 200 with a two-field JSON object:

```bash
curl -sS -i "http://192.168.237.150:8080/search?query=test"
```

```
HTTP/1.1 200 
Content-Type: text/plain;charset=UTF-8
Content-Length: 25
Date: Mon, 16 Nov 2026 01:47:05 GMT

{"query":"test","result":""}
```

`result` is **always** an empty string — for `test`, for `*`, for garbage, for everything. And
`query` is the input echoed back byte-for-byte, including the characters that would have been
consumed by any evaluation.

## 2.4 In-band probes

The standard first round on a parameter that ends up in a template or expression language:

**On Kali**

```bash
for p in '${7*7}' '#{7*7}' '${sys:java.version}' '${env:PATH}' '${date:yyyy-MM-dd}' '{{7*7}}' "a' OR '1'='1"; do
  printf '%-22s => ' "$p"
  curl -sS -m 8 -G --data-urlencode "query=$p" "http://192.168.237.150:8080/search"
  echo
done
```

```
${7*7}                 => {"query":"${7*7}","result":""}
#{7*7}                 => {"query":"#{7*7}","result":""}
${sys:java.version}    => {"query":"${sys:java.version}","result":""}
${env:PATH}            => {"query":"${env:PATH}","result":""}
${date:yyyy-MM-dd}     => {"query":"${date:yyyy-MM-dd}","result":""}
{{7*7}}                => {"query":"{{7*7}}","result":""}
a' OR '1'='1           => {"query":"a' OR '1'='1","result":""}
```

A naive reading is "nothing is evaluated — no 49, no `11.0.16`, no `/usr/local/sbin:...`". That
reading is **wrong**, and the mistake it invites is the whole lesson of this box:

> The handler prints the parameter it *received*, not the string it interpolated. The echo proves
> only that the input was stored and returned unchanged — it says nothing about whether a second,
> discarded copy of that string was evaluated.

So neither result is informative:

| Observation | Wrong conclusion | Actual meaning |
|---|---|---|
| `${7*7}` echoed as `${7*7}` | "no expression language" | the *result* of interpolation is not reflected |
| `result` always `""` | "the search returned nothing" | `result` is not derived from the query at all |

In-band testing is a dead end here. What we need is a **side effect** — something the server does
that we can observe from outside, without the response carrying it back. That is chapter 03, and it
starts from a library name.

## 2.5 Framework identification

Assembling what the responses have said so far:

| Evidence | Conclusion |
|---|---|
| `/search/` also matches | Spring MVC controller mapping |
| `/error` → `{"timestamp":...,"status":999,...}` | Spring Boot `BasicErrorController` |
| `Content-Type: text/plain;charset=UTF-8` + JSON body | handler returns a `String`/map, not a view |
| nmap favicon fingerprint `Spring Java Framework` | Spring Boot, embedded Tomcat |
| no actuator, no Swagger | deliberately minimal application |
| `${...}` in the response | input is passed to something that speaks `${prefix:name}` |

That last row is the one to pull on. In a Java/Spring application, `${prefix:name}` is not SpEL —
Spring's own expression language uses `#{...}`. The `${prefix:name}` form with a colon is the
**Apache Commons Text `StringSubstitutor`** lookup syntax: `${sys:java.version}`, `${env:PATH}`,
`${url:UTF-8:http://...}`, `${script:javascript:...}`.

Versions 1.5–1.9 of Commons Text ship that interpolator with the `url`, `dns` and `script` lookups
enabled by default — **CVE-2022-42889, "Text4Shell"**.

The hypothesis is now specific: a Java application that takes `query` and calls
`StringSubstitutor.replace(query)` on an affected Commons Text version will execute
`${script:javascript:...}`. To prove it we need to see a side effect. → [03 — Text4Shell](03-text4shell.md)
