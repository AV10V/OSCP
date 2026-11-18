# 05 — Host enumeration

Two minutes of enumeration decides the next hour. Everything here runs from the `dev` shell and the
answer is visible in the first `ps` — but it is worth doing the full sweep, because the *reason*
the obvious paths are closed is what makes a loopback debug port the correct target rather than a
gamble.

| Step | Runs on |
|---|---|
| 5.1 Identity and platform | target |
| 5.2 Processes and listeners | target |
| 5.3 Application and filesystem | target |
| 5.4 The dead-end checklist | target |
| 5.5 Source review | target |

---

## 5.1 Identity and platform

**On the target**

```bash
id
grep PRETTY /etc/os-release
uname -r
java -version 2>&1 | head -1
javac -version 2>&1
```

```
uid=1001(dev) gid=1001(dev) groups=1001(dev)
PRETTY_NAME="Ubuntu 22.04.1 LTS"
5.15.0-52-generic
openjdk version "11.0.16" 2022-07-19
javac 18.0.2-ea
```

**Reading it:**

- **Ubuntu 22.04.1, kernel 5.15.0-52** — recent enough that local kernel exploits are a research
  project, not a step. Nothing here is a kernel bug box.
- **The JVM is 11.0.16 — and `javac` is 18.0.2-ea.** A JDK 18 compiler with a Java 11 runtime is a
  mismatch that will bite in chapter 06: anything compiled with the default `javac` targets class
  file version 62, which Java 11 refuses to load. `javac --release 11` is mandatory.
- Java 11 still bundles **Nashorn**, which is why the `script:javascript:` lookup worked in
  chapter 03.

## 5.2 Processes and listeners

This is the command that ends the box:

**On the target**

```bash
ps -eo user,pid,args | grep '[j]ava'
```

```
dev          680 java -jar /opt/dev/api.jar
root         698 java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
```

**Reading it:** a **root-owned** JVM with a **JDWP debug agent** listening on socket 8000. JDWP has
no authentication — anything that can open a TCP connection to that port is a debugger, and a
debugger can invoke arbitrary methods in the JVM. As root.

The listener inventory confirms it is loopback-only:

**On the target**

```bash
ss -ltnp 2>/dev/null | sed 's/  */ /g'
```

```
State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 1 127.0.0.1:8000 0.0.0.0:*
LISTEN 0 100 *:8080 *:* users:(("java",pid=680,fd=11))
LISTEN 0 128 [::]:22 [::]:*
LISTEN 0 50 *:5000 *:*
```

Which closes the loop on chapter 01: **port 5000 is the root process's own socket**, bound to all
interfaces, which is why nmap saw it from outside and why it printed JVM memory statistics. And
`127.0.0.1:8000` is reachable **only** from localhost — which is fine, because we are localhost.

## 5.3 Application and filesystem

**On the target**

```bash
ls -la /opt/dev /opt/stats
```

```
/opt/dev:
total 16992
drwxr-xr-x 2 root root     4096 Nov  7  2022 .
drwxr-xr-x 4 root root     4096 Nov  7  2022 ..
-rw-r--r-- 1 root root 17383754 Nov  7  2022 api.jar
-rw-r--r-- 1 root root      195 Nov  7  2022 CHANGELOG

/opt/stats:
total 12
drwxr-xr-x 2 root root     4096 Nov  7  2022 .
drwxr-xr-x 4 root root     4096 Nov  7  2022 ..
-rw-r--r-- 1 root root     1076 Nov  7  2022 App.java
```

Both directories are world-readable, including the source of the root process. That is unusual
enough to read carefully.

**On the target**

```bash
cat /opt/dev/CHANGELOG
python3 -c "import zipfile;print('\n'.join(n for n in zipfile.ZipFile('/opt/dev/api.jar').namelist() if 'commons-text' in n))"
```

```
# Changelog

Version 0.2
- Added Apache Commons Text 1.8 Dependency for String Interpolation

Version 0.1
- Initial beta version based on Spring Boot Framework
- Added basic search functionality

BOOT-INF/lib/commons-text-1.8.jar
```

**Reading it:** the root cause, in the vendor's own words. Version 0.2 added **Commons Text 1.8**
"for String Interpolation" — the exact version, the exact feature, and the exact CVE range from
chapter 03. The `query` parameter is interpolated server-side, the result is discarded, and the
response echo was always a red herring.

## 5.4 The dead-end checklist

Before committing to the debug port, everything conventional:

**On the target**

```bash
sudo -n -l 2>&1 | head -3
find / -perm -4000 -type f 2>/dev/null | grep -v '^/snap'
getcap -r / 2>/dev/null
grep -E 'sh$' /etc/passwd
```

```
sudo: a password is required
/usr/libexec/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/umount
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/snap/core20/1405/usr/bin/ping cap_net_raw=ep
/snap/core20/1634/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:user:/home/user:/bin/bash
dev:x:1001:1001:,,,:/home/dev:/bin/bash
ubuntu:x:1002:1003:Ubuntu:/home/ubuntu:/bin/bash
```

| Vector | Result |
|---|---|
| `sudo -n -l` | password required → dead |
| SUID | **stock Ubuntu only** — `passwd`, `su`, `mount`, `pkexec`, `sudo`… → dead |
| Capabilities | stock `ping`/`mtr-packet`/`gst-ptp-helper` → dead |
| Users | `dev` is the only non-root account we can use; `user`/`ubuntu` have no shells we can reach |
| Kernel | 5.15.0-52 — no cheap local root |
| Cron | not used; nothing writable by `dev` found |

Every traditional local-privilege path is closed. That matters, because it means the root debug
agent is not a shortcut chosen out of laziness — it is the only thing on the box that crosses the
privilege boundary, and it is deliberate.

## 5.5 Source review of the root process

`/opt/stats/App.java` is world-readable. It is also the file the root JVM was launched with:

**On the target**

```bash
cat /opt/stats/App.java
cat /proc/698/cmdline | tr '\0' ' '; echo
```

```java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

class StatsApp {
    public static void main(String[] args) {
        System.out.println("System Stats\n");
        Runtime rt = Runtime.getRuntime();
        String output = new String();

        try {
            ServerSocket echod = new ServerSocket(5000);
            while (true) {
              output = "";
              output += "Available Processors: " + rt.availableProcessors() +"\r\n";
              output += "Free Memory: " + rt.freeMemory() + "\r\n";
              output += "Total Memory: " + rt.totalMemory() +"\r\n";

              Socket socket = echod.accept();
              InputStream in = socket.getInputStream();
              OutputStream out = socket.getOutputStream();
              out.write((output + "\r\n").getBytes());
              System.out.println(output);
            }
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
}
```

```
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
```

**Reading it:**

- The class opens `ServerSocket(5000)` and loops: print stats → `accept()` → write stats → repeat.
  It never reads the request (`in` is assigned but unused). That is the service from chapter 01.
- It is launched as a **single-file source program** — `java ... /opt/stats/App.java`, no `App.class`,
  no jar. Java 11 supports this, and it explains why the source is still sitting on disk.
- `server=y` on the JDWP agent means the process listens for a debugger and — because `suspend` is
  not specified — the default `suspend=y` applies, meaning it waits for a debugger to attach before
  running `main`. It is not currently waiting (the service works), so something already went through
  or the default was overridden at packaging time. Either way, the port is open and authenticated
  by nothing.

Two independent wins on one host: an unpatched library reachable over HTTP, and a root debug port
reachable from any local account. The first is how we got here; the second is how we leave as root.
→ [06 — Privilege escalation](06-privilege-escalation.md)
