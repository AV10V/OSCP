import com.sun.jdi.Bootstrap;
import com.sun.jdi.ClassType;
import com.sun.jdi.Method;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.ReferenceType;
import com.sun.jdi.ThreadReference;
import com.sun.jdi.Value;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;

import java.util.Collections;
import java.util.Map;

public class JdiVmSuspend {
    public static void main(String[] args) throws Exception {
        AttachingConnector conn = null;
        for (AttachingConnector c : Bootstrap.virtualMachineManager().attachingConnectors()) {
            if ("com.sun.jdi.SocketAttach".equals(c.name())) {
                conn = c;
            }
        }
        Map<String, Connector.Argument> cargs = conn.defaultArguments();
        cargs.get("hostname").setValue("127.0.0.1");
        cargs.get("port").setValue("8000");
        VirtualMachine vm = conn.attach(cargs);
        System.out.println("[*] attached to " + vm.name() + " " + vm.version());

        vm.suspend();
        ThreadReference thread = null;
        for (ThreadReference t : vm.allThreads()) {
            if ("main".equals(t.name())) {
                thread = t;
                break;
            }
        }
        System.out.println("[*] thread=" + thread.name()
                + " suspended=" + thread.isSuspended()
                + " frames=" + thread.frameCount());

        ReferenceType rt = vm.classesByName("java.lang.Runtime").get(0);
        Method getRuntime = null;
        for (Method m : rt.methodsByName("getRuntime")) {
            if (m.signature().equals("()Ljava/lang/Runtime;")) {
                getRuntime = m;
            }
        }
        ObjectReference rtObj = (ObjectReference) ((ClassType) rt).invokeMethod(
                thread, getRuntime, Collections.<Value>emptyList(), 0);
        System.out.println("[*] Runtime = " + rtObj);
        vm.resume();
        vm.dispose();
    }
}
