# 01 — Reconnaissance: one routable host, two networks

This set is not a box, it is a domain. `oscp.exam` sits behind a dual-homed member server, and the
first job was to work out which parts of it I could actually reach from Kali.

## 1.1 Host discovery

```bash
nmap -sn 192.168.118.0/24 -oG - | grep -i up | awk '{print $2}'
```

```
192.168.118.147
192.168.118.149
192.168.118.150
192.168.118.151
192.168.118.254
```

Five live addresses. `.254` is the gateway. Working each target down:

| Host | Identity | Bearing on this chain |
|---|---|---|
| `192.168.118.147` | Windows Server 2019 build 19041, `MS01.oscp.exam` | **the door** — domain-joined, dual-homed |
| `192.168.118.149` | Ubuntu, only 21/22/80 | credential-gated, nothing anonymous |
| `192.168.118.150` | Ubuntu, Spring Boot API on 8080 | separate box |
| `192.168.118.151` | Windows Server 2019, `WORKGROUP` | separate box, not domain-joined |
| `192.168.118.254` | gateway | infrastructure |

Only `.147` is domain-joined, so only `.147` can lead into the domain.

## 1.2 Ports that matter

```bash
nmap -p- --min-rate 2000 -T4 -oN scans/ms01-allports.txt 192.168.118.147
nmap -sVC -p 445,5985 -oN scans/ms01-services.txt 192.168.118.147
```

> Full scan output is not committed — `scans/` is in `.gitignore`. The two ports below are the only
> ones that changed the next step.

| Port | Service | What it gave |
|---|---|---|
| 445/tcp | SMB | hostname `MS01`, domain `oscp.exam`, **signing: False** |
| 5985/tcp | WinRM | the way in, once a credential existed |

The SMB fingerprint is one command and tells you the shape of the whole set:

```bash
nxc smb 192.168.118.147
```

Condensed from the session:

| Field | Value |
|---|---|
| Hostname | `MS01` |
| Domain | `oscp.exam` |
| OS | Windows Server 2019 build 19041 |
| SMB signing | `False` |

Two things to carry forward: the host is a **domain member**, and SMB signing is **off** — which is
a relay opportunity, and also a hint that the set was built to be attacked from the middle, not from
the edge.

## 1.3 The network that is not there

`DC01.oscp.exam` is the domain controller. It is not in `192.168.118.0/24`, and there is no route to
it from Kali: the lab hands out a route for the Kali-facing subnet only, so packets aimed at
`10.10.118.0/24` leave `tun0` and die at the gateway.

That is confirmed later, from the other side — `ipconfig /all` on MS01 shows a **second NIC** on
`10.10.118.0/24` with `10.10.118.146` as its DNS server. The DC is one hop away from MS01 and
invisible from Kali. Everything after the foothold is therefore a pivoting problem before it is an
Active Directory problem.

## 1.4 The starting credential

The set is provisioned with one domain account:

| Account | Secret | Rights |
|---|---|---|
| `OSCP\eric.wallows` | `EricLikesRunning800` | domain user — **not** a local administrator |

Checked over SMB before anything else:

```bash
nxc smb 192.168.118.147 -u eric.wallows -p 'EricLikesRunning800'
```

```
SMB         192.168.118.147  445    MS01    [+] oscp.exam\eric.wallows:EricLikesRunning800
```

`[+]` with **no** `(Pwn3d!)` — the credential authenticates, and that is all it does over SMB. The
same account is a member of `BUILTIN\Remote Management Users`, which is the more interesting fact:
it is enough to open a WinRM session without being an administrator anywhere.

That is the whole reconnaissance result: one host, one valid credential, one service that turns the
credential into a shell.

## 1.5 Gotchas

- `-d oscp` for NTLM-facing tools (`nxc`, `hydra`); `-d oscp.exam` for Kerberos-facing ones
  (`certipy`, `impacket` with `-k`). Mixing them produces authentication errors that look like bad
  passwords.
- The NetBIOS name is `OSCP`, the DNS domain is `oscp.exam`. `whoami` returns `oscp\eric.wallows`
  even though nothing in the DNS namespace is called `oscp`.
