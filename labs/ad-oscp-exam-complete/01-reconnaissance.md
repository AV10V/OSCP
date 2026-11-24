# 01 — Reconnaissance: one routable host, two networks

## 1.1 What Kali can see

The set is delivered as a single reachable address. Everything else lives on a second NIC
inside MS01, which is why a sweep of the visible subnet returns one host and not three.

```bash
sudo nmap -sn 192.168.133.0/24 -oG -            # who answers
sudo nmap -Pn -p- --min-rate 2000 192.168.133.153 -oN ms01-alltcp.txt
```

**Captured** — the ports that mattered:

| Port | Service | Note |
|---|---|---|
| 445 | SMB | signing **not required** → NTLM relay is possible |
| 5985 | WinRM | the way in for a domain user |
| 3389 | RDP | present, not needed |
| 135 / 139 | RPC / NetBIOS | support services |
| 8000 | HTTP | IIS site, runs as `web_svc` (chapter 04) |

`smb signing:False` is worth noting early: it makes MS01 a viable relay target even though
it does not end up being the path used.

## 1.2 Host identity without credentials

SMB and WinRM both leak the host name and domain before authentication:

```bash
nxc smb 192.168.133.153
nxc winrm 192.168.133.153
```

**Captured**:

```
SMB   192.168.133.153 445  MS01  [*] Windows 10 / Server 2019 Build 19041 x64
                                 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:None)
```

Three facts follow immediately: the host is a **member server**, not a DC (a DC would answer
on 88 and 389 too); the domain is `oscp.exam`; and SMB signing is off.

## 1.3 The second NIC

This is the finding that shapes the whole engagement. `ipconfig` on MS01 — which requires a
shell, so it lands in chapter 02 — shows two interfaces:

| Interface | Address | Reachable from Kali |
|---|---|---|
| Kali-facing | `192.168.133.153` | yes |
| Internal | `10.10.133.153` | no |

So `10.10.133.0/24` holds MS02 (`.154`) and DC01 (`.152`), and neither will ever answer a
scan from Kali. Any enumeration of the domain has to be tunnelled through MS01 — chapter 05.

## 1.4 What the scan does *not* tell you

Two negative results that matter later:

- **No `88/tcp` on MS01.** Kerberos is a DC service. Confirming it is absent on the member
  server is how you know the KDC lives elsewhere, and therefore that any kerberoasting must be
  pointed at DC01 explicitly with `-dc-ip`.
- **No MSSQL on MS01.** The database instances (`1433`, `49700`) are on MS02 only. This is the
  detail that makes chapter 06 the natural route to the domain rather than a detour.

## 1.5 Findings that set up later chapters

| Observation | Consequence | Used in |
|---|---|---|
| SMB signing not required | relay feasible against MS01 | noted, unused |
| WinRM open | domain user can get a shell if in Remote Management Users | 02 |
| `:8000` HTTP | IIS app pool identity — a service account with an SPN | 04 |
| Second NIC `10.10.133.153` | pivot required | 05 |
| No 88 on MS01 | KDC is DC01, roast with `-dc-ip 10.10.133.152` | 06 |

## 1.6 Time skew — check this before any Kerberos work

The internal hosts drift. A skew beyond five minutes makes every Kerberos operation fail with
`KRB_AP_ERR_SKEW` while NTLM keeps working, which reads like a credential problem and is not.

```bash
nmap -p445 --script smb2-time 10.10.133.152      # DC is the time authority
sudo rdate -n 10.10.133.152 && date -u
```

**Captured** — MS02 was **+18m23s** ahead of Kali. Revert the clock when the engagement ends.
