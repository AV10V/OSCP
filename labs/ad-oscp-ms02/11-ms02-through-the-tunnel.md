# 11 — MS02 through the tunnel

MS02 is the host pass 2 spent six chapters on. In this pass it is reachable through the tunnel
for the first time, so it gets a full scan — and then the pass walks past it. This chapter records
what it exposed, the clock problem it created, and why it was not the way in.

---

## 11.1 The scan

```bash
nmap -p- -T4 --min-rate 10000 --max-retries 2 -n -Pn -sC -sV -A 10.10.131.148
```

```
Nmap scan report for 10.10.131.148
Host is up (0.056s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC

Host script results:
|_clock-skew: 26m04s
|_nbstat: NetBIOS name: MS02, NetBIOS user: <unknown>, NetBIOS MAC: fa:16:3e:3c:33:5f (unknown)
| smb2-time:
|   date: 2026-11-26T05:18:26
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 228.09 seconds
```

The retransmission warning and the timing-stats lines are omitted. The host drops everything
else — consistent with a host firewall — which is why `65528` ports are `filtered` rather than
`closed` and why the scan took nearly four minutes.

---

## 11.2 Reading the ports

| Port | Service | What it means here |
|---|---|---|
| `135`, `49664`, `49667` | MSRPC | endpoint mapper and dynamic RPC — enumeration surface, no credential |
| `139`, `445` | SMB | file sharing; signing **enabled but not required** |
| `5040` | unknown | a Windows service port; not enough banner to identify it |
| `5985` | WinRM | a shell for anyone in `Remote Management Users` |

The capture's all-port scan is **incomplete**, and a follow-up pass proves it. A second
`nmap -sV` over the same tunnel (2026-11-25 21:38) found two more listeners:

| Port | Service | Detail |
|---|---|---|
| `1433` | `ms-sql-s` | **Microsoft SQL Server 2019 15.00.2000** |
| `5986` | WinRM over TLS | `Microsoft HTTPAPI httpd 2.0` (SSL) |

Both were missing from the first run, which reported `65528` filtered ports. Treat that output as
evidence of what it saw, not as an inventory: when a host firewall drops packets instead of
resetting, an `-p-` sweep is timing-dependent, and this one had already spent 228 seconds.

`1433` changes the picture. The SQL service that pass 2 built chapters 03 and 07 around **is**
exposed in this instantiation, and `eric.wallows` holds a login on it — the follow-up spray
authenticated as `oscp.exam\Eric.Wallows:EricLikesRunning800`. Whether that login is `sysadmin`
was **not** checked here, so the `xp_cmdshell` road is open in principle and unmeasured.

`signing enabled but not required` is the one configuration worth flagging: it makes MS02 a valid
relay target in principle. Nothing was coerced into authenticating during this pass, so it stayed
a note rather than a path.

---

## 11.3 The 26-minute clock

`nmap` reports `clock-skew: 26m04s`, and `smb2-time` puts the host at
`2026-11-26T05:18:26Z` while Kali is at `2026-11-25 20:49 PST`. Kerberos rejects any request
more than five minutes off the KDC, so every Kerberos operation will fail until this is fixed.

The obvious tools did not work:

```bash
sudo rdate -n 10.10.131.148
```

```
rdate: Not enough valid responses received in time
rdate: Unable to get a reasonable time estimate
```

```bash
sudo ntpdate -u 10.10.131.148
```

```
ntpdig: no eligible servers
```

`ntpdate` is `ntpdig` on this Kali, and MS02 is not offering time service on the query port. With
the target unreachable as a time source, the clock was moved by hand:

```bash
sudo date -s "$(date -d '+0 hour 26 minutes 04 seconds' '+%Y-%m-%d %H:%M:%S')"
```

```
Wed Nov 25 09:21:36 PM PST 2026
```

That aligns Kali with the host to within a few seconds. It is a lab workaround, not a fix: the
clock will drift again, and on a real engagement setting the system time by hand can break
tickets, logs and file timestamps in ways that are harder to diagnose than the skew. Prefer a
reachable NTP source, or correct only the offset when the tooling allows it.

---

## 11.4 Why MS02 was not needed

MS02 was reachable, enumerated, and no attack on it appears in this capture. That is not an
oversight — the credential that finishes the set was already in hand:

- the DCC2 entry in chapter 09 is the **domain** Administrator, so it applies to DC01 directly;
- the SQL login on `1433` was never tested for `sysadmin`, so it was an unknown, not a lead;
- attacking MS02 would have added a hop, not removed one.

Pass 2 reached the opposite conclusion for a different position: with DC01 direct, MS02 was the
only host whose token could be escalated, so `sql_svc` was the plan. Here the plan is unnecessary
— and that is the useful comparison. The "second hop" is not always on the path.

| Host | Address | State after this chapter |
|---|---|---|
| MS01 | `10.10.131.147` | SYSTEM, local admin add in place |
| MS02 | `10.10.131.148` | reachable · enumerated · **no attack in this capture** |
| DC01 | `10.10.131.146` | not contacted yet — credential in hand |

**A road not taken, and where it starts.** MS02's *local* Administrator password does not have to
be cracked. In another pass over this same set it was sitting in a console history file. As
`Administrator` on MS01:

```powershell
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd
C:\users\support\admintool.exe cmd
shutdown /s /t 7
```

An administrator ran a helper that takes the local-admin password as an argument, and `PSReadLine`
kept the line. Sprayed with **local** authentication, that password opens MS02 as
`MS02\Administrator`; MS02's own `SECURITY` hive then hands over the domain Administrator through
`DefaultPassword` and the same DCC2 entry seen in chapter 09.

**This was not run in this pass.** It is recorded because it is the cheapest demonstration that
MS02's credential store is reachable without touching MS02's services at all — and because it
answers where that password comes from.

DC01 is next.
